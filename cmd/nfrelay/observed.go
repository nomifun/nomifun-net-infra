package main

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/console"
)

// 学习模式的观测存储。
//
// # 它交付的承诺
//
// 「一键收窄暴露面」：一条隧道刚建好时 allow_cidrs 通常是空的（放行一切），
// 而运维并不知道该填什么 —— 真实客户端的地址他手上没有。学习模式把中继
// **实际观测到**的来源攒起来，让他据此收窄。此前这个承诺只交付了一半：
// 前端有客户端方法与类型，后端两个端点都不存在。
//
// # 为什么只在内存里，且**绝不落库**
//
// 这些是运行时观测到的**第三方地址**。库会被 store.Backup 备份、事件表会被
// 支持包外发，而支持包的用途恰恰是发给别人看（见 handleSupportBundle）。
// 一条「谁在什么时候连过这台中继」的记录进到那份文件里就是一次信息泄露，
// 而且泄的不是我们的信息。
//
// 代价是**重启即清空**，这一点必须在界面上说清 —— 一份看起来完整但其实
// 只攒了五分钟的列表，一键应用下去会把所有还没露面的客户端锁在门外。
//
// # 为什么必须有上限，而且上限被截断时要能看出来
//
// 键是**来源 IP**，由任何能连上来的人指定。没有上限就是一个可被外部驱动的
// 内存耗尽面（与 loginguard、udpflow 会话表同一类问题）。
//
// 但这里比那两处多一个要求：截断必须**可见**。一份被截断过的列表拿去
// 「一键收窄」会写出一个不完整的白名单，把没上榜的真实客户端全部锁死 ——
// 而现象是「我点了一下推荐按钮，然后一半客户端连不上了」。所以
// truncated 一路传到界面，界面据此换成一条警告而不是一个推荐。
const (
	// learnMaxPerTunnel 是每条隧道最多记多少个来源前缀。
	//
	// 256 条：一个家庭/工厂部署的真实客户端数量远低于此，
	// 而一次端口扫描会瞬间打满它 —— 那正是 truncated 要告诉运维的事。
	learnMaxPerTunnel = 256

	// learnMaxTunnels 是最多跟踪多少条隧道。
	//
	// 隧道 ID 由中继分配（不是攻击者指定的），所以这个上限只是防
	// 「删了又建几万条」之后表不回落；到顶时拒绝**新增**而不是驱逐旧的，
	// 因为旧条目正是运维可能正在看的那些。
	learnMaxTunnels = 512
)

// learnedSource 是一条被观测到的来源前缀。
type learnedSource struct {
	prefix netip.Prefix
	hits   uint64
	first  time.Time
	last   time.Time
}

// tunnelObservations 是一条隧道的观测集合。
type tunnelObservations struct {
	sources map[netip.Prefix]*learnedSource
	since   time.Time
	// truncated 一旦为真就**不再翻回假**：它记录的是「这份列表曾经不完整」，
	// 而那件事不会因为后来腾出了空位而变得无害 —— 被挤掉的那个客户端
	// 已经不在列表里了。
	truncated bool
	declined  bool
}

// observedSources 是全中继的学习模式存储。并发安全。
type observedSources struct {
	mu      sync.Mutex
	tunnels map[string]*tunnelObservations

	// nowForTest 让测试控制时间；生产恒为 nil。
	nowForTest func() time.Time
}

func newObservedSources() *observedSources {
	return &observedSources{tunnels: make(map[string]*tunnelObservations)}
}

func (o *observedSources) now() time.Time {
	if o.nowForTest != nil {
		return o.nowForTest()
	}
	return time.Now()
}

// learnPrefix 把一个观测到的地址归一成要记下来的前缀。
//
// IPv4 → /32，IPv6 → /64。
//
// IPv6 不用 /128 是因为住宅 IPv6 客户端会在自己的 /64 里换地址
// （SLAAC 隐私扩展，Windows 与 Android 默认每天换）。按 /128 收窄的白名单
// 在几小时内就会把同一个用户锁在门外，而现象是「昨天还能用」——
// 那种失效比不收窄糟得多。/64 是运营商分给一个用户的最小单位，
// 收窄到它既真实又稳定。
//
// 这也与 loginguard 的 /64 归并一致：同一份判断在仓库里只有一种答案。
func learnPrefix(addr netip.Addr) (netip.Prefix, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	// 只滤掉未指定地址（0.0.0.0 / ::）。
	//
	// # 为什么**不**滤回环与链路本地
	//
	// 第一版滤了，理由是「它们不是外部客户端，把 127.0.0.1 推荐进白名单会让
	// 运维以为收窄生效了」。那个理由是错的：allow_cidrs 里有 127.0.0.1/32
	// 之后，**所有非回环来源都会被拒**——那不是「没有约束」，
	// 而是可能的最强约束。链路本地同理，fe80::/10 是局域网客户端的真实来源。
	//
	// 滤掉它们还有一个更实际的代价：本机部署与开发环境里所有流量都来自
	// 回环，于是这个功能在那些环境下**永远是空的**，而看到空列表的人
	// 会得出「学习模式坏了」的结论。
	//
	// 判据只有一条：中继**真的从这个地址接受过流量**，那它就是一个合法的
	// 观测。未指定地址不满足这一条（那不是任何一个真实对端的地址，
	// 出现它只意味着上游解析出了问题），所以只滤它。
	if addr.IsUnspecified() {
		return netip.Prefix{}, false
	}
	bits := 32
	if addr.Is6() {
		bits = 64
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// note 记一次观测。**只该在流量被放行之后调用**。
//
// 被 allow_cidrs 拒掉的来源不进列表：否则一条已经收窄过的隧道会把
// 每一个撞门的扫描器都攒进「推荐白名单」，而运维一键应用就是把
// 攻击者请进来。学习窗口内（allow_cidrs 为空、放行一切）扫描器仍然会上榜，
// 那是这个功能的固有局限 —— 界面靠命中次数与首见时间把判断交回给人，
// 而不是假装列表干净。
func (o *observedSources) note(tunnelID string, addr netip.Addr) {
	p, ok := learnPrefix(addr)
	if !ok || tunnelID == "" {
		return
	}
	now := o.now()

	o.mu.Lock()
	defer o.mu.Unlock()

	obs := o.tunnels[tunnelID]
	if obs == nil {
		if len(o.tunnels) >= learnMaxTunnels {
			return
		}
		obs = &tunnelObservations{
			sources: make(map[netip.Prefix]*learnedSource),
			since:   now,
		}
		o.tunnels[tunnelID] = obs
	}

	if s := obs.sources[p]; s != nil {
		s.hits++
		s.last = now
		return
	}
	if len(obs.sources) >= learnMaxPerTunnel {
		// 到顶：不再收新的，并把「这份列表不完整」永久记下来。
		//
		// 选「拒新」而不是「挤掉最旧」：挤掉最旧会让一次扫描把运维
		// 真正在找的那几个早期客户端全部冲走，而拒新至少保住它们。
		obs.truncated = true
		return
	}
	obs.sources[p] = &learnedSource{prefix: p, hits: 1, first: now, last: now}
}

// ObservedSources 取一条隧道的观测结果，实现 console.SourceObserver。
//
// 排序按「命中次数降序、然后 CIDR 升序」：运维要找的是「谁经常连」，
// 而次数相同时按字面排序让列表在两次刷新之间稳定 ——
// map 迭代顺序是随机的，不排的话列表每秒都在跳，勾选框根本没法用。
func (o *observedSources) ObservedSources(tunnelID string) (console.LearnedSources, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	obs := o.tunnels[tunnelID]
	if obs == nil {
		return console.LearnedSources{}, false
	}
	out := console.LearnedSources{
		TunnelID:     tunnelID,
		Sources:      make([]console.LearnedSource, 0, len(obs.sources)),
		ObservedFrom: obs.since,
		Truncated:    obs.truncated,
		Declined:     obs.declined,
	}
	for _, s := range obs.sources {
		out.Sources = append(out.Sources, console.LearnedSource{
			CIDR:      s.prefix.String(),
			Hits:      s.hits,
			FirstSeen: s.first,
			LastSeen:  s.last,
		})
	}
	slices.SortFunc(out.Sources, func(a, b console.LearnedSource) int {
		if a.Hits != b.Hits {
			return cmp.Compare(b.Hits, a.Hits)
		}
		return cmp.Compare(a.CIDR, b.CIDR)
	})
	return out, true
}

// DeclineLearnedSources 实现 console.SourceObserver。
func (o *observedSources) DeclineLearnedSources(tunnelID string) { o.decline(tunnelID) }

// 钉住 runtime 满足 console.SourceObserver。
//
// 这条断言不是形式主义：console 那两个端点是用**类型断言**取这个接口的
// （可选能力的既有模式），少一个方法不会编译失败，而是在运行时静默退化成
// 501「本中继版本不观测来源地址」—— 一个功能就这样消失，且没有任何日志。
var _ console.SourceObserver = (*runtime)(nil)

// 存储自己也要满足：runtime 的两个方法只是转发，而共享入口与 UDP 那两个
// 观测点直接拿 observedSources.note 当回调用。
var _ console.SourceObserver = (*observedSources)(nil)

// decline 记下「运维明确拒绝过这条隧道的推荐」，界面据此不再提示。
//
// 与观测数据同生命周期（重启即忘）：它是对**当前这份列表**的判断，
// 而重启之后列表本身也没了，再提示一次是对的。
func (o *observedSources) decline(tunnelID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	obs := o.tunnels[tunnelID]
	if obs == nil {
		obs = &tunnelObservations{
			sources: make(map[netip.Prefix]*learnedSource),
			since:   o.now(),
		}
		if len(o.tunnels) >= learnMaxTunnels {
			return
		}
		o.tunnels[tunnelID] = obs
	}
	obs.declined = true
}

// retain 只保留仍然存在的隧道，其余丢掉。每次 ApplyTunnels 后调用。
func (o *observedSources) retain(live map[string]bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for id := range o.tunnels {
		if !live[id] {
			delete(o.tunnels, id)
		}
	}
}
