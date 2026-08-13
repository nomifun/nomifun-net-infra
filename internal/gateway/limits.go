package gateway

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/nomifun/nomifun-net-infra/internal/limiter"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 共享入口上的每隧道限额。
//
// # 它补的是什么
//
// `policy` 的四项里此前只有 `allow_cidrs` 在共享入口上生效。
// `max_conns` / `max_conns_per_ip` / `bytes_per_second` 全链路可配（向导有输入框、
// 详情页显示「已设置」、库里存着），而共享入口路径上零读取点 —— 用户给一条
// 公网隧道配了 1 Mbps，界面确认「已设置」，它照样跑满。
//
// 那比没有这个功能糟糕得多：用户以为自己保护了一条暴露在公网的隧道。
//
// # 为什么状态必须活在路由表**之外**
//
// 这是这个文件存在的主要理由，也是最容易写错的一点。
//
// `applyShared` 每次都造一张新注册表再 `ReplaceWith` 整体替换，并对**每一条**
// 隧道调 `Invalidate`（cmd/nfrelay/shared.go）。而它由两处调用：`ApplyTunnels`
// 与 `refreshStates` —— 后者在**每次 agent 上下线**时都跑。
//
// 于是「把限额状态放进路由表、或者随 Invalidate 一起回收」会导致：
//
//   - **令牌桶每次 agent 抖动都被清零**。桶是初始满的，所以每次清零都送出一份
//     完整的突发额度。一个能让 agent 反复重连的人（拔网线就够）由此拿到
//     不受限的带宽 —— 限速变成了一个可被外部驱动关掉的开关。
//   - **在飞计数被清零而连接还开着**。释放路径会把一个已经归零的计数器再减，
//     计数变负或永久偏移，闸门从此要么恒开要么恒关。
//
// 所以：状态挂在 `Registry` 上一个 `ReplaceWith` **不碰**的字段里
//（Registry 是网关与判别器共享的**同一个实例**，且明确「换内容不换指针」），
// 回收走 `RetainLimits(仍然存在的隧道)`，而桶**只在策略数字真的变了时**才重建。

// limitSpec 是一条隧道限额的**取值**。
//
// 单独拎出来是为了回答「策略变了吗」这个问题：只有它变了才该重建桶。
// 拿 *tunnel.Tunnel 比对不行 —— ListTunnels 每次都新分配对象，指针必然不同，
// 而按整个对象深比会把「改了后端地址」也当成「限额变了」，
// 于是每次改后端都白送一份突发额度。
type limitSpec struct {
	maxConns         int
	maxPerIP         int
	bytesPerSecond   int64
	packetsPerSecond int64
}

func specOf(t *tunnel.Tunnel) limitSpec {
	if t == nil || t.Policy == nil {
		return limitSpec{}
	}
	return limitSpec{
		maxConns:         t.Policy.MaxConns,
		maxPerIP:         t.Policy.MaxConnsPerIP,
		bytesPerSecond:   t.Policy.BytesPerSecond,
		packetsPerSecond: t.Policy.PacketsPerSecond,
	}
}

func (s limitSpec) zero() bool { return s == limitSpec{} }

// tunnelLimits 是一条隧道在共享入口上的限额状态。并发安全。
type tunnelLimits struct {
	spec limitSpec

	// lim 是字节速率桶。**可原子替换**，nil 表示不限速。
	//
	// 每隧道一个、被这条隧道所有连接与请求共享 —— 用户设的是「这条隧道最多
	// 多少带宽」。每连接一个桶的话一百条连接就是一百倍带宽。
	//
	// # 为什么必须可替换，而且包装不能捕获它
	//
	// 把桶捕获在连接包装里的话，一条长命连接（WebSocket、splice 出去的裸 TCP，
	// 都可以活几天）会一直用建立那一刻的桶。而把 10 Mbps 调成 1 Mbps 的典型
	// 动机恰恰是压住**正在进行**的滥用 —— 那条连接却不受影响，而详情页显示的
	// 是新值「已设置」。那就是这一整轮要消灭的那类谎的残留。
	//
	// 所以：桶挂在这个**每隧道稳定**的对象上，包装持有的是这个对象，
	// 每次读写现取桶。改带宽于是对在飞连接立刻生效。
	lim atomic.Pointer[limiter.Limiter]

	// sem 是并发上限的信号量。nil 表示不限并发。
	sem chan struct{}

	// metered 是**经过这条隧道令牌桶结账**的字节总数。
	//
	// 存在的理由是「双重计费」这个失效形态没法用挂钟测出来：正确实现与
	// 双扣一遍只差一个倍数，而挂钟上界在 -race + 真 TCP 下不可靠
	//（本仓的限速测试通篇只用下界，理由写在 limiter_test.go 里）。
	// 有了它，「每个字节只被结账一次」就是一条确定性断言。
	//
	// 它也顺带回答了一个此前无法回答的问题：「我配的限速真的在起作用吗」——
	// TCP 路径上限速表现为变慢而不是丢弃，所以没有任何「被拒」计数器。
	metered atomic.Int64

	// maxPerIP 为 0 表示不额外按源 IP 限制。
	maxPerIP int
	perIPMu  sync.Mutex
	perIP    map[netip.Addr]int
}

func newTunnelLimits(s limitSpec) *tunnelLimits {
	tl := &tunnelLimits{spec: s}
	tl.setBucket(s)
	if s.maxConns > 0 {
		tl.sem = make(chan struct{}, s.maxConns)
	}
	if s.maxPerIP > 0 {
		// 每源 IP 配额大于全局上限时收敛到全局上限。
		//
		// 一个永远不触发的闸门比没有闸门更糟：用户以为自己配了保护。
		// 与独立监听器同一条规则（internal/relay/entry.go 的 maxPerIP）。
		tl.maxPerIP = s.maxPerIP
		if s.maxConns > 0 {
			tl.maxPerIP = min(s.maxPerIP, s.maxConns)
		}
		tl.perIP = make(map[netip.Addr]int)
	}
	return tl
}

// setBucket 按取值造/换字节桶。
//
// packets_per_second **刻意不传进来**：它的设计目标是 UDP 小包洪水，
// 而在 TCP/HTTP 上「包」这个概念不存在，它能限的只是「每次 read」——
// 那个语义没有任何用户能预期。与其做一个名字对、语义走形的版本，
// 不如让它在共享入口上明确不生效，并在界面与文档里说清。
func (tl *tunnelLimits) setBucket(s limitSpec) {
	tl.lim.Store(limiter.New(limiter.Limits{BytesPerSecond: s.bytesPerSecond}))
}

// denyReason 说明一次准入被哪一道闸拒了。
//
// 「拒了多少」没用，「在哪一道闸拒的」才告诉运维该调什么：
// 全局上限满 → 加容量；每源配额满 → 提每源上限或查那个源。
type denyReason string

const (
	// denyNone 表示放行。
	denyNone denyReason = ""
	// denyMaxConns 是这条隧道的全局并发上限满了。
	denyMaxConns denyReason = "max_conns"
	// denyPerIP 是这个源 IP 的配额满了。
	denyPerIP denyReason = "max_conns_per_ip"
)

// admit 申请一个并发额度。返回的 release **必须**被调用（用 defer）。
//
// 放行时 reason 为 denyNone；被拒时 release 是一个安全的空操作 ——
// 调用方无条件 defer release() 就不会写错，而「按返回值决定要不要 defer」
// 是这类代码最常见的漏释放形态。
func (tl *tunnelLimits) admit(src netip.Addr) (release func(), reason denyReason) {
	if tl == nil {
		return func() {}, denyNone
	}

	// 先要全局额度：它最便宜（一次 channel 非阻塞发送），
	// 而且被它拒掉时不需要碰 per-IP 那张表。
	if tl.sem != nil {
		select {
		case tl.sem <- struct{}{}:
		default:
			return func() {}, denyMaxConns
		}
	}

	if tl.maxPerIP > 0 {
		if !tl.acquirePerIP(src) {
			if tl.sem != nil {
				<-tl.sem
			}
			return func() {}, denyPerIP
		}
	}

	var once sync.Once
	return func() {
		// once：释放路径会被 defer 调用，而调用方可能在别处也调一次。
		// 多释放一次会把额度凭空造出来，那比漏释放更危险
		//（漏释放最终耗尽额度、可见；多释放让闸门静默失效）。
		once.Do(func() {
			if tl.maxPerIP > 0 {
				tl.releasePerIP(src)
			}
			if tl.sem != nil {
				<-tl.sem
			}
		})
	}, denyNone
}

func (tl *tunnelLimits) acquirePerIP(src netip.Addr) bool {
	tl.perIPMu.Lock()
	defer tl.perIPMu.Unlock()
	if tl.perIP[src] >= tl.maxPerIP {
		return false
	}
	tl.perIP[src]++
	return true
}

func (tl *tunnelLimits) releasePerIP(src netip.Addr) {
	tl.perIPMu.Lock()
	defer tl.perIPMu.Unlock()
	n := tl.perIP[src] - 1
	if n <= 0 {
		// **归零即删。** 键是源 IP，由任何能连上来的人指定 ——
		// 不删的话这张表只增不减，那是一个可被外部驱动的内存耗尽面。
		// 与独立监听器、loginguard、学习模式同一条纪律。
		delete(tl.perIP, src)
		return
	}
	tl.perIP[src] = n
}

// bucket 返回**当前**的字节速率桶（可能为 nil，表示不限速）。
//
// 每次读写都要调它而不是把结果存下来 —— 见 tunnelLimits.lim 的说明。
func (tl *tunnelLimits) bucket() *limiter.Limiter {
	if tl == nil {
		return nil
	}
	return tl.lim.Load()
}

// throttled 把一条连接包成受这条隧道限额约束的。
//
// 它持有 *tunnelLimits 而**不是**桶：桶每次现取，所以改带宽对已经建立的
// 连接立刻生效（WebSocket 与 splice 连接可以活几天）。
//
// 两个方向的记账时机刻意不对称，两者都对：
//   - 读侧**先读再等**：先等只能按 len(p) 申请，而实际读到的往往少得多，
//     于是限速会比配置值严好几倍。按实际读到的字节结账才准。
//   - 写侧**先等再写**：调用前就确切知道要写多少，先结账才准；
//     而且先写再等意味着字节已经出去了，限速变成「事后道歉」。
type throttled struct {
	net.Conn
	tl  *tunnelLimits
	ctx context.Context
}

// charge 为 n 字节结账（现取桶，所以改带宽立刻生效）。
func (tl *tunnelLimits) charge(ctx context.Context, n int) error {
	lim := tl.bucket()
	if lim == nil || n <= 0 {
		return nil
	}
	tl.metered.Add(int64(n))
	return lim.Wait(ctx, n)
}

func (c *throttled) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		// ctx 结束时把已读字节交出去，错误留给下一次 Read ——
		// 丢掉它们等于在一条 TCP 流中间挖一个洞。
		_ = c.tl.charge(c.ctx, n)
	}
	return n, err
}

func (c *throttled) Write(p []byte) (int, error) {
	if err := c.tl.charge(c.ctx, len(p)); err != nil {
		// 还没写，直接失败不会损坏任何东西（与读侧不对称，那是对的）。
		return 0, err
	}
	return c.Conn.Write(p)
}

// throttle 把一条连接的**两个方向**都接上限速，不需要时原样返回。
//
// 只给「两个方向承载的是不同字节」的挂点用 —— 网关路径的隧道侧连接就是那样：
// Read 是后端→客户端、Write 是客户端→后端，每个字节各自结账一次。
//
// **不要**用它包一条 splice 管道的两端：那时同一批字节会先过一端的 Read
// 再过另一端的 Write，被同一个桶结账两次，有效带宽减半 ——
// 「配了 1 Mbps 只跑 500 kbps」也是谎。那条路用 throttleRead。
func (tl *tunnelLimits) throttle(ctx context.Context, c net.Conn) net.Conn {
	if tl == nil || tl.bucket() == nil {
		return c
	}
	return &throttled{Conn: c, tl: tl, ctx: ctx}
}

// throttleRead 只给**读**侧接上限速，返回 io.Reader。
//
// 返回 io.Reader 而不是 net.Conn 是刻意的：它拿不去写，所以「一条管道的两端
// 都包一层」这个双重计费的写法根本写不出来。splice 的两个方向各自只在读侧
// 结账，每个字节因此只被算一次；等在读侧还能让反压自然传播回发送方的窗口。
func (tl *tunnelLimits) throttleRead(ctx context.Context, r io.Reader) io.Reader {
	if tl == nil || tl.bucket() == nil {
		return r
	}
	return &throttledReader{r: r, tl: tl, ctx: ctx}
}

type throttledReader struct {
	r   io.Reader
	tl  *tunnelLimits
	ctx context.Context
}

func (r *throttledReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		_ = r.tl.charge(r.ctx, n)
	}
	return n, err
}

// limitStore 按隧道 ID 持有限额状态。
type limitStore struct {
	mu       sync.Mutex
	byTunnel map[string]*tunnelLimits
}

func newLimitStore() *limitStore {
	return &limitStore{byTunnel: make(map[string]*tunnelLimits)}
}

// for_ 取一条隧道的限额状态，按需创建或重建。
//
// 完全不限额的隧道返回 nil —— 绝大多数隧道不配限额，不该为它们付任何代价
// （一次 map 查找已经是全部开销，连状态对象都不分配）。
func (s *limitStore) for_(t *tunnel.Tunnel) *tunnelLimits {
	if t == nil || t.ID == "" {
		return nil
	}
	spec := specOf(t)

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.byTunnel[t.ID]
	if spec.zero() {
		// 限额被改成「全不限」：把状态丢掉。
		//
		// 留着一个空状态无害，但丢掉之后 for_ 会走上面那条快路径，
		// 而且「表里有它」这件事就真的等于「它有限额」，读代码时少一层歧义。
		if ok {
			delete(s.byTunnel, t.ID)
		}
		return nil
	}
	if ok {
		if cur.spec == spec {
			// **策略没变就复用。** applyShared 在每次 agent 上下线时都会跑
			// 一遍，若这里无条件重建，令牌桶会被清零（桶初始是满的 →
			// 每次抖动白送一份突发额度），在飞计数也会与还开着的连接脱节。
			return cur
		}
		if cur.spec.maxConns == spec.maxConns && cur.spec.maxPerIP == spec.maxPerIP {
			// 只有带宽变了：**原地换桶，保住这个对象**。
			//
			// 保住对象有两个后果，都是要的：已经建立的连接（它们持有这个对象）
			// 立刻用上新速率；在飞的并发计数不被重置。
			// 换对象则相反 —— 老连接一直跑旧桶，而新旧两个信号量并存时
			// 有效并发上限短时变成「旧 + 新」。
			cur.spec = spec
			cur.setBucket(spec)
			return cur
		}
		// 并发参数变了：信号量容量无法原地改，只能换对象。
		// 在飞的请求持着旧对象的额度，所以有效上限会短暂变成「旧 + 新」——
		// 它有界且自愈（旧对象随最后一个 release 被 GC），如实记在文档里。
	}
	fresh := newTunnelLimits(spec)
	s.byTunnel[t.ID] = fresh
	return fresh
}

// retain 只保留仍然存在的隧道，其余丢掉。
//
// 由 applyShared 在同步完路由表之后调用。**不能**挂在 Invalidate 上 ——
// 那个每次 apply 都会对每条隧道调一遍，等于每次 agent 抖动清零一次。
func (s *limitStore) retain(live map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.byTunnel {
		if !live[id] {
			delete(s.byTunnel, id)
		}
	}
}

// tracked 报告当前跟踪着多少条隧道的限额状态。只给测试与诊断用。
func (s *limitStore) tracked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byTunnel)
}
