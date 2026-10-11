package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/limiter"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TunnelLookup 让入口监听器能找到隧道与承载它的会话。
type TunnelLookup interface {
	// TunnelByID 返回**当前**的隧道定义。
	//
	// 入口监听器每次处理连接时都查它，而不是持有一份创建时的快照 ——
	// 隧道的 AgentID 与 Policy 都会在运行中变化（例如把未指定 agent 的
	// 隧道绑定到刚上线的 agent 并回写），持快照会让监听器用着过期数据，
	// 表现为「控制台显示已绑定，但流量还是不通」。这是浏览器验证抓出来的。
	TunnelByID(id string) (*tunnel.Tunnel, bool)
	// TunnelByListenPort 按入口端口找隧道。
	TunnelByListenPort(port uint16) (*tunnel.Tunnel, bool)
	// SessionFor 找承载该 agent 的在线会话。
	SessionFor(agentID string) (*Session, bool)
}

// EntryStats 是一个入口监听器的计数器。
//
// 每个字段都对应一个 nf_tunnel_conns_total{outcome=...} 的标签值。
// 「拒了多少」没用，「在哪一道闸拒的」才告诉你该调什么。
type EntryStats struct {
	Accepted    atomic.Int64
	DeniedCIDR  atomic.Int64
	NoSession   atomic.Int64
	OpenFailed  atomic.Int64
	RateLimited atomic.Int64
	// Active 是**当前**在处理的连接数。
	//
	// 与 Accepted 是两个数字，混用是一个真实存在过的谎：控制台的
	// 「活跃会话」一格填的是 Accepted —— 那是累计接受数，只增不减。
	// 于是一条早就没人用的隧道会显示「活跃会话 1523」，
	// 而规格 §8.4 要的是「活跃会话」与「新会话/秒」两项，
	// 后者才是对 Accepted 做差分得出的。
	//
	// UDP 侧本来就报的是真活跃数（DatagramStats.Flows），
	// 所以两侧语义原本还是不一致的。
	Active atomic.Int64
	// PerIPQuota 是被**每源 IP 配额**拒掉的连接数。
	//
	// 与 RateLimited 分开：那一项是「这个入口的全局并发满了」（要加 max_conns），
	// 这一项是「某个源 IP 自己的份额满了」（要么它在滥用，要么
	// max_conns_per_ip 配得太小）。两者的处置方向相反 ——
	// 合成一个数字会让「有人在刷」看起来像「容量不够」。
	PerIPQuota atomic.Int64
	BytesUp    atomic.Int64
	BytesDown  atomic.Int64
}

// SessionSink 接收「一条用户会话开/关」的通知。
//
// 做成回调而不是让本包知道控制台的存在，与 RejectSink 同一个理由。
//
// 返回值是**这一帧真的发出去了吗**：调用方据此决定要不要在关闭时再发一帧 ——
// 只发了 close 而没发过 open 的话，控制台上会留下一条永不消失的幽灵行。
type SessionSink func(SessionEvent) bool

// SessionEvent 是一次会话开/关。
//
// Peer 是真实客户端地址，**只推送、绝不落库**：它是运行时观测到的第三方信息，
// 而事件表是会被支持包外发的。
type SessionEvent struct {
	TunnelID string
	// Delta 是 +1（开）或 -1（关）。
	Delta int
	// Active / Total 是发这一帧时该入口的活跃数与累计数。
	//
	// 两个都带上，前端就不必自己累加 —— 累加会在丢帧后永久偏移，
	// 而这些帧是**可牺牲的**（见 sessionTokens 的说明）。
	Active int64
	Total  int64
	Peer   string
	// Path 在 v1 恒为 "relayed"：P2P 打洞是明确的非目标。
	//
	// 仍然带这个字段，因为前端的类型是封闭联合（direct/relayed/unknown），
	// 而将来真有直连时这里就是它的出口。
	Path string
}

// RejectSink 接收「agent 拒绝了这条流」的通知。
//
// code 是 proto 的稳定错误码，message 是要原样呈现给用户的原因。
type RejectSink func(tunnelID, code, message string)

// EntryListener 在一个入口端口上接受用户连接，并为每条连接向 agent 开一条流。
type EntryListener struct {
	ln net.Listener

	// tunnelID 与 slug 是稳定的；**可变**字段（AgentID、Policy）
	// 每次处理连接时从 lookup 现取，见 TunnelLookup.TunnelByID 的说明。
	tunnelID string
	slug     string

	lookup TunnelLookup
	log    *slog.Logger

	// maxConns 限制并发连接数。
	//
	// frp 对每条接受的连接直接起一个 goroutine，既没有信号量也没有
	// accept 速率限制（server/service.go:686-740），唯一的刹车是 10s 读超时。
	// 这里必须有界。
	sem chan struct{}

	// onReject 与 setupTimeout 都在构造期定死，之后只读。
	//
	// 它们**不能**是公开的可变字段：那种字段只在 Serve 启动前写才安全，
	// 而这条约定无法被类型系统表达 —— 我第一版就是公开字段，
	// 第一次使用就在测试里写晚了一步，被 -race 抓了个正着。
	// 构造期传入让这个错误不可能发生。
	onReject     RejectSink
	onSession    SessionSink
	setupTimeout time.Duration

	// sessionTokens 是会话事件的令牌桶。
	//
	// **必须有闸**：这个事件的速率由**外部输入**（用户连接）决定。
	// 一次端口扫描会产生几千次开/关，而控制台的事件队列是共享且有界的 ——
	// 冲垮它意味着把 1Hz 的权威快照挤掉，那时界面会停在旧数据上，
	// 而用户看到的是「一个正在被扫的中继看起来风平浪静」。
	//
	// 桶挂在**入口上**而不是一张 map[tunnelID]bucket：后者的键由外部指定
	// 而没有清理点，正是本仓踩过的那类无界增长。
	sessionTokens chan struct{}

	// perIP 是每源 IP 的在用连接数。
	//
	// # 为什么全局信号量不够
	//
	// 只有全局上限时，一个源 IP 就能把它占满并把别人挤出去 —— 而「最多 N 路」
	// 这个配置在用户看来是保护，实际保护的是**中继**不被压垮，
	// 不是保护其他用户不被挤掉。UDP 侧本来就有每源配额（udpflow 的
	// PerSourceIP），TCP 侧压根没有。
	//
	// 表的键是**源 IP**，也就是由任何能连上来的人指定 —— 所以计数归零时
	// 必须 delete 而不是留一个 0：不删就是一个可被外部驱动的无界增长，
	// 而中继是长期运行的进程。这个错本仓库在别处犯过（ACME 的预算表）。
	perIPMu sync.Mutex
	perIP   map[netip.Addr]int
	// maxPerIP 为 0 表示不额外限制（与全局上限相同）。
	maxPerIP int

	// limiter 是这条隧道的限速器，nil 表示不限速。
	//
	// **每隧道一个、被所有连接与两个方向共享** —— 用户设的是「这条隧道最多
	// 多少带宽」。每连接一个桶等于把配置值乘上连接数，那个配置项就没有意义了。
	//
	// **可原子替换。** 此前它在构造期定死，注释写着「改限速值走重建入口
	// （隧道定义变了本来就要重建）」—— 而那句话是假的：ApplyTunnels 的绑定
	// 循环对已存在的入口直接 `continue`（cmd/nfrelay/runtime.go），
	// policy 的四个数字变了**不在**重建判据里。
	//
	// 于是在一条已上线的隧道上把 1 Mbps 改成 100 Kbps，进程重启前一个字节
	// 都不会变，而详情页照常显示「已设置」。那正是本仓最在意的那类谎。
	//
	// 改成原子替换而不是「加进重建判据」：重建会掐断这条隧道上所有在飞连接，
	// 而调一次带宽不该让所有用户掉线。并发连接数那两项做不到原地改
	//（信号量容量是固定的），它们仍然走重建 —— 见 ApplyTunnels 里的判据。
	limiter atomic.Pointer[limiter.Limiter]

	stats EntryStats

	closeOnce sync.Once
	done      chan struct{}
}

// DefaultMaxConns 是单个入口的默认并发连接上限。
const DefaultMaxConns = 512

// StreamSetupTimeout 是「开流 + 等 agent 确认」的期限。
//
// 必须**远小于** QUIC 的空闲超时（carrier.DefaultMaxIdleTimeout = 30s）：
// agent 被强杀时不会发关闭帧，承载在空闲超时前看起来仍然活着，
// 若这里没有独立期限，用户连接就会一直挂到客户端自己超时。
// 5 秒足够覆盖正常的跨网络开流 + 本地拨号，又能让故障快速可见。
const StreamSetupTimeout = 5 * time.Second

// EntryOptions 是入口监听器的可选参数。零值可用。
type EntryOptions struct {
	Log *slog.Logger

	// OnReject 在 agent 明确拒绝一条流时被调用，用于把原因送进事件流。
	//
	// 做成回调而不是让监听器直接写库：本包不该知道存储的存在，
	// 而且去重策略（一个配置错了的隧道会**每条连接**都被拒一次）
	// 属于调用方的职责。可以为 nil。
	OnReject RejectSink

	// OnSession 在一条用户会话开/关时被调用，用于推送会话网格。可以为 nil。
	OnSession SessionSink

	// SetupTimeout 覆盖建连期限，0 表示用 StreamSetupTimeout。
	//
	// 存在的理由是测试：验证「有期限、会快失败」这个**机制**不需要真等
	// 5 秒，而 5 秒这个**取值**由
	// TestStreamSetupTimeoutStaysWellBelowTheCarrierIdleTimeout 单独钉住。
	SetupTimeout time.Duration
}

// NewEntryListener 在 addr 上监听并服务一条隧道。
func NewEntryListener(
	addr string,
	t *tunnel.Tunnel,
	lookup TunnelLookup,
	opts EntryOptions,
) (*EntryListener, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	setup := opts.SetupTimeout
	if setup <= 0 {
		setup = StreamSetupTimeout
	}

	network := "tcp"
	if t.L4 == tunnel.L4UDP {
		return nil, errors.New("relay: UDP 入口请用 EntryDatagramListener")
	}

	ln, err := listenEntry(network, addr)
	if err != nil {
		return nil, fmt.Errorf("relay: 隧道 %s 监听 %s 失败：%w", t.Slug, addr, err)
	}

	maxConns := DefaultMaxConns
	if t.Policy != nil && t.Policy.MaxConns > 0 {
		maxConns = t.Policy.MaxConns
	}
	// 每源 IP 上限。
	//
	// 收敛到全局上限之内：大于它的话这道闸永远不会触发，而一个永远不触发的
	// 闸门比没有闸门更糟 —— 用户以为自己配了保护。
	// 这与 udpflow 那边同一条理由（那次是 max_conns=32 让 256 的每源配额失效）。
	maxPerIP := 0
	if t.Policy != nil && t.Policy.MaxConnsPerIP > 0 {
		maxPerIP = min(t.Policy.MaxConnsPerIP, maxConns)
	}

	el := &EntryListener{
		ln:           ln,
		tunnelID:     t.ID,
		slug:         t.Slug,
		lookup:       lookup,
		log:          log,
		sem:          make(chan struct{}, maxConns),
		perIP:        make(map[netip.Addr]int),
		maxPerIP:     maxPerIP,
		onReject:     opts.OnReject,
		onSession:    opts.OnSession,
		setupTimeout: setup,
		// 会话事件的令牌桶。深度是每秒允许的帧数 ——
		// 20 帧/秒足够跟上人手动开关连接的节奏，而一次端口扫描会被截住。
		sessionTokens: make(chan struct{}, sessionEventBurst),

		done: make(chan struct{}),
	}
	el.limiter.Store(limiter.New(limitsOf(t)))
	return el, nil
}

// SetLimits 原地替换限速参数。可在服务中调用。
//
// # 为什么需要它
//
// 此前限速器在构造期定死，而 ApplyTunnels 对已存在的入口直接跳过 ——
// 于是「改一条已上线隧道的带宽」在进程重启前毫无效果，而界面显示「已设置」。
//
// 只覆盖 bytes_per_second / packets_per_second。并发连接数那两项做不到原地改
// （信号量容量是固定的），它们由 ApplyTunnels 通过**重建入口**来生效 ——
// 那会掐断这条隧道上的在飞连接，所以两类参数刻意分开处理：
// 调带宽不掉线，调并发上限掉线。这个差异要写在文档里。
func (l *EntryListener) SetLimits(lim limiter.Limits) {
	l.limiter.Store(limiter.New(lim))
}

// LimitsSpec 返回这个入口构造时用的并发参数，供调用方判断要不要重建。
//
// 只回并发那两项：带宽走 SetLimits 原地改，不需要重建。
func (l *EntryListener) LimitsSpec() (maxConns, maxPerIP int) {
	return cap(l.sem), l.maxPerIP
}

// Addr 返回实际监听地址（端口为 0 时用于取得系统分配的端口）。
func (l *EntryListener) Addr() net.Addr { return l.ln.Addr() }

// Stats 返回计数器指针，供指标采集读取。
func (l *EntryListener) Stats() *EntryStats { return &l.stats }

// Serve 循环接受连接直到 ctx 取消或监听器关闭。
func (l *EntryListener) Serve(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-l.done:
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// 临时性错误（如 fd 暂时耗尽）不该让整个监听器退出。
			l.log.Warn("入口 accept 失败", "隧道", l.slug, "err", err)
			select {
			case <-time.After(50 * time.Millisecond):
				continue
			case <-l.done:
				return nil
			}
		}

		// 取**当前**隧道定义，不用创建时的快照。
		// 隧道的 AgentID 与 Policy 会在运行中变化（例如把未指定 agent 的
		// 隧道绑定到刚上线的 agent 并回写），持快照会让这里用着过期数据。
		t, ok := l.lookup.TunnelByID(l.tunnelID)
		if !ok {
			// 隧道刚被删除，而监听器还没来得及关。
			conn.Close()
			continue
		}

		// 先做最便宜的检查：源 IP 白名单。
		// 在 Accept 之后、申请 agent 流之前判定，避免为注定被拒的连接
		// 付出一次跨网络的开流成本。frp 把这个检查放在一个进程外的
		// HTTP 插件里（server/proxy/proxy.go:281），等于给每条连接加一次 RPC。
		if !l.allowSource(t, conn) {
			l.stats.DeniedCIDR.Add(1)
			conn.Close()
			continue
		}

		// 每源 IP 配额：在全局信号量**之前**判。
		//
		// 顺序有讲究：反了的话一个已经超过自己配额的 IP 会先占掉一个全局槽位
		// 再被退回，而在它高速重试时那个「占了又还」的窗口足以把全局槽位
		// 挤占给它自己。
		src, srcOK := sourceIP(conn)
		if !srcOK {
			// 解析不出源地址就拒 —— 无法判定归属时不该放行，
			// 而且配额也无从记账。
			l.stats.DeniedCIDR.Add(1)
			conn.Close()
			continue
		}
		if !l.acquirePerIP(src) {
			l.stats.PerIPQuota.Add(1)
			conn.Close()
			continue
		}

		// 并发上限：满了就直接拒，而不是无限堆 goroutine。
		select {
		case l.sem <- struct{}{}:
		default:
			l.stats.RateLimited.Add(1)
			l.releasePerIP(src)
			conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-l.sem }()
			defer l.releasePerIP(src)
			l.handle(ctx, t, conn)
		}()
	}
}

// sessionEventBurst 是会话事件的每秒帧数上界。
//
// 20：足够跟上人手动开关连接的节奏，而一次端口扫描（几千次开/关）会被截住。
const sessionEventBurst = 20

// announceSession 把一次会话开/关送进事件流；返回是否真的发了。
//
// throttled=false 用于关闭帧：它的总量被已发出的开启帧封顶，
// 而丢一个关闭帧的代价是界面上一条永不消失的行。
func (l *EntryListener) announceSession(delta int, peer string, active int64, throttled bool) bool {
	if l.onSession == nil {
		return false
	}
	if throttled {
		select {
		case l.sessionTokens <- struct{}{}:
			// 拿到令牌。用一个定时器把它还回去 —— 比自己维护时间戳简单，
			// 而且没有「谁来推进时钟」的问题。
			time.AfterFunc(time.Second, func() {
				select {
				case <-l.sessionTokens:
				default:
				}
			})
		default:
			return false
		}
	}
	return l.onSession(SessionEvent{
		TunnelID: l.tunnelID,
		Delta:    delta,
		Active:   active,
		Total:    l.stats.Accepted.Load(),
		Peer:     peer,
		// v1 恒为 relayed：P2P 打洞是明确的非目标。
		Path: "relayed",
	})
}

// sourceIP 取一条连接的源 IP（已规范化 IPv4-in-IPv6）。
//
// 规范化是必需的：::ffff:203.0.113.9 与 203.0.113.9 是同一个来源，
// 不归一化的话同一个客户端能拿到两份配额。
func sourceIP(conn net.Conn) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// acquirePerIP 为一个源 IP 申请一个配额位。
func (l *EntryListener) acquirePerIP(ip netip.Addr) bool {
	if l.maxPerIP <= 0 {
		return true
	}
	l.perIPMu.Lock()
	defer l.perIPMu.Unlock()
	if l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.perIP[ip]++
	return true
}

// releasePerIP 归还一个配额位。
//
// 归零即 delete：表的键是源 IP，由任何能连上来的人指定 ——
// 留一个 0 就是一个可被外部驱动的无界增长。
func (l *EntryListener) releasePerIP(ip netip.Addr) {
	if l.maxPerIP <= 0 {
		return
	}
	l.perIPMu.Lock()
	defer l.perIPMu.Unlock()
	n := l.perIP[ip] - 1
	if n <= 0 {
		delete(l.perIP, ip)
		return
	}
	l.perIP[ip] = n
}

func (l *EntryListener) allowSource(t *tunnel.Tunnel, conn net.Conn) bool {
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		// 解析不出来就拒 —— 宁可误拒也不要在无法判定来源时放行。
		return false
	}
	return t.SourceAllowed(ap.Addr())
}

func (l *EntryListener) handle(ctx context.Context, t *tunnel.Tunnel, conn net.Conn) {
	defer conn.Close()

	sess, ok := l.lookup.SessionFor(t.AgentID)
	if !ok {
		l.stats.NoSession.Add(1)
		l.log.Warn("隧道的代理端不在线", "隧道", l.slug, "agent", t.AgentID)
		return
	}
	// 会话可能已死但还没被清理掉（清理是异步的）。
	// 不查这一下，用户就会拿到挂死或陈旧响应而不是干净的失败。
	if !sess.Alive() {
		l.stats.NoSession.Add(1)
		l.log.Warn("隧道的代理端承载已断开", "隧道", l.slug, "agent", sess.AgentID)
		return
	}

	ap, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	localAP, _ := netip.ParseAddrPort(conn.LocalAddr().String())

	// 开流 + 等 agent 确认必须有一个**短**超时。
	//
	// 这是手工验证抓出来的真实缺陷：agent 进程被 kill -9 时不会发 QUIC 关闭帧，
	// 所以承载的 Context 要等到空闲超时（30s）才取消。在那之前会话看起来还活着，
	// 用户连接被派给一个死 agent，curl 就挂死到自己超时。
	//
	// Alive() 检查能挡住「已经确认死掉」的会话，但挡不住这个 30 秒的检测窗口 ——
	// 唯一可靠的办法是给这条路径设一个远小于空闲超时的期限，
	// 让用户在几秒内拿到干净的失败，而不是无限等待。
	openCtx, cancel := context.WithTimeout(ctx, l.setupTimeout)
	defer cancel()

	st, err := OpenTunnelStream(openCtx, sess, proto.StreamOpen{
		TunnelID: l.tunnelID,
		SrcAddr:  ap.Addr().String(),
		SrcPort:  ap.Port(),
		DstAddr:  localAP.Addr().String(),
		DstPort:  localAP.Port(),
	})
	if err != nil {
		l.stats.OpenFailed.Add(1)
		l.log.Warn("向代理端开流失败", "隧道", l.slug, "err", err)
		return
	}
	defer st.Close()

	// 等 agent 确认本地已连通，再开始搬用户字节（语义与超时见 AwaitStreamOK）。
	// 网关（internal/gateway）走同一个函数 —— 同一个故障在两条路径上必须长得一样。
	_, rest, err := AwaitStreamOK(st, l.setupTimeout)
	if err != nil {
		l.stats.OpenFailed.Add(1)
		var rej *StreamRejectedError
		if errors.As(err, &rej) {
			l.log.Warn("代理端拒绝了这条流",
				"隧道", l.slug, "code", rej.Code, "msg", rej.Message)
			// 只有「明确拒绝」才进事件流。网络类失败进不去 ——
			// 那种故障看指标（OpenFailed）比看事件流有用，
			// 而且它可能每秒发生几百次。
			if l.onReject != nil {
				l.onReject(l.tunnelID, rej.Code, rej.Message)
			}
		} else {
			l.log.Warn("等代理端确认失败", "隧道", l.slug, "err", err)
		}
		return
	}

	l.stats.Accepted.Add(1)
	active := l.stats.Active.Add(1)

	// 会话网格：开一帧、关一帧。
	//
	// announced 决定关闭时要不要再发 —— 只发了 close 而没发过 open 的话，
	// 前端的 filter(peer) 会去删一条它从没加过的行（无害），
	// 但反过来「发了 open 没发 close」会留下一条**永不消失**的幽灵行。
	// 所以开启帧过节流桶，而关闭帧**不过** —— 它的总量被已发出的开启帧封顶。
	announced := l.announceSession(1, ap.String(), active, true)
	defer func() {
		left := l.stats.Active.Add(-1)
		if announced {
			l.announceSession(-1, ap.String(), left, false)
		}
	}()

	// 限速器**每隧道一个、双向共享**。
	//
	// 用户设的是「这条隧道最多多少带宽」，所以每连接一个桶等于把配置值
	// 乘上连接数 —— 那个配置项就没有意义了。双向共享同理：
	// 一条 1 Mbps 的隧道不该在两个方向各跑 1 Mbps。
	//
	// TCP 路径**等**而不是丢：字节流丢中间一段就是把连接搞坏，
	// 而等待的反压会自然传播到发送方的窗口。
	lim := l.limiter.Load()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(st, lim.WaitReader(ctx, conn))
		l.stats.BytesUp.Add(n)
		st.Close()
	}()
	go func() {
		defer wg.Done()
		// 从 rest 读而不是从 st 读：帧读取时可能把业务字节一并缓冲了。
		n, _ := io.Copy(conn, lim.WaitReader(ctx, rest))
		l.stats.BytesDown.Add(n)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// limitsOf 从隧道策略里取限速参数。
//
// # 为什么这个函数必须存在
//
// policy.bytes_per_second / packets_per_second 全链路可配（向导有输入框、
// 详情页显示「已设置」、库里存着），而在这次改动之前**生产代码零读取点** ——
// 用户填了限速、界面确认「已设置」，实际上一个字节都没被限。
// 那比没有这个功能糟糕得多：用户以为自己保护了裸端口暴露的隧道。
func limitsOf(t *tunnel.Tunnel) limiter.Limits {
	if t.Policy == nil {
		return limiter.Limits{}
	}
	return limiter.Limits{
		BytesPerSecond:   t.Policy.BytesPerSecond,
		PacketsPerSecond: t.Policy.PacketsPerSecond,
	}
}

// Close 关闭入口监听器。可重复调用。
func (l *EntryListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.ln.Close()
	})
	return err
}
