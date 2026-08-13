package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/policy"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// UDPStats 是 agent 侧数据报路径的计数器。
type UDPStats struct {
	// 下行（中继 → 本地服务）。
	PacketsOut atomic.Int64
	BytesOut   atomic.Int64

	// 上行（本地服务 → 中继）。
	PacketsIn atomic.Int64
	BytesIn   atomic.Int64

	// 丢弃原因。
	Malformed     atomic.Int64 // 帧解析失败
	ReasmDropped  atomic.Int64 // 重组失败（超时/表满/重叠，细分见 Reassembler.Stats）
	UnknownTunnel atomic.Int64 // 短标识不在可服务集合里
	Denied        atomic.Int64 // 本地策略否决目标
	DialFailed    atomic.Int64
	TableFull     atomic.Int64
	RateLimited   atomic.Int64
	WriteFailed   atomic.Int64

	// PendingDial 是「这条流正在拨号，本包丢掉」。
	//
	// 建流是异步的（同步做会让 DNS 解析冻结整条读循环），触发建流的
	// **第一个**包被缓存下来等拨号完成，第 2..N 个包丢掉并计到这里。
	// 排一整个队会让一个拨不通的目标变成一个内存放大器。
	//
	// 稳态下它应当接近 0。持续上涨说明本地目标拨号很慢（多半是 DNS），
	// 而那是一个用户可以行动的信号：把 backend.addr 写成 IP 字面量。
	PendingDial atomic.Int64

	// BackendChanged 是「隧道的后端改了，这条在途流被拆掉」。
	//
	// 拆掉是刻意的：把包送到旧后端才是更坏的选择，尤其当用户改后端的
	// 原因正是「原来那台不该被暴露」。本包丢掉，下一包会拨到新后端。
	BackendChanged atomic.Int64

	Flows atomic.Int64
}

// localFlow 是 agent 侧一条 UDP 流：一个已连接到本地目标的 socket。
type localFlow struct {
	conn *net.UDPConn

	// key 是这条流在流表里的键。
	//
	// **必须存下来**：pumpReplies 退出时要用它把表项一起删掉。
	// 不存的后果是一条真实的永久黑洞 —— 回包读超时让 pumpReplies 关掉
	// socket，而表项还活着；此后每个下行包都 Lookup 命中（并把 lastSeen
	// 刷新到现在，于是空闲回收永远逐不掉它）、然后写一个已关闭的 socket
	// 失败。用户看到的是一条通了很久的隧道在一次一分钟的安静之后
	// 100% 丢包且永不恢复。
	key udpflow.Key

	// backendAddr 是建流时隧道的后端地址（未解析的原文）。
	//
	// 用来发现「用户在控制台改了后端」——在途流量不断的流原本会无限期
	// 继续打旧后端，而用户以为改完就生效了（尤其当他改的原因正是
	// 「原来那台不该被暴露」）。
	backendAddr string

	// defGen 是建流时的隧道集合世代。
	//
	// 只为了让上面那个字符串比较**每次 reconcile 只做一次**，
	// 而不是每包都做。用原子量因为它由读循环写、由异步建流协程读。
	defGen atomic.Uint64

	// 回包要原样带回这三个字段，中继才能找回用户。
	tunnel  uint16
	flowID  uint32
	dstPort uint16

	// replyFlags 是回包帧要带的标志，建流时按隧道策略定下。
	//
	// **不能硬编码 FlagNoReassemble**：那等于「回向永远丢弃超限包」，
	// 于是一条批量隧道的请求被分片、回包却被丢掉 —— 不对称的静默失败，
	// 表现为「发得出去收不回来」。这是补重组测试时抓出来的。
	replyFlags uint8

	closeOnce sync.Once
}

func (f *localFlow) close() {
	f.closeOnce.Do(func() { _ = f.conn.Close() })
}

// UDPHandler 处理 agent 侧的 UDP 数据报。
//
// # 与 TCP 路径的对称之处，以及必须一致的地方
//
// 目标裁决走**同一个** policy：UDP 路径若绕开它，SSRF 防线就只有一半 ——
// 攻击者把隧道的 l4 从 tcp 改成 udp 就能穿过去。所以这里也用
// policy.CheckAddr 判定已解析的地址字面量，而不是拿主机名去拨。
//
// # 为什么每条流一个 socket
//
// 本地服务的回包必须能被区分开。用一个共享 socket 的话，回包只能靠
// 源地址区分，而多条流可以指向同一个本地目标 —— 那时就分不开了。
// 每流一个 net.DialUDP 出来的**已连接** socket，读到的必然是这条流的回包，
// 内核还顺带帮我们过滤了来自其他地址的包。
//
// 代价是 fd 消耗，所以流表必须有界：容量上限 + LRU + 建表限速 + 空闲回收。
// frp 恰恰没有这些约束（pkg/proto/udp/udp.go:75,117-124 每个新源地址就
// DialUDP 一个，回收只靠 30s 读超时），向公网 UDP 端口喷包即可耗尽 fd。
type UDPHandler struct {
	Tunnels *TunnelSet
	Policy  *policy.Policy
	Log     *slog.Logger

	// Table 覆盖流表参数。
	Table udpflow.Config

	// Reassembly 覆盖分片重组参数（并发数、字节上限、超时）。
	Reassembly udpflow.ReassemblerConfig

	// DialTimeout 是拨本地目标的期限，<=0 时用 5 秒。
	//
	// UDP 的「拨号」只是绑定 + 记下对端地址，本不会慢；但目标是主机名时
	// 要先解析 DNS，那一步可以很慢。没有期限的话，一个解析不出来的目标
	// 会把这条流的建立卡住。
	DialTimeout time.Duration

	initOnce sync.Once
	flows    *udpflow.Table[*localFlow]

	// pending 是「正在拨号的流键」→ 它排着的包。
	//
	// 建流是异步的（同步做会让 DNS 解析冻结整条读循环），所以同一条新流的
	// 第 2..N 个包必须能看出「已经有人在拨了」——否则一个每秒 50 包的
	// 新流会起 50 个拨号协程去解析同一个主机名。
	pending sync.Map
	// pendingN 是并发拨号的流数。
	//
	// 单独计数而不是数 sync.Map：Map 没有 Len，而这道闸在 Admit **之前**，
	// 所以流表自己的容量与限速还没生效 —— 没有它，一次源端口喷射
	// 就是一次内存放大。
	pendingN atomic.Int64

	// reasm 把分片拼回完整数据报。
	//
	// 有界且四重约束（见 udpflow.Reassembler）：它是数据面上唯一有状态的
	// 部件，天生是个可被滥用的缓冲池 —— 不停发「某个大数据报的第一片」
	// 就能让接收方无限攒内存，而每一片都是合法帧。
	reasm *udpflow.Reassembler

	// sendStats 与 reasmStats 一样由本结构体持有，理由见 reasmStats。
	sendStats udpflow.SenderStats

	// reasmStats 由本结构体持有，而不是问 reasm 要。
	//
	// reasm 是延迟创建的（配置来自构造后才填的字段），而指标采集可能
	// 更早发生。让统计对象有一个**永远有效**的地址，调用方就不必判空 ——
	// 「未初始化返回 nil」只是把崩溃推给调用方，测试第一次跑就崩了。
	reasmStats udpflow.ReassemblerStats

	// sender 是回中继的非阻塞发送器，由 Serve 装入。
	sender atomic.Pointer[udpflow.Sender]

	// relayAddr 用作流表键里的 Src：agent 侧所有流都来自同一个中继，
	// 让它参与记账使 PerSourceIP 变成「每中继上限」这一有意义的约束。
	relayAddr netip.AddrPort

	stats UDPStats
}

// Stats 返回计数器指针。
func (h *UDPHandler) Stats() *UDPStats { return &h.stats }

// SendStats 返回回向发送器的分项计数。**永不为 nil。**
//
// 没有这个出口的话，agent 侧的发送丢弃（队列满 / 超限 / 承载失败）
// 完全不可观测 —— 表现为「下行统计都对，就是收不到回包」，
// 而没有任何数字能告诉你为什么。补重组测试时正是被这一点卡住的。
func (h *UDPHandler) SendStats() *udpflow.SenderStats { return &h.sendStats }

// ReassemblyStats 返回重组器的分项计数。**永不为 nil。**
//
// 分开暴露而不是合并进 UDPStats：重组的失败原因（超时 / 并发数满 /
// 字节数满 / 分片重叠）各自对应不同的动作，而其中「重叠」是**安全信号**，
// 不该和「超时」这种链路质量信号混在一个数字里。
func (h *UDPHandler) ReassemblyStats() *udpflow.ReassemblerStats { return &h.reasmStats }

func (h *UDPHandler) init() {
	h.initOnce.Do(func() {
		cfg := h.Table
		// agent 侧所有流都来自同一个中继，所以「每源 IP 配额」若小于容量
		// 就会抢在容量之前生效，让 Capacity 那个参数变成摆设。
		// 两者取齐，语义变成「每中继最多这么多流」。
		if cfg.PerSourceIP <= 0 {
			cfg.PerSourceIP = cfg.Capacity
			if cfg.PerSourceIP <= 0 {
				cfg.PerSourceIP = udpflow.DefaultCapacity
			}
		}
		h.flows = udpflow.New[*localFlow](cfg)
		reasmCfg := h.Reassembly
		reasmCfg.Stats = &h.reasmStats
		h.reasm = udpflow.NewReassembler(reasmCfg)
		if h.Log == nil {
			h.Log = slog.Default()
		}
	})
}

// idleTimeout 是流表配置里的空闲期限（完成默认值之后）。
//
// pumpReplies 的读期限必须用它而不是包常量：不一致的话，把 IdleTimeout
// 调大只会让「socket 已死但表项还在」的窗口变宽。
func (h *UDPHandler) idleTimeout() time.Duration {
	if h.Table.IdleTimeout > 0 {
		return h.Table.IdleTimeout
	}
	return udpflow.DefaultIdleTimeout
}

func (h *UDPHandler) dialTimeout() time.Duration {
	if h.DialTimeout > 0 {
		return h.DialTimeout
	}
	return 5 * time.Second
}

// Serve 在一条承载上收发数据报，直到 ctx 取消或承载断开。
//
// 承载不支持数据报时立刻返回 —— 那种情况下 UDP 隧道走不通，
// 中继侧会如实标记状态并计数，而不是悄悄降级到可靠流
// （那会让用户以为自己拿到了低延迟通道）。
func (h *UDPHandler) Serve(ctx context.Context, car carrier.Carrier) error {
	if !car.SupportsDatagrams() {
		return carrier.ErrDatagramUnsupported
	}
	h.init()

	if ra, err := netip.ParseAddrPort(car.RemoteAddr().String()); err == nil {
		h.relayAddr = ra
	}

	sender := udpflow.NewSender(car, 0, &h.sendStats)
	h.sender.Store(sender)
	defer func() {
		h.sender.Store(nil)
		sender.Close()
	}()
	go sender.Run(ctx)

	defer h.flows.Close(func(f *localFlow) {
		if f != nil {
			f.close()
		}
	})
	go h.sweepIdle(ctx)

	for {
		raw, err := car.ReceiveDatagram(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		h.handle(ctx, raw)
	}
}

// handle 处理一条来自中继的数据报。
func (h *UDPHandler) handle(ctx context.Context, raw []byte) {
	hdr, payload, err := udpflow.ParseFrame(raw)
	if err != nil {
		// 畸形帧只计数，**绝不**因此断开承载：一个坏包不该让整条隧道停掉。
		h.stats.Malformed.Add(1)
		return
	}

	// 分片先过重组器。凑不齐就在这里结束 —— 只有完整的数据报才该被
	// 交给本地服务，交半个出去比丢掉危险得多（对端会把它当成一个
	// 合法但内容被截断的报文）。
	if hdr.Fragmented() {
		full, complete, rerr := h.reasm.Push(hdr, payload)
		if rerr != nil {
			// 具体原因（超时/表满/重叠）由 Reassembler 自己分标签计数，
			// 这里只记一个总数供隧道级视图使用 ——
			// 两处都记全量会让同一次丢弃在看板上被数两遍。
			h.stats.ReasmDropped.Add(1)
			return
		}
		if !complete {
			return
		}
		// 重组缓冲会被复用，所以要在这一次调用里用掉它。
		// 下面的 flow.conn.Write 是同步的，所以直接用是安全的。
		payload = full
	}

	key := udpflow.Key{
		Src:     h.relayAddr,
		DstPort: hdr.DstPort,
		Tunnel:  hdr.Tunnel,
		FlowID:  hdr.FlowID,
	}

	flow, ok := h.flows.Lookup(key)
	if !ok {
		// 建流是**异步**的，本包被缓存起来等拨号完成。
		//
		// 同步做的话，这一条读循环会在 Policy.ResolveAllowed 里等 DNS ——
		// 最长 DialTimeout（默认 5 秒）。那期间这个 agent 上**所有** UDP
		// 隧道的下行全停：一条 backend.addr 写成主机名的隧道遇上局域网
		// DNS 抖动，就能把通话和游戏一起卡死，而计数器上什么都看不到。
		h.beginAdmit(ctx, key, hdr, payload)
		return
	}

	// 隧道定义变过就重新裁决一次。
	//
	// 只在世代变了的那一包做，所以稳态下是一次原子读。
	if !h.stillCurrent(flow, hdr) {
		// 目标变了：拆掉这条流，让下一包重新拨号到新后端。
		// 本包丢掉并计数 —— 把它送到旧后端才是更坏的选择，
		// 尤其当用户改后端的原因正是「原来那台不该被暴露」。
		h.flows.Delete(key, h.discard)
		h.stats.BackendChanged.Add(1)
		return
	}

	h.writeLocal(flow, payload)
}

// writeLocal 把载荷写给本地服务。
func (h *UDPHandler) writeLocal(flow *localFlow, payload []byte) {
	// 写期限是必需的。
	//
	// 已连接 UDP socket 的 Write 在发送缓冲满时会阻塞（远端主机 + 出向
	// 链路拥塞，qdisc 积压超过 sndbuf 时就会发生）。而这里跑在**共享**的
	// 读循环上，所以一条流的拥塞会冻结这个 agent 上所有 UDP 隧道的下行。
	// 那正是本包注释里点名批评 frp 的错误形状。
	//
	// 期限很短：数据报要么现在就能进缓冲，要么它已经过时了。
	_ = flow.conn.SetWriteDeadline(time.Now().Add(localWriteTimeout))
	n, err := flow.conn.Write(payload)
	if err != nil {
		h.stats.WriteFailed.Add(1)
		// 写失败就拆掉这条流，让下一包重新拨号。
		//
		// 不拆的后果是永久黑洞：本地服务重启（或压根还没起来）时，
		// 一个 ICMP 端口不可达就让这个 socket 永远写不进去，
		// 而表项被下行包不断刷新、永远逐不掉。
		//
		// 期限超时**不**拆：那是拥塞，不是坏 socket，拆了会让一次拥塞
		// 变成一次重新解析 DNS + 重新拨号。
		var ne net.Error
		if !(errors.As(err, &ne) && ne.Timeout()) {
			h.flows.Delete(flow.key, h.discard)
		}
		return
	}
	h.stats.PacketsOut.Add(1)
	h.stats.BytesOut.Add(int64(n))
}

// localWriteTimeout 是写本地 socket 的期限。
//
// 数据报要么现在就能进缓冲，要么它已经过时了 —— 排队等一秒的音频包
// 到达时已经没有价值，而排队的代价是冻结整条读循环。
const localWriteTimeout = 50 * time.Millisecond

// stillCurrent 报告这条流的后端是否仍与隧道当前定义一致。
//
// # 覆盖范围要说清楚
//
// 它比较的是 backend.addr 的**原文**，所以能发现「用户在控制台改了后端」——
// 那是报出来的症状。它发现不了两件事：
//   - 策略收紧但地址没变（策略对象也换了，但这里不比较它）
//   - 主机名的 DNS 解析结果变了
//
// 两者都要靠 socket 自己出错或空闲回收来收场。如实写在这里，
// 而不是让注释暗示「改了配置一定立刻生效」。
func (h *UDPHandler) stillCurrent(flow *localFlow, hdr udpflow.Header) bool {
	gen := h.Tunnels.Gen()
	if flow.defGen.Load() == gen {
		return true
	}
	t, ok := h.tunnelByShortID(hdr.Tunnel)
	if !ok {
		// 隧道已经不在可服务集合里（被删或被策略否决）。
		return false
	}
	if t.Backend.Addr != flow.backendAddr {
		return false
	}
	flow.defGen.Store(gen)
	return true
}

// 拨号期间的缓存上界。
//
// # 为什么要缓存，为什么必须有界
//
// 一个包都不缓存的话，每条新流的开头都会丢包：一次性的 UDP 请求
// （DNS 查询、单发控制指令）直接失败，而通话开始时的那一串关键帧
// 会丢掉大半 —— 那不是「UDP 本来就会丢包」，是我们自己造的。
//
// 而不设上界的话，一个拨不通的目标就是一个内存放大器：喷 10 万个源端口，
// 每条流各排一队，全都在等同一个解析不出来的主机名超时。
// 所以三条界都要：每流包数、每流字节数、并发拨号的流数。
const (
	maxPendingPackets = 8
	maxPendingBytes   = 64 << 10
	maxPendingDials   = 256
)

// pendingFlow 是一条正在拨号的流，以及它排着的包。
type pendingFlow struct {
	mu    sync.Mutex
	bufs  [][]byte
	bytes int
}

// enqueue 排一个包，超界返回 false。
func (p *pendingFlow) enqueue(payload []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.bufs) >= maxPendingPackets || p.bytes+len(payload) > maxPendingBytes {
		return false
	}
	// raw 缓冲会被读循环复用，所以必须拷贝。
	buf := make([]byte, len(payload))
	copy(buf, payload)
	p.bufs = append(p.bufs, buf)
	p.bytes += len(payload)
	return true
}

// drain 取走排着的包。
func (p *pendingFlow) drain() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.bufs
	p.bufs, p.bytes = nil, 0
	return out
}

// beginAdmit 异步建一条新流，并把拨号期间的包排起来。
//
// # 为什么建流必须异步
//
// 同步做的话，这一条读循环会在 Policy.ResolveAllowed 里等 DNS ——
// 最长 DialTimeout（默认 5 秒）。那期间这个 agent 上**所有** UDP 隧道的
// 下行全停：一条 backend.addr 写成主机名的隧道遇上局域网 DNS 抖动，
// 就能把通话和游戏一起卡死，而计数器上什么都看不到。
//
// # 顺序
//
// 拨通之后先把表项登记好（Admit 内部完成），再排水。于是紧随其后到达的包
// 走 Lookup 直写，可能**排在缓存的包之前** —— UDP 本来就不保证顺序，
// 而分片靠数据报标识重组，所以这是可接受的；写在这里是因为它不显然。
func (h *UDPHandler) beginAdmit(ctx context.Context, key udpflow.Key,
	hdr udpflow.Header, payload []byte) {
	if v, busy := h.pending.Load(key); busy {
		// 同一条新流的第 2..N 个包：已经有一个协程在拨了。
		if !v.(*pendingFlow).enqueue(payload) {
			h.stats.PendingDial.Add(1)
		}
		return
	}

	// 并发拨号的流数也要有界，否则一次源端口喷射就是一次内存放大 ——
	// 注意这道闸在 Admit **之前**，所以流表自己的容量与限速还没生效。
	if h.pendingN.Load() >= maxPendingDials {
		h.stats.PendingDial.Add(1)
		return
	}

	pf := &pendingFlow{}
	if v, busy := h.pending.LoadOrStore(key, pf); busy {
		// 与另一个包抢输了：它已经放进去了，我们只排队。
		if !v.(*pendingFlow).enqueue(payload) {
			h.stats.PendingDial.Add(1)
		}
		return
	}
	h.pendingN.Add(1)
	pf.enqueue(payload)

	go func() {
		flow, ok := h.admit(ctx, key, hdr)
		// 先摘掉 pending 再排水：摘掉之后新来的包走 Lookup 直写，
		// 不会一直往一个已经排完的队里塞。
		h.pending.Delete(key)
		h.pendingN.Add(-1)
		if !ok {
			return // 原因已计数
		}
		for _, buf := range pf.drain() {
			h.writeLocal(flow, buf)
		}
	}()
}

// admit 为一条新流拨本地目标并起回包读取。
func (h *UDPHandler) admit(ctx context.Context, key udpflow.Key, hdr udpflow.Header) (*localFlow, bool) {
	// 先找隧道。短标识不在可服务集合里，说明这条隧道没下发给我、
	// 或者被本地策略否决过 —— 无论哪种，都不该为它开 socket。
	// 世代要在**裁决之前**读：反了的话，一次并发的 reconcile 会让
	// 这条流带上一个比它实际依据更新的世代号，于是它逃过下一次比较。
	gen := h.Tunnels.Gen()

	t, ok := h.tunnelByShortID(hdr.Tunnel)
	if !ok {
		h.stats.UnknownTunnel.Add(1)
		return nil, false
	}

	// 回包帧的标志按隧道策略定下。
	//
	// **不能硬编码 FlagNoReassemble**：那等于「回向永远丢弃超限包」，
	// 于是一条批量隧道的请求被分片、回包却被丢掉 —— 不对称的静默失败，
	// 表现为「发得出去收不回来」。而**不设**它也一样错：实时隧道的
	// 「超限即丢」在回向方向根本不存在，README 那句承诺只兑现了一半。
	var replyFlags uint8
	if t.IsRealtimeDatagram() {
		replyFlags |= udpflow.FlagNoReassemble
	}

	var dialErr error
	flow, created, err := h.flows.Admit(key, func() (*localFlow, error) {
		// 这个回调在分片锁之外执行（见 udpflow.Table.Admit），
		// 所以这里可以做拨号这种阻塞操作 —— frp 恰恰是在全局锁内
		// 做 net.DialUDP（pkg/proto/udp/udp.go:116-126），
		// 把所有新会话的建立串行化了。
		conn, err := h.dialLocal(ctx, t)
		if err != nil {
			dialErr = err
			return nil, err
		}
		f := &localFlow{
			conn:        conn,
			key:         key,
			backendAddr: t.Backend.Addr,
			tunnel:      hdr.Tunnel,
			flowID:      hdr.FlowID,
			dstPort:     hdr.DstPort,
			replyFlags:  replyFlags,
		}
		f.defGen.Store(gen)
		return f, nil
	}, h.discard)

	if err != nil {
		switch {
		case errors.Is(err, udpflow.ErrTableFull), errors.Is(err, udpflow.ErrPerIPQuota):
			h.stats.TableFull.Add(1)
		case errors.Is(err, udpflow.ErrRateLimited):
			h.stats.RateLimited.Add(1)
		case dialErr != nil:
			var denied *policy.ErrDenied
			if errors.As(dialErr, &denied) {
				// 策略否决与拨号失败要分开 —— 前者是用户自己的规则挡住了
				// 自己的隧道，重试永远不会成功；后者是本地服务没起。
				h.stats.Denied.Add(1)
				h.Log.Warn("UDP 目标被本地策略否决",
					"隧道", t.Slug, "目标", t.Backend.Addr, "原因", denied.Decision.Reason)
			} else {
				h.stats.DialFailed.Add(1)
			}
		default:
			h.stats.DialFailed.Add(1)
		}
		return nil, false
	}

	// 只有**真的建出来**的那一次才做一次性副作用。
	//
	// 并发同键时 Admit 返回的是别人的值（我建的那个已经交给 discard 了）。
	// 对它再起一个 pumpReplies 就是两个协程读同一个 socket ——
	// 其中一个退出时 close 掉，另一个跟着死，而表项还活着。
	if created {
		h.stats.Flows.Add(1)
		go h.pumpReplies(flow)
	}
	return flow, true
}

// dialLocal 拨本地 UDP 目标，目标地址必须先经策略裁决。
//
// 与 TCP 路径共用 policy：UDP 若绕开它，把隧道的 l4 从 tcp 改成 udp
// 就能穿过 SSRF 防线。这不是理论问题 —— 那正是这道防线要挡的事。
func (h *UDPHandler) dialLocal(ctx context.Context, t *tunnel.Tunnel) (*net.UDPConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, h.dialTimeout())
	defer cancel()

	ap, err := h.Policy.ResolveAllowed(dialCtx, "udp", t.Backend.Addr)
	if err != nil {
		return nil, err
	}
	// 拨的是**已判定的字面量**，不再经过主机名 —— 从根上消除
	// 「判定用的地址与实际连的地址不同」这个 DNS 重绑定时间窗。
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
}

// pumpReplies 把本地服务的回包送回中继。
//
// 每条流一个 goroutine。这里可以这样做而入口侧不行：入口侧是「一个端口
// 多条流共享一条读循环」，这里是「一条流一个已连接 socket」，
// 读它必须有独立的 goroutine，否则多条流会互相阻塞。
func (h *UDPHandler) pumpReplies(f *localFlow) {
	// 退出即**销毁表项**，不只是关 socket。
	//
	// 原来的注释写「流表的空闲回收会把表项一并清掉」—— 那句话是错的，
	// 而它错的方式很贵：EvictIdle 的判据是 lastSeen，而 lastSeen 由
	// **下行每包**的 Lookup 刷新。于是一条 socket 已死的表项会被
	// 正在被它丢掉的那些包不断续命，永远逐不掉。
	//
	// 删掉表项之后，下一个下行包 Lookup miss → 重新拨号 → 流自愈。
	defer func() {
		if !h.flows.Delete(f.key, h.discard) {
			// 已经被逐出了：discard 早就跑过，closeOnce 保证重复关也安全。
			f.close()
		}
	}()

	buf := make([]byte, maxLocalDatagram)
	for {
		// 读超时兼作空闲检测：本地服务不再回包时让协程退出，
		// 而不是永远挂着。期限**跟随流表配置**而不是包常量 ——
		// 硬编码会让「把 IdleTimeout 调大」只改一半，
		// 而那一半正好是让窗口变宽的那一半。
		_ = f.conn.SetReadDeadline(time.Now().Add(h.idleTimeout()))
		n, err := f.conn.Read(buf)
		if err != nil {
			return
		}

		sender := h.sender.Load()
		if sender == nil {
			return // 承载已断
		}
		sender.Send(udpflow.Header{
			Tunnel:  f.tunnel,
			FlowID:  f.flowID,
			DstPort: f.dstPort,
			Flags:   f.replyFlags,
		}, buf[:n])
		// 丢弃原因由 Sender 自己按标签计数，这里再累加会数两遍。
		h.stats.PacketsIn.Add(1)
		h.stats.BytesIn.Add(int64(n))
	}
}

// maxLocalDatagram 是本地回包读缓冲大小（UDP 载荷理论上限）。
//
// 按 MTU 猜一个小缓冲会在遇到大报文时**静默截断** ——
// net.UDPConn 的读不会告诉你「还有剩下的」。
const maxLocalDatagram = 65535

// discard 是流被逐出时的清理回调：必须关掉 socket，否则 fd 泄漏。
func (h *UDPHandler) discard(f *localFlow) {
	if f == nil {
		return
	}
	f.close()
	h.stats.Flows.Add(-1)
}

func (h *UDPHandler) sweepIdle(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.flows.EvictIdle(h.discard)
		}
	}
}

// tunnelByShortID 在可服务集合里按短标识找隧道。
func (h *UDPHandler) tunnelByShortID(shortID uint16) (*tunnel.Tunnel, bool) {
	if shortID == 0 {
		// 0 是「未分配」的保留值，不该出现在线上。
		return nil, false
	}
	for _, t := range h.Tunnels.List() {
		if t.ShortID == shortID && t.L4 == tunnel.L4UDP {
			return t, true
		}
	}
	return nil, false
}

// Metrics 把本处理器的计数器打包成一份可上报的快照。
//
// # 为什么这个方法必须存在
//
// 中继只看得见自己那一侧。agent 侧有一整类丢弃是它完全不知道的：
// 拨本地目标失败、被本地策略否决、回向发送队列满、回向超限、回向重组失败。
// 症状是「下行统计都对，就是收不到回包」，而在这条上报之前**没有任何数字**
// 能告诉运维为什么 —— 这些计数器只存在于 agent 自己的内存里。
//
// SendStats() / ReassemblyStats() 原本就是为这个准备的出口，
// 而它们**一个读取点都没有**（连测试都没有）—— 那道
// 「实现了但没接上」的门禁放宽到「零引用也报」之后才抓出来。
func (h *UDPHandler) Metrics() proto.AgentUDPMetrics {
	s, snd, re := h.Stats(), h.SendStats(), h.ReassemblyStats()
	return proto.AgentUDPMetrics{
		PacketsToLocal:   s.PacketsOut.Load(),
		BytesToLocal:     s.BytesOut.Load(),
		PacketsFromLocal: s.PacketsIn.Load(),
		BytesFromLocal:   s.BytesIn.Load(),
		Flows:            s.Flows.Load(),

		Malformed:      s.Malformed.Load(),
		UnknownTunnel:  s.UnknownTunnel.Load(),
		Denied:         s.Denied.Load(),
		DialFailed:     s.DialFailed.Load(),
		TableFull:      s.TableFull.Load(),
		RateLimited:    s.RateLimited.Load(),
		WriteFailed:    s.WriteFailed.Load(),
		PendingDial:    s.PendingDial.Load(),
		BackendChanged: s.BackendChanged.Load(),

		SendQueueFull: snd.QueueFull.Load(),
		SendTooLarge:  snd.TooLarge.Load(),
		SendFailed:    snd.Failed.Load(),
		SendFragments: snd.Fragmented.Load(),
		SendMTUProbes: snd.MTUProbes.Load(),

		ReasmCompleted:   re.Completed.Load(),
		ReasmFragments:   re.Fragments.Load(),
		ReasmTimedOut:    re.TimedOut.Load(),
		ReasmOverlapping: re.Overlapping.Load(),
		ReasmTooManyFrag: re.TooManyFrags.Load(),
	}
}
