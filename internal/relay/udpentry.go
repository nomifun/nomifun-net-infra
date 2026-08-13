package relay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/limiter"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// DatagramStats 是一个 UDP 入口的计数器。
//
// 每个丢弃字段都对应一个 nf_datagram_dropped_total{reason=...} 的标签值。
// 与 TCP 入口同一条原则：「丢了多少」没用，「在哪一道闸丢的」才告诉你
// 该调哪个参数 —— 表满要加容量，配额要提每源上限，限速要放宽建表速率，
// 而这三者对应的运维动作完全不同。
type DatagramStats struct {
	// 上行（用户 → agent）。
	PacketsIn atomic.Int64
	BytesIn   atomic.Int64

	// 下行（agent → 用户）。
	PacketsOut atomic.Int64
	BytesOut   atomic.Int64

	// 上行丢弃原因。
	DeniedCIDR  atomic.Int64
	NoSession   atomic.Int64
	NoDatagram  atomic.Int64 // 承载不支持不可靠数据报
	TableFull   atomic.Int64
	PerIPQuota  atomic.Int64
	RateLimited atomic.Int64

	// 下行丢弃原因。
	UnknownFlow  atomic.Int64 // FlowID 查不到：会话已过期或来自已删隧道
	WriteFailed  atomic.Int64
	ReasmDropped atomic.Int64 // 回向重组失败（细分见 Reassembler.Stats）

	// RateLimitedBytes 是被**限速**丢掉的数据报数。
	//
	// 与 RateLimited 分开：那一项是「建流速率超限」（会话表的建表限速），
	// 这一项是「带宽/包速率超限」。两者的处置不同 ——
	// 前者调 new_flows_per_second，后者调 bytes_per_second。
	RateLimitedBytes atomic.Int64

	// DroppedCarrier 是承载发送侧丢的包（队列满 / 超限 / 承载错误）。
	//
	// # 为什么这一格必须在**每条隧道**上，不能只有会话级
	//
	// Sender 自己按原因分标签计了数，但那些计数器挂在**会话**上 ——
	// 一个 agent 上的所有 UDP 隧道共用一个。控制台是按隧道显示的，
	// 于是「这条隧道的包被丢在发送队列里」这件事在界面上无处可见：
	// PacketsIn 照常涨（旧版本在 Send **之前**就加），用户看到
	// 「收了 1000 包、没有任何丢弃计数」，而实际上一半没出去。
	//
	// 细分原因仍然只在会话级（队列满 vs 超限的处置不同：一个加带宽、
	// 一个等 PMTUD），所以两个层级都要有，不是重复。
	DroppedCarrier atomic.Int64

	// WrongAgent 是「发这个包的 agent 不是这条隧道的 agent」。
	//
	// **非零就是安全事件**，不是容量问题。它意味着某个已入网的 agent
	// 在往别人的隧道里注入数据报 —— 要么是它被攻陷了，要么有人拿到了
	// 一份凭据。所以它与其他丢弃分项的处置完全不同：其他项调参数，
	// 这一项吊销凭据。
	WrongAgent atomic.Int64

	// Flows 是当前活跃流数，供控制台显示。
	Flows atomic.Int64
	// FlowsAdmitted 是**累计**建流数，控制台对它差分得出「新会话/秒」。
	//
	// 与 Flows 是两个数字：活跃数回答「现在有多少人在用」，
	// 累计数回答「流量在增长吗」—— 一条活跃数恒为 2 的隧道，
	// 累计数是 2 还是 20000 是完全不同的两种情况。
	FlowsAdmitted atomic.Int64
}

// FlowsEvicted 返回因会话表**超出容量**而被挤掉的流数。
//
// 不并进 TableFull：那一格的语义是「这个包被拒了」，而这里是
// 「别人的流被挤掉了」——两件事，两种处置（前者调每源配额，后者加容量）。
func (e *DatagramEntry) FlowsEvicted() int64 { return e.flows.CapacityEvictions() }

// dgramFlow 是一条 UDP 流的中继侧状态。
//
// 只存「回包要送到哪」——真正的 socket 在 agent 侧，中继这边只是转发。
type dgramFlow struct {
	id     uint32
	key    udpflow.Key
	client netip.AddrPort
}

// DatagramEntry 在一个 UDP 入口端口上收发用户数据报。
//
// # 为什么它不是 EntryListener 的一个分支
//
// UDP 没有连接，所以没有「每连接一个 goroutine + 双向拷贝」这回事：
// 一个入口只有一条读循环，所有流共享它。把两者塞进一个类型会让每处都要
// 先问「这是 TCP 还是 UDP」，而两条路径的生命周期、背压、丢弃语义
// 没有一处相同。
//
// # 回向路径为什么需要 FlowID 反查
//
// 入向包天然带着源地址，可以直接算出 udpflow.Key。但从承载回来的帧里
// 只有 {Tunnel, FlowID, DstPort} —— 没有源地址（帧头装不下，也不该装：
// 那会让 agent 知道用户的真实地址）。所以中继必须自己记住
// FlowID → 客户端地址，并在会话被逐出时同步清掉，否则这张表就是内存泄漏。
type DatagramEntry struct {
	pc   *net.UDPConn
	port uint16

	// tunnelID 与 shortID、slug 是稳定的；可变字段每包从 lookup 现取，
	// 理由见 TunnelLookup.TunnelByID。
	tunnelID string
	shortID  uint16
	slug     string

	lookup TunnelLookup
	log    *slog.Logger

	// limiter 是这条隧道的限速器，nil 表示不限速。上下行共享一个桶。
	limiter *limiter.Limiter

	flows *udpflow.Table[*dgramFlow]

	// byFlow 是 FlowID → 流的反查表，只在回向路径与建/删流时用到。
	mu     sync.RWMutex
	byFlow map[uint32]*dgramFlow

	nextFlowID atomic.Uint32

	// reasm 重组**回向**的分片。
	//
	// 两侧都要重组，不是只有 agent 要。少了这一半的后果是：agent 把大回包
	// 切片后，中继把每一片单独写给客户端，客户端于是收到一个「长度只有
	// 一片」的报文并当它是完整的 —— 静默截断，而所有计数器都显示正常。
	// 这是 e2e 抓出来的，单元测试各测一侧时两边都是绿的。
	reasm *udpflow.Reassembler

	// sendStats / reasmStats 由本结构体持有，让它们有一个永远有效的地址。
	reasmStats udpflow.ReassemblerStats

	stats DatagramStats

	// onSource 见 DatagramOptions.OnSource。可以为 nil。
	onSource func(tunnelID string, addr netip.Addr)

	closeOnce sync.Once
	done      chan struct{}
}

// maxDatagramSize 是入口读缓冲大小。
//
// 65535 是 UDP 载荷的理论上限。为一个入口常驻一个 64 KiB 缓冲是值得的：
// 读循环只有一条，这块内存不随流数增长；而按 MTU 猜一个小缓冲会在
// 遇到大报文时**静默截断**（net.UDPConn 的读不会告诉你「还有剩下的」）。
const maxDatagramSize = 65535

// clientWriteTimeout 是写回客户端的期限。
//
// 数据报要么现在就能进缓冲，要么它已经过时了 —— 排队等一秒的音频包
// 到达时已经没有价值，而排队的代价是冻结整条共享解复用循环。
const clientWriteTimeout = 50 * time.Millisecond

// randomFlowIDBase 给一个入口的 FlowID 序列挑一个随机起点。
//
// 理由见 NewDatagramEntry 里的说明（短标识 + 端口 + FlowID 三者都会被复用）。
// 用 crypto/rand 不是为了抗预测 —— 而是因为这里没有别的熵源，
// 而 math/rand 的默认源在 Go 1.20 之后虽然自动种子化，
// 但一个进程内多次调用仍会给出可预测序列（同一次重建里我们要的是
// 「与上一次不同」，那正好是 crypto/rand 免费给的保证）。
func randomFlowIDBase() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 拿不到随机数时退回时间戳低位。比固定 0 好：
		// 至少两次重建之间会不同。
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// datagramIdleSweep 是空闲流回收的扫描间隔。
const datagramIdleSweep = 15 * time.Second

// DatagramOptions 是 UDP 入口的可选参数。零值可用。
type DatagramOptions struct {
	Log *slog.Logger

	// Table 覆盖会话表参数（容量、每源 IP 配额、建表限速、空闲回收）。
	Table udpflow.Config

	// Reassembly 覆盖回向分片重组参数。
	Reassembly udpflow.ReassemblerConfig

	// SendQueueDepth 覆盖每会话发送队列深度。
	SendQueueDepth int

	// OnSource 在一条**新流**被准入之后被调用，用于学习模式观测。
	//
	// 每条新流一次，不是每个包一次 —— UDP 读循环是单协程共享的热路径，
	// 在那里做一次 map 写入会按包速率放大（10 万 pps 的小包洪水是现实
	// 攻击形态，见每隧道 packets_per_second 的存在理由）。
	//
	// 只在准入之后调用：被 allow_cidrs 拒掉、或被配额/限速挡掉的来源
	// 不该进「推荐白名单」。可以为 nil。
	OnSource func(tunnelID string, addr netip.Addr)
}

// NewDatagramEntry 在 addr 上绑定一个 UDP 入口并服务一条隧道。
func NewDatagramEntry(
	addr string,
	t *tunnel.Tunnel,
	lookup TunnelLookup,
	opts DatagramOptions,
) (*DatagramEntry, error) {
	if t.L4 != tunnel.L4UDP {
		return nil, errors.New("relay: TCP 隧道请用 NewEntryListener")
	}
	// 短标识为 0 的隧道**不能**上线：0 是「未分配」的保留值，
	// 让它出去会让所有帧都带 Tunnel=0，解复用直接错位 ——
	// 那是静默把流量送到别处，比起不了服务糟糕得多。
	if t.ShortID == 0 {
		return nil, fmt.Errorf("relay: 隧道 %s 没有短标识，无法承载 UDP", t.Slug)
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	// 策略里的并发上限同时约束 UDP 流数 —— 用户设的是「这条隧道最多几路」，
	// 不该因为传输层不同而有两套语义。
	tableCfg := opts.Table
	if t.Policy != nil && t.Policy.MaxConns > 0 && tableCfg.Capacity <= 0 {
		tableCfg.Capacity = t.Policy.MaxConns
	}
	// 用户显式给了每源上限就用它（仍然收敛到容量之内）。
	//
	// 没有这个字段的时候，每源配额只能被动等于容量 —— 于是
	// 「最多 N 路，且单个 IP 不超过其中 M 路」这种意图表达不出来。
	if t.Policy != nil && t.Policy.MaxConnsPerIP > 0 {
		tableCfg.PerSourceIP = t.Policy.MaxConnsPerIP
	}

	// 每源 IP 配额必须**收敛到容量之内**，否则它就是个摆设。
	//
	// 默认容量 8192、每源 256，比例是对的。但用户一填 max_conns=32，
	// 容量就变成 32 而每源仍是 256 —— 于是每源那道闸永远轮不到触发，
	// 一个 IP 就能占满整张表并把别人的流按 LRU 挤掉，
	// 而 PerIPQuota / TableFull / RateLimited 三个计数器全是 0。
	// 用户以为自己填的是保护，实际是把保护关掉了。
	//
	// 收敛之后 max_conns=32 的语义变成「最多 32 路，且单个 IP 最多 32 路」——
	// 「单个 IP 不超过其中一部分」这种表达 v1 没有配置项（README 记账），
	// 但至少现在闸门是有效的、计数器会动。
	if tableCfg.Capacity > 0 && tableCfg.PerSourceIP > tableCfg.Capacity {
		log.Warn("每源 IP 配额大于会话表容量，已收敛到容量 —— 否则它永远不会触发",
			"隧道", t.Slug, "原配额", tableCfg.PerSourceIP, "容量", tableCfg.Capacity)
		tableCfg.PerSourceIP = tableCfg.Capacity
	}
	if tableCfg.Capacity > 0 && tableCfg.PerSourceIP <= 0 &&
		udpflow.DefaultPerSourceIP > tableCfg.Capacity {
		tableCfg.PerSourceIP = tableCfg.Capacity
	}

	pc, err := net.ListenUDP("udp", mustUDPAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("relay: 隧道 %s 绑定 UDP %s 失败：%w", t.Slug, addr, err)
	}

	local := pc.LocalAddr().(*net.UDPAddr)
	e := &DatagramEntry{
		pc:       pc,
		port:     uint16(local.Port),
		tunnelID: t.ID,
		shortID:  t.ShortID,
		slug:     t.Slug,
		lookup:   lookup,
		log:      log,
		flows:    udpflow.New[*dgramFlow](tableCfg),
		limiter:  limiter.New(limitsOf(t)),
		byFlow:   make(map[uint32]*dgramFlow),
		onSource: opts.OnSource,
		done:     make(chan struct{}),
	}
	// FlowID 从一个**随机**值起，而不是 0。
	//
	// 短标识、入口端口、FlowID 三者都会被复用：删掉一条 UDP 隧道、
	// 立刻用同一个端口新建一条（后端不同，这正是重建的动机），
	// 短标识会被 allocShortID 重新分给它，端口是用户自己填的同一个，
	// 而 FlowID 从 1 重新开始 —— 于是旧隧道在途的回包
	// （Tunnel / DstPort / FlowID 三项全对）会被送给**新**隧道的用户，
	// 而新用户的包也会被送到旧后端。双向串台，且计数器一切正常。
	//
	// 随机起点让「旧帧撞上新流」的概率降到 流数/2^32，实际上就是不会发生。
	// 这比给帧头加一个世代字段便宜（不动线协议、不需要 agent 配合），
	// 也比推迟短标识回收简单（那要在存储层维护隔离期）。
	e.nextFlowID.Store(randomFlowIDBase())
	reasmCfg := opts.Reassembly
	reasmCfg.Stats = &e.reasmStats
	e.reasm = udpflow.NewReassembler(reasmCfg)
	return e, nil
}

func mustUDPAddr(addr string) *net.UDPAddr {
	// 解析失败时返回 nil，让 ListenUDP 报出可读的错误 ——
	// 这里 panic 会把一个配置错误变成进程崩溃。
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	return ua
}

// Addr 返回实际绑定地址（端口为 0 时用于取得系统分配的端口）。
func (e *DatagramEntry) Addr() net.Addr { return e.pc.LocalAddr() }

// ShortID 返回本入口所属隧道的短标识，解复用器按它分发。
func (e *DatagramEntry) ShortID() uint16 { return e.shortID }

// Stats 返回计数器指针，供指标采集读取。
func (e *DatagramEntry) Stats() *DatagramStats { return &e.stats }

// ReassemblyStats 返回回向重组的分项计数。**永不为 nil。**
func (e *DatagramEntry) ReassemblyStats() *udpflow.ReassemblerStats { return &e.reasmStats }

// Serve 循环收用户数据报并转发给 agent，直到 ctx 取消或 Close。
func (e *DatagramEntry) Serve(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			e.Close()
		case <-e.done:
		}
	}()

	go e.sweepIdle(ctx)

	// 一条读循环、一块缓冲。UDP 没有连接，所以没有每连接一个 goroutine
	// 这回事；而复用同一块缓冲要求转发路径不得留存它 ——
	// udpflow.Sender.Send 会把内容拷进池化缓冲，正是为此。
	buf := make([]byte, maxDatagramSize)
	for {
		n, src, err := e.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// 单个包读失败（例如 ICMP 端口不可达导致的 ECONNREFUSED）
			// 不该让整个入口退出。
			e.log.Debug("UDP 入口读失败", "隧道", e.slug, "err", err)
			continue
		}
		e.forward(buf[:n], src)
	}
}

// forward 把一个用户数据报送往 agent。
func (e *DatagramEntry) forward(payload []byte, src netip.AddrPort) {
	t, ok := e.lookup.TunnelByID(e.tunnelID)
	if !ok {
		// 隧道刚被删掉而入口还没关。
		return
	}

	// 最便宜的闸门放最前面。
	if !t.SourceAllowed(unmap(src).Addr()) {
		e.stats.DeniedCIDR.Add(1)
		return
	}

	sess, ok := e.lookup.SessionFor(t.AgentID)
	if !ok || !sess.Alive() {
		e.stats.NoSession.Add(1)
		return
	}
	// 承载必须真的支持不可靠数据报。降级到可靠流承载是另一条路
	// （见 carrier.ErrDatagramUnsupported 的说明），v1 只有 QUIC 梯级，
	// 所以这里如实拒绝并计数，而不是悄悄塞进一条可靠流让用户
	// 以为自己拿到了低延迟通道 —— frp 就是那样做的。
	if !sess.SupportsDatagrams() {
		e.stats.NoDatagram.Add(1)
		return
	}
	sender := sess.DatagramSender()
	if sender == nil {
		e.stats.NoDatagram.Add(1)
		return
	}

	key := udpflow.Key{Src: unmap(src), DstPort: e.port, Tunnel: e.shortID}
	flow, ok := e.flows.Lookup(key)
	if !ok {
		flow, ok = e.admit(key)
		if !ok {
			return // 原因已在 admit 里计数
		}
	}

	// 限速：UDP 路径**丢**而不是等。
	//
	// 等一个数据报的额度不如丢掉它 —— 等一秒的音频包到达时已经没有价值，
	// 而等的代价是占住这条入口共享的读循环。
	// 与 TCP 路径相反（那里字节流丢中间一段就是把连接搞坏，所以必须等）。
	if !e.limiter.AllowN(len(payload)) {
		e.stats.RateLimitedBytes.Add(1)
		return
	}

	// 超限的数据报是分片还是丢弃，由 FlagNoReassemble 决定（见 Sender.Send）。
	//
	// 实时隧道（音视频）置它 → 丢弃：分片放大丢包影响，而一帧迟到的音频
	// 等于丢了还白占带宽。批量隧道（IoT 大报文）不置 → 分片：丢了就是
	// 功能不可用。默认是分片，因为默认要错向安全的一侧。
	var flags uint8
	if t.IsRealtimeDatagram() {
		flags |= udpflow.FlagNoReassemble
	}

	if !sender.Send(udpflow.Header{
		Tunnel:  e.shortID,
		FlowID:  flow.id,
		DstPort: e.port,
		Flags:   flags,
	}, payload) {
		// 必须在**这里**也记一笔。
		//
		// 旧版本的理由是「丢弃原因已由 Sender 自己按标签计数，
		// 在这里再累加一次会让同一次丢弃被数两遍」—— 那个理由是错的：
		// Sender 的计数器挂在**会话**上，一个 agent 的所有 UDP 隧道共用
		// 一个，而控制台是按隧道显示的。于是这条隧道的丢包在界面上
		// 一个数字都没有。两个层级记的是不同的问题（这条隧道丢了多少 /
		// 这个承载为什么丢），不是同一个数被数两遍。
		e.stats.DroppedCarrier.Add(1)
		return
	}

	// 记账放在 Send **之后**。
	//
	// 放在前面的话 PacketsIn 的含义就从「已中继」变成「已收到」，
	// 而这一段所有其他闸门（DeniedCIDR / NoSession / TableFull…）
	// 都是在 return 之前就不计 PacketsIn 的 —— 混两种语义会让
	// 「收了 1000 包、零丢弃」与「一半没出去」同时成立。
	e.stats.PacketsIn.Add(1)
	e.stats.BytesIn.Add(int64(len(payload)))
}

// admit 为一条新流申请配额并登记反查表。
func (e *DatagramEntry) admit(key udpflow.Key) (*dgramFlow, bool) {
	flow, created, err := e.flows.Admit(key, func() (*dgramFlow, error) {
		// 这个回调在**分片锁之外**执行（见 udpflow.Table.Admit 的说明），
		// 所以这里可以安全地做加锁操作。
		f := &dgramFlow{
			// FlowID 从 1 开始递增。回绕后可能与一条早已过期的流撞号，
			// 但撞号的后果只是「一个陈旧的回包被送给新流的客户端」，
			// 而回包还要经过 DstPort 与 Tunnel 校验，且流表本身有空闲回收 ——
			// 在 2^32 个号里回绕一圈之前，旧流早就不在表里了。
			id:     e.nextFlowID.Add(1),
			key:    key,
			client: key.Src,
		}
		return f, nil
	}, e.discard)
	if err != nil {
		switch {
		case errors.Is(err, udpflow.ErrTableFull):
			// 当前的流表不会返回这个（它淘汰最旧而不是拒绝新流），
			// 「表满」走 CapacityEvictions —— 见 Stats() 的读取处。
			e.stats.TableFull.Add(1)
		case errors.Is(err, udpflow.ErrPerIPQuota):
			e.stats.PerIPQuota.Add(1)
		case errors.Is(err, udpflow.ErrRateLimited):
			e.stats.RateLimited.Add(1)
		default:
			e.log.Warn("UDP 建流失败", "隧道", e.slug, "流", key.String(), "err", err)
		}
		return nil, false
	}

	// 只有**真的建出来**的那一次才登记反查表与 +1。
	//
	// 并发同键时 Admit 返回的是别人的值（我建的那个已经交给 discard 了），
	// 对它再做一遍就会把活跃流数记重，而 discard 那边的 -1 与这里的 +1
	// 谁先跑并不确定 —— 计数可以瞬时变负。
	if created {
		e.mu.Lock()
		e.byFlow[flow.id] = flow
		e.mu.Unlock()
		e.stats.Flows.Add(1)
		e.stats.FlowsAdmitted.Add(1)

		// 学习模式观测点。放在 created 里面：并发同键时只有真的建出流的
		// 那一次才通知，否则同一个客户端会被记成多次命中，
		// 而命中次数正是运维用来区分真客户端与扫描器的依据。
		if e.onSource != nil {
			e.onSource(e.tunnelID, key.Src.Addr())
		}
	}

	return flow, true
}

// discard 是会话表逐出流时的清理回调。
//
// **必须**同步清掉反查表，否则 byFlow 会随着流的增删无界增长 ——
// 中继是长期运行的进程，那就是一个慢速内存泄漏。
func (e *DatagramEntry) discard(f *dgramFlow) {
	if f == nil {
		return
	}
	e.mu.Lock()
	delete(e.byFlow, f.id)
	e.mu.Unlock()
	e.stats.Flows.Add(-1)
}

// Deliver 把一条来自 agent 的数据报送回原始客户端。
//
// fromAgent 是**发出这个包的会话**的 agent ID，由解复用循环传进来。
//
// # 为什么必须校验发送方
//
// 所有 agent 会话共用**一个**全局 DatagramRouter（进程里只有一个），
// 而帧头里的隧道短标识是明文、16 位、可枚举的。不校验发送方的话，
// 任何一个已入网的 agent 都能构造一帧、填上别人隧道的短标识与一个
// 猜中的 FlowID，让载荷从中继的公网端口发到**别人隧道的真实客户端**上。
//
// 那不是一个理论问题：源地址与正常回包完全一致（都是中继），
// 所有计数器都正常递增，控制台上看不出任何异常 ——
// 运维只会怀疑「对面那个 agent 有问题」。它同时也是一个 UDP 反射器：
// 被打的人看到的源 IP 是中继。
//
// 短标识、入口端口、FlowID 三者都会被复用，所以**没有**一个「猜不中」
// 的假设可以依赖。唯一可靠的判据是「这条隧道现在归谁」。
func (e *DatagramEntry) Deliver(fromAgent string, h udpflow.Header, payload []byte) {
	// 这一道闸放在最前面：它比查流表更便宜，而且它挡的是**注入**，
	// 不该让被注入的包先去动流表（Lookup 会刷新活跃时间，
	// 那等于让攻击者延长别人流的寿命）。
	//
	// 现取而不是建表时快照：隧道可以被改绑到另一个 agent，
	// 快照会让旧 agent 在改绑后仍然能投递。
	t, ok := e.lookup.TunnelByID(e.tunnelID)
	if !ok || t.AgentID == "" || t.AgentID != fromAgent {
		e.stats.WrongAgent.Add(1)
		// Warn：这是安全事件，不是容量问题。
		e.log.Warn("丢弃数据报：发送方不是这条隧道的代理端",
			"隧道", e.slug, "发送方", fromAgent, "应为", agentOf(t, ok))
		return
	}

	e.mu.RLock()
	flow, ok := e.byFlow[h.FlowID]
	e.mu.RUnlock()
	if !ok {
		// 流已过期，或这个包属于一条已被删掉的隧道。丢掉并计数 ——
		// 静默丢弃会让「为什么对方收不到」变成一个查不下去的问题。
		e.stats.UnknownFlow.Add(1)
		return
	}
	// 目的端口必须与本入口一致。不校验的话，一个构造过的帧就能让
	// A 隧道的回包出现在 B 隧道的客户端那里。
	if h.DstPort != e.port {
		e.stats.UnknownFlow.Add(1)
		return
	}

	// 下行也要过限速：用户设的是「这条隧道最多多少带宽」，
	// 只限上行等于让一条隧道在下行方向不受限。
	if !e.limiter.AllowN(len(payload)) {
		e.stats.RateLimitedBytes.Add(1)
		return
	}

	// 分片先重组齐再写给客户端。
	//
	// 少了这一步就是静默截断：客户端会收到一个「长度只有一片」的报文
	// 并当它是完整的，而所有计数器都显示正常。
	if h.Fragmented() {
		full, complete, err := e.reasm.Push(h, payload)
		if err != nil {
			e.stats.ReasmDropped.Add(1)
			return
		}
		if !complete {
			return
		}
		payload = full
	}

	// 写期限是必需的。
	//
	// 这条写跑在**每会话共享**的解复用循环上，而 UDP socket 的写在发送
	// 缓冲满时会阻塞（某个客户端的下行路径拥塞就会发生：上行受限的家宽
	// 在跑高码率视频、或路径上 qdisc 积压）。没有期限的话，一个客户端的
	// 拥塞会冻住同一 agent 承载上**其它所有** UDP 隧道、其它所有用户的下行。
	//
	// 期限很短：数据报要么现在就能进缓冲，要么它已经过时了。
	//
	// 多个会话的解复用循环会并发设这个期限，彼此覆盖 —— 但它们设的都是
	// 「现在 + 50ms」，所以最坏只是把别人的期限提前几微秒。
	_ = e.pc.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
	n, err := e.pc.WriteToUDPAddrPort(payload, flow.client)
	if err != nil {
		e.stats.WriteFailed.Add(1)
		return
	}
	// 刷新活跃时间：只有上行刷新的话，一条「只收不发」的流
	//（比如接收端在听一路单向音频）会被空闲回收误杀。
	e.flows.Lookup(flow.key)

	e.stats.PacketsOut.Add(1)
	e.stats.BytesOut.Add(int64(n))
}

// agentOf 给日志用：隧道查不到时如实说「查不到」而不是打一个空串。
func agentOf(t *tunnel.Tunnel, ok bool) string {
	if !ok || t == nil {
		return "（隧道已删除）"
	}
	if t.AgentID == "" {
		return "（未绑定代理端）"
	}
	return t.AgentID
}

// sweepIdle 周期性回收空闲流。
//
// 不能只靠容量上限做 LRU 淘汰：一个长期低负载的中继永远到不了容量上限，
// 那些早已结束的流就会一直占着表和反查表。
func (e *DatagramEntry) sweepIdle(ctx context.Context) {
	ticker := time.NewTicker(datagramIdleSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case <-ticker.C:
			if n := e.flows.EvictIdle(e.discard); n > 0 {
				e.log.Debug("回收空闲 UDP 流", "隧道", e.slug, "条数", n)
			}
		}
	}
}

// Close 关闭 UDP 入口。可重复调用。
func (e *DatagramEntry) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.done)
		err = e.pc.Close()
		e.flows.Close(e.discard)
	})
	return err
}

// unmap 把 IPv4-in-IPv6 规范化。
//
// 必须做：::ffff:1.2.3.4 与 1.2.3.4 是同一个来源，不规范化会让
// 同一个客户端占两份配额，也会让源 IP 白名单被绕过。
func unmap(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().Is4In6() {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap
}

// ── 解复用 ──────────────────────────────────────────────────────────────────

// DatagramRouter 把一条承载上收到的数据报按隧道短标识分发到对应入口。
//
// # 为什么必须集中解复用
//
// 数据报是**每承载**一条流（QUIC 的 ReceiveDatagram 是连接级的），
// 不是每隧道一条。所以不能让每个入口各自去 ReceiveDatagram —— 那样
// 多个入口会互相抢包，各自只拿到属于别人的帧。必须一条循环收下、
// 按帧头里的 Tunnel 分发。这也正是帧头需要那个字段的原因。
type DatagramRouter struct {
	mu      sync.RWMutex
	entries map[uint16]*DatagramEntry

	log *slog.Logger

	// 分发失败的计数。挂在路由器上而不是入口上 —— 这些包压根没能
	// 找到入口，归不到任何一条隧道名下。
	malformed atomic.Int64
	unrouted  atomic.Int64
}

// NewDatagramRouter 创建一个解复用器。
func NewDatagramRouter(log *slog.Logger) *DatagramRouter {
	if log == nil {
		log = slog.Default()
	}
	return &DatagramRouter{entries: make(map[uint16]*DatagramEntry), log: log}
}

// Register 登记一个入口。同一短标识重复登记会覆盖。
func (r *DatagramRouter) Register(e *DatagramEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[e.ShortID()] = e
}

// Unregister 注销一个入口。
//
// **按短标识删是不够的**，几乎所有调用都该用 UnregisterEntry ——
// 理由见那里。留着这个是给「隧道确实没了、手上也没有 entry 对象」的场合。
func (r *DatagramRouter) Unregister(shortID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, shortID)
}

// UnregisterEntry 只在注册表里**还是这个入口**时才注销它。
//
// # 为什么身份比较是必需的
//
// ApplyTunnels 会被并发调用（控制台改配置、agent 上线各走一次）。
// 一次「改入口端口」会先关旧入口再建新入口，而两者短标识相同。
// 于是这个交错是可能的：
//
//	调用 A：建好新入口，Register(shortID)
//	调用 B：手上还拿着**旧**入口，Unregister(shortID) → 把 A 的注册删掉
//
// 结果是这条隧道从此**单向**：上行照常（入口自己的读循环还在跑），
// 而所有回向数据报在 Dispatch 里查不到入口，被记成 unrouted 丢掉。
// 保存请求返回成功，控制台显示正常，用户看到「发得出去收不回来」。
func (r *DatagramRouter) UnregisterEntry(e *DatagramEntry) {
	if e == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[e.ShortID()] == e {
		delete(r.entries, e.ShortID())
	}
}

// Stats 返回分发失败计数。
func (r *DatagramRouter) Stats() (malformed, unrouted int64) {
	return r.malformed.Load(), r.unrouted.Load()
}

// Dispatch 解析一条数据报并投递给对应入口。
//
// fromAgent 必须是**发出这个包的会话**的 agent ID：所有会话共用一个
// 路由器，而隧道短标识可枚举，所以「谁发的」是投递路径上唯一可靠的判据
// （理由见 DatagramEntry.Deliver）。
func (r *DatagramRouter) Dispatch(fromAgent string, raw []byte) {
	h, payload, err := udpflow.ParseFrame(raw)
	if err != nil {
		// 畸形帧只计数，**绝不**因此关闭承载：一个坏包不该让
		// 整条隧道断掉。这与 proto.Reader 遇到未知帧类型的处置一致。
		r.malformed.Add(1)
		return
	}

	r.mu.RLock()
	e, ok := r.entries[h.Tunnel]
	r.mu.RUnlock()
	if !ok {
		r.unrouted.Add(1)
		return
	}
	e.Deliver(fromAgent, h, payload)
}

// RunDatagramLoop 在一个会话上循环收数据报并分发。
//
// 由中继在 agent 上线后启动，随承载断开而返回。
func RunDatagramLoop(ctx context.Context, sess *Session, r *DatagramRouter, log *slog.Logger) {
	if !sess.SupportsDatagrams() {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	for {
		raw, err := sess.Carrier.ReceiveDatagram(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Debug("数据报接收循环结束", "agent", sess.AgentID, "err", err)
			}
			return
		}
		// 会话身份必须跟着包走。丢掉它的后果是任一 agent 都能往别人的
		// 隧道里注入数据报（见 DatagramEntry.Deliver）。
		r.Dispatch(sess.AgentID, raw)
	}
}
