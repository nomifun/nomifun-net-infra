// Package relay 实现中继侧：接受 agent 承载、管理会话世代、按隧道监听入口端口、
// 主动开流把用户连接送到 agent。
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// Session 是一个 agent 的一次在线会话。
//
// 它是**观测状态**，与 Tunnel（期望状态）是不同对象。
type Session struct {
	AgentID string

	// Generation 区分同一 AgentID 的不同世代。
	//
	// 这个字段不能省：agent 重连时新连接要顶替旧连接，而旧连接的 goroutine
	// 可能还在跑。用世代号才能让迟到的旧世代操作被安全丢弃，
	// 而不是误伤新会话。frp 用 controlID 做同样的事
	//（server/control.go:414-417），那套世代管理是它多年踩坑的结晶。
	Generation uint64

	Carrier      carrier.Carrier
	Capabilities []proto.Capability
	ConnectedAt  time.Time

	// sender 是本会话的非阻塞数据报发送器，首次用到时创建。
	//
	// 每会话一个而不是每隧道一个：quic-go 的数据报队列是**连接级**的
	// （datagram_queue.go），所以真正需要被隔离的阻塞点也在连接级。
	// 每隧道一个发送器只会让 N 个 goroutine 去抢同一个会阻塞的队列。
	senderOnce sync.Once
	sender     *udpflow.Sender

	// senderMade 只在真的建过发送器时为 true。
	//
	// **不能**靠 senderOnce.Do(func(){}) 来探测：那会把 Once 消耗掉，
	// 于是之后 DatagramSender 再也不会创建发送器 —— 一旦控制台渲染过
	// 一次 agent 列表，这台 agent 上所有 UDP 隧道就永久哑掉。
	// Close 里那处 Do(func(){}) 是刻意的（它就是要阻止之后再创建），
	// 而这里要的是相反的语义，所以必须另立一个标志。
	senderMade atomic.Bool

	// dgramStats 由 Session 持有而不是问 sender 要：sender 是延迟创建的，
	// 而指标采集可能更早发生。让统计对象有一个永远有效的地址。
	dgramStats udpflow.SenderStats

	// rtt 是承载 RTT 的观测状态（Ping/Pong，见 rtt.go）。
	rtt rttState

	// closed 保证清理只做一次。
	closeOnce sync.Once
}

// DatagramSendStats 返回本会话的数据报发送统计。**永不为 nil。**
func (s *Session) DatagramSendStats() *udpflow.SenderStats { return &s.dgramStats }

// HasDatagramSender 报告本会话是否已经建过数据报发送器。
//
// 控制台用它决定「报数字」还是「报没有」：发送器是惰性创建的，没建过时
// 一整排计数器都是 0，而 0 会被读成「测过，是零」——
// 那正好把「这条承载上没有 UDP 隧道」与「有 UDP 隧道但一个包都没丢」
// 混成同一个显示。
func (s *Session) HasDatagramSender() bool { return s.senderMade.Load() }

// DatagramSender 返回本会话的数据报发送器，承载不支持数据报时返回 nil。
//
// 延迟创建：绝大多数会话上没有 UDP 隧道，不该为它们常驻一个 goroutine
// 和一条队列。发送循环的生命周期绑在承载的 Context 上 ——
// 承载一断，goroutine 自己就退了，不需要额外的关闭协调。
func (s *Session) DatagramSender() *udpflow.Sender {
	if !s.SupportsDatagrams() {
		return nil
	}
	s.senderOnce.Do(func() {
		s.sender = udpflow.NewSender(s.Carrier, 0, &s.dgramStats)
		s.senderMade.Store(true)
		go s.sender.Run(s.Carrier.Context())
	})
	return s.sender
}

// SupportsDatagrams 报告本会话能否走不可靠数据报。
//
// 它同时要求承载支持**且**双方协商出了 CapDatagram —— 承载能力与协议能力
// 是两件事，只查一个会在对端版本较旧时误判。
func (s *Session) SupportsDatagrams() bool {
	if !s.Carrier.SupportsDatagrams() {
		return false
	}
	for _, c := range s.Capabilities {
		if c == proto.CapDatagram {
			return true
		}
	}
	return false
}

// Alive 报告承载是否仍然连通。
//
// 入口监听器在派发连接前必须查这个：否则 agent 进程被强杀后，
// 中继会继续把用户连接派给一个已死的会话，用户看到的是挂死或陈旧数据，
// 而不是干净的「代理端不在线」。
func (s *Session) Alive() bool {
	select {
	case <-s.Carrier.Context().Done():
		return false
	default:
		return true
	}
}

// Close 关闭会话。可重复调用。
func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		// 先穿过 senderOnce 再读 s.sender。
		//
		// 这不是多余的：DatagramSender 在 senderOnce 里**写** s.sender，
		// 这里若直接读就是一次数据竞争。把一个空函数交给同一个 Once，
		// 效果是「要么等在飞的创建做完，要么就地占掉这个 Once
		// 让之后不再创建」—— 两种情况下读 s.sender 都是安全的，
		// 且不需要再引入一把锁。
		s.senderOnce.Do(func() {})
		if s.sender != nil {
			s.sender.Close()
		}
		_ = s.Carrier.CloseWithError(0, reason)
	})
}

// SessionManager 管理在线 agent 会话，处理同 ID 顶替。
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	nextGen  uint64

	log *slog.Logger
}

// NewSessionManager 创建会话管理器。
func NewSessionManager(log *slog.Logger) *SessionManager {
	if log == nil {
		log = slog.Default()
	}
	return &SessionManager{sessions: make(map[string]*Session), log: log}
}

// Add 登记一个会话，并顶替同 AgentID 的旧会话。
//
// 返回被顶替的旧会话（若有），由调用方决定何时关闭它 ——
// 立即关闭会让正在传输的数据被截断，所以这个决定留给上层。
func (m *SessionManager) Add(s *Session) (replaced *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextGen++
	s.Generation = m.nextGen

	if old, ok := m.sessions[s.AgentID]; ok {
		replaced = old
		m.log.Info("agent 重连，顶替旧会话",
			"agent", s.AgentID, "旧世代", old.Generation, "新世代", s.Generation)
	}
	m.sessions[s.AgentID] = s
	return replaced
}

// Get 取一个在线会话。
func (m *SessionManager) Get(agentID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[agentID]
	return s, ok
}

// Remove 按世代移除会话。
//
// **必须带世代号**：一个迟到的旧世代清理若直接按 AgentID 删除，
// 会把刚建立的新会话误删。这正是世代号存在的理由。
func (m *SessionManager) Remove(agentID string, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[agentID]
	if !ok || s.Generation != generation {
		return false
	}
	delete(m.sessions, agentID)
	return true
}

// Len 返回在线会话数。
func (m *SessionManager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// List 返回所有在线会话的快照。
func (m *SessionManager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// CloseAll 关闭全部会话，用于优雅退出。
func (m *SessionManager) CloseAll(reason string) {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()

	for _, s := range sessions {
		s.Close(reason)
	}
}

// ── 数据面：中继主动开流 ─────────────────────────────────────────────────────

// OpenTunnelStream 为一条新的用户连接向 agent 开一条流。
//
// # 这个函数是「0 额外 RTT」的落点
//
// frp 必须走 ReqWorkConn → NewWorkConn → StartWorkConn 三条控制消息
// （server/control.go:595-637）= 1.5×RTT，因为它的 Connector 只有客户端能开流。
// 这里中继直接 OpenStream 并把 StreamOpen 头**与用户首包一起**写出去，
// 那三条消息全部消失。
//
// 注意写入顺序：头必须先落到同一个写缓冲，然后立刻跟上首批用户字节，
// 这样它们尽可能合并进同一个 QUIC 包 —— 否则就白省了那半个 RTT。
func OpenTunnelStream(ctx context.Context, s *Session, open proto.StreamOpen) (carrier.Stream, error) {
	st, err := s.Carrier.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("relay: 向 agent %s 开流失败：%w", s.AgentID, err)
	}

	// 写**也**必须有期限，不能只给读加。
	//
	// 这是 internal/relay 补测试时抓出来的：ctx 的期限只作用于 OpenStream，
	// 而紧接着的这次 WriteMessage 完全没有期限。对端若已经停止消费
	//（进程被强杀、读循环卡死、或只是内存换页换到天荒地老），
	// 流的流控窗口填满后这次写就**永远**阻塞。
	//
	// 后果比「一条连接挂死」严重得多：卡住的 handle goroutine 一直占着
	// 入口的信号量槽位，攒够 MaxConns 条就把整个入口彻底堵死，
	// 之后所有新连接都被记成 RateLimited —— 一个看起来像过载的死锁。
	//
	// 修 kill -9 挂死那次只补了 AwaitStreamOK 的读期限，漏了这一侧。
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetWriteDeadline(dl)
	}

	w := proto.NewWriter(st)
	if err := w.WriteMessage(proto.TypeStreamOpen, 0, 0, open); err != nil {
		st.Close()
		return nil, fmt.Errorf("relay: 写 StreamOpen 失败：%w", err)
	}
	// 期限只管建连阶段：之后是长连接业务流量，不该被它打断。
	_ = st.SetWriteDeadline(time.Time{})
	return st, nil
}

// StreamRejectedError 表示 agent 明确拒绝了这条流（本地策略否决、拨号失败等）。
//
// 单独一个类型是为了让调用方能把「agent 说不」与「网络出问题」分开计数：
// 前者要把原因原样呈现给用户（他自己的策略挡住了自己的隧道），
// 后者要指向承载链路。
type StreamRejectedError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *StreamRejectedError) Error() string {
	return fmt.Sprintf("relay: 代理端拒绝了这条流：%s（%s）", e.Message, e.Code)
}

// AwaitStreamOK 等 agent 确认本地已连通。
//
// 这一步不能省：若本地服务拨不通，我们要在**用户连接上**给出干净的失败，
// 而不是让用户对着一个已建立但永远没有响应的连接干等。
//
// 读也必须有期限 —— 死 agent 不会回任何东西。这是手工验证抓出来的真实缺陷：
// agent 进程被 kill -9 时不发 QUIC 关闭帧，承载要等到空闲超时（30s）才取消，
// 期间会话看起来还活着。Session.Alive() 挡不住这个检测窗口，
// 唯一可靠的办法是给这条路径一个远小于空闲超时的期限。
//
// 确认到达后期限会被清掉：之后是长连接业务流量，不该被这个超时打断。
// 返回的 io.Reader 是**必须**用于后续拷贝的读取器：它先吐出帧读取时被
// 一并缓冲的业务字节，再接回流本身。直接从 st 拷贝会静默丢掉那些字节 ——
// 见 proto.Reader.Remainder 的说明。
func AwaitStreamOK(st carrier.Stream, timeout time.Duration) (*proto.StreamOK, io.Reader, error) {
	_ = st.SetReadDeadline(time.Now().Add(timeout))

	r := proto.NewReader(st)
	fr, err := r.ReadFrame()
	if err != nil {
		return nil, nil, fmt.Errorf("relay: 等代理端确认失败：%w", err)
	}
	_ = st.SetReadDeadline(time.Time{})
	rest := r.Remainder(st)

	switch fr.Header.Type {
	case proto.TypeStreamOK:
		var ok proto.StreamOK
		// 解码失败不致命：确认已经到了，LocalAddr 只是给控制台排障用的。
		_ = proto.Decode(fr, &ok)
		return &ok, rest, nil

	case proto.TypeError:
		var e proto.Error
		_ = proto.Decode(fr, &e)
		return nil, nil, &StreamRejectedError{Code: e.Code, Message: e.Message, Retryable: e.Retryable}

	default:
		return nil, nil, fmt.Errorf("relay: 代理端回了意外帧 %s", fr.Header.Type)
	}
}

// DialTunnelStream 是「开流 + 等确认」的合体，供入口监听器与网关共用。
//
// 两条路径（L4 入口与 L7 网关）必须共用同一套超时与确认语义，
// 否则同一个故障在两处的表现会不一样，排障时要先猜自己走的是哪条路。
// 返回的 TunnelStream 把「写向流」与「从余量读」分开保存：
// 直接对 carrier.Stream 做双向拷贝会丢掉被缓冲的首批业务字节。
func DialTunnelStream(
	ctx context.Context,
	s *Session,
	open proto.StreamOpen,
	timeout time.Duration,
) (*TunnelStream, error) {
	st, err := OpenTunnelStream(ctx, s, open)
	if err != nil {
		return nil, err
	}
	_, rest, err := AwaitStreamOK(st, timeout)
	if err != nil {
		st.Close()
		return nil, err
	}
	return &TunnelStream{Stream: st, Reader: rest}, nil
}

// TunnelStream 是一条已确认可用的隧道流。
//
// Stream 用于写与关闭；**读必须走 Reader** —— 它先吐出帧读取时被一并缓冲的
// 业务字节。把这两者分开是刻意的：类型签名让调用方无法「不小心」直接读 Stream。
type TunnelStream struct {
	Stream carrier.Stream
	Reader io.Reader
}

// Close 关闭底层流。
func (t *TunnelStream) Close() error { return t.Stream.Close() }

// ── 握手 ────────────────────────────────────────────────────────────────────

// AgentAuthenticator 校验 agent 的握手。
//
// 抽成接口是为了让存储层可替换（v1 是 SQLite，测试用内存实现）。
type AgentAuthenticator interface {
	// LookupKey 返回 agentID 对应的密钥。agent 不存在或已撤销时返回 ok=false。
	LookupKey(agentID string) (key []byte, ok bool)

	// RedeemEnrolToken 兑换一个一次性入网令牌，返回新签发的 agentID 与密钥。
	//
	// profile 是 agent 在 Hello 里上报的设备画像（主机名、OS、架构、版本、
	// machine_id）。实现应当把它一并落库 —— 否则控制台的节点清单里
	// OS 与架构会是空的，而那正是用户最想看的两列。
	//
	// 实现必须保证令牌**只能用一次**，且有过期时间。
	RedeemEnrolToken(token string, profile AgentProfile) (agentID string, key []byte, err error)
}

// AgentProfile 是 agent 上报的设备画像。
//
// 它同时是场景三「设备台账」的雏形：那个场景需要按 OS 分派不同的
// computer-use 指令，而这些字段正是分派依据。现在就收集，
// 将来不必再改线协议。
type AgentProfile struct {
	MachineID string
	Hostname  string
	OS        string
	Arch      string
	Version   string
}

// HandshakeConfig 是握手参数。
type HandshakeConfig struct {
	Auth  AgentAuthenticator
	Guard *proto.ReplayGuard

	// RelayVersion 会回给 agent，用于控制台展示与兼容判断。
	RelayVersion string

	// MinProtocolVersion 低于此值的 agent 被拒，且返回结构化错误
	// 让控制台显示「代理端过旧，请升级到 ≥ X」而不是一个裸断连。
	MinProtocolVersion uint32

	// Now 可注入以便测试。
	Now func() time.Time

	Log *slog.Logger
}

func (c *HandshakeConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// 握手错误。
var (
	ErrHandshakeAuth      = errors.New("relay: agent 握手鉴权失败")
	ErrHandshakeReplay    = errors.New("relay: agent 握手 nonce 重放")
	ErrHandshakeTooOld    = errors.New("relay: agent 协议版本过旧")
	ErrHandshakeMalformed = errors.New("relay: agent 握手报文非法")
)

// HandshakeOutcome 是握手结果，其 Outcome 字段直接用作
// nf_agent_handshakes_total{outcome} 的标签值 —— 这个指标本身就是安全看板。
type HandshakeOutcome struct {
	AgentID      string
	Capabilities []proto.Capability
	Outcome      string

	// Profile 是本次握手上报的设备画像。
	//
	// 已注册 agent 重连时也要用它刷新库里的记录 —— 用户升级了 agent 版本、
	// 改了主机名，控制台应当立刻反映出来，而不是一直显示首次入网时的值。
	Profile AgentProfile

	// Rest 是**握手之后必须用它继续读控制流**的 reader。
	//
	// 握手用的 proto.Reader 内部是一个 16 KiB bufio，一次 Read 可能把
	// Hello **之后**的字节一起吞进缓冲。丢掉那个 Reader 就是静默丢掉那些
	// 字节，而新 Reader 会从一个帧的中间开始解析 → 版本不匹配 →
	// 整条控制流死掉（连 agent 的计量上报与 Pong 一起）。
	//
	// proto.Reader.Remainder 的注释把这条写成了硬要求。
	// 今天不咬人只是因为 agent 要等 5 秒才发第一帧上报 —— 缓冲那时已经空了。
	Rest io.Reader
}

// 握手结果标签。
const (
	OutcomeOK           = "ok"
	OutcomeBadMAC       = "bad_mac"
	OutcomeStale        = "stale"
	OutcomeReplay       = "replay"
	OutcomeUnknownAgent = "unknown_agent"
	OutcomeRevoked      = "revoked"
	OutcomeTooOld       = "version_reject"
	OutcomeMalformed    = "malformed"
)

// Handshake 在一条已建立的控制流上完成 agent 握手。
//
// exporter 应当是 TLS 的 ExportKeyingMaterial 输出，用于把证明绑定到本条会话；
// 它使得「在时间窗内把证明重放到另一条 TLS 连接」也会失败。
func Handshake(
	st carrier.Stream,
	exporter []byte,
	cfg HandshakeConfig,
) (*HandshakeOutcome, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}

	r := proto.NewReader(st)
	w := proto.NewWriter(st)

	fr, err := r.ReadFrame()
	if err != nil {
		return &HandshakeOutcome{Outcome: OutcomeMalformed},
			fmt.Errorf("%w: 读 Hello 失败：%w", ErrHandshakeMalformed, err)
	}
	if fr.Header.Type != proto.TypeHello {
		return &HandshakeOutcome{Outcome: OutcomeMalformed},
			fmt.Errorf("%w: 首帧应为 Hello，收到 %s", ErrHandshakeMalformed, fr.Header.Type)
	}

	var hello proto.Hello
	if err := proto.Decode(fr, &hello); err != nil {
		return &HandshakeOutcome{Outcome: OutcomeMalformed},
			fmt.Errorf("%w: %w", ErrHandshakeMalformed, err)
	}

	if hello.ProtocolVersion < cfg.MinProtocolVersion {
		// 结构化拒绝，而不是裸断连 —— 控制台要能显示「升级到 ≥ X」。
		_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
			Code: proto.ErrCodeAgentTooOld,
			Message: fmt.Sprintf("代理端协议版本 %d 过旧，请升级到 ≥ %d",
				hello.ProtocolVersion, cfg.MinProtocolVersion),
			Retryable: false,
		})
		return &HandshakeOutcome{Outcome: OutcomeTooOld},
			fmt.Errorf("%w: %d < %d", ErrHandshakeTooOld, hello.ProtocolVersion, cfg.MinProtocolVersion)
	}

	var (
		agentID  string
		agentKey []byte
		issued   string // 首次入网时下发的密钥（hex），否则为空
	)

	switch {
	case hello.EnrolToken != "":
		// 首次入网：兑换一次性令牌。
		id, key, err := cfg.Auth.RedeemEnrolToken(hello.EnrolToken, AgentProfile{
			MachineID: hello.MachineID,
			Hostname:  hello.Hostname,
			OS:        hello.OS,
			Arch:      hello.Arch,
			Version:   hello.Version,
		})
		if err != nil {
			_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
				Code: proto.ErrCodeAuthFailed, Message: "入网令牌无效或已使用", Retryable: false,
			})
			return &HandshakeOutcome{Outcome: OutcomeUnknownAgent},
				fmt.Errorf("%w: 入网令牌兑换失败：%w", ErrHandshakeAuth, err)
		}
		agentID, agentKey = id, key
		issued = hexEncode(key)
		log.Info("新 agent 入网", "agent", agentID, "os", hello.OS, "arch", hello.Arch)

	case hello.AgentID != "":
		key, ok := cfg.Auth.LookupKey(hello.AgentID)
		if !ok {
			_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
				Code: proto.ErrCodeRevoked, Message: "该代理端未注册或凭据已撤销", Retryable: false,
			})
			return &HandshakeOutcome{Outcome: OutcomeUnknownAgent},
				fmt.Errorf("%w: agent %s 未注册或已撤销", ErrHandshakeAuth, hello.AgentID)
		}
		// 先校验无状态部分（时钟窗 + MAC + 信道绑定）。
		if err := hello.Auth.Verify(key, hello.ProtocolVersion, proto.ALPN, exporter, cfg.now()); err != nil {
			outcome := OutcomeBadMAC
			if errors.Is(err, proto.ErrProofStale) {
				outcome = OutcomeStale
			}
			_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
				Code: proto.ErrCodeAuthFailed, Message: "握手证明校验失败", Retryable: true,
			})
			return &HandshakeOutcome{Outcome: outcome}, fmt.Errorf("%w: %w", ErrHandshakeAuth, err)
		}
		// 再查有状态部分（这个 nonce 用过没有）。两者都过才算成功。
		if !cfg.Guard.Check(hello.AgentID, hello.Auth.Nonce) {
			_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
				Code: proto.ErrCodeAuthFailed, Message: "握手 nonce 已被使用", Retryable: true,
			})
			return &HandshakeOutcome{Outcome: OutcomeReplay},
				fmt.Errorf("%w: agent %s nonce %s", ErrHandshakeReplay, hello.AgentID, hello.Auth.Nonce)
		}
		agentID, agentKey = hello.AgentID, key

	default:
		return &HandshakeOutcome{Outcome: OutcomeMalformed},
			fmt.Errorf("%w: Hello 既无 agent_id 也无 enrol_token", ErrHandshakeMalformed)
	}
	_ = agentKey // 密钥在后续 rekey 时才需要，这里只做校验

	caps := proto.NegotiateCapabilities(proto.RelayCapabilities(), hello.Capabilities)

	resp := proto.HelloOK{
		AgentID:              agentID,
		AgentKey:             issued,
		Capabilities:         caps,
		MinSupportedProtocol: cfg.MinProtocolVersion,
		RelayVersion:         cfg.RelayVersion,
		ServerUnixMilli:      cfg.now().UnixMilli(),
	}
	if err := w.WriteMessage(proto.TypeHelloOK, fr.Header.CorrID, proto.FlagResponse, resp); err != nil {
		return &HandshakeOutcome{Outcome: OutcomeMalformed},
			fmt.Errorf("relay: 写 HelloOK 失败：%w", err)
	}

	return &HandshakeOutcome{
		AgentID:      agentID,
		Capabilities: caps,
		Outcome:      OutcomeOK,
		Profile: AgentProfile{
			MachineID: hello.MachineID,
			Hostname:  hello.Hostname,
			OS:        hello.OS,
			Arch:      hello.Arch,
			Version:   hello.Version,
		},
		// 把 bufio 里已经吞掉的字节接回去，理由见 Rest 的说明。
		Rest: r.Remainder(st),
	}, nil
}

// hexEncode 是一个小工具，避免为它单独引入 encoding/hex 的 import 到多处。
func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}
