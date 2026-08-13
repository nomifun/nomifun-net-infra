// Package agent 实现 agent 侧：入网、握手、协调隧道集合、经 policy 拨本地目标。
//
// 本包**不得** import internal/store —— modernc.org/sqlite 没有 MIPS 移植，
// 而 MIPS 路由器只构建 nfagent。`make check` 会用 go list -deps 断言这条。
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/policy"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// ProtocolVersion 是本 agent 实现的语义层协议版本。
const ProtocolVersion uint32 = 1

// Credential 是 agent 的持久化凭据。
type Credential struct {
	AgentID string `json:"agent_id"`
	// Key 是 hex 编码的密钥。
	Key string `json:"key"`
	// MachineID 标识物理机，与 AgentID 不同：AgentID 可撤销重发。
	MachineID string `json:"machine_id"`
}

// Identity 是握手时上报的设备画像。
type Identity struct {
	Version  string
	Hostname string
}

// HandshakeResult 是握手成功后的协商结果。
type HandshakeResult struct {
	AgentID      string
	Capabilities []proto.Capability
	RelayVersion string

	// IssuedKey 在首次入网时非空，调用方必须持久化它。
	IssuedKey string

	// ClockSkew 是本地时钟与中继时钟的差值。
	//
	// 必须暴露出来：时钟错是握手失败最常见的现场原因，
	// `nfagent status` 要能直接报出来让用户自查，而不是只说「鉴权失败」。
	ClockSkew time.Duration

	// Rest 是**握手之后必须用它继续读控制流**的 reader。
	//
	// # 为什么不能直接拿裸流再新建一个 Reader
	//
	// 握手用的 proto.Reader 内部是一个 16 KiB bufio，一次 Read 可能把
	// HelloOK **之后**的字节一起吞进缓冲。丢掉那个 Reader 就是静默丢掉
	// 那些字节，而新 Reader 会从一个帧的中间开始解析 → 版本不匹配 →
	// 整条控制流死掉（连计量上报与 Ping/Pong 一起）。
	//
	// proto.Reader.Remainder 的注释把这条写成了硬要求：
	// 「凡是先用 Reader 读一个帧、再把同一条流交给拷贝循环的地方，
	// **必须**用本方法而不是原始流」。
	//
	// 今天不咬人只是因为中继要等 5 秒才发第一个 Ping —— 那时缓冲里已经空了。
	// 换一个承载（smux over TCP 会合并写）或者把首个 Ping 提前，它立刻就咬。
	Rest io.Reader
}

// SupportsDatagrams 报告协商结果里是否含数据报能力。
func (r *HandshakeResult) SupportsDatagrams() bool {
	for _, c := range r.Capabilities {
		if c == proto.CapDatagram {
			return true
		}
	}
	return false
}

// Handshake 在一条控制流上完成 agent 侧握手。
//
// cred.AgentID 为空时用 enrolToken 首次入网；否则用已有密钥生成信道绑定的证明。
func Handshake(
	st carrier.Stream,
	cred Credential,
	enrolToken string,
	exporter []byte,
	ident Identity,
) (*HandshakeResult, error) {
	hello := proto.Hello{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    proto.AgentCapabilities(),
		Version:         ident.Version,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Hostname:        ident.Hostname,
		MachineID:       cred.MachineID,
	}

	switch {
	case cred.AgentID != "":
		key, err := hex.DecodeString(cred.Key)
		if err != nil {
			return nil, fmt.Errorf("agent: 凭据里的密钥不是合法 hex：%w", err)
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("agent: 生成 nonce 失败：%w", err)
		}
		p := &proto.Proof{
			UnixMilli: time.Now().UnixMilli(),
			Nonce:     hex.EncodeToString(nonce),
		}
		p.Sign(key, ProtocolVersion, proto.ALPN, exporter)
		hello.AgentID = cred.AgentID
		hello.Auth = p

	case enrolToken != "":
		hello.EnrolToken = enrolToken

	default:
		return nil, errors.New("agent: 既无已有凭据也无入网令牌")
	}

	w := proto.NewWriter(st)
	if err := w.WriteMessage(proto.TypeHello, 1, 0, hello); err != nil {
		return nil, fmt.Errorf("agent: 发送 Hello 失败：%w", err)
	}

	r := proto.NewReader(st)
	fr, err := r.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("agent: 读握手响应失败：%w", err)
	}

	switch fr.Header.Type {
	case proto.TypeHelloOK:
		var ok proto.HelloOK
		if err := proto.Decode(fr, &ok); err != nil {
			return nil, err
		}
		return &HandshakeResult{
			AgentID:      ok.AgentID,
			Capabilities: ok.Capabilities,
			RelayVersion: ok.RelayVersion,
			IssuedKey:    ok.AgentKey,
			ClockSkew:    time.Since(time.UnixMilli(ok.ServerUnixMilli)),
			// 把 bufio 里已经吞掉的字节接回去，理由见 Rest 的说明。
			Rest: r.Remainder(st),
		}, nil

	case proto.TypeError:
		var e proto.Error
		if err := proto.Decode(fr, &e); err != nil {
			return nil, err
		}
		return nil, &e

	default:
		return nil, fmt.Errorf("agent: 握手期收到意外帧 %s", fr.Header.Type)
	}
}

// ── 数据面 ──────────────────────────────────────────────────────────────────

// TunnelSet 是 agent 当前承载的隧道集合（中继下发的期望状态）。
type TunnelSet struct {
	mu      sync.RWMutex
	byID    map[string]*tunnel.Tunnel
	rejects map[string]string // tunnelID → 拒绝原因

	// gen 每次 Reconcile 递增。
	//
	// 数据面用它做「自上次以来定义变过吗」的**便宜**判据：在途的 UDP 流
	// 只在世代变了的那一包去比较隧道定义，稳态下就是一次原子读。
	// 没有它的话要么每包都比较（浪费），要么永不比较 ——
	// 而永不比较意味着用户改了后端地址、在途流量却无限期继续打旧后端。
	gen atomic.Uint64
}

// Gen 返回当前世代号。每次 Reconcile 之后它一定变大。
func (s *TunnelSet) Gen() uint64 { return s.gen.Load() }

// NewTunnelSet 创建一个空集合。
func NewTunnelSet() *TunnelSet {
	return &TunnelSet{
		byID:    make(map[string]*tunnel.Tunnel),
		rejects: make(map[string]string),
	}
}

// Reconcile 用中继下发的期望集合替换当前集合，并对每条隧道执行本地策略裁决。
//
// 返回被拒绝的隧道及原因，调用方须通过 TypeTunnelRejected 上报，
// 使控制台能把状态显示为 rejected_by_agent 并附上原因 ——
// 否则用户只会看到一条「不通」的隧道，却不知道是自己的策略挡住的。
func (s *TunnelSet) Reconcile(desired []*tunnel.Tunnel, pol *policy.Policy) map[string]string {
	accepted := make(map[string]*tunnel.Tunnel, len(desired))
	rejected := make(map[string]string)

	for _, t := range desired {
		if !t.IsEnabled() {
			continue
		}
		if reason, ok := checkBackend(t, pol); !ok {
			rejected[t.ID] = reason
			continue
		}
		accepted[t.ID] = t.Clone()
	}

	s.mu.Lock()
	s.byID = accepted
	s.rejects = rejected
	s.mu.Unlock()

	// 世代在**发布之后**递增：反了的话数据面可能看到新世代号却读到旧集合，
	// 于是它会把「已经比较过了」记在一份还没生效的定义上。
	s.gen.Add(1)

	return rejected
}

// checkBackend 用本地策略裁决一条隧道的后端目标。
//
// 这里只做「配置期」预检以便尽早给出反馈；**真正的裁决在每次拨号时
// 由 policy.DialContext 做**，因为 DNS 可以在预检之后改变解析结果。
// 预检只对 IP 字面量有意义，主机名一律放过、留给拨号时判定。
func checkBackend(t *tunnel.Tunnel, pol *policy.Policy) (reason string, ok bool) {
	switch t.Backend.Kind {
	case tunnel.BackendAddr:
		host, portStr, err := net.SplitHostPort(t.Backend.Addr)
		if err != nil {
			return fmt.Sprintf("后端地址 %q 格式非法", t.Backend.Addr), false
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return fmt.Sprintf("后端地址 %q 的端口非法", t.Backend.Addr), false
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if d := pol.CheckAddr(netip.AddrPortFrom(addr, uint16(port))); !d.Allowed {
				return d.Reason, false
			}
		}
		return "", true

	case tunnel.BackendUnix:
		if t.Backend.Path == "" {
			return "后端 unix 路径为空", false
		}
		return "", true

	case tunnel.BackendHandler:
		// 场景三预留位，v1 的 agent 不实现。
		return "本代理端不支持 handler 型后端（场景三预留）", false

	default:
		return fmt.Sprintf("未知后端类型 %q", t.Backend.Kind), false
	}
}

// Get 取一条隧道。
func (s *TunnelSet) Get(id string) (*tunnel.Tunnel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	return t, ok
}

// Len 返回已接受的隧道数。
func (s *TunnelSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// List 返回当前可服务隧道的快照。
//
// 返回的是**副本**：调用方可能在遍历时正好有一次 Reconcile 落地，
// 直接暴露内部 map 会 panic。
func (s *TunnelSet) List() []*tunnel.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tunnel.Tunnel, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, t)
	}
	return out
}

// StreamHandler 处理中继开来的一条数据流。
type StreamHandler struct {
	Tunnels *TunnelSet
	Policy  *policy.Policy
	Log     *slog.Logger

	// DialTimeout 是拨本地目标的超时。
	DialTimeout time.Duration
}

// DefaultDialTimeout 是拨本地目标的默认超时。
const DefaultDialTimeout = 10 * time.Second

// Serve 读取 StreamOpen 头，拨本地目标，然后双向搬字节。
func (h *StreamHandler) Serve(ctx context.Context, st carrier.Stream) error {
	r := proto.NewReader(st)
	fr, err := r.ReadFrame()
	if err != nil {
		st.Close()
		return fmt.Errorf("agent: 读 StreamOpen 失败：%w", err)
	}
	return h.ServeWithOpen(ctx, st, fr, r.Remainder(st))
}

// ServeWithOpen 与 Serve 相同，但首帧已由调用方读出。
//
// 之所以要这个入口：控制流与数据流共用 AcceptStream，由**首帧类型**分派
// （TunnelSet 是控制、StreamOpen 是数据）。调用方必须先读首帧才能分派，
// 所以不能让 Serve 再读一次。
//
// 这个设计顺带避免了 frp「用 runID 认领连接」的整套机制及其安全问题
// （server/service.go:856 按 runID 查 Control，而 workConn 校验默认关闭，
// 拿到 64 位 runID 的任何人都能注入 workConn）——
// 流是在已认证的承载会话内部开的，天然继承会话身份，无需二次认领。
// rest 必须是 proto.Reader.Remainder 的返回值，而不是裸流。
func (h *StreamHandler) ServeWithOpen(
	ctx context.Context, st carrier.Stream, fr proto.Frame, rest io.Reader,
) error {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	defer st.Close()

	if fr.Header.Type != proto.TypeStreamOpen {
		return fmt.Errorf("agent: 数据流首帧应为 StreamOpen，收到 %s", fr.Header.Type)
	}

	var open proto.StreamOpen
	if err := proto.Decode(fr, &open); err != nil {
		return err
	}

	t, ok := h.Tunnels.Get(open.TunnelID)
	if !ok {
		w := proto.NewWriter(st)
		_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
			Code:    proto.ErrCodeUnknownTunnel,
			Message: "本代理端没有该隧道（可能已被本地策略否决）",
		})
		return fmt.Errorf("agent: 未知隧道 %s", open.TunnelID)
	}

	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		local net.Conn
		err   error
	)
	switch t.Backend.Kind {
	case tunnel.BackendUnix:
		var d net.Dialer
		local, err = d.DialContext(dialCtx, "unix", t.Backend.Path)
	default:
		// 走 policy.DialContext —— 这是 agent 唯一的出网路径，
		// 它在每次拨号时校验已解析的地址，从根上消除 DNS 重绑定的时间窗。
		local, err = h.Policy.DialContext(dialCtx, "tcp", t.Backend.Addr)
	}
	if err != nil {
		// 策略否决与拨号失败是两件不同的事，报同一个码会误导用户。
		//
		// 策略否决：他自己的 allow/deny 规则挡住了自己的隧道。重试永远不会
		// 成功，控制台该显示的是「改策略或改目标」，而不是「请重试」。
		// 拨号失败：本地服务没起、端口写错、防火墙 —— 服务起来后重试就能通。
		code, retryable := proto.ErrCodeInternal, true
		msg := "拨本地目标失败：" + err.Error()
		var denied *policy.ErrDenied
		if errors.As(err, &denied) {
			code, retryable = proto.ErrCodeTargetDenied, false
			msg = "目标被本地策略否决：" + err.Error()
		}
		w := proto.NewWriter(st)
		_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
			Code:      code,
			Message:   msg,
			Retryable: retryable,
		})
		return fmt.Errorf("agent: 隧道 %s 拨 %s 失败：%w", t.Slug, t.Backend.Addr, err)
	}
	defer local.Close()

	w := proto.NewWriter(st)
	if err := w.WriteMessage(proto.TypeStreamOK, fr.Header.CorrID, proto.FlagResponse,
		proto.StreamOK{LocalAddr: local.LocalAddr().String()}); err != nil {
		return fmt.Errorf("agent: 写 StreamOK 失败：%w", err)
	}

	log.Debug("隧道流已建立", "隧道", t.Slug, "本地", local.RemoteAddr(), "源", open.SrcAddr)
	// 从 rest 读而不是从 st 读：ServeWithOpen 的调用方读 StreamOpen 帧时，
	// 中继 pipeline 过来的用户首包可能已被一并缓冲。
	return pipe(st, rest, local)
}

// pipe 双向搬字节，任一方向结束即收敛。
func pipe(a carrier.Stream, aRead io.Reader, b net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var upErr, downErr error
	go func() {
		defer wg.Done()
		_, upErr = io.Copy(b, aRead)
		// 半关闭：告诉本地服务「不会再有请求数据了」，
		// 这样 HTTP/1.0 或某些等 EOF 的协议才能正常收尾。
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, downErr = io.Copy(a, b)
		a.Close()
	}()
	wg.Wait()

	// 对端主动关闭流是**正常收尾**，不是错误。
	//
	// 不做这个归一化的话，每条正常结束的连接都会在日志里留一条 WARN，
	// 于是真正的故障被噪音埋掉 —— 这类「正常路径产生错误日志」的设计
	// 最终会让人学会忽略告警。
	if err := firstRealError(upErr, downErr); err != nil {
		return err
	}
	return nil
}

// firstRealError 返回第一个真正需要关注的错误，把正常收尾过滤掉。
func firstRealError(errs ...error) error {
	for _, err := range errs {
		if err == nil || isNormalClose(err) {
			continue
		}
		return err
	}
	return nil
}

// isNormalClose 判断一个错误是否只是「对端正常关闭」。
func isNormalClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// QUIC 的流取消（错误码 0）表示对端主动收尾，不是故障。
	// quic-go 把它表达为 *quic.StreamError，这里用字符串匹配是因为
	// 我们不想让 agent 包直接依赖 quic-go —— 它必须能在没有 QUIC 的
	// 回退承载上同样工作。
	msg := err.Error()
	return strings.Contains(msg, "canceled by local with error code 0") ||
		strings.Contains(msg, "canceled by remote with error code 0") ||
		strings.Contains(msg, "use of closed network connection")
}
