package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// Action 是判别结果要执行的动作。
//
// 用字符串而不是 int：它会直接进日志与指标标签，可读性比一个 iota 值值钱。
type Action string

const (
	// ActionSplice 直接把连接拼接到隧道，一个字节都不解析（透传 / 裸端口）。
	ActionSplice Action = "splice"
	// ActionGateway 本地终止 TLS，然后走 L7。
	ActionGateway Action = "gateway"
	// ActionCleartext 明文 HTTP，直接走 L7（无 TLS 可终止）。
	ActionCleartext Action = "cleartext"
	// ActionACME 本地终止，交给 TLS-ALPN-01 挑战处理器。
	ActionACME Action = "acme"

	// ActionCarrier 把连接交给 agent 承载入口（L2 = TLS/TCP:443 + smux）。
	//
	// 它与 ActionGateway 共用同一个端口，靠 ALPN 区分：业务流量协商
	// h2/http/1.1（或什么都不协商），而 agent 协商 nomifun-relay/1。
	// 规格 §5.1 要的正是这个形态 —— 只放行 443/tcp 的网络里 agent 也能接进来。
	ActionCarrier Action = "carrier"
	// ActionReject 拒绝。
	ActionReject Action = "reject"
)

// Step 标识命中的判别步骤，取值与 spec §7.3 的编号一一对应。
type Step string

const (
	StepDedicated     Step = "dedicated"      // 0. 专用端口绑定
	StepProxyProtocol Step = "proxy_protocol" // 1. PROXY protocol v1/v2
	StepFirstByte     Step = "first_byte"     // 2. 首字节
	StepALPNACME      Step = "alpn_acme"      // 3. ALPN acme-tls/1
	StepALPNCarrier   Step = "alpn_carrier"   // 3b. ALPN nomifun-relay/1（L2 承载）
	StepSNI           Step = "sni"            // 4. SNI
	StepHostPath      Step = "host_path"      // 5. 明文 Host + 路径前缀
	StepPortDefault   Step = "port_default"   // 无判别信息 → 端口默认绑定
	StepReject        Step = "reject"         // 6. 拒绝
)

// 步骤 1 与步骤 2 是**非终止**步骤：PROXY 头只修正来源地址，首字节只选择
// 后续分支，两者都不单独决定目的地，所以它们不会作为 Decision.Step 出现
// （命中的终止步骤才会）。枚举位仍然保留，因为指标上要能按「在哪一步花了时间」
// 拆分，而 Step 的取值必须与 spec §7.3 的编号一一对应。
var _ = []Step{StepProxyProtocol, StepFirstByte}

// RejectMode 决定「怎么拒」。
//
// spec §7.3 第 6 步明确要求：TLS 要回一个**真正的** unrecognized_name 告警，
// 不是裸关闭 —— 裸关闭在浏览器里表现为无信息的连接错误，
// 用户与运维都无法据此区分「域名没注册」与「中继挂了」。
type RejectMode string

const (
	RejectClose      RejectMode = "close"       // 裸 L4：只能关
	RejectTLSAlert   RejectMode = "tls_alert"   // 回 unrecognized_name
	RejectHTTPStatus RejectMode = "http_status" // 明文：回一行 HTTP 响应
)

// Decision 是一条连接的判别结果。
//
// Decide 是**无副作用**的（除了消费 PROXY 头），所以它可以被单测直接断言；
// 真正的动作在 Handle 里执行。
type Decision struct {
	Action Action
	Step   Step

	// Conn 是可重放的连接：被 peek 过的字节仍会原样交给最终消费者。
	Conn *PeekConn

	Tunnel *tunnel.Tunnel
	Route  *Route

	// ServerName / ALPN 来自同一次 ClientHello peek。
	ServerName string
	ALPN       []string

	// ClientAddr 是唯一真实客户端地址；可信监听器上可能来自 PROXY 头。
	ClientAddr netip.AddrPort
	// LocalAddr 是用户打到的中继入口地址。
	LocalAddr netip.AddrPort

	// ProxyProtocol 记录是否消费了 PROXY 头，供指标与排障。
	ProxyProtocol bool

	// TLS 为真表示公网侧是 TLS（首字节 0x16），决定拒绝方式与 X-Forwarded-Proto。
	TLS bool

	RejectMode RejectMode
	Reason     string
}

// scheme 返回公网侧 scheme。
func (d Decision) scheme() string {
	if d.TLS {
		return "https"
	}
	return "http"
}

func (d Decision) meta() connMeta {
	return connMeta{client: d.ClientAddr, local: d.LocalAddr, scheme: d.scheme()}
}

// DiscriminatorStats 是判别器的计数器。
//
// 字段即 nf_mux_conns_total{step=...} 的标签值。「拒了多少」没用，
// 「在哪一步拒的」才告诉你是域名没注册、还是有人在扫端口。
type DiscriminatorStats struct {
	Dedicated     atomic.Int64
	ProxyProtocol atomic.Int64
	SNIPassthru   atomic.Int64
	SNIGateway    atomic.Int64
	Cleartext     atomic.Int64
	ACME          atomic.Int64
	// CarrierALPN 是被认成 agent 承载（L2 梯级）的连接数。
	//
	// 它涨起来意味着有 agent 走在降级路径上（它的网络封了 UDP）——
	// 那条路上 UDP 隧道不可用，所以这个数字是解释「为什么某条 UDP 隧道
	// 一直 degraded」的第一现场。
	CarrierALPN atomic.Int64

	// SpliceDeniedMaxConns / SpliceDeniedPerIP 是被**隧道自己的** policy 拒掉的
	// splice 连接数。
	//
	// 名字里带 Splice 是刻意的：网关那条路上有一对同义的计数器
	//（GatewayStats.DeniedMaxConns / DeniedPerIP），但它按**请求**算而这里按
	// **连接**算。名字不同才提醒读的人这是两个不同的量 ——
	// 而快照里的落点也因此分成 gateway_* 与 splice_* 两组。
	//
	// 与上面那个 AtCapacity 是两回事：那个是**整个共享端口**的并发上限
	//（判别器的 MaxConns，保护中继不被压垮），这两个是**单条隧道**的配额
	//（保护其他隧道与其他来源不被一条隧道挤掉）。混在一起的话，
	// 「加中继容量」与「提这条隧道的上限」这两个完全不同的动作就分不出来了。
	SpliceDeniedMaxConns atomic.Int64
	SpliceDeniedPerIP    atomic.Int64
	PortDefault          atomic.Int64
	Rejected             atomic.Int64
	DeniedCIDR           atomic.Int64
	AtCapacity           atomic.Int64
}

// DiscriminatorConfig 是判别器的装配参数。
type DiscriminatorConfig struct {
	Registry *Registry

	// Gateway 处理需要 L7 的连接。为 nil 时相应动作退化为拒绝。
	Gateway *Gateway

	// Dialer 用于透传拼接。为 nil 时取 Gateway 的 dialer。
	Dialer StreamDialer

	// TLSConfig 用于 gateway 模式终止 TLS。为 nil 时 gateway 动作退化为拒绝。
	//
	// 按仓库约定，CurvePreferences 必须保持 nil（手动设置会静默关掉后量子曲线）。
	TLSConfig *tls.Config

	// ACME 处理 ALPN 为 acme-tls/1 的连接（TLS-ALPN-01）。为 nil 时拒绝。
	ACME func(net.Conn)

	// Carrier 处理 ALPN 为 nomifun-relay/1 的连接：那是一个 agent 在走
	// L2 梯级（TLS/TCP:443 + smux），因为它的网络封了 UDP。
	//
	// 为 nil 时**拒绝**而不是当成业务流量：一个协商了我们承载 ALPN 的连接
	// 只可能是 agent，把它丢给网关只会让它在一堆 HTTP 解析错误里挣扎，
	// 而 agent 侧看到的是「连上了又被断开」——那比一个明确的拒绝难查得多。
	Carrier func(net.Conn)

	// PeekStep 是**单步**期限，0 用 DefaultPeekStep。
	PeekStep time.Duration

	// PeekBudget 是整条连接的判别总预算，0 用 DefaultPeekBudget。
	PeekBudget time.Duration

	// MaxConns 限制这个共享端口上同时在处理的连接数，0 用 DefaultMaxConns。
	//
	// 必须有界：frp 对每条接受的连接直接起一个 goroutine，既没有信号量也没有
	// accept 速率限制（server/service.go:686-740），唯一的刹车是 10s 读超时 ——
	// 而共享端口是公网暴露的。
	MaxConns int

	Log *slog.Logger
}

// 判别期限。
//
// # 为什么是两个数而不是 frp 的一个 10 秒
//
// frp 对每条连接压一个硬编码 10s 的读超时并 io.ReadFull 全局最大字节数
// （golib/net/mux/mux.go:189-198），所以「首包短」等于「建连慢 10 秒」。
// 这里单步期限只覆盖「拿到本步判别所需字节」这一件事，
// 总预算再挡住「每步都在期限内到一个字节」的慢速消耗。
const (
	// DefaultPeekStep 是单步期限。1 秒对一次跨洲 RTT 也足够宽松。
	DefaultPeekStep = 1 * time.Second
	// DefaultPeekBudget 是整条连接的判别总预算。
	DefaultPeekBudget = 5 * time.Second
)

// DefaultMaxConns 是共享端口的默认并发连接上限，与 relay.DefaultMaxConns 一致。
const DefaultMaxConns = 512

// Discriminator 是共享端口的判别器，实现 spec §7.3 的顺序。
type Discriminator struct {
	cfg   DiscriminatorConfig
	log   *slog.Logger
	stats DiscriminatorStats

	// sem 限制并发处理的连接数：满了就直接拒，而不是无限堆 goroutine。
	sem chan struct{}

	closeOnce sync.Once
	done      chan struct{}
}

// NewDiscriminator 装配一个判别器。
func NewDiscriminator(cfg DiscriminatorConfig) *Discriminator {
	if cfg.Registry == nil {
		if cfg.Gateway != nil {
			cfg.Registry = cfg.Gateway.reg
		} else {
			cfg.Registry = NewRegistry()
		}
	}
	if cfg.Dialer == nil && cfg.Gateway != nil {
		cfg.Dialer = cfg.Gateway.dialer
	}
	if cfg.PeekStep <= 0 {
		cfg.PeekStep = DefaultPeekStep
	}
	if cfg.PeekBudget <= 0 {
		cfg.PeekBudget = DefaultPeekBudget
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Discriminator{
		cfg:  cfg,
		log:  log,
		sem:  make(chan struct{}, cfg.MaxConns),
		done: make(chan struct{}),
	}
}

// Stats 返回计数器指针，供指标采集读取。
func (d *Discriminator) Stats() *DiscriminatorStats { return &d.stats }

// Serve 在一个共享端口上接受连接并逐条判别。
func (d *Discriminator) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-d.done:
			_ = ln.Close()
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// 临时性错误（如 fd 暂时耗尽）不该让整个监听器退出。
			d.log.Warn("共享端口 accept 失败", "err", err)
			select {
			case <-time.After(50 * time.Millisecond):
				continue
			case <-d.done:
				return nil
			}
		}

		local, _ := netip.ParseAddrPort(c.LocalAddr().String())

		// 并发上限：满了就直接拒。判别本身要读 socket、要跑 TLS 解析，
		// 无界并发等于把「谁能耗尽中继内存」的决定权交给公网。
		select {
		case d.sem <- struct{}{}:
		default:
			d.stats.AtCapacity.Add(1)
			_ = c.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-d.sem }()
			d.Handle(ctx, c, local)
		}()
	}
}

// Close 停止 Serve。可重复调用。
func (d *Discriminator) Close() error {
	d.closeOnce.Do(func() { close(d.done) })
	return nil
}

// Decide 按 spec §7.3 的顺序判别一条连接，不产生任何输出副作用。
//
//  0. 专用端口绑定           → 立即拼接，不 peek
//  1. PROXY protocol v1/v2   → 仅当监听器被标记为可信
//  2. 首字节                 0x16 → TLS；可打印 ASCII → 明文 HTTP；否则按端口默认
//  3. ALPN acme-tls/1        → 永远本地终止
//  4. SNI                    → 查 (port, sni)，由隧道的 tls 字段决定透传或网关
//  5. 明文 Host + 路径前缀
//  6. 拒绝                   → 回真正的 unrecognized_name 告警
func (d *Discriminator) Decide(raw net.Conn, local netip.AddrPort) Decision {
	pc, ok := raw.(*PeekConn)
	if !ok {
		pc = NewPeekConn(raw)
	}
	pc.SetPeekBudget(d.cfg.PeekBudget)

	dec := Decision{Conn: pc, LocalAddr: local}
	if raw.RemoteAddr() != nil {
		if ap, err := netip.ParseAddrPort(raw.RemoteAddr().String()); err == nil {
			dec.ClientAddr = ap
		}
	}

	view, found := d.cfg.Registry.View(local.Port())
	if !found {
		return d.reject(dec, RejectClose, "端口 "+local.Addr().String()+" 上没有任何绑定")
	}

	// ── 步骤 0：专用端口绑定 ────────────────────────────────────────────────
	//
	// 注意这一步**先于**步骤 3 的 acme-tls/1。那是对的（专用端口上不该有
	// 任何解析），但它也意味着「把共享端口交给一条隧道」会静默吞掉证书挑战 ——
	// 所以那种配置刻意不提供，理由钉在 Registry.BindDedicated 上。
	//
	// 一个字节都不看。场景二的 ESP32 走这条：它不发 SNI，Host 可能是 IP
	// 字面量甚至缺失，任何解析都是纯风险 —— 端口**就是**判别依据。
	if view.Dedicated != nil {
		d.stats.Dedicated.Add(1)
		dec.Action, dec.Step, dec.Tunnel = ActionSplice, StepDedicated, view.Dedicated
		return dec
	}

	// ── 步骤 1：PROXY protocol ─────────────────────────────────────────────
	if view.TrustProxyProtocol {
		h, err := readProxyHeader(pc, d.cfg.PeekStep)
		if err != nil {
			return d.reject(dec, RejectClose, "PROXY 头解析失败："+err.Error())
		}
		if h != nil {
			if err := pc.Discard(h.Len); err != nil {
				return d.reject(dec, RejectClose, "丢弃 PROXY 头失败："+err.Error())
			}
			d.stats.ProxyProtocol.Add(1)
			dec.ProxyProtocol = true
			// UNKNOWN / LOCAL 不带地址：保留内核看到的对端，绝不编一个出来。
			if h.Src.IsValid() {
				dec.ClientAddr = h.Src
			}
		}
	}

	// ── 步骤 2：首字节 ─────────────────────────────────────────────────────
	first, err := pc.Peek(1, d.cfg.PeekStep)
	if err != nil {
		// 连一个字节都没等到。frp 在这里要挂满 10 秒，我们必须立刻收工。
		return d.reject(dec, RejectClose, "首字节未在期限内到达："+err.Error())
	}
	switch {
	case first[0] == recordTypeHandshake:
		dec.TLS = true
		return d.decideTLS(dec, view)
	case isPrintableASCII(first[0]):
		return d.decideCleartext(dec, view)
	default:
		// 既不是 TLS 也不是明文 HTTP：只能按端口默认绑定当裸 L4 处理。
		if view.Fallback != nil {
			return d.portDefault(dec, view.Fallback, false)
		}
		return d.reject(dec, RejectClose, "首字节既非 TLS 也非可打印 ASCII，且该端口无默认绑定")
	}
}

func (d *Discriminator) decideTLS(dec Decision, view PortView) Decision {
	hello, err := peekClientHello(dec.Conn, d.cfg.PeekStep)
	if err != nil {
		return d.reject(dec, RejectTLSAlert, "ClientHello 解析失败："+err.Error())
	}
	dec.ServerName = hello.ServerName
	// 一次 peek 同时拿到 SNI 与 ALPN —— 步骤 3 与步骤 4 共用这一次读取。
	dec.ALPN = slices.Clone(hello.SupportedProtos)

	// ── 步骤 3：ALPN acme-tls/1 ────────────────────────────────────────────
	//
	// 无条件本地终止：这样即使这个端口上同时挂着透传隧道，
	// TLS-ALPN-01 挑战也能完成（否则一签证书就要停服）。
	if slices.Contains(dec.ALPN, ACMETLSALPNProto) {
		if d.cfg.ACME == nil {
			return d.reject(dec, RejectTLSAlert, "收到 acme-tls/1 但没有装配 ACME 处理器")
		}
		d.stats.ACME.Add(1)
		dec.Action, dec.Step = ActionACME, StepALPNACME
		return dec
	}

	// ── 步骤 3b：ALPN nomifun-relay/1 → agent 承载（L2）────────────────────
	//
	// 位置刻意在 acme-tls/1 **之后**、SNI **之前**：
	//
	//   * 在 ACME 之后 —— 那是一次性的证书挑战，不该被任何东西挡住
	//     （挡住的后果是签发静默超时，而它的现象是「60 天后续签失败」）。
	//   * 在 SNI 之前 —— agent 用 IP 直连时没有 SNI，会落到「无判别信息 →
	//     端口默认绑定」，于是一条 agent 承载被当成业务流量喂给某条隧道。
	//     那时 agent 看到的是「连上了又被断开」，而中继侧的计数器显示
	//     一切正常。ALPN 是这条连接**唯一**可靠的自我说明，必须先看它。
	if slices.Contains(dec.ALPN, proto.ALPN) {
		if d.cfg.Carrier == nil {
			return d.reject(dec, RejectTLSAlert,
				"收到 agent 承载 ALPN 但本端口没有装配承载入口")
		}
		d.stats.CarrierALPN.Add(1)
		dec.Action, dec.Step = ActionCarrier, StepALPNCarrier
		return dec
	}

	// ── 步骤 4：SNI ────────────────────────────────────────────────────────
	if dec.ServerName == "" {
		// IP 字面量拨号没有 SNI。ECH 普及后这条路会变宽 ——
		// 届时兜底就是 ALPN 或一条隧道一个专用端口（spec §7.2）。
		if view.Fallback != nil {
			return d.portDefault(dec, view.Fallback, false)
		}
		return d.reject(dec, RejectTLSAlert, "ClientHello 没有 SNI，且该端口无默认绑定")
	}

	// SNI 阶段只能按域名匹配：TLS 还没解密，路径根本不存在。
	route, ok := view.Hosts.MatchHost(dec.ServerName)
	if !ok {
		if view.Fallback != nil {
			return d.portDefault(dec, view.Fallback, false)
		}
		return d.reject(dec, RejectTLSAlert, "SNI "+dec.ServerName+" 未注册")
	}
	dec.Route, dec.Tunnel, dec.Step = route, route.Tunnel, StepSNI

	// 由隧道的 tls 字段（而不是 router.kind）决定透传还是网关 —— 两个正交轴。
	if route.Tunnel.TLS == tunnel.TLSPassthrough {
		d.stats.SNIPassthru.Add(1)
		dec.Action = ActionSplice
		return dec
	}
	if d.cfg.TLSConfig == nil || d.cfg.Gateway == nil {
		return d.reject(dec, RejectTLSAlert, "隧道要求 gateway 模式但中继没装配 TLS 或网关")
	}
	d.stats.SNIGateway.Add(1)
	dec.Action = ActionGateway
	return dec
}

func (d *Discriminator) decideCleartext(dec Decision, view PortView) Decision {
	// ── 步骤 5：明文 Host + 路径前缀 ───────────────────────────────────────
	//
	// 这里读的是**副本**：PeekReader 只推进 peek 偏移，不消费连接，
	// 所以随后 http.Server 会重新看到完整的请求头。
	req, err := peekRequestHead(dec.Conn, d.cfg.PeekStep)
	if err != nil {
		return d.reject(dec, RejectHTTPStatus, "明文请求头解析失败："+err.Error())
	}

	host := normalizeHost(req.Host)
	if host == "" || isIPLiteralOrLocalhost(host) {
		// IP 字面量或缺失 Host 没有判别价值 —— 场景二的机器人就是这样。
		if view.Fallback != nil {
			return d.portDefault(dec, view.Fallback, true)
		}
		return d.reject(dec, RejectHTTPStatus, "Host 是 IP 字面量或缺失，且该端口无默认绑定")
	}

	route, ok := view.Hosts.Match(host, req.URL.Path)
	if !ok {
		if view.Fallback != nil {
			return d.portDefault(dec, view.Fallback, true)
		}
		return d.reject(dec, RejectHTTPStatus, "Host "+host+" 路径 "+req.URL.Path+" 未注册")
	}
	dec.Route, dec.Tunnel, dec.Step = route, route.Tunnel, StepHostPath

	if route.Tunnel.TLS == tunnel.TLSPassthrough {
		// 明文 + 透传：没有 TLS 可终止，按 L4 拼接。
		d.stats.SNIPassthru.Add(1)
		dec.Action = ActionSplice
		return dec
	}
	if d.cfg.Gateway == nil {
		return d.reject(dec, RejectHTTPStatus, "隧道要求 gateway 模式但中继没装配网关")
	}
	d.stats.Cleartext.Add(1)
	dec.Action = ActionCleartext
	return dec
}

// portDefault 落到端口默认绑定。cleartext 表示公网侧是明文 HTTP。
func (d *Discriminator) portDefault(dec Decision, t *tunnel.Tunnel, cleartext bool) Decision {
	d.stats.PortDefault.Add(1)
	dec.Tunnel, dec.Step = t, StepPortDefault

	switch {
	case t.TLS == tunnel.TLSGateway && cleartext && d.cfg.Gateway != nil:
		dec.Action = ActionCleartext
	case t.TLS == tunnel.TLSGateway && dec.TLS && d.cfg.Gateway != nil && d.cfg.TLSConfig != nil:
		dec.Action = ActionGateway
	default:
		// 透传，或者网关没装配 —— 按 L4 原样搬字节。
		dec.Action = ActionSplice
	}
	return dec
}

func (d *Discriminator) reject(dec Decision, mode RejectMode, reason string) Decision {
	d.stats.Rejected.Add(1)
	dec.Action, dec.Step, dec.RejectMode, dec.Reason = ActionReject, StepReject, mode, reason
	return dec
}

// Handle 判别并落地：这是唯一会写连接的地方。
func (d *Discriminator) Handle(ctx context.Context, c net.Conn, local netip.AddrPort) {
	dec := d.Decide(c, local)

	// 源 IP 白名单要在这里查，而不是 accept 之后就查：共享端口上「这条连接属于
	// 哪条隧道」是判别之后才知道的事，而策略是挂在隧道上的。
	// 与 relay.EntryListener.allowSource 是同一道闸，只是必须晚一步。
	if dec.Tunnel != nil && dec.Action != ActionReject && !d.allowSource(dec) {
		d.stats.DeniedCIDR.Add(1)
		d.log.Info("源 IP 不在隧道白名单内", "隧道", dec.Tunnel.Slug, "来源", dec.ClientAddr.String())
		dec.Action = ActionReject
		dec.Reason = "源 IP 不在该隧道的白名单内"
		if dec.RejectMode == "" {
			dec.RejectMode = RejectClose
			if dec.TLS {
				dec.RejectMode = RejectTLSAlert
			}
		}
	}

	switch dec.Action {
	case ActionSplice:
		d.splice(ctx, dec)

	case ActionCleartext:
		d.cfg.Gateway.ServeConn(ctx, dec.Conn, dec.meta())

	case ActionGateway:
		// 交给 crypto/tls 终止。PeekConn 会先重放 ClientHello，
		// 所以这是一次完整的、正常的握手 —— 我们没有代握手，也没有解密过任何东西。
		tc := tls.Server(dec.Conn, d.cfg.TLSConfig)
		d.cfg.Gateway.ServeConn(ctx, tc, dec.meta())

	case ActionACME:
		d.cfg.ACME(dec.Conn)

	case ActionCarrier:
		// agent 承载：把连接交出去，**不在这里终止 TLS**。
		//
		// 承载入口自己要那条 *tls.Conn 才能导出信道绑定材料
		// （ExportKeyingMaterial 挂在 tls.ConnectionState 上）。在这里
		// tls.Server(...) 之后只把 net.Conn 传过去，那份材料就取不到了 ——
		// 而没有它握手会 MAC 不匹配，agent 每次都被拒。
		d.cfg.Carrier(dec.Conn)

	case ActionReject:
		d.rejectConn(dec)

	default:
		_ = dec.Conn.Close()
	}
}

// allowSource 查隧道策略。地址解析不出来时**拒绝** ——
// 宁可误拒也不要在无法判定来源时放行。
func (d *Discriminator) allowSource(dec Decision) bool {
	if dec.Tunnel.Policy == nil || len(dec.Tunnel.Policy.AllowCIDRs) == 0 {
		return true
	}
	if !dec.ClientAddr.IsValid() {
		return false
	}
	return dec.Tunnel.SourceAllowed(dec.ClientAddr.Addr())
}

func (d *Discriminator) rejectConn(dec Decision) {
	defer dec.Conn.Close()

	d.log.Info("共享端口拒绝连接",
		"来源", dec.ClientAddr.String(), "入口", dec.LocalAddr.String(),
		"sni", dec.ServerName, "方式", string(dec.RejectMode), "原因", dec.Reason)

	// 写也要有期限：一个不读的对端不该把拒绝路径上的 goroutine 钉住。
	_ = dec.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

	switch dec.RejectMode {
	case RejectTLSAlert:
		// 真正的 unrecognized_name，不是裸关闭（spec §7.3 第 6 步）。
		sendUnrecognizedName(dec.Conn)
	case RejectHTTPStatus:
		// 明文侧给一个能被 curl/浏览器读懂的最小响应。
		_, _ = io.WriteString(dec.Conn,
			"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}
}

// splice 把一条连接原样拼接到隧道。
//
// 与 internal/relay/entry.go 的拷贝循环同形：任一方向结束就半关另一侧，
// 这样后端才能看到「上行已结束」而不是等一个永远不来的请求尾。
func (d *Discriminator) splice(ctx context.Context, dec Decision) {
	defer dec.Conn.Close()

	// 每隧道限额。
	//
	// 这条路上隧道是**固定的**（由 SNI 或首字节判定，之后不会变），所以
	// 「并发连接数」与「这条隧道的带宽」都能精确归属 —— 语义与独立监听器
	// （internal/relay/entry.go）完全一致，不需要任何退化解释。
	//
	// 而网关那条路不同：keep-alive 连接上第二个请求换个 Host 就落到别的隧道，
	// 所以那边只能按**请求**算。两处的差异写在 ServeHTTP 的注释里。
	tl := d.cfg.Registry.limitsFor(dec.Tunnel)
	release, denied := tl.admit(dec.ClientAddr.Addr())
	defer release()
	if denied != denyNone {
		switch denied {
		case denyMaxConns:
			d.stats.SpliceDeniedMaxConns.Add(1)
		case denyPerIP:
			d.stats.SpliceDeniedPerIP.Add(1)
		}
		d.log.Debug("拼接被隧道限额拒绝",
			"隧道", tunnelSlug(dec.Tunnel), "闸门", string(denied), "来源", dec.ClientAddr)
		return
	}

	if d.cfg.Dialer == nil {
		d.log.Warn("没有装配 StreamDialer，无法拼接", "隧道", tunnelSlug(dec.Tunnel))
		return
	}
	up, err := d.cfg.Dialer.DialTunnel(ctx, dec.Tunnel, dec.ClientAddr, dec.LocalAddr)
	if err != nil {
		d.log.Warn("拼接到隧道失败", "隧道", tunnelSlug(dec.Tunnel), "err", err)
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	// 两个方向**各自只在读侧**结账。
	//
	// 只包读侧是为了避免双重计费：把管道两端都包成受限连接的话，同一批字节
	// 会先过一端的 Read 再过另一端的 Write，被同一个桶算两次，
	// 有效带宽减半 ——「配了 1 Mbps 只跑 500 kbps」也是谎。
	// throttleRead 返回 io.Reader（拿不去写），所以那个写法根本写不出来。
	//
	// 包装持有的是每隧道那个**稳定对象**而不是桶：桶每次读现取，
	// 所以调带宽对已经建立的连接立刻生效 —— 而 splice 出去的裸 TCP
	//（工厂设备那种）可以活几天，此前它会一直跑建立那一刻的速率。
	cliR := tl.throttleRead(ctx, dec.Conn)
	upR := tl.throttleRead(ctx, up)
	go func() {
		defer wg.Done()
		// 从 PeekConn 读 —— 被 peek 过的字节在这里原样重放给后端，
		// 后端因此看到一个逐字节完整的首包（透传时它要用它做真实 TLS 握手）。
		//
		// WaitReader 包在**读**侧：TCP 路径必须**等**而不是丢
		//（字节流丢中间一段就是把连接搞坏），而等在读侧会让反压自然传播回
		// 发送方的窗口。与 internal/relay/entry.go 的拷贝循环同形。
		_, _ = io.Copy(up, cliR)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dec.Conn, upR)
		_ = dec.Conn.CloseWrite()
	}()
	wg.Wait()
}

func tunnelSlug(t *tunnel.Tunnel) string {
	if t == nil {
		return "<无>"
	}
	return t.Slug
}

// isPrintableASCII 判断首字节是否像明文协议的开头。
//
// HTTP 方法都是大写字母，但按 spec §7.3 的字面要求用「可打印 ASCII」这个更宽的判据：
// 判别错了还有端口默认绑定兜，判死了就没救。
func isPrintableASCII(b byte) bool { return b >= 0x20 && b < 0x7f }

// peekRequestHead 只「看」一份明文请求头的副本。
//
// 用 http.ReadRequest 而不是自己找 CRLF：请求行折行、Host 出现在绝对 URI 里、
// 头部大小写与重复，这些边界 stdlib 已经全部处理过，自己写只会写出一个
// 与 http.Server 判断不一致的解析器 —— 而「判别器与真正的服务器对同一条
// 请求的理解不同」正是请求走私（request smuggling）的温床。
func peekRequestHead(c *PeekConn, step time.Duration) (*http.Request, error) {
	// bufio 的大小与 peek 缓冲一致：两者一起给出「头块必须在这个界内」的硬上限，
	// 超出即拒绝。判别阶段的缓冲必须有界，否则一条连接就能让中继替它攒内存。
	br := bufio.NewReaderSize(c.PeekReader(step), c.br.Size())
	return http.ReadRequest(br)
}
