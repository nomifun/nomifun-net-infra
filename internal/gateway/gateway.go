// Package gateway 实现共享端口的判别（L4 分流）与 gateway 模式的 L7 反向代理。
//
// 三个零件，按依赖顺序：
//
//  1. PeekConn（peek.go）——「先看后取」的连接，**惰性分级** peek，
//     修掉 frp 那个「按全局最大字节数 io.ReadFull + 硬编码 10s」的建连延迟缺陷。
//  2. Discriminator（discriminator.go）—— spec §7.3 的判别顺序，
//     把一条连接判成 splice / gateway / cleartext / acme / reject。
//  3. Gateway（本文件）—— httputil.ReverseProxy，DialContext 拨**进隧道**，
//     请求头按 spec §12 改写。
//
// # 两个轴不能混
//
// tunnel.TLS（passthrough / gateway）决定中继是否解密；tunnel.Router.Kind
// 决定怎么找到这条隧道。本包同时消费两者，但从不用一个词代表两件事。
//
// # WebSocket 不需要写一行 Hijack
//
// Go 1.26 的 httputil.ReverseProxy 原生处理 Upgrade/101：
// reverseproxy.go:573-579 判 StatusSwitchingProtocols → handleUpgradeResponse
// （:820-890）里自己做 ResponseController.Hijack() + 双向拷贝。
// 所以本包**刻意没有** Hijack 代码路径 —— 手写一份只会多一个 bug 面。
// 代价是入站必须是 HTTP/1.1（h2 的 ResponseWriter 不支持 Hijack，
// 而 RFC 8441 的 WebSocket-over-h2 在 ReverseProxy 里没有实现），
// 这与场景二的 ESP32 只会说明文 HTTP/1.1 正好一致。
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// slogErrorLog 把 net/http 与 ReverseProxy 那两个只认 *log.Logger 的字段
// 桥到 slog。
//
// 仓库约定日志只用 log/slog；但 stdlib 这两处的类型是历史包袱，
// 不桥的话它们会直接写 os.Stderr，绕过结构化日志与日志级别。
func slogErrorLog(log *slog.Logger) *stdlog.Logger {
	return stdlog.New(slogWriter{log: log}, "", 0)
}

type slogWriter struct{ log *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Warn("net/http 内部错误", "msg", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// StreamDialer 把一条公网请求接到隧道另一端。
//
// 抽成接口只为可测：生产实现是 TunnelDialer，测试里换成一个内存承载。
type StreamDialer interface {
	// DialTunnel 为一次请求（或一条透传连接）开一条到 agent 的流。
	//
	// src 是真实客户端地址，dst 是用户打到的中继入口地址；两者都会随
	// StreamOpen 过隧道，让 agent 能生成 PROXY 头、也让控制台能显示
	//「我从哪进，落到哪」。
	DialTunnel(ctx context.Context, t *tunnel.Tunnel, src, dst netip.AddrPort) (net.Conn, error)
}

// SessionSource 是本包需要的 relay.TunnelLookup 子集。
//
// 只要 SessionFor：隧道对象由路由表给出，不需要再按端口反查。
// relay.TunnelLookup 天然满足这个接口。
type SessionSource interface {
	SessionFor(agentID string) (*relay.Session, bool)
}

// TunnelDialer 是 StreamDialer 的生产实现。
type TunnelDialer struct {
	Lookup SessionSource

	// Timeout 是「开流 + 等 agent 确认」的期限，0 用 relay.StreamSetupTimeout。
	Timeout time.Duration
}

// 拨号错误。
var (
	ErrNoAgent  = errors.New("gateway: 隧道的代理端不在线")
	ErrNoTunnel = errors.New("gateway: 该连接没有匹配到任何隧道")
)

// DialTunnel 开流并等 agent 的 StreamOK 确认。
//
// 「等确认」这一步不能省，理由与 internal/relay/entry.go 完全一样：
// 若本地服务拨不通，我们要在**这条请求上**给出干净的 502，
// 而不是让用户对着一个已建立但永远没有响应的连接干等。
// 这里直接复用 relay.DialTunnelStream，不重写一遍那套超时语义。
func (d *TunnelDialer) DialTunnel(
	ctx context.Context,
	t *tunnel.Tunnel,
	src, dst netip.AddrPort,
) (net.Conn, error) {
	if t == nil {
		return nil, ErrNoTunnel
	}
	sess, ok := d.Lookup.SessionFor(t.AgentID)
	if !ok || !sess.Alive() {
		return nil, fmt.Errorf("%w：隧道 %s，agent %s", ErrNoAgent, t.Slug, t.AgentID)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = relay.StreamSetupTimeout
	}
	openCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	st, err := relay.DialTunnelStream(openCtx, sess, proto.StreamOpen{
		TunnelID: t.ID,
		SrcAddr:  src.Addr().String(),
		SrcPort:  src.Port(),
		DstAddr:  dst.Addr().String(),
		DstPort:  dst.Port(),
	}, timeout)
	if err != nil {
		return nil, err
	}
	return &streamConn{
		Stream: st.Stream, reader: st.Reader,
		local: addrOf(dst), remote: addrOf(src),
	}, nil
}

// streamConn 把一条隧道流适配成 net.Conn，供 http.Transport 使用。
//
// carrier.Stream 刻意不带地址（它是流，不是连接），但 http.Transport 要 net.Conn，
// 所以这里补上两个只用于日志与错误信息的地址。
//
// **读走 reader 而不是嵌入的 Stream**：等 StreamOK 时那一次读可能把
// 中继 pipeline 过来的业务字节一并缓冲了，直接读裸流会静默丢掉它们。
// 见 proto.Reader.Remainder 的说明。
type streamConn struct {
	carrier.Stream
	reader io.Reader
	local  net.Addr
	remote net.Addr
}

// Read 覆盖嵌入的 Stream.Read，改从缓冲余量读。
func (c *streamConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func addrOf(ap netip.AddrPort) net.Addr {
	if !ap.IsValid() {
		return tunnelAddr{}
	}
	return net.TCPAddrFromAddrPort(ap)
}

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "nomirelay" }
func (tunnelAddr) String() string  { return "tunnel" }

// ── 网关 ────────────────────────────────────────────────────────────────────

// GatewayStats 是网关的计数器。
//
// 每个字段对应一个 nf_gateway_requests_total{outcome=...} 的标签值：
// 「返了多少 502」没用，「在哪一道闸失败的」才告诉你该看隧道还是看后端。
type GatewayStats struct {
	Requests   atomic.Int64
	NoRoute    atomic.Int64
	BadGateway atomic.Int64
	Upgrades   atomic.Int64

	// DeniedCIDR 是被隧道的 allow_cidrs 在**请求级**拒掉的次数。
	//
	// 与判别器那个同名计数器分开：那个是每连接一次（按首个请求的 Host/SNI
	// 定的隧道），这个是每请求一次。两者的差值恰好就是「同一条 keep-alive
	// 连接上换了 Host」的量 —— 而那正是本文件 ServeHTTP 里那道补充检查
	// 拦下来的绕过。
	DeniedCIDR atomic.Int64

	// DeniedMaxConns / DeniedPerIP 是被**隧道自己的** policy 并发额度拒掉的
	// 请求数。
	//
	// 与 Requests / NoRoute 分开的理由与别处一样：「拒了多少」没用，
	// 「在哪一道闸拒的」才告诉运维该调什么 —— 前者是「加这条隧道的上限」，
	// 后者是「提每源上限，或者去查那个源在干什么」。
	DeniedMaxConns atomic.Int64
	DeniedPerIP    atomic.Int64

	// DeniedPassthrough 是「明文降级绕过」被拦下的次数。
	//
	// **必须与 NoRoute 分开。** 它此前混进 NoRoute，而 NoRoute 同时装着
	// 「这个域名没配」—— 那是运维每天都会看到的正常噪声。于是一次真实的
	// 降级绕过尝试在计量上与「有人访问了一个拼错的域名」完全一样，
	// 而 07-operations 恰好教人靠这几个分级计数去排查「443 上到底发生了什么」。
	//
	// 两者的处置也完全不同：NoRoute 涨是「去把域名配上」，
	// 这一项涨是「有人在试着让中继解密一条 passthrough 隧道」——
	// 后者要查来源、查审计，而不是去改配置。
	DeniedPassthrough atomic.Int64
}

// GatewayConfig 是网关的装配参数。
type GatewayConfig struct {
	Registry *Registry
	Dialer   StreamDialer
	Log      *slog.Logger

	// ReadHeaderTimeout 限制「连上但慢慢发头」的连接，0 用默认 30s。
	ReadHeaderTimeout time.Duration

	// IdleTimeout 覆盖请求之间的空闲上限，0 用默认 60s。
	//
	// 存在的理由是测试：验证「空闲连接会被回收、槽位会被还回去」这个**机制**
	// 不需要真等 60 秒，而 60 秒这个**取值**由 server() 里的注释与
	// TestGatewaySetsAnIdleTimeout 分别钉住。
	// 与 relay.EntryOptions.SetupTimeout 同一个模式。
	IdleTimeout time.Duration

	// OnSource 在一个请求**通过**来源校验之后被调用，用于学习模式观测。
	//
	// 做成回调而不是让网关自己存：本包不该知道「学习模式」的存在，
	// 而观测数据的生命周期、上限、脱敏策略都属于调用方。可以为 nil。
	//
	// 只在放行之后调用 —— 把被拒的来源也攒进「推荐白名单」，
	// 等于让运维一键把撞门的人请进来。
	OnSource func(tunnelID string, addr netip.Addr)
}

// Gateway 是 gateway 模式的 L7 处理器。
type Gateway struct {
	reg    *Registry
	dialer StreamDialer
	log    *slog.Logger
	stats  GatewayStats

	readHeaderTimeout time.Duration

	idleTimeout time.Duration

	// onSource 见 GatewayConfig.OnSource。可以为 nil。
	onSource func(tunnelID string, addr netip.Addr)

	mu sync.Mutex
	// proxies 的键是「隧道 ID | 后端 authority」，见 proxyFor 里的理由。
	proxies map[string]*httputil.ReverseProxy
	srv     *http.Server
}

// NewGateway 装配一个网关。
func NewGateway(cfg GatewayConfig) *Gateway {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	reg := cfg.Registry
	if reg == nil {
		reg = NewRegistry()
	}
	rht := cfg.ReadHeaderTimeout
	if rht <= 0 {
		rht = 30 * time.Second
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	return &Gateway{
		reg:               reg,
		dialer:            cfg.Dialer,
		log:               log,
		readHeaderTimeout: rht,
		idleTimeout:       idle,
		onSource:          cfg.OnSource,
		proxies:           make(map[string]*httputil.ReverseProxy),
	}
}

// defaultIdleTimeout 是请求之间的空闲上限。理由见 server() 里那段注释。
const defaultIdleTimeout = 60 * time.Second

// Stats 返回计数器指针，供指标采集读取。
func (g *Gateway) Stats() *GatewayStats { return &g.stats }

// ServeHTTP 按 (端口, Host, 路径) 找隧道，然后交给对应的反向代理。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.stats.Requests.Add(1)

	t, ok := g.resolve(r)
	if !ok {
		g.stats.NoRoute.Add(1)
		// 404 而不是 502：没有匹配的隧道是**配置**问题，不是后端故障。
		// 把两者混成同一个状态码会让运维分不清该查控制台还是查家里的机器。
		http.Error(w, "没有匹配的隧道", http.StatusNotFound)
		return
	}

	// tls=passthrough 的隧道**绝不能**从网关这条路被服务到。
	//
	// # 为什么这不是多余的检查
	//
	// 判别器确实看隧道的 tls 字段：SNI 命中一条 passthrough 隧道时它走
	// ActionSplice，字节级搬运、一个头都不碰。但那是**连接级**的判定，
	// 而这里的 resolve 是**请求级**重查路由，且它只看 Host 与 path，
	// 完全不看 tunnel.TLS（AddShared 也不分 tls 模式，passthrough 隧道
	// 照样进 Hosts 表）。
	//
	// 于是有一条绕过：用**另一条** gateway 隧道的 SNI 建 TLS（中继因此终止 TLS），
	// 然后在解密后的 HTTP 里把 Host 换成那条 passthrough 隧道的域名 ——
	// 它的后端就会收到解密并按改写表改过的明文 HTTP。实测确认过：
	// 后端返回 200，且 proto 头是 https（也就是它确实被当成网关请求处理了）。
	//
	// 而运维选 passthrough 的意图恰恰是「中继绝不看这条隧道的明文」。
	// 破掉它不只是配置不符：那条隧道后面可能是一个**假设自己在说 TLS**的服务
	// （客户端证书、端到端加密），而它收到的是明文。
	//
	// 同一条端口上的 catch_all 隧道会让这条路更容易走到 —— 那时任何 Host
	// 都会落到网关。
	if t.TLS == tunnel.TLSPassthrough {
		g.stats.DeniedPassthrough.Add(1)
		g.log.Warn("拒绝把 tls=passthrough 的隧道从网关路径服务出去（明文降级绕过）",
			"隧道", t.Slug, "host", publicHostOf(r), "来源", r.RemoteAddr)
		// 404 与「未注册域名」同一个回复：不确认它的存在。
		http.Error(w, "没有匹配的隧道", http.StatusNotFound)
		return
	}

	// 源 IP 白名单必须在**每个请求**上再查一次，不能只靠判别器那一次。
	//
	// # 为什么，这是一个真实的绕过
	//
	// 判别器每**连接**判一次隧道，判据是首个请求的 Host（或 TLS 的 SNI），
	// 并对那条隧道查一次 allow_cidrs。而这里的 resolve 是每**请求**重查路由 ——
	// 于是一条 keep-alive 连接上的第二个请求换一个 Host 就会落到**另一条**隧道，
	// 而那条隧道的白名单从来没有被检查过。
	//
	// 攻击形态很直接：先用一个自己被放行的域名建连（判别器放行），
	// 然后在同一条连接上请求那个受限域名。现象是「白名单看起来配了、
	// DeniedCIDR 计数器也在动，但受限域名照样能访问」。
	//
	// TLS 侧同理：SNI 决定了判别器用哪条隧道的策略，而解密后的 Host 可以指向别的。
	srcAddr, srcOK := remoteAddrOf(r.RemoteAddr)
	if !srcOK || !sourceAllowed(t, r.RemoteAddr) {
		g.stats.DeniedCIDR.Add(1)
		// 404 而不是 403：一个不在白名单里的来源不该被告知「这个域名存在，
		// 只是不让你访问」——那是一次免费的存在性确认。与未注册域名同一个回复。
		http.Error(w, "没有匹配的隧道", http.StatusNotFound)
		return
	}

	// 每隧道并发额度。**按请求算，不按连接算。**
	//
	// connMeta 刻意不带隧道（见它的定义）：resolve 是每请求重查路由，
	// 一条 keep-alive 连接上第二个请求换个 Host 就落到另一条隧道。
	// 本仓已经因为「连接级判断约束请求级路由」修过两个真实绕过
	//（上面那两道闸就是），所以这里不重复那个错误 —— 归属永远与路由一致。
	//
	// 语义与独立监听器（exposure=port）的差异要说清：那边一条连接算一个额度，
	// 这边一个**在飞请求**算一个额度。差异是承载形态决定的，不是随意的：
	// 共享入口上一条连接可以服务任意多个请求、还可以中途换隧道。
	// 而协议升级（WebSocket）之后连接不再是 HTTP、也就不可能再换隧道，
	// 于是那一整段自然算作同一条在飞请求 —— 两种语义在这里正好接上。
	tl := g.reg.limitsFor(t)
	release, denied := tl.admit(srcAddr)
	defer release()
	if denied != denyNone {
		switch denied {
		case denyMaxConns:
			g.stats.DeniedMaxConns.Add(1)
		case denyPerIP:
			g.stats.DeniedPerIP.Add(1)
		}
		g.log.Debug("请求被隧道限额拒绝",
			"隧道", t.Slug, "闸门", string(denied), "来源", r.RemoteAddr)
		// 503 而不是 429：这是**并发**上限而不是速率上限，
		// 重试要等的是「别人用完」而不是一个可以算出来的时间窗，
		// 所以不给 Retry-After（编一个数字比不给更糟）。
		http.Error(w, "这条隧道的并发上限已满", http.StatusServiceUnavailable)
		return
	}

	// 学习模式观测点：来源已通过白名单校验，可以记。
	if g.onSource != nil {
		if addr, ok := remoteAddrOf(r.RemoteAddr); ok {
			g.onSource(t.ID, addr)
		}
	}

	g.proxyFor(t).ServeHTTP(w, r)
}

// sourceAllowed 按隧道的 allow_cidrs 校验一个请求的来源地址。
//
// remoteAddr 取自 http.Request.RemoteAddr，也就是**这条 TCP 连接**的对端 ——
// 刻意不看任何请求头（X-Forwarded-For 是可伪造的，用它做白名单等于没有白名单）。
// 共享入口开了 PROXY protocol 时 RemoteAddr 已经是被还原过的真实来源。
//
// 解析不出地址时**拒绝**（而不是放行）：宁可错在保守的一侧。
func sourceAllowed(t *tunnel.Tunnel, remoteAddr string) bool {
	if t.Policy == nil || len(t.Policy.AllowCIDRs) == 0 {
		return true
	}
	addr, ok := remoteAddrOf(remoteAddr)
	if !ok {
		// 解析不出来的来源**拒绝**。白名单的语义是「只放行列举的」，
		// 一个解不出的地址不可能在列举里。
		return false
	}
	return t.SourceAllowed(addr)
}

// remoteAddrOf 从 http.Request.RemoteAddr 解出规范化的地址。
//
// 一处解析，两个消费者（白名单校验与学习模式观测）—— 两边必须看到
// **同一个**地址，否则会出现「按 A 判放行、把 B 记进推荐列表」这种
// 自相矛盾的组合。
func remoteAddrOf(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// resolve 找出这条请求该落到哪条隧道。
func (g *Gateway) resolve(r *http.Request) (*tunnel.Tunnel, bool) {
	view, ok := g.reg.View(localPortOf(r))
	if !ok {
		return nil, false
	}
	if route, ok := view.Hosts.Match(publicHostOf(r), r.URL.Path); ok {
		return route.Tunnel, true
	}
	// Host 是 IP 字面量或未注册的域名 → 端口默认绑定。
	// 场景二的 ESP32 走这条：它发的 Host 是中继的 IP。
	if view.Fallback != nil {
		return view.Fallback, true
	}
	return nil, false
}

// proxyFor 取（或建）一条隧道的反向代理。
//
// # 一条隧道一个 Transport，而不是 frp 的假 URL.Host
//
// http.Transport 的空闲连接池按 URL.Host 分桶。frp 为了让「同一条路由」的请求
// 复用同一条 work conn，把域名/路径/用户/端点 base64 拼进 req.URL.Host
// （pkg/util/vhost/http.go:81-85）—— 一个能工作但把路由数据塞进协议字段的 hack。
// 这里改成**每条隧道一个 Transport**：池天然按隧道隔离，URL.Host 保持真实的
// 后端 authority（这也正是 §12 需要的 Host 值），不需要任何编码。
//
// 顺带说明为什么隧道腿上**不**用 PROXY protocol：PROXY 头是连接级的，
// 而这里的连接会被 keep-alive 复用，于是手机 A 建的流被手机 B 的请求复用时，
// 后端从 PROXY 头读到的仍是 A 的 IP。frp 正是这个形状
// （docs/research/03-frp-l7-vhost.md §3 第 4 点）。真实客户端 IP 走
// 逐请求的 X-Forwarded-For，不走连接级元数据。
func (g *Gateway) proxyFor(t *tunnel.Tunnel) *httputil.ReverseProxy {
	backend := backendAuthority(t)
	// 缓存键带上**所有**被闭包捕获、又会在热重载时变的字段。
	//
	// backend authority：改了后端地址（或 host_rewrite）之后，旧
	// ReverseProxy 里那个 backend 是闭包捕获的常量，只按隧道 ID 缓存
	// 就会一直把请求改写成旧地址。
	//
	// AgentID：transportFor 把整个 *tunnel.Tunnel 闭包捕获进 DialContext，
	// 而 DialTunnel 读的是 t.AgentID。它**不在**键里的后果是一条真实的
	// 「永久 502」：用户在还没有 agent 在线时建一条共享隧道（这是允许的，
	// 路由表不看 AgentID），打开域名看一眼 → 502（此刻正确），
	// 但这一次请求把 AgentID="" 的代理**永久**写进了缓存；
	// 之后 agent 上线、bindUnassigned 绑好、路由表全量重建 ——
	// 刷新页面仍然 502，而且永远 502，直到重启中继。
	// 控制台这时显示 active（它读的是新对象），浏览器显示 502，
	// 两边都不指向真正的原因。
	//
	// 只靠调用方记得调 Invalidate 是不够的：那还有一个窄竞态 ——
	// goroutine A 在 ReplaceWith 之前解析到旧对象、被调度走，B 完成
	// ReplaceWith + Invalidate，A 恢复后又把陈旧条目写回同一个键。
	// 把字段并进键之后，忘记调用最坏只是漏回收内存，不再是 502。
	key := t.ID + "|" + t.AgentID + "|" + backend

	g.mu.Lock()
	defer g.mu.Unlock()

	if p, ok := g.proxies[key]; ok {
		return p
	}

	if !isIPLiteralOrLocalhost(backend) {
		// 这不是致命错误（后端可能不是 nomifun-tauri），但必须说出来：
		// nomifun-tauri 的 host guard 会 403 掉域名型 Host，而它挂在路由器之外，
		// 后端配置改不动。控制台应当在创建时就建议填 Router.HostRewrite。
		g.log.Warn("网关改写出的 Host 不是 IP 字面量，若后端是 nomifun-tauri 会被 403",
			"隧道", t.Slug, "host", backend, "建议", "给 router.host_rewrite 填 ip:port")
	}

	p := &httputil.ReverseProxy{
		// 用 Rewrite 而不是已废弃的 Director。
		// Director 的文档自己写了原因：入站的 X-Forwarded-* 会被默认保留，
		// 那等于放行 IP 伪造。Rewrite 模式下 stdlib 先删这几个头再回调。
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: backend})
			rewriteIdentityHeaders(pr.Out, legInfo{
				Backend:   backend,
				Public:    publicHostOf(pr.In),
				Client:    clientIPOf(pr.In),
				Scheme:    publicSchemeOf(pr.In),
				HadOrigin: pr.In.Header.Get("Origin") != "",
			})
		},

		// -1 表示每次写都立刻 flush。SSE、长轮询、以及 101 之后的双向流量
		// 都要求不缓冲；默认的 ~1ms 合批会给交互式流量加一跳可感知的延迟。
		FlushInterval: -1,

		Transport: g.transportFor(t),

		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.stats.BadGateway.Add(1)
			g.log.Warn("网关回源失败", "隧道", t.Slug, "host", r.Host, "path", r.URL.Path, "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},

		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusSwitchingProtocols {
				g.stats.Upgrades.Add(1)
			}
			return nil
		},

		ErrorLog: slogErrorLog(g.log),
	}
	g.proxies[key] = p
	return p
}

// Invalidate 丢掉一条隧道的反向代理与其空闲隧道流。
//
// 隧道定义变更（改后端、改 host_rewrite、删除）时必须调用，否则那条隧道的
// 空闲连接会被下一次请求复用到**旧**目标上。spec §13 的零停机重载只定义了
// 监听器的 diff，隧道定义变更的语义还没定稿（§16 记账），所以这里给出的
// 是最保守的一条：显式失效。
func (g *Gateway) Invalidate(tunnelID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	prefix := tunnelID + "|"
	for key, p := range g.proxies {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if tr, ok := p.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		delete(g.proxies, key)
	}
}

func (g *Gateway) transportFor(t *tunnel.Tunnel) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// network/addr 被刻意忽略：这条「连接」不是拨给一个 IP 的，
			// 而是隧道里的一条流。addr 只是 URL.Host 的回显。
			if g.dialer == nil {
				return nil, errors.New("gateway: 没有装配 StreamDialer")
			}
			src, dst := legAddrsFromContext(ctx)
			c, err := g.dialer.DialTunnel(ctx, t, src, dst)
			if err != nil {
				return nil, err
			}

			// 字节限速挂在**隧道那一侧的连接**上。
			//
			// 这一个挂点同时覆盖三件事，而分头去包会漏掉其中一件：
			//   * 请求体（客户端→后端）走这条连接的 Write；
			//   * 响应体（后端→客户端）走它的 Read；
			//   * **协议升级之后的双向字节**也走它 —— ReverseProxy 在升级时
			//     劫持客户端连接，然后在它与这条后端连接之间双向 io.Copy。
			//
			// 最后一条是关键：只包 r.Body 与响应体的话，WebSocket 隧道上的
			// 限速会静默失效，而场景一的核心恰好是 WebSocket。
			//
			// 包装持有的是**每隧道那个稳定对象**而不是桶本身：桶每次读写现取，
			// 所以调带宽对已经建立的连接（WebSocket 可以活几天）立刻生效。
			//
			// 用请求的 ctx：请求结束时等在桶上的读/写应当解除，
			// 否则一个被取消的请求会把一个 goroutine 留在那里等额度。
			return g.reg.limitsFor(t).throttle(ctx, c), nil
		},

		// 后端在隧道另一端，是明文 HTTP/1.1（nomifun-tauri 的 LAN 口就是），
		// 且 ReverseProxy 不实现 RFC 8441 的 WebSocket-over-h2，
		// 所以刻意不尝试 HTTP/2 —— 那样 WS 会在 101 处失败。
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,

		// 刻意**不设** ResponseHeaderTimeout。frp 默认 60s
		//（pkg/util/vhost/http.go:50-52），于是 60 秒内不吐头的 SSE / 长轮询
		// 直接变 504。慢后端由请求自己的 ctx 与入口的空闲超时兜。
	}
}

// ServeConn 在一条已判别的连接上服务 HTTP/1.1，阻塞到连接结束。
//
// http.Server 没有「服务单条连接」的公开 API，只能喂一个一次性 listener；
// 而 Serve 会在 Accept 第二次返回错误时立刻返回（此时连接还在被服务），
// 所以这里用连接自己的 Close 作为完成信号。
func (g *Gateway) ServeConn(ctx context.Context, c net.Conn, meta connMeta) {
	mc := &metaConn{Conn: c, meta: meta, done: make(chan struct{})}

	srv := g.server()
	go func() {
		// 一次性 listener：第一次 Accept 交出连接，之后永远返回 net.ErrClosed。
		_ = srv.Serve(&oneConnListener{c: mc, addr: c.LocalAddr()})
	}()

	select {
	case <-mc.done:
	case <-ctx.Done():
		_ = mc.Close()
	}
}

func (g *Gateway) server() *http.Server {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.srv != nil {
		return g.srv
	}
	// 只开 HTTP/1.1：WebSocket 升级需要 ResponseWriter 支持 Hijack，
	// 而 h2 的不支持；场景二的 ESP32 也只会说明文 HTTP/1.1。
	var protos http.Protocols
	protos.SetHTTP1(true)

	g.srv = &http.Server{
		Handler:           g,
		Protocols:         &protos,
		ReadHeaderTimeout: g.readHeaderTimeout,

		// IdleTimeout 是**必需**的，不是调优。
		//
		// # 不设它是一个远程可触发的拒绝服务
		//
		// 判别器在 Accept 之后、Decide 之前就占一个槽位（共 512，
		// DefaultMaxConns），Handle 返回才还。而 Handle 对网关分支来说要等到
		// **连接关闭**才返回。
		//
		// Go 的 Server.idleTimeout() 在 IdleTimeout 为 0 时回落到 ReadTimeout
		//（net/http/server.go），而这里两个都没设 —— 于是一条 keep-alive 连接
		// 在完成一个请求（哪怕是 404）之后可以永远空闲挂着，槽位一直被占。
		//
		// 实测：512 条这样的连接就把整个共享端口占死，**无需鉴权、无需负载、
		// 也不需要配任何限速**。之后：
		//   * 新连接被 RST；
		//   * **ACME 挑战在信号量那一步就被关掉** → 证书首签/续签静默超时，
		//     或者更糟：签成功、60 天后续签失败，届时全部 https 端点一起挂；
		//   * 走 L2 降级的 agent 连不上（现象是「网络明明通却连不上」）。
		// 运维唯一的痕迹是 shared 面板上的 at_capacity，而没人知道要看那一格。
		//
		// 60 秒：比常见的浏览器 keep-alive 空闲期（Chrome ~30s）宽，
		// 所以正常复用不受影响。
		//
		// # 但它**不足以**关掉那个洞，别把它当成修好了
		//
		// 它回收的是**被遗弃**的连接（客户端崩了、扫描器开完就走），
		// 那是常见情形，所以这一行是实打实的改进。
		//
		// 而一个刻意的攻击者只要每 55 秒给每条连接发一个廉价请求，就能一直
		// 占着全部 512 个槽位 —— 流量小到可以忽略，而端口级信号量上**没有
		// 任何每源 IP 记账**（Serve 循环里一处都没有），所以一台主机就够。
		//
		// 真正的修法要三样：判别期用短命额度、判完按 action 换成对应类别的
		// 额度（给 ACME 与承载留位）、端口容量可配。那一条还留在 README 的
		// 诚实清单里，是当前**唯一**的发布阻断项。
		//
		// **只影响请求之间的空闲**：协议升级（WebSocket）之后连接被 Hijack，
		// http.Server 不再管它，所以长命 WS 不会被这个超时切断。
		IdleTimeout: g.idleTimeout,
		ErrorLog:    slogErrorLog(g.log),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// 把判别阶段已知的真相（真实客户端、入口地址、公网 scheme）
			// 挂到这条连接的 ctx 上。请求 ctx 由它派生，所以
			// Rewrite 与 Transport.DialContext 都能读到。
			if mc, ok := c.(*metaConn); ok {
				return withMeta(ctx, mc.meta)
			}
			return ctx
		},
	}
	return g.srv
}

// Close 关闭网关持有的 http.Server 与所有空闲隧道流。
func (g *Gateway) Close() error {
	g.mu.Lock()
	for _, p := range g.proxies {
		if tr, ok := p.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	g.proxies = make(map[string]*httputil.ReverseProxy)
	srv := g.srv
	g.mu.Unlock()

	if srv != nil {
		return srv.Close()
	}
	return nil
}

// ── 连接级元数据 ────────────────────────────────────────────────────────────

// connMeta 是判别阶段确定、整条连接共享的事实。
type connMeta struct {
	// client 是唯一真实客户端地址。可信监听器上它可能来自 PROXY 头。
	client netip.AddrPort
	// local 是用户实际打到的中继入口地址。
	local netip.AddrPort
	// scheme 是公网侧 scheme：判别器知道自己有没有终止 TLS，
	// 不能靠后面的 r.TLS 反推（那是 frp 把 X-Forwarded-Proto 永远写成 http 的原因）。
	scheme string
}

type metaKey struct{}

func withMeta(ctx context.Context, m connMeta) context.Context {
	return context.WithValue(ctx, metaKey{}, m)
}

func metaFromContext(ctx context.Context) (connMeta, bool) {
	m, ok := ctx.Value(metaKey{}).(connMeta)
	return m, ok
}

// legAddrsFromContext 取 StreamOpen 需要的 (src, dst)。
func legAddrsFromContext(ctx context.Context) (src, dst netip.AddrPort) {
	if m, ok := metaFromContext(ctx); ok {
		return m.client, m.local
	}
	return netip.AddrPort{}, netip.AddrPort{}
}

// localPortOf 取用户打到的入口端口，用于查端口绑定表。
//
// http.Server 在 Serve 里把 listener 的地址塞进 ctx（LocalAddrContextKey），
// 所以一次性 listener 必须回报真实连接的本地地址（见 oneConnListener.Addr）。
func localPortOf(r *http.Request) uint16 {
	if m, ok := metaFromContext(r.Context()); ok && m.local.IsValid() {
		return m.local.Port()
	}
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && a != nil {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Port()
		}
	}
	return 0
}

// metaConn 携带连接级元数据，并在 Close 时通知 ServeConn。
//
// Close 一定会被调用：正常连接由 http.Server 关，升级后的连接由
// ReverseProxy 的 handleUpgradeResponse 关（它 defer conn.Close()）。
type metaConn struct {
	net.Conn
	meta connMeta

	once sync.Once
	done chan struct{}
}

func (c *metaConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// oneConnListener 是只交出一条连接的 listener。
type oneConnListener struct {
	mu   sync.Mutex
	c    net.Conn
	addr net.Addr
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c == nil {
		return nil, net.ErrClosed
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneConnListener) Close() error { return nil }

func (l *oneConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return tunnelAddr{}
}
