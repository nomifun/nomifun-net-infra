package gateway

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 会被无条件删除的身份类请求头。
//
// # 为什么是「删除」而不是「透传」
//
// nomifun-tauri 从 X-Forwarded-For / X-Real-IP 取客户端 IP，取的是
// `split(',').next()`，而且**没有可信代理白名单**
// （nomifun-tauri/crates/backend/nomifun-auth/src/extract.rs:13-32）。
// 也就是说后端把这些头的第一个值当权威客户端 IP 用。
//
// 于是只要中继做「列表追加」，公网上任何人都能先发一个
// `X-Forwarded-For: 10.0.0.1`，后端读到的就是攻击者选的那个 IP ——
// 这是一个现成的源 IP 伪造原语，能绕过任何基于客户端 IP 的判断。
// 这也正是 frp 的缺陷：它主动把入站 XFF 抄回出站请求
// （pkg/util/vhost/http.go:60）再 SetXForwarded 追加。
//
// 所以规则是 spec §12 的那句话：**先删再设为单值，绝不追加**。
// 后端配置救不了这一点（它没有白名单可配），只能由中继保证。
var strippedRequestHeaders = []string{
	// RFC 7239 的 Forwarded：后端不解析它，留着只会制造歧义。
	"Forwarded",
	// 下面这三个是各家 CDN 的私有头。后端今天不读，但删掉是纵深防御：
	// 将来后端加一行读 CF-Connecting-IP 的代码，就不该同时是一个漏洞。
	"X-Client-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	// 这两个我们随后会设成中继计算出的单值，所以先删干净。
	"X-Real-IP",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
}

// legInfo 是改写请求头需要的四个量，命名与 spec §12 的表一致。
type legInfo struct {
	// Backend 是 B：后端的 ip:port（或 Router.HostRewrite 指定的值）。
	Backend string
	// Public 是 P：公网主机名，即入站请求的 Host。
	Public string
	// Client 是 C：唯一的真实客户端 IP。
	Client string
	// Scheme 是公网侧的 scheme。
	Scheme string
	// HadOrigin 表示入站请求带了 Origin 头。
	HadOrigin bool
}

// rewriteIdentityHeaders 就地实现 spec §12 的改写表。
//
//	| Host              | 设置           | B          |
//	| Origin            | 入站有则设置   | http://B   |
//	| X-Forwarded-Host  | 设置为单值     | P          |
//	| X-Forwarded-For   | 先删再设为单值 | C          |
//	| X-Real-IP         | 先删再设       | C          |
//	| X-Forwarded-Proto | 设置           | 公网侧 scheme |
//	| Forwarded / X-Client-IP / CF-Connecting-IP / True-Client-IP | 删除 | — |
//
// Host 与 Origin 必须变成 **IP 字面量形式**：nomifun-tauri 的
// host_guard_middleware 挂在**路由器之外**，会在 validate_origin 运行之前
// 403 掉任何域名型 Host/Origin（desktop.rs:1205,1710-1730），
// 所以改后端的 allowed_origins 配置**救不了**转发过来的公网主机名。
// 改写之后后端反而零配置：Origin 与 Host 同源，握手被判为 SameOrigin。
//
// 注意：httputil.ReverseProxy 在 Rewrite 模式下已经会先删掉
// Forwarded / X-Forwarded-{For,Host,Proto}（reverseproxy.go:498-507），
// 但**不删** X-Real-IP 与各家私有头。这里仍然把这几个头全部自己删一遍：
// 这条不变量的正确性不该依赖 stdlib 某个版本的实现细节。
func rewriteIdentityHeaders(out *http.Request, leg legInfo) {
	for _, h := range strippedRequestHeaders {
		out.Header.Del(h)
	}

	// Host 走 Request.Host 而不是 Header —— net/http 写线时以前者为准。
	out.Host = leg.Backend
	if out.URL != nil {
		out.URL.Host = leg.Backend
	}

	if leg.HadOrigin {
		// 永远不要把 https://P 转发过去：那是会被 403 的形态。
		out.Header.Set("Origin", "http://"+leg.Backend)
	}

	out.Header.Set("X-Forwarded-Host", leg.Public)
	out.Header.Set("X-Forwarded-Proto", leg.Scheme)
	if leg.Client != "" {
		// Set 而不是 Add：单值，无列表。
		out.Header.Set("X-Forwarded-For", leg.Client)
		out.Header.Set("X-Real-IP", leg.Client)
	}
}

// backendAuthority 算出 B。
//
// 优先 Router.HostRewrite（控制台可以为「后端期望的 Host 与拨号地址不同」的
// 情况显式指定），否则从 Backend 派生：
//   - addr 后端直接用 ip:port，这正是 §12 要的形态；
//   - unix 后端没有 ip:port 可用，退化为 "localhost" ——
//     它是 host_guard 唯一放行的非 IP 值（desktop.rs:1726-1729）。
func backendAuthority(t *tunnel.Tunnel) string {
	if t.Router != nil && t.Router.HostRewrite != "" {
		return t.Router.HostRewrite
	}
	if t.Backend.Kind == tunnel.BackendAddr && t.Backend.Addr != "" {
		return t.Backend.Addr
	}
	return "localhost"
}

// clientIPOf 从请求里取唯一的真实客户端 IP。
//
// 只认**内核看到的对端**（或判别阶段由可信 PROXY 头覆盖过的地址），
// 绝不看任何请求头 —— 请求头在这一层全是攻击者可控的输入。
func clientIPOf(r *http.Request) string {
	if meta, ok := metaFromContext(r.Context()); ok && meta.client.IsValid() {
		return canonicalIP(meta.client.Addr())
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return canonicalIP(ap.Addr())
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// canonicalIP 把 ::ffff:1.2.3.4 规范成 1.2.3.4。
//
// 不做这一步，后端的 IPv4 白名单会被 v4-in-v6 形式绕过 ——
// 与 tunnel.SourceAllowed 里同一个理由。
func canonicalIP(a netip.Addr) string {
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.String()
}

// publicSchemeOf 返回公网侧的 scheme。
//
// frp 这里永远写 http（它的 vhost server 不带 TLS，r.TLS 恒为 nil，
// docs/research/03-frp-l7-vhost.md §3 第 3 点），于是后端的 OAuth 回跳与
// Secure cookie 全算错。我们从判别阶段带下来的 connMeta 取真值。
func publicSchemeOf(r *http.Request) string {
	if meta, ok := metaFromContext(r.Context()); ok && meta.scheme != "" {
		return meta.scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// publicHostOf 返回 P：入站请求里的公网主机名。
func publicHostOf(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	if r.URL != nil {
		return r.URL.Host
	}
	return ""
}

// isIPLiteralOrLocalhost 复刻 nomifun-tauri 的 host_is_ip_or_localhost
// （desktop.rs:1726-1729）：只接受 "localhost" 或能被 IP 解析器接受的字面量。
//
// 我们自己也做这个判断，是为了在装配路由时就能警告
// 「这个后端地址是域名，改写后的 Host 会被后端 403」，
// 而不是等用户在浏览器里撞一堵 403 的墙。
func isIPLiteralOrLocalhost(authority string) bool {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}
