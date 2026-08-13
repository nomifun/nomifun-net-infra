package gateway

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestKeepAliveCannotHopToATunnelWhoseWhitelistWouldRejectYou 复现并钉住一个真实的绕过。
//
// # 绕过是怎么成立的
//
// 判别器每**连接**判一次隧道（判据是首个请求的 Host，TLS 侧是 SNI），并对**那条**
// 隧道查一次 allow_cidrs。而网关的 ServeHTTP 是每**请求**重查路由 —— 于是同一条
// keep-alive 连接上的第二个请求换一个 Host，就会落到另一条隧道，
// 而那条隧道的白名单从来没有被检查过。
//
// 攻击形态很直接：先用一个自己被放行的域名建连（判别器放行），
// 然后在**同一条连接**上请求那个受限域名。
//
// 现象是「白名单看起来配了、DeniedCIDR 计数器也在动，但受限域名照样能访问」——
// 也就是一道看起来在工作的防线。
func TestKeepAliveCannotHopToATunnelWhoseWhitelistWouldRejectYou(t *testing.T) {
	f := newGatewayFixture(t, true)

	// 再注册一条**带白名单**的隧道，白名单里只有一个与本机无关的网段。
	// 夹具已注册的 api.example.com 没有白名单，任何人都能连 —— 那正是攻击者的入口。
	locked := sharedTunnel("locked", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"locked.example.com"}, nil)
	locked.Policy = &tunnel.Policy{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	if err := f.reg.AddShared(f.relayPort, locked); err != nil {
		t.Fatal(err)
	}

	// **必须手工复用同一个 socket。**
	//
	// 用 http.Client 复现不出来：Go 的 Transport 按 (scheme, host) 分连接池，
	// 换一个 Host 会新建连接，于是判别器会按新 Host 重新判一次隧道并正确拒绝。
	// 而攻击者不受这个约束 —— 他就是**故意**在同一条连接上换 Host 的。
	conn, err := net.Dial("tcp", f.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	send := func(host string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/api/hello", nil)
		req.Host = host
		if err := req.Write(conn); err != nil {
			t.Fatalf("写请求失败（Host=%s）：%v", host, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("读响应失败（Host=%s）：%v", host, err)
		}
		return resp
	}

	// 第一步：用没有白名单的域名建连。判别器按这条隧道放行。
	resp := send("api.example.com")
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("前置不成立：入口域名应当可访问，实际 %d", resp.StatusCode)
	}

	// 第二步：**同一条连接**上换 Host，指向受限隧道。
	// 我们的来源是 127.0.0.1，不在 198.51.100.0/24 里 —— 必须被拒。
	resp2 := send("locked.example.com")
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)

	if resp2.StatusCode == http.StatusOK {
		t.Fatalf("**绕过成立**：在一条已被放行的 keep-alive 连接上换 Host，"+
			"就访问到了白名单本该拒绝的隧道。响应体：%s", body)
	}
	// 404 而不是 403：不该告知「这个域名存在，只是不让你访问」——
	// 那是一次免费的存在性确认。与未注册域名同一个回复。
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404（与未注册域名同一个回复，不泄露存在性）",
			resp2.StatusCode)
	}
	if n := f.gw.Stats().DeniedCIDR.Load(); n == 0 {
		t.Error("请求级的 DeniedCIDR 计数器没动 —— 那它就无法回答" +
			"「有没有人在试这条绕过」")
	}
}

// TestSourceAllowedFailsClosedOnUnparseableAddresses 钉住解析失败时的方向。
//
// 拿不到来源地址时必须**拒绝**。放行才是危险的默认：那意味着任何让
// RemoteAddr 变得不可解析的情形（未来换传输层、加一层包装）都会把白名单整个绕过。
func TestSourceAllowedFailsClosedOnUnparseableAddresses(t *testing.T) {
	locked := &tunnel.Tunnel{Policy: &tunnel.Policy{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}}
	for _, bad := range []string{"", "garbage", "not-an-ip:1234", "[::1"} {
		if sourceAllowed(locked, bad) {
			t.Errorf("RemoteAddr=%q 解析不出地址时必须拒绝（fail closed）", bad)
		}
	}
	// 正常地址照常判定。
	if !sourceAllowed(locked, "10.1.2.3:5555") {
		t.Error("白名单内的地址应当放行")
	}
	if sourceAllowed(locked, "192.0.2.1:5555") {
		t.Error("白名单外的地址应当拒绝")
	}
	// 没配白名单的隧道一律放行（绝大多数隧道不配它）。
	if !sourceAllowed(&tunnel.Tunnel{}, "garbage") {
		t.Error("没有 allow_cidrs 的隧道不该受影响")
	}
	// IPv4-in-IPv6 必须与裸 IPv4 等价，否则换个书写形式就绕过了。
	if !sourceAllowed(locked, "[::ffff:10.1.2.3]:5555") {
		t.Error("IPv4-in-IPv6 应当与裸 IPv4 同等判定")
	}
}

// TestPassthroughTunnelIsNeverServedThroughTheGateway 钉住第二条同源的绕过。
//
// # 绕过是怎么成立的
//
// 判别器确实看隧道的 tls 字段：SNI 命中 passthrough 隧道时走 ActionSplice，
// 字节级搬运、一个头都不碰。但那是**连接级**判定，而网关的 resolve 是**请求级**
// 重查路由，只看 Host 与 path、完全不看 tunnel.TLS（AddShared 也不分 tls 模式，
// passthrough 隧道照样进 Hosts 表）。
//
// 于是：用**另一条** gateway 隧道的 SNI 建 TLS（中继因此终止 TLS），然后在解密后的
// HTTP 里把 Host 换成那条 passthrough 隧道的域名 —— 它的后端就收到解密并按改写表
// 改过的明文 HTTP。
//
// # 为什么这不只是「配置不符」
//
// 运维选 passthrough 的意图恰恰是「中继绝不看这条隧道的明文」。那条隧道后面可能是
// 一个**假设自己在说 TLS** 的服务（客户端证书、端到端加密），而它收到的是明文 ——
// 于是它自己的那层保护在中继这里被静默摘掉了。
func TestPassthroughTunnelIsNeverServedThroughTheGateway(t *testing.T) {
	f := newGatewayFixture(t, true)

	pt := sharedTunnel("pt", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		f.backendAddr, []string{"pt.example.com"}, nil)
	if err := f.reg.AddShared(f.relayPort, pt); err != nil {
		t.Fatal(err)
	}

	// 用 api.example.com 的 SNI 建 TLS —— 那是一条 gateway 隧道，中继会终止 TLS。
	// 然后在解密后的 HTTP 里把 Host 换成 passthrough 隧道的域名。
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/api/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "pt.example.com"

	resp, err := f.client(true).Do(req)
	if err != nil {
		// 连接层面就被拒也算通过（更严）。
		t.Logf("请求在连接层被拒：%v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("**绕过成立**：tls=passthrough 隧道的后端收到了解密并改写过的"+
			"明文 HTTP。响应体：%s", body)
	}
	// 404 与「未注册域名」同一个回复：不确认它的存在。
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404（与未注册域名同一个回复）", resp.StatusCode)
	}

	// 反面：passthrough 隧道走它**自己**的 SNI 时必须照常工作。
	//
	// 少了这一格，上面那道检查可能是靠「把 passthrough 整个弄坏」换来的绿 ——
	// 那会把一个安全修复变成一次功能回归，而两者在测试输出里长得一模一样。
	//
	// 这条隧道的证书不在夹具的自签证书里（夹具只签了 api/ws.example.com），
	// 所以这里断言的是**判别层面**的行为：SNI 命中 passthrough 隧道时走
	// ActionSplice，于是字节被原样搬给后端 —— 后端是个 HTTP 服务，
	// 它收到 TLS ClientHello 会当成垃圾请求，客户端因此拿到一个 TLS 错误
	// 而**不是** 404。两者的区别正是「splice 了」与「被网关拦了」。
	own, err := http.NewRequest(http.MethodGet, "https://pt.example.com/api/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client(true).Do(own); err == nil {
		t.Error("走自己的 SNI 时应当被 splice 到后端（后端是 HTTP 服务，" +
			"收到 TLS 字节会导致客户端握手失败）—— 拿到一个成功响应说明它" +
			"仍然走了网关路径")
	} else if strings.Contains(err.Error(), "404") {
		t.Errorf("走自己的 SNI 却被网关拦了（%v）—— 那道检查把 passthrough "+
			"整个弄坏了，这是功能回归而不是安全修复", err)
	}
}
