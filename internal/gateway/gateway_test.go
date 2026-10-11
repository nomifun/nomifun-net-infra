package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// gwFixture 是一整套跑起来的网关：真实 TCP 入口 + 判别器 + 网关 +
// 内存承载上的假 agent + 真实 httptest 后端。
type gwFixture struct {
	relayAddr string
	relayPort uint16

	reg  *Registry
	gw   *Gateway
	disc *Discriminator

	// seen 收集后端**实际收到**的请求（头已被改写过）。
	seen chan *http.Request

	backendAddr string
	tlsCfg      *tls.Config
	agentOnline bool
}

// newGatewayFixture 拉起夹具。online=false 时不注册会话，用于验证 502 路径。
func newGatewayFixture(t *testing.T, online bool) *gwFixture {
	t.Helper()
	return newGatewayFixtureWith(t, online, nil)
}

// newGatewayFixtureWith 与 newGatewayFixture 相同，外加一个改 GatewayConfig 的钩子。
//
// 抽出来是因为有些行为只在**非默认** config 下才测得到（比如空闲回收：
// 真等 60 秒不现实），而那些分支正是最容易变成零覆盖死代码的地方。
func newGatewayFixtureWith(t *testing.T, online bool, mutate func(*GatewayConfig)) *gwFixture {
	t.Helper()

	f := &gwFixture{seen: make(chan *http.Request, 8), agentOnline: online}

	// ── 后端：一个真实的 HTTP 服务，扮演家里的 nomifun-desktop LAN 口 ──────────
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(context.Background())
		clone.Body = nil
		select {
		case f.seen <- clone:
		default:
		}

		switch {
		case strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
			// 后端自己完成 101 与升级后的回显 —— 中继侧不写一行 Hijack 代码。
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()
			for {
				line, err := buf.ReadString('\n')
				if err != nil {
					return
				}
				if _, err := buf.WriteString("echo:" + line); err != nil {
					return
				}
				if err := buf.Flush(); err != nil {
					return
				}
			}

		case r.URL.Path == "/api/sink":
			// 吞掉请求体，给上行限速测试用。必须**读完**，否则限速挂在
			// 隧道那侧连接的写方向上就没有字节流过它。
			n, _ := io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, `{"got":%d}`, n)

		case r.URL.Path == "/api/bulk":
			// 定长大响应体，给限速测试用：只有足够大的载荷才会溢出令牌桶的
			// 初始突发，而不溢出的话「限速生效」就测不出来。
			n, _ := strconv.Atoi(r.URL.Query().Get("n"))
			if n <= 0 {
				n = 1024
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(n))
			chunk := make([]byte, 32<<10)
			for i := range chunk {
				chunk[i] = 'x'
			}
			for n > 0 {
				k := min(n, len(chunk))
				if _, err := w.Write(chunk[:k]); err != nil {
					return
				}
				n -= k
			}

		case r.URL.Path == "/api/slow":
			// 流式响应：验证 FlushInterval=-1 真的不缓冲。
			fl := http.NewResponseController(w)
			for i := range 3 {
				fmt.Fprintf(w, "chunk-%d\n", i)
				_ = fl.Flush()
				time.Sleep(10 * time.Millisecond)
			}

		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"host":%q,"xff":%q,"proto":%q}`,
				r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"))
		}
	}))
	t.Cleanup(backend.Close)
	f.backendAddr = strings.TrimPrefix(backend.URL, "http://")

	// ── 假 agent：读 StreamOpen → 拨后端 → 回 StreamOK → 双向搬字节 ─────────
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", f.backendAddr)
	})
	sessions := sessionMap{}
	if online {
		sessions["agent-1"] = agent.session("agent-1")
	}

	// ── 中继：判别器 + 网关 ────────────────────────────────────────────────
	f.reg = NewRegistry()
	gwCfg := GatewayConfig{
		Registry: f.reg,
		Dialer:   &TunnelDialer{Lookup: sessions},
		Log:      testLogger(t),
	}
	if mutate != nil {
		mutate(&gwCfg)
	}
	f.gw = NewGateway(gwCfg)
	t.Cleanup(func() { _ = f.gw.Close() })

	f.tlsCfg = selfSignedTLS(t, "api.example.com", "ws.example.com")
	f.disc = NewDiscriminator(DiscriminatorConfig{
		Registry:  f.reg,
		Gateway:   f.gw,
		TLSConfig: f.tlsCfg,
		Log:       testLogger(t),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.relayAddr = ln.Addr().String()
	f.relayPort = uint16(ln.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = f.disc.Close()
	})
	go func() { _ = f.disc.Serve(ctx, ln) }()

	// 网关模式隧道：api.example.com 与 ws.example.com 都落到同一个后端。
	api := sharedTunnel("api", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"api.example.com", "ws.example.com", "*.wild.example.com"}, nil)
	if err := f.reg.AddShared(f.relayPort, api); err != nil {
		t.Fatal(err)
	}
	return f
}

// client 造一个 http.Client，其 DialContext 恒指向中继入口。
//
// 这样走的是**真实** HTTP 栈与真实 Host 头，而不是手搓一个看起来像 HTTP 的字符串。
func (f *gwFixture) client(withTLS bool) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.relayAddr)
		},
	}
	if withTLS {
		pool := x509.NewCertPool()
		pool.AddCert(f.tlsCfg.Certificates[0].Leaf)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// TestGatewayEndToEndCleartext 走一遍完整的明文网关路径：
// 真实 http.Client → 真实 TCP 入口 → 判别 → ReverseProxy → 隧道 → 真实后端。
func TestGatewayEndToEndCleartext(t *testing.T) {
	f := newGatewayFixture(t, true)

	req, err := http.NewRequest(http.MethodGet, "http://api.example.com/api/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	// 攻击者伪造的整套身份头。断言它们**一个都不能**到后端。
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Add("X-Forwarded-For", "10.0.0.2")
	req.Header.Set("X-Real-IP", "10.0.0.3")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	req.Header.Set("Forwarded", "for=10.0.0.4")
	req.Header.Set("X-Client-IP", "10.0.0.5")
	req.Header.Set("CF-Connecting-IP", "10.0.0.6")
	req.Header.Set("True-Client-IP", "10.0.0.7")
	req.Header.Set("Origin", "http://api.example.com")

	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatalf("经网关发请求失败：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，响应体：%s", resp.StatusCode, body)
	}
	t.Logf("后端响应：%s", body)

	got := f.mustSeen(t)
	// 真实客户端 IP 是 loopback（测试里客户端与中继同机）。
	wantClient := "127.0.0.1"

	rows := []struct {
		name   string
		header string
		want   string
	}{
		{"Host 改写为后端 ip:port", "Host", f.backendAddr},
		{"Origin 改写为 http://B", "Origin", "http://" + f.backendAddr},
		{"X-Forwarded-Host 是公网主机名", "X-Forwarded-Host", "api.example.com"},
		{"X-Forwarded-For 是唯一真实客户端 IP", "X-Forwarded-For", wantClient},
		{"X-Real-IP 是唯一真实客户端 IP", "X-Real-IP", wantClient},
		{"X-Forwarded-Proto 是公网侧 scheme", "X-Forwarded-Proto", "http"},
		{"Forwarded 被删除", "Forwarded", ""},
		{"X-Client-IP 被删除", "X-Client-IP", ""},
		{"CF-Connecting-IP 被删除", "CF-Connecting-IP", ""},
		{"True-Client-IP 被删除", "True-Client-IP", ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			v := got.Header.Get(row.header)
			if row.header == "Host" {
				v = got.Host
			}
			if v != row.want {
				t.Fatalf("后端收到 %s = %q，期望 %q", row.header, v, row.want)
			}
		})
	}

	t.Run("XFF 是替换而不是追加", func(t *testing.T) {
		// 后端取 X-Forwarded-For 的第一个元素且没有可信代理白名单
		//（nomifun-auth/src/extract.rs:13-32），所以只要留下客户端可控的元素，
		// 公网就拿到了源 IP 伪造原语。
		vals := got.Header.Values("X-Forwarded-For")
		if len(vals) != 1 {
			t.Fatalf("X-Forwarded-For 有 %d 个值 %v —— 必须先删再设为单值", len(vals), vals)
		}
		if strings.Contains(vals[0], ",") {
			t.Fatalf("X-Forwarded-For = %q 含列表 —— 追加模式会把伪造能力送给公网", vals[0])
		}
		if strings.Contains(vals[0], "10.0.0.") {
			t.Fatalf("X-Forwarded-For = %q 含伪造项", vals[0])
		}
	})

	t.Run("路径与查询原样透传", func(t *testing.T) {
		if got.URL.Path != "/api/hello" {
			t.Fatalf("后端收到路径 %q", got.URL.Path)
		}
	})
}

// TestGatewayEndToEndTLSTermination 走 SNI → 本地终止 TLS → L7 的路径，
// 并断言 X-Forwarded-Proto 是 https。
//
// frp 在这里永远写 http（它的 vhost server 不带 TLS，r.TLS 恒为 nil），
// 于是后端的 OAuth 回跳与 Secure cookie 全算错。
func TestGatewayEndToEndTLSTermination(t *testing.T) {
	f := newGatewayFixture(t, true)

	resp, err := f.client(true).Get("https://api.example.com/api/hello")
	if err != nil {
		t.Fatalf("经网关发 https 请求失败：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，响应体：%s", resp.StatusCode, body)
	}

	got := f.mustSeen(t)
	if v := got.Header.Get("X-Forwarded-Proto"); v != "https" {
		t.Fatalf("X-Forwarded-Proto = %q，期望 https", v)
	}
	if got.Host != f.backendAddr {
		t.Fatalf("Host = %q，期望 %q", got.Host, f.backendAddr)
	}
	t.Logf("TLS 终止后后端看到 Host=%s proto=https，响应：%s", got.Host, body)
}

// TestGatewayWildcardHostRouting 证明通配域名在真实请求上也生效。
func TestGatewayWildcardHostRouting(t *testing.T) {
	f := newGatewayFixture(t, true)

	resp, err := f.client(false).Get("http://tenant7.wild.example.com/api/hello")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d", resp.StatusCode)
	}
	got := f.mustSeen(t)
	if v := got.Header.Get("X-Forwarded-Host"); v != "tenant7.wild.example.com" {
		t.Fatalf("X-Forwarded-Host = %q", v)
	}
}

// TestGatewayWebSocketThroughReverseProxy 证明 WebSocket 升级穿过网关。
//
// 关键：中继侧**没有一行 Hijack 代码**。Go 1.26 的 httputil.ReverseProxy
// 原生处理 101（reverseproxy.go:573-579 → handleUpgradeResponse:820-890），
// 我们只要不把它换成手写 pipe、并且保证入站是 HTTP/1.1 就行。
func TestGatewayWebSocketThroughReverseProxy(t *testing.T) {
	f := newGatewayFixture(t, true)

	conn, err := net.Dial("tcp", f.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 手写 Upgrade 请求，这样能确认 101 与升级后的字节都原样穿过。
	req := "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败：%v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("状态行 = %q，期望含 101", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	for i := range 3 {
		msg := fmt.Sprintf("消息%d\n", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读回显失败：%v", err)
		}
		if want := "echo:" + msg; got != want {
			t.Fatalf("回显 = %q，期望 %q", got, want)
		}
	}

	if n := f.gw.Stats().Upgrades.Load(); n != 1 {
		t.Errorf("Upgrades 计数 = %d，期望 1", n)
	}

	// 升级后的请求同样要经过 §12 的改写 —— 否则 nomifun-realtime 的
	// validate_origin 会因为域名型 Origin 被外层 host guard 403 掉。
	got := f.mustSeen(t)
	if got.Host != f.backendAddr {
		t.Fatalf("升级请求的 Host = %q，期望 %q", got.Host, f.backendAddr)
	}
	t.Log("WebSocket 升级与双向消息均穿过网关，且请求头已改写")
}

// TestGatewayStreamingIsNotBuffered 证明 FlushInterval=-1 生效：
// 分块响应逐块到达，而不是等后端关闭才一次吐出。
func TestGatewayStreamingIsNotBuffered(t *testing.T) {
	f := newGatewayFixture(t, true)

	resp, err := f.client(false).Get("http://api.example.com/api/slow")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	for i := range 3 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读第 %d 块失败：%v", i, err)
		}
		if want := fmt.Sprintf("chunk-%d\n", i); line != want {
			t.Fatalf("第 %d 块 = %q，期望 %q", i, line, want)
		}
	}
}

// TestGatewayNoRouteIs404 证明「没有匹配的隧道」是配置问题，回 404 而不是 502。
//
// 把两者混成同一个状态码会让运维分不清该查控制台还是查家里的机器。
func TestGatewayNoRouteIs404(t *testing.T) {
	f := newGatewayFixture(t, true)

	// 域名注册过（判别器放行），但路径路由不到 —— 这里用一条只注册了 /api 的隧道。
	only := sharedTunnel("only-api", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"strict.example.com"}, []string{"/api"})
	if err := f.reg.AddShared(f.relayPort, only); err != nil {
		t.Fatal(err)
	}

	// /admin 在判别阶段就被拒（无默认绑定）→ 连接被回 404 后关闭。
	resp, err := f.client(false).Get("http://strict.example.com/admin")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404", resp.StatusCode)
	}
}

// TestGatewayAgentOfflineIs502 证明后端不可达时是 502，并且计数器动了。
func TestGatewayAgentOfflineIs502(t *testing.T) {
	f := newGatewayFixture(t, false) // 不注册会话 = 代理端不在线

	resp, err := f.client(false).Get("http://api.example.com/api/hello")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("状态码 = %d，期望 502", resp.StatusCode)
	}
	if n := f.gw.Stats().BadGateway.Load(); n != 1 {
		t.Fatalf("BadGateway 计数 = %d，期望 1", n)
	}
}

// TestGatewayReusesOneTransportPerTunnel 证明连接池按隧道隔离。
//
// frp 为了让同一条路由复用 work conn，把域名/路径/用户/端点 base64 拼进
// req.URL.Host（pkg/util/vhost/http.go:81-85）。我们用真实的 map + 每隧道一个
// Transport 达到同样效果，不往协议字段里塞编码数据。
func TestGatewayReusesOneTransportPerTunnel(t *testing.T) {
	f := newGatewayFixture(t, true)

	c := f.client(false)
	for range 3 {
		resp, err := c.Get("http://api.example.com/api/hello")
		if err != nil {
			t.Fatalf("请求失败：%v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		f.mustSeen(t)
	}

	f.gw.mu.Lock()
	n := len(f.gw.proxies)
	f.gw.mu.Unlock()
	if n != 1 {
		t.Fatalf("代理缓存里有 %d 条，期望按隧道 ID 只有 1 条", n)
	}
}

// TestGatewayReroutesEachRequestOnKeepAliveConn 是一条容易被忽略的安全性质：
// 判别器只看**首个**请求，同一条 keep-alive 连接上的后续请求必须由网关
// 逐个重新路由，绝不能继承首个请求命中的隧道。
//
// 否则攻击者只要先用一个合法 Host 建连，就能在同一条连接上用任意 Host
// 把请求送进那条隧道 —— 一个纯粹由「连接级缓存路由」造成的越权。
func TestGatewayReroutesEachRequestOnKeepAliveConn(t *testing.T) {
	f := newGatewayFixture(t, true)

	conn, err := net.Dial("tcp", f.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 第一个请求：合法 Host，应当 200。
	if _, err := conn.Write([]byte("GET /api/hello HTTP/1.1\r\nHost: api.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读第一个响应失败：%v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("第一个请求状态码 = %d，期望 200", resp.StatusCode)
	}
	f.mustSeen(t)

	// 第二个请求：同一条连接，换成未注册的 Host —— 必须 404，且**不能**打到后端。
	if _, err := conn.Write([]byte("GET /api/hello HTTP/1.1\r\nHost: attacker.example.net\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读第二个响应失败：%v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("第二个请求状态码 = %d，期望 404 —— 路由必须逐请求重算", resp2.StatusCode)
	}
	if n := f.gw.Stats().NoRoute.Load(); n != 1 {
		t.Fatalf("NoRoute 计数 = %d，期望 1", n)
	}
	select {
	case r := <-f.seen:
		t.Fatalf("未注册 Host 的请求竟然打到了后端：%s %s", r.Host, r.URL.Path)
	default:
	}
}

// TestGatewayProxyCacheFollowsBackendChange 证明改了后端地址之后，
// 网关不会继续把请求改写成旧的 Host。
//
// 这是热重载里最难查的一类 bug：ReverseProxy 的 Rewrite 闭包捕获的是
// 装配时算出的 backend，若缓存只按隧道 ID 分桶，改配置就成了空操作。
func TestGatewayProxyCacheFollowsBackendChange(t *testing.T) {
	f := newGatewayFixture(t, true)

	tn := sharedTunnel("mutable", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"mutable.example.com"}, nil)

	first := f.gw.proxyFor(tn)

	// 控制台把后端换成另一个地址（同一条隧道）。
	tn.Router.HostRewrite = "192.168.77.77:25808"
	second := f.gw.proxyFor(tn)

	if first == second {
		t.Fatal("改了后端 authority 之后必须换一个 ReverseProxy，否则改写值是旧的")
	}

	// 显式失效应当把这条隧道的所有条目清掉。
	f.gw.Invalidate(tn.ID)
	f.gw.mu.Lock()
	n := len(f.gw.proxies)
	f.gw.mu.Unlock()
	if n != 0 {
		t.Fatalf("Invalidate 之后还剩 %d 条缓存", n)
	}
}

func (f *gwFixture) mustSeen(t *testing.T) *http.Request {
	t.Helper()
	select {
	case r := <-f.seen:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("后端没在 5 秒内收到请求")
		return nil
	}
}

// TestGatewayProxyCacheFollowsALateAgentBinding 钉住一条真实的「永久 502」。
//
// # 触发链全是默认行为
//
//  1. 用户在还没有 agent 在线时建一条 exposure=shared 的隧道。
//     这是**允许**的：路由表只看 IsEnabled / Exposure / L4，不看 AgentID。
//  2. 用户打开域名想看看通了没有 → 502。此刻 502 是对的，
//     但这一次请求把 AgentID="" 的 ReverseProxy 写进了缓存。
//  3. 启动 agent。bindUnassigned 把 AgentID 绑好、回写库、路由表全量重建。
//  4. 用户刷新页面 —— **仍然 502，而且永远 502**，直到重启中继。
//
// 因为 transportFor 把整个 *tunnel.Tunnel 闭包捕获进 DialContext，
// 而 DialTunnel 读的是 t.AgentID；缓存键原本只有 ID 与后端 authority，
// AgentID 变了键不变，于是旧闭包一直被复用。
//
// 控制台这时显示 active（它读的是重建后的新对象），浏览器显示 502 ——
// 两边都不指向真正的原因。而「先开页面看一眼、再启动 agent」
// 恰好是最自然的首次使用顺序。
//
// 现有的 TestGatewayProxyCacheFollowsBackendChange 覆盖不到：它改的是
// 后端 authority，那一类本来就在键里。
func TestGatewayProxyCacheFollowsALateAgentBinding(t *testing.T) {
	f := newGatewayFixture(t, true)

	// 第 1 步：隧道存在，但还没绑定 agent。
	unbound := sharedTunnel("late", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"late.example.com"}, nil)
	unbound.AgentID = ""

	// 第 2 步：一次请求把「没有 agent」的代理写进缓存。
	stale := f.gw.proxyFor(unbound)

	// 第 3 步：agent 上线，bindUnassigned 绑好 —— 注意这是一个**新对象**
	//（store 的 scanTunnel 每次 ListTunnels 都新分配），后端地址没变。
	bound := sharedTunnel("late", tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{"late.example.com"}, nil)
	bound.ID = unbound.ID
	bound.AgentID = "agent-1"

	// 第 4 步：必须拿到一个**不同**的代理，否则它的 DialContext 里
	// 还闭包着 AgentID="" 的旧对象。
	fresh := f.gw.proxyFor(bound)
	if fresh == stale {
		t.Fatal("agent 迟到绑定后仍然复用旧代理 —— 那条隧道会永久 502，" +
			"而控制台显示 active（AgentID 不在缓存键里）")
	}

	// Invalidate 要能按隧道 ID 前缀把**两条**都清掉（键现在是三段式）。
	f.gw.Invalidate(unbound.ID)
	f.gw.mu.Lock()
	n := len(f.gw.proxies)
	f.gw.mu.Unlock()
	if n != 0 {
		t.Fatalf("Invalidate 应当按隧道 ID 清掉全部条目，还剩 %d 条", n)
	}
}
