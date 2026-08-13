package main

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/acmecert"
	"github.com/nomifun/nomifun-net-infra/internal/gateway"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestACMEALPNConstantsAgree 钉住两个包里各自写的 "acme-tls/1"。
//
// gateway 用它判别入站连接、acmecert 用它应答挑战。一旦漂开，
// 判别器会把挑战连接当成普通 TLS 处理 —— 现象是 ACME 挑战**静默超时**，
// 而两边的代码单看都没错。这类跨包字面量必须有一处钉子。
func TestACMEALPNConstantsAgree(t *testing.T) {
	if gateway.ACMETLSALPNProto != acmecert.ACMETLSALPNProto {
		t.Fatalf("acme-tls/1 常量漂了：gateway=%q acmecert=%q",
			gateway.ACMETLSALPNProto, acmecert.ACMETLSALPNProto)
	}
}

// TestGatewayTLSFallsBackToSelfSignedWhenACMECannotSign 是场景二的保命路径。
//
// 工厂机器人用裸 IP 直连，永远签不出公网证书。如果 ACME 一接上就把
// Certificates 挤掉，那些设备会在证书这一步全线掉线 —— 而它们本来靠
// 固件里的指纹校验，不需要可信证书。
func TestGatewayTLSFallsBackToSelfSignedWhenACMECannotSign(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x30}}}

	bare := gatewayTLS(cert, nil)
	if len(bare.Certificates) != 1 {
		t.Fatal("未启用 ACME 时必须留着自签证书")
	}
	if bare.GetCertificate != nil {
		t.Fatal("未启用 ACME 时不该设 GetCertificate")
	}

	m := newTestACME(t)
	withACME := gatewayTLS(cert, m)
	if withACME.GetCertificate == nil {
		t.Fatal("启用 ACME 后必须设 GetCertificate")
	}
	if len(withACME.Certificates) != 1 {
		t.Fatal("启用 ACME 后**仍然**要留着自签证书作回落 —— " +
			"裸 IP 的设备签不出证书，挤掉它等于让那些设备全线掉线")
	}
}

// TestTurnTLSDoesNotAdvertiseHTTPALPN 防的是一类只在客户端侧看得见的故障。
//
// turns: 不用 ALPN。若照搬网关的 ["http/1.1"]，一个**带上** ALPN 的
// turns: 客户端会拿到 no_application_protocol 告警 —— 现象是「ICE 连不上」，
// 而中继侧日志里只有一次失败的握手。
func TestTurnTLSDoesNotAdvertiseHTTPALPN(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x30}}}

	if cfg := turnTLS("", cert, nil); cfg != nil {
		t.Fatal("未指定 turns: 地址时必须返回 nil，否则 turnsrv 会去起一个空地址的监听")
	}

	cfg := turnTLS("0.0.0.0:5349", cert, nil)
	if slices.Contains(cfg.NextProtos, "http/1.1") {
		t.Fatalf("turns: 不该宣告 http/1.1，实际 %v", cfg.NextProtos)
	}
	if len(cfg.NextProtos) != 0 {
		t.Fatalf("turns: 不用 ALPN，一项都不该宣告，实际 %v", cfg.NextProtos)
	}

	// 网关那一份必须**仍然**宣告 http/1.1：它确实只说 HTTP/1.1
	//（WebSocket 升级要 Hijack，h2 的 ResponseWriter 没有）。
	if got := gatewayTLS(cert, nil).NextProtos; !slices.Equal(got, []string{"http/1.1"}) {
		t.Fatalf("网关的 ALPN 不该被这次改动带偏，实际 %v", got)
	}
}

// TestKnowsHostOnlyAcceptsExactlyRegisteredDomains 是 ACME 的第二道闸门。
//
// 通配回落对**转发**是对的，对**签证书**是错的：任何人都能拿
// <随机>.b.example.com 发一次握手让我们去要一张新证书，几十次就把全局预算烧光。
func TestKnowsHostOnlyAcceptsExactlyRegisteredDomains(t *testing.T) {
	rt := newTestRuntime(t)
	if err := rt.startShared("127.0.0.1:0", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	// 共享入口还没有任何路由时，一切都不认 —— 这是启动早期的真实状态，
	// 而它必须是「拒签」而不是「放行」。
	if rt.KnowsHost("web.example.com") {
		t.Fatal("路由表为空时不该认识任何域名")
	}

	exact := &tunnel.Tunnel{
		Slug: "exact", Kind: tunnel.KindService, TLS: tunnel.TLSGateway,
		Exposure: tunnel.ExposureShared, L4: tunnel.L4TCP,
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{"web.example.com"}},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9001"},
		AgentID: "a1",
	}
	wild := &tunnel.Tunnel{
		Slug: "wild", Kind: tunnel.KindService, TLS: tunnel.TLSGateway,
		Exposure: tunnel.ExposureShared, L4: tunnel.L4TCP,
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{"*.wild.example.com"}},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9002"},
		AgentID: "a1",
	}
	for _, tn := range []*tunnel.Tunnel{exact, wild} {
		tn.Complete()
		if err := tn.Validate(); err != nil {
			t.Fatalf("测试隧道自己就不合法：%v", err)
		}
	}
	rt.applyShared([]*tunnel.Tunnel{exact, wild})

	cases := []struct {
		name string
		want bool
		why  string
	}{
		{"web.example.com", true, "逐字注册过"},
		{"WEB.example.com", true, "域名大小写无关（certmagic 会小写化，但闸门自己也要正确）"},
		{"*.wild.example.com", true, "通配本身是逐字注册的键"},
		{"a.wild.example.com", false,
			"只被通配覆盖 —— 放行它等于让任意子域都能触发一次签发"},
		{"nope.example.com", false, "没注册过"},
		{"", false, "空 SNI"},
	}
	for _, c := range cases {
		if got := rt.KnowsHost(c.name); got != c.want {
			t.Errorf("KnowsHost(%q)=%v，想要 %v（%s）", c.name, got, c.want, c.why)
		}
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestACME(t *testing.T) *acmecert.Manager {
	t.Helper()
	m, err := acmecert.New(acmecert.Config{
		Enabled: true, Email: "ops@example.com",
		StorageDir: t.TempDir(), Hosts: acmecert.StaticHosts{"web.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestACMEChallengeConnReachesTheHandler 验证那条**会静默失败**的接线。
//
// certmagic 的 TLS-ALPN-01 solver 自己去 bind :443，撞上「已被占用」后
// **返回 (nil, nil) 静默假设占用者会应答挑战**，只打一行 WARNING。
// 也就是说：判别器没把 acme-tls/1 交给我们的处理器时，唯一的现象是
// 挑战超时 —— 没有报错、没有堆栈，两边代码单看都对。
//
// 所以这里不测「证书签出来了」（那要真的 CA），只测**连接到达了处理器**。
// 那正是会断的那一环。
func TestACMEChallengeConnReachesTheHandler(t *testing.T) {
	rt := newTestRuntime(t)

	var got atomic.Int64
	handler := func(c net.Conn) {
		got.Add(1)
		c.Close()
	}
	cert := tls.Certificate{Certificate: [][]byte{{0x30}}}
	if err := rt.startShared("127.0.0.1:0", gatewayTLS(cert, nil), nil, handler, false); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	rt.mu.RLock()
	addr := rt.shared.ln.Addr().String()
	rt.mu.RUnlock()

	// 客户端只需要发出带 acme-tls/1 的 ClientHello；握手会失败
	//（我们的处理器直接关连接），但判别器的分派已经发生了。
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "web.example.com",
		NextProtos:         []string{acmecert.ACMETLSALPNProto},
		InsecureSkipVerify: true, //nolint:gosec // 测的是分派，不是证书
	})
	if err == nil {
		c.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for got.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got.Load() == 0 {
		t.Fatal("带 acme-tls/1 的连接没有到达 ACME 处理器 —— " +
			"这正是 certmagic 会静默假设「有人会应答」的那一环")
	}
}

// TestACMEChallengeIsRejectedWhenNotConfigured 钉住相反的默认。
//
// 没接 ACME 却收到挑战请求，说明有人在试探。此时必须**拒绝**，
// 而不是当成普通 TLS 去终止 —— 后者会让攻击者拿到一次真实握手。
func TestACMEChallengeIsRejectedWhenNotConfigured(t *testing.T) {
	rt := newTestRuntime(t)
	cert := tls.Certificate{Certificate: [][]byte{{0x30}}}
	if err := rt.startShared("127.0.0.1:0", gatewayTLS(cert, nil), nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	rt.mu.RLock()
	addr := rt.shared.ln.Addr().String()
	rt.mu.RUnlock()

	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "web.example.com",
		NextProtos:         []string{acmecert.ACMETLSALPNProto},
		InsecureSkipVerify: true, //nolint:gosec // 断言的是连接被拒
	})
	if err == nil {
		c.Close()
		t.Fatal("未装配 ACME 时不该让 acme-tls/1 握手成功")
	}
}

// TestACMEChallengeSurvivesARouteTableRebuild 钉住全量重建最容易丢的那一格。
//
// applyShared 每次都从零造一张新注册表再整体替换。「这个端口我们在听」
// 不由任何一条隧道产生，所以它是重建时最容易漏掉的状态 ——
// 漏掉之后现象是「建过隧道又全删了，从此签不出证书」。
func TestACMEChallengeSurvivesARouteTableRebuild(t *testing.T) {
	rt := newTestRuntime(t)

	var got atomic.Int64
	cert := tls.Certificate{Certificate: [][]byte{{0x30}}}
	err := rt.startShared("127.0.0.1:0", gatewayTLS(cert, nil), nil, func(c net.Conn) {
		got.Add(1)
		c.Close()
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	// 一条共享隧道都没有 —— 这正是「只跑 turns:」或「隧道全停用」的状态。
	rt.applyShared(nil)

	rt.mu.RLock()
	addr := rt.shared.ln.Addr().String()
	rt.mu.RUnlock()

	if c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "turn.example.com",
		NextProtos:         []string{acmecert.ACMETLSALPNProto},
		InsecureSkipVerify: true, //nolint:gosec // 测的是分派
	}); err == nil {
		c.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for got.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got.Load() == 0 {
		t.Fatal("重建路由表后 ACME 挑战不再到达处理器 —— " +
			"turns: 的域名永远不在路由表里，它的挑战只能走这条路")
	}
}

// TestACMEStartupRefusesConfigsWhereTheChallengeCanNeverArrive 把一类
// 「静默超时」故障提前到启动时。
//
// TLS-ALPN-01 按 RFC 8737 只走 443、HTTP-01 按 RFC 8555 只走 80，
// 都不能重定向到别的端口。开了 ACME 却没有这两个端口，结果是签发一直重试
// 到超时 —— 日志里只有 certmagic 的重试，没有任何一句说明原因。
func TestACMEStartupRefusesConfigsWhereTheChallengeCanNeverArrive(t *testing.T) {
	m := newTestACME(t)
	cases := []struct {
		name, shared, http string
		wantErr            bool
		why                string
	}{
		{"两条都没有", "", "", true, "证书永远签不出来"},
		{"共享入口不在 443", "0.0.0.0:8443", "", true,
			"TLS-ALPN-01 不能重定向到 8443"},
		{"HTTP 不在 80", "", "0.0.0.0:8080", true, "HTTP-01 不能重定向到 8080"},
		{"443 可用", "0.0.0.0:443", "", false, "主路径"},
		{"只有 80 可用", "", "0.0.0.0:80", false,
			"能签，但共享入口不在 443 时用得上的人很少 —— 该 warn 不该拒"},
		{"两条都有", "0.0.0.0:443", "0.0.0.0:80", false, "最健壮的配置"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkACMEReachable(m, c.shared, c.http, quietLog())
			if c.wantErr && err == nil {
				t.Fatalf("这个配置应当被拒：%s", c.why)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("这个配置应当被放过（%s），实际：%v", c.why, err)
			}
		})
	}

	// 未启用 ACME 时这道检查必须什么都不做 —— 否则一个不打算用 ACME 的
	// 部署会因为「没监听 443」而起不来。
	if err := checkACMEReachable(nil, "", "", quietLog()); err != nil {
		t.Fatalf("未启用 ACME 时不该有任何要求：%v", err)
	}
}

// TestACMEHTTPChallengeListenerRedirectsNonChallengeTraffic 钉住备份路径的
// 兜底行为。
//
// 一个开着 80 的中继如果对普通请求回 404，用户会以为服务没起 ——
// 而他其实只是访问了错的协议。
func TestACMEHTTPChallengeListenerRedirectsNonChallengeTraffic(t *testing.T) {
	m := newTestACME(t)

	// 用 :0 拿一个随机端口：这里测的是处理器行为，不是端口号。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           m.HTTPChallengeHandler(redirectToHTTPS()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := cl.Get("http://" + ln.Addr().String() + "/some/page?a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("普通请求应当 301 到 https，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "https://") ||
		!strings.HasSuffix(loc, "/some/page?a=1") {
		t.Fatalf("重定向目标应当保留原路径与查询串，实际 %q", loc)
	}
}
