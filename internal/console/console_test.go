package console

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func newTestServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith 造一个可改 Options 的控制台。
//
// mutate 为 nil 时与 newTestServer 等价。抽出来是因为有些行为只在**非默认**
// Options 下才存在（比如 HSTS 挂在 Secure 上），而那些分支正是最容易变成
// 零覆盖死代码的地方 —— 没有这个接缝就只能不测。
func newTestServerWith(t *testing.T, mutate func(*Options)) (*Server, *store.DB) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	opts := Options{DB: db, Log: quiet, Snapshot: &fakeSnapshot{}}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

type fakeSnapshot struct {
	applyErr error
	applied  int
}

func (f *fakeSnapshot) Snapshot() Snapshot {
	return Snapshot{RelayVersion: "test", Agents: []AgentStatus{}, Tunnels: []TunnelStatus{}}
}
func (f *fakeSnapshot) IssueEnrolToken(time.Duration, string) (string, string, error) {
	return "nf_enrol_test", "nfagent -relay x -pin y -token nf_enrol_test", nil
}
func (f *fakeSnapshot) ApplyTunnels() error { f.applied++; return f.applyErr }

// req 构造一个带正确 Host 的请求。
func req(method, path string, body any) *http.Request {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "127.0.0.1:9443"
	return r
}

// setupAndLogin 完成首启并返回一个已认证的请求装饰器。
func setupAndLogin(t *testing.T, s *Server) func(*http.Request) *http.Request {
	t.Helper()

	r := req(http.MethodPost, "/api/setup", setupRequest{
		Username: "admin", Password: "a-very-long-password",
	})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("首启失败：%d %s", w.Code, w.Body.String())
	}

	var lr LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &lr); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("首启后应当下发会话 Cookie")
	}

	return func(r *http.Request) *http.Request {
		for _, c := range cookies {
			r.AddCookie(c)
		}
		r.Header.Set(CSRFHeaderName, lr.CSRFToken)
		r.Header.Set("Origin", "http://127.0.0.1:9443")
		return r
	}
}

// TestHostCheckBlocksDNSRebinding 是最重要的一条安全断言。
//
// 不校验 Host 的话，攻击者可以让恶意页面用一个解析到 127.0.0.1 的域名
// 访问 loopback 上的控制台，浏览器会自动带上 Cookie —— 一个「只监听本机
// 所以很安全」的控制台就这样被接管了。frp 完全没有这个检查。
func TestHostCheckBlocksDNSRebinding(t *testing.T) {
	s, _ := newTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/api/setup", nil)
	r.Host = "evil.attacker.example" // 解析到 127.0.0.1 的恶意域名
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("状态码 = %d，期望 421（可疑 Host 必须被拒）", w.Code)
	}
}

func TestHostCheckAllowsLoopbackAndConfigured(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "h.db"), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	s, err := New(Options{
		DB: db, Log: quiet,
		AllowedHosts: []string{"relay.example.com"},
		BindAddr:     "10.0.0.5:9443",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{
		"127.0.0.1:9443", "localhost:9443", "relay.example.com",
		"relay.example.com:443", "10.0.0.5:9443",
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/setup", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code == http.StatusMisdirectedRequest {
			t.Errorf("Host %q 应当被放行", host)
		}
	}
}

// TestSetupCanOnlyRunOnce 防止「管理员创建后再被别人覆盖」。
func TestSetupCanOnlyRunOnce(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/setup", setupRequest{
		Username: "attacker", Password: "another-long-password",
	}))
	if w.Code != http.StatusConflict {
		t.Fatalf("状态码 = %d，期望 409（首启只能做一次）", w.Code)
	}
}

// TestSetupRejectsWeakAndEmptyCredentials 对着 frp 的漏洞设计。
//
// frp 的中间件在用户名密码双空时**放行一切**（pkg/util/net/http.go:48），
// 而校验从不要求填凭据 —— 于是 `webServer.port = 7500` 一行就得到一个
// 监听 0.0.0.0 的无鉴权控制台。
func TestSetupRejectsWeakAndEmptyCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username string
		password string
	}{
		{"空用户名", "", "a-very-long-password"},
		{"空密码", "admin", ""},
		{"双空（frp 的漏洞形态）", "", ""},
		{"密码过短", "admin", "short"},
		{"密码刚好差一位", "admin", strings.Repeat("x", MinPasswordLen-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/setup", setupRequest{
				Username: tc.username, Password: tc.password,
			}))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("状态码 = %d，期望 400；弱凭据必须被拒", w.Code)
			}
			// 且不该创建任何管理员。
			var st SetupState
			w2 := httptest.NewRecorder()
			s.Handler().ServeHTTP(w2, req(http.MethodGet, "/api/setup", nil))
			json.Unmarshal(w2.Body.Bytes(), &st)
			if !st.NeedsSetup {
				t.Error("被拒的首启不该留下管理员记录")
			}
		})
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s) // 已有管理员，但下面的请求不带 Cookie

	for _, path := range []string{
		"/api/snapshot", "/api/tunnels", "/api/agents", "/api/events/recent",
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s 未认证时状态码 = %d，期望 401", path, w.Code)
		}
	}
}

// TestCSRFRequiredForMutations 验证双提交 + Origin 检查。
func TestCSRFRequiredForMutations(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	body := &tunnel.Tunnel{
		Slug:    "csrf-test",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}

	t.Run("缺少 CSRF 头", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/tunnels", body))
		r.Header.Del(CSRFHeaderName)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码 = %d，期望 403", w.Code)
		}
	})

	t.Run("CSRF 头不匹配", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/tunnels", body))
		r.Header.Set(CSRFHeaderName, "wrong-token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码 = %d，期望 403", w.Code)
		}
	})

	t.Run("缺少 Origin", func(t *testing.T) {
		// 只做双提交是不够的：能写 Cookie 的子域攻击者可以同时设置两边。
		// Origin 检查才形成有效防线。
		r := auth(req(http.MethodPost, "/api/tunnels", body))
		r.Header.Del("Origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码 = %d，期望 403", w.Code)
		}
	})

	t.Run("Origin 是外部站点", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/tunnels", body))
		r.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码 = %d，期望 403", w.Code)
		}
	})

	t.Run("GET 不需要 CSRF", func(t *testing.T) {
		r := auth(req(http.MethodGet, "/api/tunnels", nil))
		r.Header.Del(CSRFHeaderName)
		r.Header.Del("Origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("状态码 = %d，期望 200（读请求不需要 CSRF）", w.Code)
		}
	})
}

func TestLoginDoesNotLeakUsernameExistence(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	var codes []int
	var msgs []string
	for _, c := range []loginRequest{
		{Username: "admin", Password: "wrong-password-here"},
		{Username: "nonexistent", Password: "wrong-password-here"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/login", c))
		codes = append(codes, w.Code)
		var e APIError
		json.Unmarshal(w.Body.Bytes(), &e)
		msgs = append(msgs, e.Message)
	}
	if codes[0] != codes[1] {
		t.Errorf("状态码不同（%v）—— 会泄露用户名是否存在", codes)
	}
	if msgs[0] != msgs[1] {
		t.Errorf("错误信息不同（%q vs %q）—— 会变成用户名枚举接口", msgs[0], msgs[1])
	}
}

func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	// 被盗会话不该能直接改密锁定账号。
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/password",
		changePasswordRequest{Current: "wrong", New: "new-long-password-x"})))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d，期望 401", w.Code)
	}

	// 正确的旧密码则允许。
	w2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w2, auth(req(http.MethodPost, "/api/password",
		changePasswordRequest{Current: "a-very-long-password", New: "new-long-password-x"})))
	if w2.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200：%s", w2.Code, w2.Body.String())
	}
}

// ── 隧道 CRUD ───────────────────────────────────────────────────────────────

func TestTunnelCRUD(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	body := &tunnel.Tunnel{
		Slug:       "my-api",
		ListenPort: 9090,
		Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}

	// 创建
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels", body)))
	if w.Code != http.StatusOK {
		t.Fatalf("创建失败：%d %s", w.Code, w.Body.String())
	}
	var created tunnel.Tunnel
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("应当自动生成 ID")
	}

	// 列表
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/tunnels", nil)))
	var list []tunnel.Tunnel
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("列表返回 %d 条，期望 1", len(list))
	}

	// 更新
	created.Backend.Addr = "127.0.0.1:9999"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPut, "/api/tunnels/"+created.ID, &created)))
	if w.Code != http.StatusOK {
		t.Fatalf("更新失败：%d %s", w.Code, w.Body.String())
	}

	// 删除
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodDelete, "/api/tunnels/"+created.ID, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("删除失败：%d %s", w.Code, w.Body.String())
	}

	// 再取应当 404
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/tunnels/"+created.ID, nil)))
	if w.Code != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404", w.Code)
	}
}

// TestUpdateCannotChangeIDViaBody 防越权：请求体里的 ID 不得覆盖 URL 里的。
func TestUpdateCannotChangeIDViaBody(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	for i, slug := range []string{"first", "second"} {
		tn := &tunnel.Tunnel{
			ID: "t-" + slug, Slug: slug, ListenPort: uint16(9100 + i),
			Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		}
		tn.Complete()
		if err := db.PutTunnel(t.Context(), tn); err != nil {
			t.Fatal(err)
		}
	}

	// 用 t-first 的 URL，但请求体里写 t-second 的 ID。
	payload := &tunnel.Tunnel{
		ID: "t-second", Slug: "first", ListenPort: 9100,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:7777"},
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPut, "/api/tunnels/t-first", payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("更新失败：%d %s", w.Code, w.Body.String())
	}

	// t-second 必须未被改动。
	second, err := db.GetTunnel(t.Context(), "t-second")
	if err != nil {
		t.Fatal(err)
	}
	if second.Backend.Addr == "127.0.0.1:7777" {
		t.Error("请求体里的 ID 覆盖了 URL —— 这是一个越权改写漏洞")
	}
}

// TestUnknownFieldsInConfigAreRejected 验证配置输入严格。
//
// 这与线协议恰好相反：线上要容忍未知字段以便演进，而配置里的未知字段
// 几乎总是拼写错误，静默忽略会让用户以为自己设置了某个选项。
func TestUnknownFieldsInConfigAreRejected(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	raw := `{"slug":"typo-test","listen_prot":9090,` + // 故意拼错 listen_port
		`"backend":{"kind":"addr","addr":"127.0.0.1:8080"}}`
	r := auth(req(http.MethodPost, "/api/tunnels", nil))
	r.Body = io.NopCloser(strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d，期望 400；配置里的拼写错误必须报错而不是静默忽略", w.Code)
	}
}

// TestValidateEndpointIsDryRun 验证 dry-run 不写库。
//
// 这修的是 frp store API 的缺陷：控制台接受一个中继后来会拒绝的配置，
// 表现为隧道进 error 相而不是写入时 400。
func TestValidateEndpointIsDryRun(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	good := &tunnel.Tunnel{
		Slug: "dry-run", ListenPort: 9200,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels:validate", good)))
	if w.Code != http.StatusOK {
		t.Fatalf("合法定义校验应当通过：%d %s", w.Code, w.Body.String())
	}

	// 不该写进库。
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/tunnels", nil)))
	var list []tunnel.Tunnel
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Error("validate 是 dry-run，不该写库")
	}
}

// TestValidationReturnsPerFieldErrors 验证一次返回全部坏字段。
func TestValidationReturnsPerFieldErrors(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	bad := &tunnel.Tunnel{
		Slug:     "Bad Slug!",
		Exposure: tunnel.ExposureShared, // 缺 router
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr},
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels:validate", bad)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d，期望 400", w.Code)
	}
	var e APIError
	json.Unmarshal(w.Body.Bytes(), &e)
	if len(e.Fields) < 2 {
		t.Errorf("只返回 %d 个字段错误，期望 ≥2（要让前端一次高亮全部坏字段）：%+v",
			len(e.Fields), e)
	}
}

func TestDuplicateSlugReturns409(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	mk := func(port uint16) *tunnel.Tunnel {
		return &tunnel.Tunnel{
			Slug: "dup", ListenPort: port,
			Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels", mk(9300))))
	if w.Code != http.StatusOK {
		t.Fatalf("首次创建失败：%s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels", mk(9301))))
	if w.Code != http.StatusConflict {
		t.Fatalf("状态码 = %d，期望 409", w.Code)
	}
}

func TestApplyFailureIsReportedNotSwallowed(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "a.db"), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	fake := &fakeSnapshot{applyErr: errListenFailed{}}
	s, err := New(Options{DB: db, Log: quiet, Snapshot: fake})
	if err != nil {
		t.Fatal(err)
	}
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels", &tunnel.Tunnel{
		Slug: "apply-fail", ListenPort: 9400,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	})))
	// 运行时应用失败必须如实报出，不能假装成功 ——
	// 否则用户以为隧道通了，实际端口根本没绑上。
	if w.Code != http.StatusConflict {
		t.Fatalf("状态码 = %d，期望 409（应用失败要如实报告）", w.Code)
	}
	if !strings.Contains(w.Body.String(), "运行时应用失败") {
		t.Errorf("响应应说明是运行时应用失败：%s", w.Body.String())
	}
}

type errListenFailed struct{}

func (errListenFailed) Error() string { return "端口已被占用" }

// ── 入网令牌与 SSE ──────────────────────────────────────────────────────────

func TestIssueEnrolTokenReturnsCopyableCommand(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/enrol-tokens",
		enrolTokenRequest{Note: "家里的桌面"})))
	if w.Code != http.StatusOK {
		t.Fatalf("签发失败：%d %s", w.Code, w.Body.String())
	}
	var resp EnrolTokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Error("应返回明文令牌")
	}
	// 「可复制的一行命令」是首启体验的核心：frp 完全没有 onboarding，
	// 新用户必须读 README 并手写 TOML。
	if !strings.Contains(resp.InstallCmd, "nfagent") || !strings.Contains(resp.InstallCmd, resp.Token) {
		t.Errorf("安装命令应当可直接复制且含令牌：%q", resp.InstallCmd)
	}
	if resp.ExpiresAt.IsZero() {
		t.Error("应返回过期时间")
	}
}

func TestHealthzIsUnauthenticatedAndLeaksNothing(t *testing.T) {
	s, _ := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200（探针拿不到凭据）", w.Code)
	}
	// 不该泄露版本、隧道数之类的内部信息。
	body := w.Body.String()
	for _, leak := range []string{"version", "tunnel", "agent"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("/healthz 泄露了内部信息 %q：%s", leak, body)
		}
	}
}

// TestEventHubNeverBlocks 是 SSE 的核心法则验证。
//
// 慢客户端不能拖慢中继。队列满了就丢弃并计数，与数据面同一条法则。
// frp 的下行 UDP 队列满时会阻塞（server/proxy/udp.go:140），
// 那个错误在这里绝不重复。
func TestEventHubNeverBlocks(t *testing.T) {
	hub := newEventHub(slog.New(slog.NewTextHandler(io.Discard, nil)))
	id, sub := hub.subscribe()
	defer hub.unsubscribe(id)

	// 灌远超队列深度的事件，且**完全不消费**。
	const flood = subscriberQueueDepth * 10
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range flood {
			hub.publish(Event{Type: EventMetric, Data: map[string]int{"i": i}})
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publish 阻塞了 —— 一个慢客户端就能拖垮中继")
	}

	if got := sub.dropped.Load(); got == 0 {
		t.Error("应当有丢弃计数 —— 静默丢弃才是真正的问题")
	}
	if len(sub.ch) > subscriberQueueDepth {
		t.Errorf("队列长度 %d 超过深度上限 %d", len(sub.ch), subscriberQueueDepth)
	}
}

func TestSSEStreamSendsHelloThenEvents(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	r := auth(req(http.MethodGet, "/api/events", nil))
	ctx, cancel := contextWithTimeout(t, 2*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	rec := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Handler().ServeHTTP(rec, r)
	}()

	// 等 hello 帧。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), "event: "+EventHello) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.String(), "event: "+EventHello) {
		t.Fatalf("未收到 hello 帧：%q", rec.String())
	}
	// hello 必须带服务器时间：排查「图表时间轴不对」时第一个要看的东西。
	if !strings.Contains(rec.String(), "server_time") {
		t.Error("hello 帧应含 server_time")
	}

	s.hub.publish(Event{Type: EventState, Data: map[string]string{"tunnel": "t-x"}})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), "event: "+EventState) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.String(), "event: "+EventState) {
		t.Errorf("未收到 state 事件：%q", rec.String())
	}
	// SSE 帧必须带 id，客户端断线重连才能带 Last-Event-ID。
	if !strings.Contains(rec.String(), "id: ") {
		t.Error("SSE 帧应带 id 字段")
	}

	cancel()
	<-done
}

// TestSecurityHeadersArePresent 只覆盖本包的路由。
//
// 控制台监听器上还有一个 `/`（内嵌 SPA），它在 Handler() 外面 ——
// 那一半的判据在 cmd/nfrelay 的
// TestSecurityHeadersCoverTheSPAAndNotOnlyJSON，别以为这条绿了就够了。
func TestSecurityHeadersArePresent(t *testing.T) {
	s, _ := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/api/setup", nil))

	// 读 Result().Header（WriteHeader 时刻的快照）而不是 w.Header()：
	// 后者是活 map，中间件在 next.ServeHTTP **之后**才 Set 也照样看得见，
	// 而真实的 net/http 那时早把头发走了。读 w.Header() 会让
	// 「顺序写反」这个改法保持绿色，线上却一个安全头都没有。
	got := w.Result().Header

	for h, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if v := got.Get(h); v != want {
			t.Errorf("%s = %q，期望 %q", h, v, want)
		}
	}
	if csp := got.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP 缺少 frame-ancestors：%q", csp)
	}
}

// TestHSTSOnlyShipsWhenTheConsoleIsServedOverTLS 让 HSTS 那条分支不再是死代码。
//
// # 为什么单独写这一条
//
// SecurityHeaders 里 HSTS 挂在 `if s.secure` 下，而 Options.Secure 目前
// **没有任何生产调用点会赋值**（cmd/nfrelay 构造 Options 时不传它）。
// 也就是说那一行今天零覆盖：既没人证明它在该发时发得出来，
// 也没人证明它在不该发时不发。零覆盖的安全分支会以两种方式坏掉而无人知晓
// —— 要么将来接线时发现它压根不工作，要么被当成死代码删掉。
//
// # 为什么「不该发时不发」这一半同样要断言
//
// 控制台默认是明文 loopback。在明文端口上下发 HSTS 本身不会被浏览器采纳
// （RFC 6797 §8.1：经非安全传输收到的 STS 头必须忽略），所以它不会把主机名
// 钉死 —— 但它会让运维在抓包里看到一个与实际传输矛盾的头，
// 排查「为什么浏览器不肯用 HTTP 打开」时多绕一圈。
func TestHSTSOnlyShipsWhenTheConsoleIsServedOverTLS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
		want   bool
	}{
		{"明文（默认形态）", false, false},
		{"经 TLS 提供", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServerWith(t, func(o *Options) { o.Secure = tc.secure })
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req(http.MethodGet, "/api/setup", nil))

			got := w.Result().Header.Get("Strict-Transport-Security")
			if tc.want && got == "" {
				t.Error("经 TLS 提供时必须下发 HSTS —— 这条分支今天没有任何" +
					"生产调用点会赋值 Secure，没有断言它就是死代码")
			}
			if !tc.want && got != "" {
				t.Errorf("明文形态不该下发 HSTS，实际 %q", got)
			}
		})
	}
}

// TestHealthFrameIsARealEventNotAComment 守护一个联调时暴露的缺陷。
//
// 我原本把丢帧数写进 SSE 的**注释行**（`: heartbeat dropped=N`），
// 但 `EventSource` 按规范看不见注释 —— 前端拿不到它，
// 那个「流健康点」就成了恒为 0 的死指标。
//
// 所以丢帧数必须走一个真实的 `event: health` 帧。
func TestHealthFrameIsARealEventNotAComment(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	// 把心跳间隔临时改短，否则这个测试要等 15 秒。
	orig := heartbeatIntervalForTest
	heartbeatIntervalForTest = 80 * time.Millisecond
	defer func() { heartbeatIntervalForTest = orig }()

	r := auth(req(http.MethodGet, "/api/events", nil))
	ctx, cancel := contextWithTimeout(t, 3*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	rec := newStreamRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.Handler().ServeHTTP(rec, r) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), "event: "+EventHealth) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	body := rec.String()
	cancel()
	<-done

	if !strings.Contains(body, "event: "+EventHealth) {
		t.Fatalf("未收到 health 事件帧（丢帧数只在注释里的话前端读不到）：%q", body)
	}
	if !strings.Contains(body, `"dropped"`) {
		t.Error("health 帧应含 dropped 字段")
	}
	// 注释行仍应存在（它负责保活），但不再是丢帧数的唯一载体。
	if !strings.Contains(body, ": keepalive") {
		t.Error("应保留一个注释行做保活，防中间盒掐连接")
	}
}

// fullSnapshot 是一个实现了全部可选接口的假运行时。
//
// 分开一个类型而不是往 fakeSnapshot 上堆：那个类型被很多测试共用，
// 让它突然实现 AgentKicker 会改变那些测试里「不支持该能力」的分支。
type fullSnapshot struct {
	fakeSnapshot
	kicked   []string
	kickOK   bool
	probeRes ProbeResult
}

func (f *fullSnapshot) KickAgent(id string) bool {
	f.kicked = append(f.kicked, id)
	return f.kickOK
}

func (f *fullSnapshot) Settings() []SettingsGroup {
	return []SettingsGroup{{
		Group: "listeners",
		Items: []SettingItem{{
			Key: "bind", Value: "0.0.0.0:8443",
			Provenance: ProvenanceEnv, SourceRef: "-bind", Editable: false,
		}},
	}}
}

func (f *fullSnapshot) ProbeTunnel(context.Context, *tunnel.Tunnel) ProbeResult {
	return f.probeRes
}

func newFullServer(t *testing.T) (*Server, *store.DB, *fullSnapshot) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	snap := &fullSnapshot{kickOK: true}
	s, err := New(Options{DB: db, Log: quiet, Snapshot: snap, Settings: snap})
	if err != nil {
		t.Fatal(err)
	}
	return s, db, snap
}

func TestVerbEndpointsAreRoutedNotSwallowedByStdlib404(t *testing.T) {
	// Go 的 ServeMux **不接受通配符不占满整个路径段**：注册
	// "POST /api/tunnels/{id}:test" 会在 pattern 解析时 panic
	//（net/http/pattern.go 的 "bad wildcard segment"）。而 routes() 是在
	// console.New() 里调用的 —— 于是中继**直接起不来**，不是返回 404。
	//
	// 所以动词在处理器里切。这条测试钉住两件事：注册不 panic
	//（能构造出 Server 就说明了），以及动词端点真的被路由到 ——
	// 判据是「不是 stdlib 的 404 text/plain」，因为前端正是靠那个响应
	// 显示「中继还没实现这个接口」。
	s, _, _ := newFullServer(t)
	auth := setupAndLogin(t, s)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/tunnels/t-nope:test"},
		{http.MethodPost, "/api/agents/a-nope:kick"},
		{http.MethodPost, "/api/tunnels:preview"},
		{http.MethodGet, "/api/settings"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, auth(req(tc.method, tc.path, nil)))
			ct := w.Header().Get("Content-Type")
			if w.Code == http.StatusNotFound && strings.HasPrefix(ct, "text/plain") {
				t.Fatalf("路由没注册：拿到了 stdlib 的 404 text/plain")
			}
		})
	}
}

func TestUnknownVerbIsDistinguishableFromMissingEndpoint(t *testing.T) {
	// 前端靠「404 且 code=='http_404'」判断「端点不存在」，而 http_404 是它在
	// body 解析不出 JSON 时的兜底。所以「端点存在但动词不对」必须回一个
	// **结构化** JSON 错误，否则界面会显示成「中继还没实现这个接口」——
	// 那会让人去查版本，而问题其实在请求本身。
	s, _, _ := newFullServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/agents/a-1:frobnicate", nil)))

	if w.Code != http.StatusNotFound {
		t.Fatalf("未知动词应当回 404，实际 %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("必须是结构化 JSON（否则被误读成「端点不存在」），实际 %s", ct)
	}
	var body struct{ Code, Message string }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code == "http_404" {
		t.Fatal("code 不能是 http_404 —— 那是前端判断「端点不存在」的值")
	}
	if !strings.Contains(body.Message, "frobnicate") {
		t.Errorf("错误信息应当点明是哪个动词，实际：%s", body.Message)
	}
}

func TestKickAgentIsAuditedAsAConnectionLevelActionNotARevocation(t *testing.T) {
	// 踢是**连接层**操作：agent 会立刻按退避重连。事件文案必须与撤销能
	// 区分，否则用户以为踢了就永久生效，然后在它十秒后重新上线时
	// 以为功能坏了。
	s, db, snap := newFullServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/agents/a-42:kick", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("踢下线应当成功，实际 %d %s", w.Code, w.Body.String())
	}
	if len(snap.kicked) != 1 || snap.kicked[0] != "a-42" {
		t.Fatalf("应当把 a-42 踢下线，实际 %v", snap.kicked)
	}

	events, err := db.ListEvents(context.Background(), 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.Event
	for i := range events {
		if events[i].Kind == store.KindAgentKicked {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatal("踢下线必须留痕 —— 那是一次运维动作，事后要能追溯谁做的")
	}
	if found.Actor == "" {
		t.Error("事件必须记下操作者")
	}
	// 文案要明说「会自动重连」，否则用户会以为这是永久封禁。
	if !strings.Contains(found.Message, "重连") {
		t.Errorf("事件文案应当说明代理端会自动重连，实际：%s", found.Message)
	}
	if found.Kind == store.KindAgentRevoked {
		t.Error("踢下线不能用撤销的事件种类 —— 两者的持久性完全不同")
	}
}

func TestKickAgentReports409WhenThereIsNoLiveSession(t *testing.T) {
	// 「没踢到」不是 404：库里有这个 agent，只是它现在不在线。
	// 回 404 会让界面显示「找不到这个代理端」，那是错的诊断。
	s, _, snap := newFullServer(t)
	snap.kickOK = false
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/agents/a-1:kick", nil)))
	if w.Code != http.StatusConflict {
		t.Fatalf("没有活会话时应当回 409，实际 %d", w.Code)
	}
}

func TestPreviewProducesBothConfigSides(t *testing.T) {
	// 前端把两个字段都无条件渲染进 CopyBlock，所以**两个都不能省**。
	s, _, _ := newFullServer(t)
	auth := setupAndLogin(t, s)

	draft := map[string]any{
		"slug": "web", "exposure": "shared", "tls": "gateway",
		"router": map[string]any{
			"kind": "http", "domains": []string{"a.example.com"}, "host_rewrite": "127.0.0.1",
		},
		"backend": map[string]any{"kind": "addr", "addr": "127.0.0.1:8080"},
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels:preview", draft)))
	if w.Code != http.StatusOK {
		t.Fatalf("预览应当成功，实际 %d：%s", w.Code, w.Body.String())
	}

	var body struct {
		AgentYAML string `json:"agent_yaml"`
		RelayYAML string `json:"relay_yaml"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AgentYAML == "" || body.RelayYAML == "" {
		t.Fatal("两个字段都必须有内容 —— 前端会把它们都渲染出来")
	}
	// 预览的价值在**可核对**，所以关键字段必须真的出现在里面。
	for _, want := range []string{"web", "a.example.com", "127.0.0.1:8080", "host_rewrite"} {
		if !strings.Contains(body.RelayYAML, want) {
			t.Errorf("中继侧预览应当包含 %q，实际：\n%s", want, body.RelayYAML)
		}
	}
	if !strings.Contains(body.AgentYAML, "nfagent -relay") {
		t.Error("agent 侧预览应当给出可复制的启动命令")
	}
}

func TestSettingsReportsProvenanceForEveryItem(t *testing.T) {
	// 「显示生效值」只回答了一半。用户真正要问的是「为什么是这个值」——
	// 不给来源，一个「监听地址是 0.0.0.0」的显示就无法判断该去改哪里。
	s, _, _ := newFullServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/settings", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("应当成功，实际 %d", w.Code)
	}

	var body struct {
		Groups []SettingsGroup `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Groups) == 0 {
		t.Fatal("至少要有一组配置")
	}
	// group 的取值是**规范性**的：前端 locale 只翻了这几个，
	// 其他值会原样显示成一个英文标识符。
	valid := map[string]bool{
		"listeners": true, "tls": true, "auth": true,
		"retention": true, "backup": true, "other": true,
	}
	for _, g := range body.Groups {
		if !valid[g.Group] {
			t.Errorf("group %q 不在规格定义的取值内，界面会原样显示英文标识符", g.Group)
		}
		for _, it := range g.Items {
			if it.Provenance == "" {
				t.Errorf("%s/%s 没有来源 —— 那让「为什么是这个值」无法回答", g.Group, it.Key)
			}
		}
	}
}

func TestSettingsSaysNotImplementedWhenNoSourceIsWired(t *testing.T) {
	// 没装配来源时必须如实回「未实现」，而不是回一个空 groups ——
	// 空列表会让用户以为「中继没有任何配置」，然后去别处找。
	s, _ := newTestServer(t) // 这个夹具**不**装配 Settings
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/settings", nil)))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("未装配配置视图时应当回 501，实际 %d：%s", w.Code, w.Body.String())
	}
}

func TestProbeAlwaysHasAFailedStepWhenItReportsFailure(t *testing.T) {
	// 前端的失败结论是「第一个 ok=false 的 step」，取不到时会退化显示成
	// 第一跳（listener_bound）。所以 ok=false 而所有 step 都 ok=true 是
	// 一个**会误导用户**的响应：它会把故障点指到一个其实正常的环节。
	s, db, snap := newFullServer(t)
	auth := setupAndLogin(t, s)

	tn := &tunnel.Tunnel{
		ID: "t-1", Slug: "svc",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:1"},
	}
	tn.Complete()
	if err := db.PutTunnel(context.Background(), tn); err != nil {
		t.Fatal(err)
	}

	// 运行时返回一个自相矛盾的结果：整体失败但每一跳都成功。
	snap.probeRes = ProbeResult{
		OK: false,
		Steps: []ProbeStep{
			{Hop: HopListenerBound, OK: true},
			{Hop: HopAgentReachable, OK: true},
		},
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels/t-1:test", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("探测应当成功返回，实际 %d：%s", w.Code, w.Body.String())
	}

	var res ProbeResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("整体结论应当是失败")
	}
	var failed bool
	for _, st := range res.Steps {
		if !st.OK {
			failed = true
		}
	}
	if !failed {
		t.Fatal("ok=false 时必须至少有一步 ok=false —— " +
			"否则界面会把故障点指到一个其实正常的环节")
	}
}

func TestProbeNeverClaimsToHaveTestedFromTheInternet(t *testing.T) {
	// 从外网视角复测需要一个外部回声服务。中继自己去连自己的公网地址，
	// 在 NAT 回环失败的网络里会得出错误的「不通」结论 —— 那比不测更糟。
	// 所以 from_internet 恒为 false，即使请求里要求了。
	s, db, snap := newFullServer(t)
	auth := setupAndLogin(t, s)

	tn := &tunnel.Tunnel{
		ID: "t-1", Slug: "svc",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:1"},
	}
	tn.Complete()
	if err := db.PutTunnel(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	// 运行时**声称**测过外网 —— 处理器必须覆盖掉这个声明。
	snap.probeRes = ProbeResult{OK: true, FromInternet: true,
		Steps: []ProbeStep{{Hop: HopListenerBound, OK: true}}}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels/t-1:test",
		map[string]any{"from_internet": true})))

	var res ProbeResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.FromInternet {
		t.Fatal("from_internet 必须为 false —— 我们没有外部回声服务，不能声称测过")
	}
	// 而且要**说明**为什么没测，否则用户会以为勾选没生效。
	var explained bool
	for _, st := range res.Steps {
		if strings.Contains(st.Detail, "外网") {
			explained = true
		}
	}
	if !explained {
		t.Error("要求了外网复测却没做时，必须在步骤里说明原因")
	}
}

// fakeTurn 是 TurnSource 的测试实现。
type fakeTurn struct{ minted int }

func (f *fakeTurn) Allocations() []TurnAllocation { return nil }
func (f *fakeTurn) MintCredential(string, time.Duration) (any, error) {
	f.minted++
	return map[string]any{"ice_servers": []any{}}, nil
}

func TestTurnCredentialTTLIsCapped(t *testing.T) {
	// TURN 临时凭据**无法吊销**：校验方只做 HMAC-SHA1(secret, username)，
	// 而 username 里的时间戳就是它唯一的有效期。换 secret 会让所有在用的
	// 凭据一起失效（包括正在通话的），所以那不是一条可用的应急手段。
	//
	// 于是一张 ttl_seconds=3153600000 的凭据就是一张 100 年有效、
	// 谁都收不回来的中继通行证 —— 而它会被塞进浏览器的 RTCPeerConnection
	// 配置里，对任何能看 devtools 的人都是明文。
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	turn := &fakeTurn{}
	s, err := New(Options{DB: db, Log: quiet, Snapshot: &fakeSnapshot{}, Turn: turn})
	if err != nil {
		t.Fatal(err)
	}
	auth := setupAndLogin(t, s)

	post := func(ttl int) (int, string) {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/turn/credentials",
			turnCredentialRequest{UserID: "tenant", TTLSeconds: ttl})))
		return w.Code, w.Body.String()
	}

	// 100 年。
	code, body := post(3153600000)
	if code != http.StatusBadRequest {
		t.Fatalf("100 年有效期应当被拒，实际 %d：%s", code, body)
	}
	if !strings.Contains(body, "ttl_too_long") {
		t.Errorf("错误码应当是 ttl_too_long，实际：%s", body)
	}
	if turn.minted != 0 {
		t.Error("被拒的请求不该真的签发出一张凭据")
	}

	// 刚好在上限内的照常签发 —— 这道闸不能把正常用法一起关掉。
	code, body = post(int(MaxTurnCredentialTTL.Seconds()))
	if code != http.StatusOK {
		t.Fatalf("上限之内应当签发成功，实际 %d：%s", code, body)
	}
	if turn.minted != 1 {
		t.Errorf("应当签发 1 次，实际 %d", turn.minted)
	}
}

func TestCSRFCookieIsActuallyIssuedAndReadable(t *testing.T) {
	// CSRFCookieName 这个常量存在、前端也有 readCookie 兜底
	//（client.ts 的 `csrfToken || readCookie(CSRF_COOKIE)`），
	// 但服务端**从来没设过这个 Cookie** —— 于是那条兜底永远走不到，
	// 而它要兜的正是「刷新页面之后、/api/me 回来之前发出的写请求」。
	// 一个看起来存在的安全网，其实是空的。
	s, _ := newTestServer(t)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/setup", setupRequest{
		Username: "admin", Password: "a-very-long-password",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("首启失败：%d %s", w.Code, w.Body.String())
	}

	var csrf *http.Cookie
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case CSRFCookieName:
			csrf = c
		case s.sessionCookieName():
			session = c
		}
	}
	if csrf == nil {
		t.Fatal("必须下发 CSRF Cookie，否则前端那条 readCookie 兜底是空的")
	}
	if csrf.HttpOnly {
		t.Error("CSRF Cookie 必须 HttpOnly=false —— 前端要读它。" +
			"双提交的安全性来自同源策略（攻击者的页面读不到我们的 Cookie），" +
			"不来自「令牌本身保密」")
	}
	if csrf.SameSite != http.SameSiteStrictMode {
		t.Error("CSRF Cookie 也要 SameSite=Strict")
	}
	if csrf.Value == "" {
		t.Error("CSRF Cookie 的值不能是空的")
	}

	// 会话 Cookie 仍然必须是 HttpOnly —— 这两个的要求正好相反，
	// 一起断言才能防住「顺手把两个都改成一样」。
	if session == nil || !session.HttpOnly {
		t.Error("会话 Cookie 必须保持 HttpOnly=true")
	}

	// 拿 Cookie 里的值当 CSRF 头必须真的能通过校验（双提交的前提）。
	w2 := httptest.NewRecorder()
	r2 := req(http.MethodPost, "/api/tunnels", map[string]any{
		"slug":    "csrf-cookie-test",
		"backend": map[string]any{"kind": "addr", "addr": "127.0.0.1:8080"},
	})
	r2.AddCookie(session)
	r2.AddCookie(csrf)
	r2.Header.Set(CSRFHeaderName, csrf.Value)
	r2.Header.Set("Origin", "http://127.0.0.1:9443")
	s.Handler().ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK && w2.Code != http.StatusCreated {
		t.Fatalf("用 Cookie 里的令牌当 CSRF 头应当通过，实际 %d：%s",
			w2.Code, w2.Body.String())
	}
}
