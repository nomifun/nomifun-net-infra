package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/web"
)

func newTestConsoleHandler(t *testing.T) http.Handler {
	t.Helper()
	return newTestConsoleHandlerWith(t, nil)
}

// newTestConsoleHandlerWith 造一个可改 Options 的控制台处理器。
//
// 抽出来是因为有些行为只在**非默认** Options 下才存在（Host 白名单、
// 绑定地址），而那些分支正是最容易变成零覆盖死代码的地方。
func newTestConsoleHandlerWith(t *testing.T, mutate func(*console.Options)) http.Handler {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	db, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet})
	if err != nil {
		t.Fatalf("打开库失败：%v", err)
	}
	t.Cleanup(func() { db.Close() })
	opts := console.Options{DB: db, Log: quiet, BindAddr: "127.0.0.1:9443"}
	if mutate != nil {
		mutate(&opts)
	}
	cons, err := console.New(opts)
	if err != nil {
		t.Fatalf("构造控制台失败：%v", err)
	}
	return consoleHandler(cons)
}

func TestSecurityHeadersCoverTheSPAAndNotOnlyJSON(t *testing.T) {
	h := newTestConsoleHandler(t)

	for _, path := range []string{
		"/", "/index.html", "/theme-boot.js",
		"/tunnels/deep/link",
		"/assets/definitely-missing.js",
		"/healthz", "/api/setup",
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "127.0.0.1:9443"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		// **必须读 Result().Header，不能读 w.Header()。**
		// ResponseRecorder.Header() 是那张活的 map，中间件在
		// next.ServeHTTP 之后再往里塞头一样看得见 —— 而真实的
		// net/http 早在 WriteHeader 那一刻就把头发走了，之后的
		// Set 全部丢弃。读 w.Header() 的测试会在「中间件把
		// next.ServeHTTP 写在设置头之前」这种改法下**保持绿色**，
		// 而线上一个安全头都没有。Result() 读的是 WriteHeader
		// 时刻的快照，这才是浏览器实际收到的那一份。
		got := w.Result().Header

		for name, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if v := got.Get(name); v != want {
				t.Errorf("GET %s：%s = %q，期望 %q", path, name, v, want)
			}
		}
		csp := got.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s：CSP 缺少 frame-ancestors 'none'：%q", path, csp)
		}
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("GET %s：CSP 缺少 default-src 'self'：%q", path, csp)
		}
	}
}

func TestIndexHTMLIsTheThingThatCarriesTheCSP(t *testing.T) {
	if !web.Embedded() {
		t.Skip("noweb 构建：根路径是一句说明而不是 index.html")
	}
	h := newTestConsoleHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "127.0.0.1:9443"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d，期望 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<div id="root">`) {
		t.Fatalf("GET / 没返回 index.html：%q", body[:min(200, len(body))])
	}
	if csp := w.Result().Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("index.html 没有 CSP —— 这正是那个洞")
	}
}

func TestScriptSourcesStayLockedDown(t *testing.T) {
	h := newTestConsoleHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "127.0.0.1:9443"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	csp := w.Result().Header.Get("Content-Security-Policy")
	// 先断言它非空。少了这一句本测试在「CSP 根本没下发」时会**空转通过**：
	// 遍历一个空串找不到任何坏指令，于是绿 —— 一个在最糟情况下变绿的
	// 断言比没有断言更坏。
	if csp == "" {
		t.Fatal("GET / 没有 CSP，后面的收紧断言全是空转")
	}
	for _, dir := range strings.Split(csp, ";") {
		dir = strings.TrimSpace(dir)
		name, rest, _ := strings.Cut(dir, " ")
		if name != "default-src" && name != "script-src" && name != "script-src-elem" {
			continue
		}
		for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*"} {
			if strings.Contains(rest, bad) {
				t.Errorf("%s 出现 %s —— CSP 对 XSS 就不再有任何作用了：%q", name, bad, csp)
			}
		}
	}
}

// TestWrappingDoesNotBreakAssetCachingOrCompression 守的是「包装本身」。
//
// 安全头是包在 mux **外面**的一层 http.HandlerFunc。这类包装最容易悄悄弄坏
// 两件事：把响应体缓冲住（于是 Content-Length 变了、预压缩的 .br 字节被重新
// 编码），或者吃掉/覆盖下游设的头（Cache-Control、Content-Encoding）。
//
// web/handler_test.go 只在 AssetHandler **单独**一层上测过这些，
// 没有任何测试穿过 consoleHandler 的组合。而线上跑的正是组合。
// 不测的后果不是报错：控制台照样能用，只是每次刷新都重下 500 KiB 的 JS
// （immutable 丢了），或者浏览器收到一坨没标 Content-Encoding 的 brotli
// 字节（那时才是白屏）。
func TestWrappingDoesNotBreakAssetCachingOrCompression(t *testing.T) {
	if !web.Embedded() {
		t.Skip("noweb 构建：没有资源可发")
	}
	h := newTestConsoleHandler(t)

	// 从 index.html 里抠出真实的哈希资源名。写死名字会在每次改前端时红，
	// 而那种红与本测试要守的东西无关。
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "127.0.0.1:9443"
	h.ServeHTTP(w, r)
	m := regexp.MustCompile(`/assets/[A-Za-z0-9._-]+\.js`).FindString(w.Body.String())
	if m == "" {
		t.Fatalf("index.html 里找不到哈希资源名，本测试没测到目标：%q",
			w.Body.String()[:min(300, w.Body.Len())])
	}

	// 哈希资源必须 immutable；index.html 必须 no-cache。
	// 反了的后果是「升级后用户永远看到旧 SPA」。
	for _, tc := range []struct{ path, wantCache string }{
		{"/", "no-cache"},
		{m, "immutable"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.Host = "127.0.0.1:9443"
		h.ServeHTTP(w, r)
		got := w.Result().Header
		if cc := got.Get("Cache-Control"); !strings.Contains(cc, tc.wantCache) {
			t.Errorf("GET %s：Cache-Control = %q，期望含 %q", tc.path, cc, tc.wantCache)
		}
		// 顺带确认包装层没把安全头丢在这条路径上。
		if got.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s：包了缓存头却丢了 CSP", tc.path)
		}
	}

	// 预压缩协商必须穿过包装层活下来。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, m, nil)
	r.Host = "127.0.0.1:9443"
	r.Header.Set("Accept-Encoding", "br")
	h.ServeHTTP(w, r)
	res := w.Result()
	if enc := res.Header.Get("Content-Encoding"); enc != "br" {
		t.Errorf("GET %s（Accept-Encoding: br）：Content-Encoding = %q，期望 br —— "+
			"包装层把预压缩协商弄没了，每个请求都要现场再压一遍", m, enc)
	}
	if res.Header.Get("Content-Security-Policy") == "" {
		t.Error("预压缩分支丢了 CSP —— 它走的是 io.Copy 而不是 ServeContent，" +
			"是最容易被漏掉的那条出口")
	}
	if !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") {
		t.Error("缺 Vary: Accept-Encoding —— 中间缓存会把 br 响应喂给不支持它的客户端")
	}
}
