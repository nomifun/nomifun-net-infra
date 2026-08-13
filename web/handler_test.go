package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestAssetHandlerSetsAJavaScriptContentTypeForScripts 守护 nosniff 的另一半。
//
// 控制台的响应现在带 `X-Content-Type-Options: nosniff`（cmd/nfrelay 的
// consoleHandler 把 console.SecurityHeaders 包在最外层）。nosniff 的含义是
// **浏览器不再猜类型**：一个 Content-Type 不属于 JavaScript MIME 类型的
// /assets/*.js 会被直接拒绝执行。表现是控制台白屏，而服务端一切正常、
// 状态码全是 200 —— 没有任何服务端信号能指向它。
//
// 这条测试真正抓的是**类型按哪个名字算**。
// 删掉 handler 里那两行 h.Set("Content-Type", …) 它并不会全红，
// 因为 http.ServeContent 自己也会按传给它的 name 算一次 ——
// 那层兜底掩盖了删除。抓得住的是「按 r.URL.Path 的扩展名算」这种改法：
// 带 .js 后缀却命中 SPA 回退的请求会拿到一坨贴着 text/javascript 的 HTML。
func TestAssetHandlerSetsAJavaScriptContentTypeForScripts(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":       {Data: []byte(`<div id="root"></div>`)},
		"assets/app.js":    {Data: []byte("export const x = 1\n")},
		"assets/app.css":   {Data: []byte("body{}\n")},
		"theme-boot.js":    {Data: []byte("void 0\n")},
		"favicon.svg":      {Data: []byte(`<svg/>`)},
		"assets/app.js.br": {Data: []byte("\x1b\x00\x00brotli")},
	}
	h := AssetHandler(fsys)

	// JavaScript MIME 类型集合（WHATWG mimesniff §"JavaScript MIME type"）里
	// 我们可能碰到的那几个。不写死单个值：宿主的 mime.types 里 .js 映射成
	// application/javascript 也是合法的，那不该让测试红。
	jsOK := func(ct string) bool {
		ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
		switch ct {
		case "text/javascript", "application/javascript",
			"application/x-javascript", "text/ecmascript",
			"application/ecmascript", "module":
			return true
		}
		return false
	}

	for _, tc := range []struct {
		path string
		want func(string) bool
		desc string
	}{
		{"/assets/app.js", jsOK, "JavaScript MIME 类型"},
		{"/theme-boot.js", jsOK, "JavaScript MIME 类型"},
		{"/assets/app.css", func(ct string) bool {
			return strings.HasPrefix(ct, "text/css")
		}, "text/css"},
		{"/index.html", func(ct string) bool {
			return strings.HasPrefix(ct, "text/html")
		}, "text/html"},
		{"/tunnels/deep/link", func(ct string) bool {
			return strings.HasPrefix(ct, "text/html")
		}, "text/html（SPA 回退）"},
		// 关键一例：一个**带 .js 扩展名**却命中 SPA 回退的路径。
		// 现实里它天天发生 —— 升级后旧标签页还在请求上一版的
		// /assets/index-OLD.js，回退把 index.html 发了回去。
		// 类型必须按**实际发出的文件**算，不能按请求路径的扩展名算：
		// 后者会给一坨 HTML 贴上 text/javascript，nosniff 之下浏览器
		// 直接拒收，而状态码是 200、日志里什么都看不出来。
		{"/assets/index-STALE.js", func(ct string) bool {
			return strings.HasPrefix(ct, "text/html")
		}, "text/html（带 .js 扩展名的 SPA 回退）"},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d，期望 200", tc.path, w.Code)
			continue
		}
		// 读 Result().Header 而不是 w.Header()：后者是那张活的 map，
		// 「Set 挪到写响应体之后」这种改法在它眼里照样是绿的，
		// 而线上浏览器一个头都收不到。同一条理由见
		// internal/console/server.go 的 SecurityHeaders。
		if ct := w.Result().Header.Get("Content-Type"); !tc.want(ct) {
			t.Errorf("GET %s：Content-Type = %q，期望 %s —— nosniff 下浏览器会拒收",
				tc.path, ct, tc.desc)
		}
	}
}

// TestPrecompressedVariantKeepsTheOriginalContentType 守护预压缩路径。
//
// 发 app.js.br 时 Content-Type 必须仍是 JavaScript（类型来自 app.js），
// 而不是 .br 的类型或空。这条单独写，因为预压缩走的是 io.Copy 分支 ——
// 它绕开了 http.ServeContent，也就绕开了 Go 的类型嗅探兜底：
// 这里一旦不设类型，就是**真的什么都没有**，nosniff 之下必然白屏。
func TestPrecompressedVariantKeepsTheOriginalContentType(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":       {Data: []byte(`<div id="root"></div>`)},
		"assets/app.js":    {Data: []byte("export const x = 1\n")},
		"assets/app.js.br": {Data: []byte("BROTLI-BYTES")},
	}
	h := AssetHandler(fsys)

	r := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	r.Header.Set("Accept-Encoding", "br, gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Result().Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding = %q，期望 br（预压缩协商没生效，本测试没测到目标分支）", got)
	}
	if w.Body.String() != "BROTLI-BYTES" {
		t.Fatalf("发的不是 .br 变体：%q", w.Body.String())
	}
	ct := strings.ToLower(w.Result().Header.Get("Content-Type"))
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q，期望 JavaScript 类型", ct)
	}
}
