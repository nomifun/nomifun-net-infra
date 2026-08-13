package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSessionCookieRoundTripsUnderBothModes 钉住 __Host- 前缀最容易踩的那一处。
//
// `__Host-` 前缀是浏览器强制的加固（要求 Secure + Path=/ + 无 Domain，
// 因此子域无法覆盖它，挡住「子域接管」这一类会话固定攻击）。但它意味着
// **Cookie 的名字随模式变化** —— 而服务端读取时若用的是另一个名字，
// 会话会**立刻**失效：登录返回 200、下一个请求 401，两侧日志都显示成功。
//
// 这条测试走完整的「下发 → 带回来 → 被认出来」往返，两种模式各一次。
func TestSessionCookieRoundTripsUnderBothModes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secure     bool
		wantPrefix string
	}{
		{"明文（默认形态）", false, "nfr_session"},
		{"经 TLS 反代加固", true, "__Host-nfr_session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServerWith(t, func(o *Options) { o.Secure = tc.secure })

			// 首启并拿到 Cookie。
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/setup", setupRequest{
				Username: "admin", Password: "a-very-long-password",
			}))
			if w.Code != http.StatusOK {
				t.Fatalf("首启失败：%d %s", w.Code, w.Body.String())
			}

			var session *http.Cookie
			for _, c := range w.Result().Cookies() {
				if strings.Contains(c.Name, "nfr_session") {
					session = c
				}
			}
			if session == nil {
				t.Fatal("没有下发会话 Cookie")
			}
			if session.Name != tc.wantPrefix {
				t.Errorf("会话 Cookie 名 = %q，期望 %q", session.Name, tc.wantPrefix)
			}
			if session.Secure != tc.secure {
				t.Errorf("Secure = %v，期望 %v", session.Secure, tc.secure)
			}
			if !session.HttpOnly {
				t.Error("会话 Cookie 必须 HttpOnly")
			}
			// __Host- 前缀的浏览器强制要求：Path=/ 且**没有** Domain。
			if tc.secure {
				if session.Path != "/" {
					t.Errorf("__Host- 前缀要求 Path=/，实际 %q", session.Path)
				}
				if session.Domain != "" {
					t.Errorf("__Host- 前缀**不允许** Domain 属性，实际 %q —— "+
						"浏览器会直接丢掉这个 Cookie", session.Domain)
				}
			}

			// 关键的一半：把它带回来，服务端必须认出来。
			r := req(http.MethodGet, "/api/me", nil)
			r.AddCookie(session)
			w2 := httptest.NewRecorder()
			s.Handler().ServeHTTP(w2, r)
			if w2.Code != http.StatusOK {
				t.Fatalf("带着刚下发的 Cookie 请求 /api/me 得到 %d —— "+
					"写入与读取用的名字不一致，会话立刻失效（现象是登录 200、"+
					"下一个请求 401，而两侧日志都显示成功）", w2.Code)
			}
		})
	}
}

// TestCSRFCookieKeepsAStableNameAcrossModes 钉住一条**刻意的**不对称。
//
// 会话 Cookie 随模式改名（拿到 __Host- 的全部好处），而 CSRF Cookie **不改名**。
//
// 理由：CSRF Cookie 必须能被前端 JS 读取（双提交模式），而前端是按字面量
// 'nfr_csrf' 去找的（web/src/api/client.ts）。跟着改名就需要前端同时认两个名字，
// 而那是一处没有测试守着的跨语言耦合 —— 漏掉的后果是「刷新页面后第一个写请求
// 静默 403」。加固它能挡的攻击（子域覆盖 CSRF Cookie）在双提交下本来就不成立：
// 跨站请求无法设置自定义请求头，所以「头与 Cookie 相等」这个条件永远满足不了。
//
// Secure 属性仍然跟着模式走 —— 那一半没有跨语言耦合。
func TestCSRFCookieKeepsAStableNameAcrossModes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		s, _ := newTestServerWith(t, func(o *Options) { o.Secure = secure })
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, "/api/setup", setupRequest{
			Username: "admin", Password: "a-very-long-password",
		}))

		var csrf *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == CSRFCookieName {
				csrf = c
			}
		}
		if csrf == nil {
			t.Fatalf("secure=%v：没有下发 CSRF Cookie（名字必须恒为 %q，"+
				"前端按字面量找它）", secure, CSRFCookieName)
		}
		if csrf.HttpOnly {
			t.Error("CSRF Cookie 必须可被脚本读取（双提交模式），HttpOnly 会让它没用")
		}
		if csrf.Secure != secure {
			t.Errorf("secure=%v：CSRF Cookie 的 Secure = %v", secure, csrf.Secure)
		}
	}
}
