package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fcClient struct {
	h       http.Handler
	cookies []*http.Cookie
	csrf    string
}

func (c *fcClient) do(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.Host = "127.0.0.1:9443"
	r.Header.Set("Origin", "http://127.0.0.1:9443")
	if c.csrf != "" {
		r.Header.Set(CSRFHeaderName, c.csrf)
	}
	for _, ck := range c.cookies {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	res := w.Result()
	if cs := res.Cookies(); len(cs) > 0 {
		c.cookies = append(c.cookies, cs...)
	}
	return res
}

func dump(t *testing.T, tag string, res *http.Response) string {
	t.Helper()
	b := make([]byte, 4096)
	n, _ := res.Body.Read(b)
	body := string(b[:n])
	t.Logf("%s -> %d ct=%q cl=%q body=%q", tag, res.StatusCode,
		res.Header.Get("Content-Type"), res.Header.Get("Content-Length"), body)
	return body
}

func TestZZZFactCheck(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	c := &fcClient{h: h}

	// setup
	body := dump(t, "POST /api/setup", c.do(t, "POST", "/api/setup",
		`{"username":"admin","password":"correct-horse-battery","extra":1}`))
	var lr LoginResponse
	_ = json.Unmarshal([]byte(body), &lr)
	c.csrf = lr.CSRFToken
	t.Logf("setup cookies=%v must_rotate=%v", c.cookies, lr.MustRotate)

	dump(t, "GET /api/me", c.do(t, "GET", "/api/me", ""))
	dump(t, "GET /api/snapshot", c.do(t, "GET", "/api/snapshot", ""))
	dump(t, "GET /api/tunnels", c.do(t, "GET", "/api/tunnels", ""))
	dump(t, "GET /api/events/recent", c.do(t, "GET", "/api/events/recent?limit=1", ""))
	dump(t, "GET /api/settings", c.do(t, "GET", "/api/settings", ""))
	dump(t, "GET /api/turn/allocations", c.do(t, "GET", "/api/turn/allocations", ""))

	// preview with garbage body
	dump(t, "POST :preview garbage", c.do(t, "POST", "/api/tunnels:preview", `{"nope":1}`))
	// preview with valid body
	dump(t, "POST :preview ok", c.do(t, "POST", "/api/tunnels:preview",
		`{"slug":"web","backend":{"addr":"127.0.0.1:8080"}}`))

	// create minimal tunnel
	body = dump(t, "POST /api/tunnels", c.do(t, "POST", "/api/tunnels",
		`{"slug":"web","backend":{"addr":"127.0.0.1:8080"}}`))
	var created map[string]any
	_ = json.Unmarshal([]byte(body), &created)
	id, _ := created["id"].(string)

	dump(t, "GET tunnel by slug", c.do(t, "GET", "/api/tunnels/web", ""))
	dump(t, "POST verb apply-learned", c.do(t, "POST", "/api/tunnels/"+id+":apply-learned", ""))
	dump(t, "GET learned-sources", c.do(t, "GET", "/api/tunnels/"+id+"/learned-sources", ""))
	dump(t, "POST diagnostics:selftest", c.do(t, "POST", "/api/diagnostics:selftest", ""))
	dump(t, "GET samples of missing", c.do(t, "GET", "/api/tunnels/t-nope/samples", ""))
	dump(t, "POST :test", c.do(t, "POST", "/api/tunnels/"+id+":test", `{}`))
	dump(t, "POST agent kick", c.do(t, "POST", "/api/agents/a-nope:kick", ""))
	dump(t, "GET login (405?)", c.do(t, "GET", "/api/login", ""))
	dump(t, "GET support-bundle", c.do(t, "GET", "/api/diagnostics/support-bundle", ""))

	// private exposure accepted?
	dump(t, "POST tunnels private", c.do(t, "POST", "/api/tunnels",
		`{"slug":"priv","exposure":"private","backend":{"addr":"127.0.0.1:9","kind":"addr"}}`))
	// gateway tls + port exposure accepted?
	dump(t, "POST tunnels gw+port", c.do(t, "POST", "/api/tunnels",
		`{"slug":"gw","tls":"gateway","exposure":"port","backend":{"addr":"127.0.0.1:9"}}`))

	// config validate / apply emptying
	dump(t, "POST config:validate empty", c.do(t, "POST", "/api/config:validate",
		`{"doc":"{\"version\":1,\"tunnels\":[]}"}`))
	dump(t, "POST config:validate badver", c.do(t, "POST", "/api/config:validate",
		`{"doc":"{\"version\":2,\"tunnels\":[]}"}`))
	dump(t, "POST config:validate emptydoc", c.do(t, "POST", "/api/config:validate", `{}`))

	// csrf: no origin
	{
		r := httptest.NewRequest("POST", "/api/logout", nil)
		r.Host = "127.0.0.1:9443"
		r.Header.Set(CSRFHeaderName, c.csrf)
		for _, ck := range c.cookies {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		dump(t, "POST /api/logout no Origin", w.Result())
	}

	// bad host
	for _, m := range []string{"GET", "POST", "HEAD"} {
		r := httptest.NewRequest(m, "/healthz", nil)
		r.Host = "evil.example"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		dump(t, "healthz badhost "+m, w.Result())
	}
	{
		r := httptest.NewRequest("GET", "/api/setup", nil)
		r.Host = "evil.example"
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		dump(t, "421 html", w.Result())
	}

	// apply emptying everything
	dump(t, "POST config:apply empty", c.do(t, "POST", "/api/config:apply",
		`{"doc":"{\"version\":1,\"tunnels\":[]}"}`))
	dump(t, "GET /api/tunnels after apply", c.do(t, "GET", "/api/tunnels", ""))

	// unknown field
	dump(t, "POST tunnels unknown field", c.do(t, "POST", "/api/tunnels",
		`{"slug":"x","backend":{"addr":"1.2.3.4:9"},"note":"hi"}`))
	// validate
	dump(t, "POST tunnels:validate bad", c.do(t, "POST", "/api/tunnels:validate",
		`{"slug":"BAD_SLUG","backend":{}}`))
}
