package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestZZZFactCheck2(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	c := &fcClient{h: h}
	body := dump(t, "setup", c.do(t, "POST", "/api/setup",
		`{"username":"admin","password":"correct-horse-battery"}`))
	_ = body
	// grab csrf from cookie
	for _, ck := range c.cookies {
		if ck.Name == CSRFCookieName {
			c.csrf = ck.Value
		}
	}
	t.Logf("csrf from cookie=%q", c.csrf)

	// guessField determinism
	for i := 0; i < 6; i++ {
		dump(t, "validate backend-missing", c.do(t, "POST", "/api/tunnels:validate",
			`{"slug":"ok","backend":{"kind":"addr"}}`))
	}

	// client-supplied id + state + short_id
	dump(t, "create with id/state", c.do(t, "POST", "/api/tunnels",
		`{"id":"t-deadbeef0001","slug":"a","state":"active","short_id":77,"backend":{"addr":"1.2.3.4:9"}}`))
	// POST again with same id, different slug -> upsert or conflict?
	dump(t, "create again same id", c.do(t, "POST", "/api/tunnels",
		`{"id":"t-deadbeef0001","slug":"b","backend":{"addr":"1.2.3.4:10"}}`))
	dump(t, "list", c.do(t, "GET", "/api/tunnels", ""))
	// duplicate slug different id
	dump(t, "create dup slug", c.do(t, "POST", "/api/tunnels",
		`{"slug":"b","backend":{"addr":"1.2.3.4:11"}}`))
	// duplicate listen_port
	dump(t, "create port 9000", c.do(t, "POST", "/api/tunnels",
		`{"slug":"p1","listen_port":9000,"backend":{"addr":"1.2.3.4:11"}}`))
	dump(t, "create port 9000 again", c.do(t, "POST", "/api/tunnels",
		`{"slug":"p2","listen_port":9000,"backend":{"addr":"1.2.3.4:11"}}`))

	// PUT to nonexistent
	dump(t, "PUT missing", c.do(t, "PUT", "/api/tunnels/t-nope",
		`{"slug":"z","backend":{"addr":"1.2.3.4:9"}}`))
	// DELETE twice
	dump(t, "DELETE once", c.do(t, "DELETE", "/api/tunnels/t-deadbeef0001", ""))
	dump(t, "DELETE twice", c.do(t, "DELETE", "/api/tunnels/t-deadbeef0001", ""))

	// enrol token with wrong field name
	dump(t, "enrol wrong field", c.do(t, "POST", "/api/enrol-tokens", `{"ttlSeconds":3600}`))
	dump(t, "enrol garbage", c.do(t, "POST", "/api/enrol-tokens", `not json`))

	// password
	dump(t, "password short", c.do(t, "POST", "/api/password",
		`{"current":"correct-horse-battery","new":"short"}`))
	dump(t, "password wrong cur", c.do(t, "POST", "/api/password",
		`{"current":"nope","new":"another-long-password"}`))

	// agent unknown verb / plain id
	dump(t, "agent no verb", c.do(t, "POST", "/api/agents/a-1", ""))
	dump(t, "tunnel no verb", c.do(t, "POST", "/api/tunnels/t-1", ""))

	// events recent since / limit
	dump(t, "recent limit 9999", c.do(t, "GET", "/api/events/recent?limit=9999", ""))
	dump(t, "recent since=99", c.do(t, "GET", "/api/events/recent?since=99", ""))
	dump(t, "recent limit=abc", c.do(t, "GET", "/api/events/recent?limit=abc&page_size=1", ""))

	// SSE headers
	{
		r := httptest.NewRequest("GET", "/api/events", nil)
		r.Host = "127.0.0.1:9443"
		r.Header.Set("Last-Event-ID", "5")
		for _, ck := range c.cookies {
			r.AddCookie(ck)
		}
		ctx, cancel := contextWithTimeout(t, 150*1000*1000)
		defer cancel()
		rec := newStreamRecorder()
		done := make(chan struct{})
		go func() { h.ServeHTTP(rec, r.WithContext(ctx)); close(done) }()
		<-done
		t.Logf("SSE code=%d headers=%v body=%q", rec.code, rec.header, rec.String())
	}

	// wrong csrf token
	{
		r := httptest.NewRequest("POST", "/api/logout", nil)
		r.Host = "127.0.0.1:9443"
		r.Header.Set("Origin", "http://127.0.0.1:9443")
		r.Header.Set(CSRFHeaderName, "wrong")
		for _, ck := range c.cookies {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		dump(t, "logout wrong csrf", w.Result())
	}
	// no session at all
	{
		r := httptest.NewRequest("POST", "/api/logout", nil)
		r.Host = "127.0.0.1:9443"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		dump(t, "logout no session", w.Result())
	}
	// oversized body on tunnels (>64KiB)
	dump(t, "oversized tunnel", c.do(t, "POST", "/api/tunnels",
		`{"slug":"big","backend":{"addr":"`+strings.Repeat("a", 70000)+`"}}`))
	// oversized enrol body (>4KiB) silently ignored?
	dump(t, "oversized enrol", c.do(t, "POST", "/api/enrol-tokens",
		`{"note":"`+strings.Repeat("n", 5000)+`","ttl_seconds":60}`))
	// turn credentials without turn
	dump(t, "turn cred", c.do(t, "POST", "/api/turn/credentials", `{"user_id":"u","ttl_seconds":99999}`))
	// logout then me
	dump(t, "logout", c.do(t, "POST", "/api/logout", ""))
	dump(t, "me after logout", c.do(t, "GET", "/api/me", ""))
	var _ = http.MethodGet
}
