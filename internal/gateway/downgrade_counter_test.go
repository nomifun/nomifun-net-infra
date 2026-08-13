package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestPassthroughDowngradeHasItsOwnCounter 钉住这个计数器的**独立性**。
//
// 它此前混进 NoRoute，而 NoRoute 同时装着「这个域名没配上」—— 那是运维
// 每天都会看到的正常噪声。于是一次真实的降级绕过尝试在计量上与「有人访问了
// 一个拼错的域名」完全一样，而 07-operations 恰好教人靠这几个分级计数去排查
// 「443 上到底发生了什么」。
//
// 两者的处置也完全不同：NoRoute 涨是「去把域名配上」，这一项涨是
// 「有人在试着让中继解密一条 passthrough 隧道」—— 后者要查来源、查审计。
func TestPassthroughDowngradeHasItsOwnCounter(t *testing.T) {
	reg := NewRegistry()
	pt := &tunnel.Tunnel{
		ID: "t-pt", Slug: "pt", TLS: tunnel.TLSPassthrough,
		Exposure: tunnel.ExposureShared, L4: tunnel.L4TCP,
		Router:  &tunnel.Router{Kind: tunnel.RouterTLSSNI, Domains: []string{"secret.example"}},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9"},
	}
	pt.Complete()
	if err := reg.AddShared(0, pt); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(GatewayConfig{Registry: reg, Dialer: nil})

	r := httptest.NewRequest(http.MethodGet, "http://secret.example/", nil)
	r.Host = "secret.example"
	r.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("状态 %d，期望 404（与未注册域名同一个回复，不确认存在性）", w.Code)
	}
	st := g.Stats()
	if st.DeniedPassthrough.Load() != 1 {
		t.Errorf("DeniedPassthrough = %d，期望 1", st.DeniedPassthrough.Load())
	}
	if n := st.NoRoute.Load(); n != 0 {
		t.Errorf("NoRoute = %d，期望 0 —— 混进它就与「域名没配上」这种日常噪声"+
			"共用一个数字，真实的降级绕过尝试因此不可见", n)
	}
}
