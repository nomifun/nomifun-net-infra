package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestRewriteIdentityHeaders 逐行断言 spec §12 的改写表。
//
// 入站请求刻意带上一整套**伪造**的身份头（攻击者能发的全套），
// 断言出站请求里每一行都被换成中继计算出的值。
func TestRewriteIdentityHeaders(t *testing.T) {
	const (
		backend = "192.168.1.5:25808"
		public  = "api.example.com"
		client  = "203.0.113.9"
	)

	in := httptest.NewRequest(http.MethodGet, "http://"+public+"/api/hello", nil)
	in.Host = public
	in.Header.Set("Origin", "https://"+public)
	// 攻击者伪造的全套身份头。
	in.Header.Set("X-Forwarded-For", "10.0.0.1")
	in.Header.Add("X-Forwarded-For", "10.0.0.2")
	in.Header.Set("X-Real-IP", "10.0.0.3")
	in.Header.Set("X-Forwarded-Host", "evil.example.com")
	in.Header.Set("X-Forwarded-Proto", "http")
	in.Header.Set("Forwarded", "for=10.0.0.4;proto=http")
	in.Header.Set("X-Client-IP", "10.0.0.5")
	in.Header.Set("CF-Connecting-IP", "10.0.0.6")
	in.Header.Set("True-Client-IP", "10.0.0.7")
	// 业务头必须原样透传。
	in.Header.Set("Authorization", "Bearer 用户令牌")

	out := in.Clone(in.Context())
	rewriteIdentityHeaders(out, legInfo{
		Backend:   backend,
		Public:    public,
		Client:    client,
		Scheme:    "https",
		HadOrigin: true,
	})

	cases := []struct {
		name   string
		header string
		want   string // "" 表示这个头必须不存在
	}{
		{"Host 设为后端 ip:port（后端的 host guard 只放行 IP 字面量）", "Host", backend},
		{"Origin 设为 http://B（入站有 Origin 时）", "Origin", "http://" + backend},
		{"X-Forwarded-Host 设为公网主机名", "X-Forwarded-Host", public},
		{"X-Forwarded-For 换成唯一真实客户端 IP", "X-Forwarded-For", client},
		{"X-Real-IP 换成唯一真实客户端 IP", "X-Real-IP", client},
		{"X-Forwarded-Proto 是公网侧 scheme", "X-Forwarded-Proto", "https"},
		{"Forwarded 被删除", "Forwarded", ""},
		{"X-Client-IP 被删除", "X-Client-IP", ""},
		{"CF-Connecting-IP 被删除", "CF-Connecting-IP", ""},
		{"True-Client-IP 被删除", "True-Client-IP", ""},
		{"业务头原样透传", "Authorization", "Bearer 用户令牌"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.header == "Host" {
				got = out.Host
			} else {
				got = out.Header.Get(tc.header)
			}
			if got != tc.want {
				t.Fatalf("%s = %q，期望 %q", tc.header, got, tc.want)
			}
		})
	}

	// 最关键的一条单独断言：**替换而不是追加**。
	//
	// nomifun-tauri 取 X-Forwarded-For 的第一个元素且没有可信代理白名单
	//（extract.rs:13-32），所以只要留下一个客户端可控的元素，
	// 公网就拿到了源 IP 伪造原语。
	t.Run("X-Forwarded-For 只能有一个值且不含伪造项", func(t *testing.T) {
		vals := out.Header.Values("X-Forwarded-For")
		if len(vals) != 1 {
			t.Fatalf("X-Forwarded-For 有 %d 个值 %v —— 必须先删再设为单值", len(vals), vals)
		}
		if vals[0] != client {
			t.Fatalf("X-Forwarded-For = %q，期望 %q", vals[0], client)
		}
	})
	t.Run("X-Real-IP 也只能有一个值", func(t *testing.T) {
		if vals := out.Header.Values("X-Real-IP"); len(vals) != 1 {
			t.Fatalf("X-Real-IP 有 %d 个值 %v", len(vals), vals)
		}
	})
}

// TestRewriteOmitsOriginWhenAbsent 证明入站没有 Origin 时我们不凭空造一个。
//
// 凭空加 Origin 会把一个「同源」请求变成「跨源」请求的形状，
// 后端的 CSRF/Origin 逻辑会因此改变行为 —— 中继不该悄悄改变语义。
func TestRewriteOmitsOriginWhenAbsent(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	out := in.Clone(in.Context())
	rewriteIdentityHeaders(out, legInfo{
		Backend: "10.0.0.9:25808", Public: "api.example.com",
		Client: "203.0.113.9", Scheme: "https", HadOrigin: false,
	})
	if v := out.Header.Get("Origin"); v != "" {
		t.Fatalf("入站无 Origin 时不该注入，实际 %q", v)
	}
}

// TestBackendAuthority 覆盖 B 的推导。
func TestBackendAuthority(t *testing.T) {
	cases := []struct {
		name string
		tn   *tunnel.Tunnel
		want string
	}{
		{
			name: "默认用后端 ip:port",
			tn: sharedTunnel("plain", tunnel.TLSGateway, tunnel.RouterHTTP,
				"192.168.1.5:25808", []string{"a.example.com"}, nil),
			want: "192.168.1.5:25808",
		},
		{
			name: "HostRewrite 优先",
			tn: func() *tunnel.Tunnel {
				tn := sharedTunnel("rewrite", tunnel.TLSGateway, tunnel.RouterHTTP,
					"10.9.9.9:8080", []string{"a.example.com"}, nil)
				tn.Router.HostRewrite = "192.168.1.5:25808"
				return tn
			}(),
			want: "192.168.1.5:25808",
		},
		{
			name: "unix 后端退化为 localhost（host guard 唯一放行的非 IP 值）",
			tn: func() *tunnel.Tunnel {
				tn := sharedTunnel("unix", tunnel.TLSGateway, tunnel.RouterHTTP,
					"", []string{"a.example.com"}, nil)
				tn.Backend = tunnel.Backend{Kind: tunnel.BackendUnix, Path: "/run/nomifun.sock"}
				return tn
			}(),
			want: "localhost",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendAuthority(tc.tn); got != tc.want {
				t.Fatalf("B = %q，期望 %q", got, tc.want)
			}
		})
	}
}

// TestIsIPLiteralOrLocalhost 复刻 nomifun-tauri 的 host_is_ip_or_localhost
// （desktop.rs:1726-1729）的判定，我们据此在装配期警告。
func TestIsIPLiteralOrLocalhost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.1.5:25808", true},
		{"127.0.0.1", true},
		{"localhost", true},
		{"LocalHost:8080", true},
		{"[::1]:80", true},
		{"::1", true},
		{"desktop.lan:8080", false},
		{"api.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isIPLiteralOrLocalhost(tc.in); got != tc.want {
				t.Fatalf("isIPLiteralOrLocalhost(%q) = %v，期望 %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestClientIPPrefersConnectionOverHeaders 证明客户端 IP 只认连接事实。
//
// 请求头在这一层全是攻击者可控输入；一旦允许它们参与计算，
// 后端读到的「真实客户端 IP」就是攻击者写的那个。
func TestClientIPPrefersConnectionOverHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	r.RemoteAddr = "203.0.113.9:44321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.2")

	if got := clientIPOf(r); got != "203.0.113.9" {
		t.Fatalf("C = %q，期望内核看到的对端 203.0.113.9", got)
	}

	// v4-in-v6 必须规范化，否则后端的 IPv4 白名单会被 ::ffff: 形式绕过。
	r.RemoteAddr = "[::ffff:203.0.113.9]:44321"
	if got := clientIPOf(r); got != "203.0.113.9" {
		t.Fatalf("C = %q，期望规范化成 203.0.113.9", got)
	}
}
