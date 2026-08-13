package gateway

import (
	"errors"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestHostRouterMatch 覆盖手写 Host 路由器的全部匹配语义。
//
// 之所以手写而不用 net/http 的 ServeMux：ServeMux 的主机模式**只支持字面量**，
// 不支持 *.example.com（spec §7.3 记了这一条），而多租户 vhost 必须有
// a.b.c → *.b.c → * 的回落链。
func TestHostRouterMatch(t *testing.T) {
	exact := sharedTunnel("exact", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1001", []string{"api.example.com"}, nil)
	wildSub := sharedTunnel("wild-sub", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1002", []string{"*.example.com"}, nil)
	wildDeep := sharedTunnel("wild-deep", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1003", []string{"*.eu.example.com"}, nil)
	catchAll := sharedTunnel("catch-all", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1004", []string{"*"}, nil)
	pathAPI := sharedTunnel("path-api", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1005", []string{"paths.example.com"}, []string{"/"})
	pathDeep := sharedTunnel("path-deep", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1006", []string{"paths.example.com"}, []string{"/api/v2"})
	pathMid := sharedTunnel("path-mid", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1007", []string{"paths.example.com"}, []string{"/api"})

	r := NewHostRouter()
	for _, spec := range []struct {
		domain, location string
		t                *tunnel.Tunnel
	}{
		{"api.example.com", "", exact},
		{"*.example.com", "", wildSub},
		{"*.eu.example.com", "", wildDeep},
		{"*", "", catchAll},
		{"paths.example.com", "/", pathAPI},
		{"paths.example.com", "/api/v2", pathDeep},
		{"paths.example.com", "/api", pathMid},
	} {
		if err := r.Add(spec.domain, spec.location, spec.t); err != nil {
			t.Fatalf("注册 %s%s 失败：%v", spec.domain, spec.location, err)
		}
	}

	cases := []struct {
		name     string
		host     string
		path     string
		wantSlug string
	}{
		{"精确域名胜过通配", "api.example.com", "/", "exact"},
		{"带端口的 Host 也能匹配", "api.example.com:8443", "/", "exact"},
		{"大写 Host 归一化后匹配", "API.Example.COM", "/", "exact"},
		{"尾点 Host 归一化后匹配", "api.example.com.", "/", "exact"},
		{"未注册子域回落到 *.example.com", "shop.example.com", "/", "wild-sub"},
		{"更具体的通配胜过更宽的通配", "a.eu.example.com", "/", "wild-deep"},
		{"两段域名不进通配走查，落到 *", "example.com", "/", "catch-all"},
		{"完全无关的域名落到 *", "somewhere.else.net", "/", "catch-all"},
		{"最长路径前缀优先", "paths.example.com", "/api/v2/items", "path-deep"},
		{"次长路径前缀", "paths.example.com", "/api/v1/items", "path-mid"},
		{"根路径兜底", "paths.example.com", "/other", "path-api"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Match(tc.host, tc.path)
			if !ok {
				t.Fatalf("%s%s 没匹配到任何路由", tc.host, tc.path)
			}
			if got.Tunnel.Slug != tc.wantSlug {
				t.Fatalf("命中 %s，期望 %s（域名 %s，前缀 %q）",
					got.Tunnel.Slug, tc.wantSlug, got.Domain, got.Location)
			}
		})
	}
}

// TestHostRouterNoMatchIsRejected 证明没有兜底路由时不匹配就是不匹配 ——
// 判别器据此走第 6 步的拒绝路径。
func TestHostRouterNoMatchIsRejected(t *testing.T) {
	r := NewHostRouter()
	tn := sharedTunnel("only", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1001", []string{"api.example.com"}, []string{"/api"})
	if err := r.Add("api.example.com", "/api", tn); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		host string
		path string
	}{
		{"未注册域名", "nope.example.com", "/api"},
		{"域名对但路径前缀不对", "api.example.com", "/admin"},
		{"空 Host", "", "/api"},
		{"IP 字面量 Host", "203.0.113.7", "/api"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := r.Match(tc.host, tc.path); ok {
				t.Fatalf("不该匹配，却命中了 %s", got.Tunnel.Slug)
			}
		})
	}
}

// TestHostRouterMatchHostIgnoresPath 证明 SNI 判别只按域名匹配。
//
// SNI 阶段 TLS 还没解密，路径根本不存在；若那一步也要求路径命中，
// 一条只注册了 /api 的网关隧道就永远收不到 TLS 连接。
func TestHostRouterMatchHostIgnoresPath(t *testing.T) {
	r := NewHostRouter()
	tn := sharedTunnel("api-only", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1001", []string{"api.example.com"}, []string{"/api"})
	if err := r.Add("api.example.com", "/api", tn); err != nil {
		t.Fatal(err)
	}

	if _, ok := r.Match("api.example.com", "/"); ok {
		t.Fatal("按路径匹配时 / 不该命中 /api 前缀")
	}
	got, ok := r.MatchHost("api.example.com")
	if !ok {
		t.Fatal("MatchHost 必须只看域名")
	}
	if got.Tunnel.Slug != "api-only" {
		t.Fatalf("命中 %s", got.Tunnel.Slug)
	}
}

// TestHostRouterConflicts 钉住注册期的两条不变量。
func TestHostRouterConflicts(t *testing.T) {
	t.Run("同域名同路径前缀冲突", func(t *testing.T) {
		r := NewHostRouter()
		a := sharedTunnel("a", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:1", []string{"x.example.com"}, nil)
		b := sharedTunnel("b", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:2", []string{"x.example.com"}, nil)
		if err := r.Add("x.example.com", "/api", a); err != nil {
			t.Fatal(err)
		}
		err := r.Add("x.example.com", "/api", b)
		if !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("err = %v，期望 ErrRouteConflict", err)
		}
	})

	t.Run("同域名混用透传与网关被拒", func(t *testing.T) {
		// 研究档案 15 §B1 的不变量 (b)：SNI 命中后必须能唯一决定要不要解密。
		r := NewHostRouter()
		gw := sharedTunnel("gw", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:1", []string{"dual.example.com"}, nil)
		pt := sharedTunnel("pt", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
			"127.0.0.1:2", []string{"dual.example.com"}, nil)
		if err := r.Add("dual.example.com", "", gw); err != nil {
			t.Fatal(err)
		}
		err := r.Add("dual.example.com", "/x", pt)
		if !errors.Is(err, ErrModeConflict) {
			t.Fatalf("err = %v，期望 ErrModeConflict", err)
		}
	})
}

// TestHostRouterRemoveDropsEmptyDomain 证明摘掉最后一条路由后 map 条目也消失。
//
// frp 的 Routers.Del 只清切片、留下空 map 条目（router.go:162-184），
// 长期动态注册会缓慢泄漏。
func TestHostRouterRemoveDropsEmptyDomain(t *testing.T) {
	r := NewHostRouter()
	tn := sharedTunnel("x", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:1", []string{"x.example.com"}, nil)
	if err := r.Add("x.example.com", "/a", tn); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("x.example.com", "/b", tn); err != nil {
		t.Fatal(err)
	}

	r.Remove("x.example.com", "/a")
	if r.Len() != 1 {
		t.Fatalf("还剩一条路由时域名条目应当保留，Len = %d", r.Len())
	}
	r.Remove("x.example.com", "/b")
	if r.Len() != 0 {
		t.Fatalf("最后一条路由摘掉后域名条目必须删除，Len = %d", r.Len())
	}
}

// TestRegistryBindings 覆盖端口绑定表的三条不变量。
func TestRegistryBindings(t *testing.T) {
	t.Run("独占端口与共享绑定互斥", func(t *testing.T) {
		reg := NewRegistry()
		robot := portTunnel("robot", tunnel.TLSPassthrough, "192.168.1.5:8080")
		if err := reg.BindDedicated(9001, robot); err != nil {
			t.Fatal(err)
		}
		shared := sharedTunnel("web", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:3000", []string{"web.example.com"}, nil)
		if err := reg.AddShared(9001, shared); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("err = %v，期望 ErrRouteConflict", err)
		}
	})

	t.Run("一个端口只能有一个默认绑定", func(t *testing.T) {
		// 不变量 (a)：IP 字面量流量没有任何判别信息，第二个默认绑定无从选择。
		reg := NewRegistry()
		a := portTunnel("a", tunnel.TLSPassthrough, "127.0.0.1:1")
		b := portTunnel("b", tunnel.TLSPassthrough, "127.0.0.1:2")
		if err := reg.BindDefault(443, a); err != nil {
			t.Fatal(err)
		}
		if err := reg.BindDefault(443, b); !errors.Is(err, ErrDuplicateDefault) {
			t.Fatalf("err = %v，期望 ErrDuplicateDefault", err)
		}
	})

	t.Run("端口 0 是通配端口", func(t *testing.T) {
		reg := NewRegistry()
		tn := sharedTunnel("any", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:1", []string{"any.example.com"}, nil)
		if err := reg.AddShared(0, tn); err != nil {
			t.Fatal(err)
		}
		view, ok := reg.View(45123)
		if !ok {
			t.Fatal("精确端口查不到时必须回落到通配端口 0")
		}
		if _, ok := view.Hosts.MatchHost("any.example.com"); !ok {
			t.Fatal("通配端口上的路由必须可见")
		}
	})

	t.Run("AddShared 一次返回全部失败", func(t *testing.T) {
		// 与 tunnel.Validate 同风格：控制台要能一次高亮所有坏字段。
		reg := NewRegistry()
		first := sharedTunnel("first", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:1", []string{"a.example.com", "b.example.com"}, nil)
		if err := reg.AddShared(443, first); err != nil {
			t.Fatal(err)
		}
		second := sharedTunnel("second", tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:2", []string{"a.example.com", "b.example.com"}, nil)
		err := reg.AddShared(443, second)
		if err == nil {
			t.Fatal("两个域名都冲突，必须报错")
		}
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 2 {
			t.Fatalf("应当用 errors.Join 返回 2 个错误，实际：%v", err)
		}
	})
}

func TestHasExactDomainDoesNotFollowTheWildcardChain(t *testing.T) {
	// 通配回落对**转发**是对的（用户注册 *.b.c 就是要这个效果），
	// 对**签证书**是错的：任何人都能拿 <随机>.b.c 发一次握手让我们去要
	// 一张新证书。每个名字只算一次 per-name 预算，可名字有无穷多个 ——
	// 于是全局预算在几十次握手里烧光，真域名之后也签不出来。
	r := NewHostRouter()
	if err := r.Add("web.example.com", "", &tunnel.Tunnel{Slug: "exact"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("*.wild.example.com", "", &tunnel.Tunnel{Slug: "wild"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		want bool
	}{
		{"web.example.com", true},
		{"WEB.EXAMPLE.COM", true},
		{"*.wild.example.com", true},
		{"a.wild.example.com", false},
		{"nope.example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := r.HasExactDomain(c.name); got != c.want {
			t.Errorf("HasExactDomain(%q)=%v，想要 %v", c.name, got, c.want)
		}
		// 反面对照：MatchHost **应当**跟着通配走。两个方法的差异
		// 就是这条测试要钉住的东西。
		if c.name == "a.wild.example.com" {
			if _, ok := r.MatchHost(c.name); !ok {
				t.Error("MatchHost 必须仍然跟着通配回落 —— 转发要靠它")
			}
		}
	}

	// 摘掉之后立刻不再认识：Remove 会删空条目，而 len(nil slice) == 0。
	r.Remove("web.example.com", "")
	if r.HasExactDomain("web.example.com") {
		t.Error("摘掉的域名不该还被认识 —— 否则删了隧道还能为它签证书")
	}
}
