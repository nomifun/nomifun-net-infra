package tunnel

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func base() *Tunnel {
	t := &Tunnel{
		Slug:    "my-api",
		Backend: Backend{Kind: BackendAddr, Addr: "127.0.0.1:8080"},
	}
	t.Complete()
	return t
}

func TestCompleteFillsSafeDefaults(t *testing.T) {
	tn := &Tunnel{Slug: "x", Backend: Backend{Addr: "127.0.0.1:1"}}
	tn.Complete()

	if tn.TenantID != DefaultTenantID {
		t.Errorf("TenantID = %q，期望 %q（v1 单租户但列非空保留）", tn.TenantID, DefaultTenantID)
	}
	if tn.Kind != KindService {
		t.Errorf("Kind = %q，期望 service", tn.Kind)
	}
	// 默认必须是透传：它假设最少、信任最少。
	if tn.TLS != TLSPassthrough {
		t.Errorf("TLS = %q，期望 passthrough —— 默认不该让中继看见明文", tn.TLS)
	}
	if tn.Backend.Kind != BackendAddr {
		t.Errorf("Backend.Kind = %q，期望 addr", tn.Backend.Kind)
	}
	if tn.State != StateDraft {
		t.Errorf("State = %q，期望 draft", tn.State)
	}
}

func TestCompleteIsIdempotent(t *testing.T) {
	a := base()
	b := a.Clone()
	b.Complete()
	b.Complete()

	if a.TLS != b.TLS || a.Kind != b.Kind || a.Exposure != b.Exposure || a.TenantID != b.TenantID {
		t.Error("Complete 不幂等 —— 多次调用产生了不同结果")
	}
}

// TestHTTPRouterRequiresGateway 是本包最重要的校验之一。
//
// 按 Host 与路径路由**必须能读明文**，这不是可以放宽的策略，是物理事实。
// 若允许 router=http + tls=passthrough 通过校验，运行期只会得到一条
// 神秘不通的隧道。
func TestHTTPRouterRequiresGateway(t *testing.T) {
	tn := base()
	tn.Exposure = ExposureShared
	tn.TLS = TLSPassthrough
	tn.Router = &Router{Kind: RouterHTTP, Domains: []string{"api.example.com"}}

	err := tn.Validate()
	if !errors.Is(err, ErrModeConflict) {
		t.Fatalf("router=http + tls=passthrough 必须被拒，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "读不到") {
		t.Errorf("错误信息应当解释为什么不可能，而不只是说「不允许」：%v", err)
	}

	// 改成 gateway 就应当通过。
	tn.TLS = TLSGateway
	if err := tn.Validate(); err != nil {
		t.Fatalf("router=http + tls=gateway 应当合法：%v", err)
	}
}

// TestSNIRouterWorksWithPassthrough 验证「SNI 是明文所以透传也能路由」这个洞见。
//
// 我一开始以为「域名路由必须能读明文」，这是错的 —— SNI 在 ClientHello 里是明文，
// 读它不需要解密。frp 的 https 代理正是这么做的（pkg/util/vhost/https.go:39-71）。
func TestSNIRouterWorksWithPassthrough(t *testing.T) {
	tn := base()
	tn.Exposure = ExposureShared
	tn.TLS = TLSPassthrough
	tn.Router = &Router{Kind: RouterTLSSNI, Domains: []string{"api.example.com"}}

	if err := tn.Validate(); err != nil {
		t.Fatalf("router=tls-sni + tls=passthrough 应当合法（SNI 是明文）：%v", err)
	}

	// 但 tls-sni + gateway 是矛盾的：既然要终止 TLS 就该用 http 路由。
	tn.TLS = TLSGateway
	if err := tn.Validate(); !errors.Is(err, ErrModeConflict) {
		t.Errorf("router=tls-sni + tls=gateway 应当被拒，得到 %v", err)
	}
}

// TestSNIRouterCannotRewriteOrRoutePaths 确认透传模式的能力边界被强制。
//
// 这两个字段在透传下没有任何实现路径，静默忽略会让用户以为它们生效了。
func TestSNIRouterCannotRewriteOrRoutePaths(t *testing.T) {
	mk := func(mut func(*Router)) error {
		tn := base()
		tn.Exposure = ExposureShared
		tn.TLS = TLSPassthrough
		tn.Router = &Router{Kind: RouterTLSSNI, Domains: []string{"a.example.com"}}
		mut(tn.Router)
		return tn.Validate()
	}

	if err := mk(func(r *Router) { r.Locations = []string{"/api"} }); !errors.Is(err, ErrModeConflict) {
		t.Errorf("透传模式配路径前缀应当被拒，得到 %v", err)
	}
	if err := mk(func(r *Router) { r.HostRewrite = "127.0.0.1:8080" }); !errors.Is(err, ErrModeConflict) {
		t.Errorf("透传模式配 Host 改写应当被拒，得到 %v", err)
	}
}

func TestSharedExposureRequiresRouterAndTCP(t *testing.T) {
	tn := base()
	tn.Exposure = ExposureShared
	if err := tn.Validate(); !errors.Is(err, ErrMissingField) {
		t.Errorf("exposure=shared 缺 router 应当被拒，得到 %v", err)
	}

	// UDP 没有 SNI 或 Host 可读，共享端口分流对它没有意义。
	tn.L4 = L4UDP
	tn.Router = &Router{Kind: RouterTLSSNI, Domains: []string{"a.example.com"}}
	if err := tn.Validate(); !errors.Is(err, ErrModeConflict) {
		t.Errorf("UDP + exposure=shared 应当被拒，得到 %v", err)
	}
}

func TestRouterOnNonSharedExposureIsRejected(t *testing.T) {
	tn := base()
	tn.Exposure = ExposurePort
	tn.Router = &Router{Kind: RouterHTTP, Domains: []string{"a.example.com"}}
	if err := tn.Validate(); !errors.Is(err, ErrModeConflict) {
		t.Errorf("exposure=port 配 router 应当被拒，得到 %v", err)
	}
}

// TestScenario3EnumsAreReservedButRejected 守护场景三的前向兼容接缝。
//
// 枚举位现在就必须存在（事后加 Kind 是 schema 迁移、加 Backend 是线协议破坏），
// 但 v1 必须明确拒绝使用它们 —— 而且错误信息要说清「这是预留位」，
// 而不是含糊的「未知值」，否则将来的人会以为是拼写错误。
func TestScenario3EnumsAreReservedButRejected(t *testing.T) {
	t.Run("kind=peer", func(t *testing.T) {
		tn := base()
		tn.Kind = KindPeer
		err := tn.Validate()
		if !errors.Is(err, ErrUnsupportedKind) {
			t.Fatalf("得到 %v", err)
		}
		if !strings.Contains(err.Error(), "预留") {
			t.Errorf("错误信息应说明这是预留位：%v", err)
		}
	})
	t.Run("backend=handler", func(t *testing.T) {
		tn := base()
		tn.Backend = Backend{Kind: BackendHandler}
		if err := tn.Validate(); !errors.Is(err, ErrUnsupportedKind) {
			t.Fatalf("得到 %v", err)
		}
	})
	t.Run("exposure=p2p", func(t *testing.T) {
		tn := base()
		tn.Exposure = ExposureP2P
		if err := tn.Validate(); !errors.Is(err, ErrUnsupportedKind) {
			t.Fatalf("得到 %v", err)
		}
	})

	// 常量的线上拼写不能改 —— 将来实现时若换了拼写，新旧端互不识别。
	if KindPeer != "peer" || BackendHandler != "handler" || ExposureP2P != "p2p" {
		t.Error("预留枚举的线上拼写被改动了，这会破坏与将来实现的互操作")
	}
}

func TestValidateReportsAllProblemsAtOnce(t *testing.T) {
	tn := &Tunnel{
		Slug:     "Bad Slug!",                // 非法
		Kind:     Kind("nonsense"),           // 非法
		L4:       L4("sctp"),                 // 非法
		Exposure: ExposureShared,             // 缺 router
		Backend:  Backend{Kind: BackendAddr}, // 缺 addr
	}
	tn.Complete()

	err := tn.Validate()
	if err == nil {
		t.Fatal("应当报错")
	}
	msg := err.Error()
	// errors.Join 会把所有问题串起来，控制台才能一次高亮全部坏字段。
	for _, want := range []string{"slug", "kind", "l4", "router", "addr"} {
		if !strings.Contains(strings.ToLower(msg), want) {
			t.Errorf("错误信息里缺少 %q，说明不是一次返回全部问题：\n%s", want, msg)
		}
	}
}

func TestSlugValidation(t *testing.T) {
	for _, tc := range []struct {
		slug string
		ok   bool
	}{
		{"my-api", true},
		{"a", true},
		{"a1", true},
		{"web-8080", true},
		{"", false},
		{"-leading", false},
		{"trailing-", false},
		{"Upper", false},
		{"with_underscore", false},
		{"with.dot", false},
		{"with space", false},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
	} {
		tn := base()
		tn.Slug = tc.slug
		err := tn.Validate()
		got := !errors.Is(err, ErrInvalidSlug)
		if got != tc.ok {
			t.Errorf("slug %q：合法=%v，期望 %v", tc.slug, got, tc.ok)
		}
	}
}

func TestUnixBackendRejectsUDP(t *testing.T) {
	tn := base()
	tn.Backend = Backend{Kind: BackendUnix, Path: "/run/app.sock"}
	tn.L4 = L4UDP
	if err := tn.Validate(); !errors.Is(err, ErrModeConflict) {
		t.Errorf("unix socket 后端 + UDP 应当被拒，得到 %v", err)
	}

	tn.L4 = L4TCP
	if err := tn.Validate(); err != nil {
		t.Errorf("unix socket 后端 + TCP 应当合法：%v", err)
	}
}

// TestCloneIsDeep 验证 Clone 真的是深拷贝 ——
// 热重载依赖它先构候选再原子换，浅拷贝会让候选与现行配置共享底层数组。
func TestCloneIsDeep(t *testing.T) {
	enabled := true
	orig := base()
	orig.Router = &Router{
		Kind:      RouterHTTP,
		Domains:   []string{"a.example.com"},
		Locations: []string{"/v1"},
	}
	orig.Policy = &Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	orig.Enabled = &enabled

	c := orig.Clone()

	// 改动副本不得影响原件。
	c.Router.Domains[0] = "changed"
	c.Router.Locations = append(c.Router.Locations, "/v2")
	c.Policy.AllowCIDRs[0] = netip.MustParsePrefix("192.168.0.0/16")
	*c.Enabled = false

	if orig.Router.Domains[0] != "a.example.com" {
		t.Error("Router.Domains 是浅拷贝")
	}
	if len(orig.Router.Locations) != 1 {
		t.Error("Router.Locations 是浅拷贝")
	}
	if orig.Policy.AllowCIDRs[0].String() != "10.0.0.0/8" {
		t.Error("Policy.AllowCIDRs 是浅拷贝")
	}
	if *orig.Enabled != true {
		t.Error("Enabled 指针被共享")
	}
}

func TestCloneNilIsSafe(t *testing.T) {
	var tn *Tunnel
	if tn.Clone() != nil {
		t.Error("nil.Clone() 应当返回 nil")
	}
}

// TestEnabledIsTriState 验证 *bool 的三态语义。
//
// 这是从 frp 抄来的好设计（pkg/config/v1/proxy.go:124）：
// 用 *bool 才能区分「没设置」与「显式设成 false」。
func TestEnabledIsTriState(t *testing.T) {
	tn := base()
	if !tn.IsEnabled() {
		t.Error("未设置时应当视为启用")
	}

	f := false
	tn.Enabled = &f
	if tn.IsEnabled() {
		t.Error("显式 false 应当视为停用")
	}

	tr := true
	tn.Enabled = &tr
	if !tn.IsEnabled() {
		t.Error("显式 true 应当视为启用")
	}
}

// ── 来源策略 ────────────────────────────────────────────────────────────────

// TestBareExposureIsIdentifiedNotRejected 验证「裸端口」被识别但不被拒绝。
//
// 所有者已决定场景二接受裸端口开放，所以这里只负责让控制台能打风险标记。
func TestBareExposureIsIdentifiedNotRejected(t *testing.T) {
	tn := base()
	tn.Exposure = ExposurePort
	tn.Kind = KindReverse

	if !tn.IsBareExposure() {
		t.Error("独占端口且无来源限制应当被识别为裸暴露")
	}
	if err := tn.Validate(); err != nil {
		t.Errorf("裸暴露是被接受的形态，不该校验失败：%v", err)
	}

	tn.Policy = &Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if tn.IsBareExposure() {
		t.Error("配了来源白名单之后不该再算裸暴露")
	}
}

func TestSourceAllowed(t *testing.T) {
	tn := base()

	// 无策略 → 一律放行（裸端口语义）。
	if !tn.SourceAllowed(netip.MustParseAddr("8.8.8.8")) {
		t.Error("无策略时应当放行任意来源")
	}

	tn.Policy = &Policy{AllowCIDRs: []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}}

	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"203.0.113.9", true},
		{"203.0.114.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		// IPv4-in-IPv6 必须先规范化，否则 ::ffff: 形式绕过 IPv4 白名单。
		{"::ffff:203.0.113.9", true},
		{"::ffff:8.8.8.8", false},
	} {
		got := tn.SourceAllowed(netip.MustParseAddr(tc.addr))
		if got != tc.want {
			t.Errorf("来源 %s：放行=%v，期望 %v", tc.addr, got, tc.want)
		}
	}
}
