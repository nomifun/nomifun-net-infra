package policy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustPolicy(t *testing.T, cfg Config) *Policy {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestCloudMetadataIsAlwaysDenied 是本包最重要的测试。
//
// 云元数据地址是 SSRF 的最高价值目标：一次成功即换来一套云凭据。
// frp 在这里毫无防护 —— localIP 默认 127.0.0.1，而 TCP/UDP 代理的客户端校验
// 是空实现（pkg/config/v1/validation/proxy.go:129-135 直接 return nil），
// 配 169.254.169.254 一路畅通。
func TestCloudMetadataIsAlwaysDenied(t *testing.T) {
	// 故意配一个非常宽松的 allow，证明它**无法**覆盖永久拒绝段。
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	targets := []string{
		"169.254.169.254:80", // AWS / GCP / Azure
		"169.254.170.2:80",   // ECS 任务元数据
		"100.100.100.200:80", // 阿里云
		"169.254.1.1:80",     // 链路本地其余部分
		"[fd00:ec2::254]:80", // EC2 IPv6 元数据
		"[fe80::1]:80",       // IPv6 链路本地
		"0.0.0.0:80",         // 未指定
		"224.0.0.1:80",       // 多播
		"255.255.255.255:80", // 广播
	}
	for _, target := range targets {
		ap := netip.MustParseAddrPort(target)
		d := p.CheckAddr(ap)
		if d.Allowed {
			t.Errorf("%s 必须被拒绝，却被放行了", target)
		}
		if d.Rule == "" {
			t.Errorf("%s 被拒但没有给出规则标识，排障时无从下手", target)
		}
	}
}

// TestIPv4In6CannotBypassDenylist 验证 ::ffff:a.b.c.d 形式不能绕过 IPv4 黑名单。
//
// 这是一个经典绕过手法：黑名单只写了 IPv4 前缀，攻击者用 IPv4-mapped IPv6
// 表示同一个地址，Contains 检查就落空了。必须先 Unmap 规范化。
func TestIPv4In6CannotBypassDenylist(t *testing.T) {
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	mapped := netip.MustParseAddr("::ffff:169.254.169.254")
	if !mapped.Is4In6() {
		t.Fatal("测试前提不成立：该地址应当是 IPv4-in-IPv6")
	}

	d := p.CheckAddr(netip.AddrPortFrom(mapped, 80))
	if d.Allowed {
		t.Fatal("::ffff:169.254.169.254 绕过了元数据黑名单 —— 必须先 Unmap 规范化")
	}
	if d.Rule != "default-deny:cloud-metadata" {
		t.Errorf("命中规则 = %q，期望 default-deny:cloud-metadata（说明规范化后走对了分支）", d.Rule)
	}
}

// TestDefaultDenyWhenNoRuleMatches 确认默认拒绝，而不是默认放行。
func TestDefaultDenyWhenNoRuleMatches(t *testing.T) {
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}})

	if d := p.CheckAddr(netip.MustParseAddrPort("8.8.8.8:53")); d.Allowed {
		t.Error("未命中任何 allow 的公网地址必须被拒（默认拒绝）")
	}
	if d := p.CheckAddr(netip.MustParseAddrPort("192.168.2.1:80")); d.Allowed {
		t.Error("相邻但不在 allow 段内的地址必须被拒")
	}
	if d := p.CheckAddr(netip.MustParseAddrPort("192.168.1.50:80")); !d.Allowed {
		t.Error("allow 段内的地址应当放行")
	}
}

func TestUserDenyBeatsUserAllow(t *testing.T) {
	p := mustPolicy(t, Config{
		Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Deny:  []netip.Prefix{netip.MustParsePrefix("10.1.2.0/24")},
	})

	if d := p.CheckAddr(netip.MustParseAddrPort("10.1.2.3:80")); d.Allowed {
		t.Error("deny 应当优先于 allow")
	}
	if d := p.CheckAddr(netip.MustParseAddrPort("10.9.9.9:80")); !d.Allowed {
		t.Error("未被 deny 覆盖的 allow 段应当放行")
	}
}

// TestPartialOverlapWithDefaultDenyIsAConfigError 验证「以为开通了、其实开不通」
// 这种沉默失败被转成了显式的配置错误。
//
// 注意区分两种情形（见 New 的文档）：
//   - allow **真包含** deny → 安全，放行（否则用户被迫手工切分 CIDR，那更易错）
//   - allow 与 deny **部分交叠或被其包含** → 配置错误，必须报错
func TestPartialOverlapWithDefaultDenyIsAConfigError(t *testing.T) {
	// 169.254.0.0/16 是永久拒绝段。allow 169.254.1.0/24 被它**包含** ——
	// 用户以为开通了这个 /24，实际一个地址都不通。必须报错。
	_, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("169.254.1.0/24")}})
	if !errors.Is(err, ErrAllowOverlapsDefaultDeny) {
		t.Fatalf("被永久拒绝段包含的 allow 必须报错，得到 %v", err)
	}

	// 位数相同的完全重合，同样是「整段不通」。
	_, err = New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}})
	if !errors.Is(err, ErrAllowOverlapsDefaultDeny) {
		t.Fatalf("与永久拒绝段完全重合的 allow 必须报错，得到 %v", err)
	}
}

// TestAllowStrictlyContainingDefaultDenyIsAccepted 验证真包含的情形被放行，
// 且判定时拒绝段仍然优先。
//
// 这是必须放行的：把 fc00::/7 减去一个 /32 需要十几条子段，
// 强迫用户手算 CIDR 只会让他算错、反而扩大暴露面。
func TestAllowStrictlyContainingDefaultDenyIsAccepted(t *testing.T) {
	p, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("fc00::/7")}})
	if err != nil {
		t.Fatalf("allow 真包含 deny 应当被接受：%v", err)
	}

	// 段内的普通地址放行。
	if d := p.CheckAddr(netip.MustParseAddrPort("[fd12:3456::1]:80")); !d.Allowed {
		t.Errorf("段内普通地址应当放行：%s", d.Reason)
	}
	// 但里面那个元数据地址仍然被拒 —— 拒绝段优先。
	if d := p.CheckAddr(netip.MustParseAddrPort("[fd00:ec2::254]:80")); d.Allowed {
		t.Error("即使被更宽的 allow 包含，永久拒绝段内的地址也必须被拒")
	}
}

func TestNoAllowRulesIsAnError(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoAllowRules) {
		t.Fatalf("err = %v，期望 ErrNoAllowRules（默认拒绝一切会让所有隧道被否决，"+
			"必须在构造时就说清楚而不是让用户猜）", err)
	}
}

func TestDefaultConfigIsUsableAndSafe(t *testing.T) {
	p, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("默认配置必须能构造成功：%v", err)
	}

	// 常见的内网目标应当可用 —— 否则产品第一步就撞墙。
	for _, ok := range []string{"127.0.0.1:8080", "192.168.1.10:80", "10.0.0.5:443", "172.16.0.1:22", "[::1]:8080"} {
		if d := p.CheckAddr(netip.MustParseAddrPort(ok)); !d.Allowed {
			t.Errorf("默认配置应当放行常见内网目标 %s，却拒绝了：%s", ok, d.Reason)
		}
	}
	// 但元数据与公网仍然被拒。
	for _, bad := range []string{"169.254.169.254:80", "100.100.100.200:80", "8.8.8.8:53"} {
		if d := p.CheckAddr(netip.MustParseAddrPort(bad)); d.Allowed {
			t.Errorf("默认配置不该放行 %s", bad)
		}
	}
}

func TestPortRangeEnforcement(t *testing.T) {
	p := mustPolicy(t, Config{
		Allow:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AllowPorts: []PortRange{{Lo: 80, Hi: 80}, {Lo: 8000, Hi: 8100}},
	})

	for _, tc := range []struct {
		port uint16
		want bool
	}{
		{80, true}, {79, false}, {81, false},
		{8000, true}, {8050, true}, {8100, true}, {8101, false},
	} {
		d := p.CheckAddr(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), tc.port))
		if d.Allowed != tc.want {
			t.Errorf("端口 %d：Allowed=%v，期望 %v", tc.port, d.Allowed, tc.want)
		}
	}
}

func TestInvalidPortRangeRejected(t *testing.T) {
	base := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if _, err := New(Config{Allow: base, AllowPorts: []PortRange{{Lo: 100, Hi: 50}}}); err == nil {
		t.Error("下界大于上界的端口范围应当被拒")
	}
	if _, err := New(Config{Allow: base, AllowPorts: []PortRange{{Lo: 0, Hi: 100}}}); err == nil {
		t.Error("端口 0 应当被拒")
	}
}

// ── DNS 重绑定 ──────────────────────────────────────────────────────────────

// fakeResolver 让我们精确控制一个主机名解析出什么。
type fakeResolver struct {
	addrs []netip.Addr
	err   error
	calls int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return r.addrs, nil
}

// TestDialRejectsHostnameResolvingToMetadata 验证 DNS 重绑定被挡住。
//
// 攻击形态：目标写成一个看起来正常的主机名，但它解析到 169.254.169.254。
// 只在配置解析时校验主机名是无效的 —— 必须校验**解析结果**。
func TestDialRejectsHostnameResolvingToMetadata(t *testing.T) {
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	r := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	p.resolver = r

	_, err := p.DialContext(context.Background(), "tcp", "innocent-looking.example.com:80")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("解析到元数据地址的主机名必须被拒，得到 %v", err)
	}
	if denied.Decision.Rule != "default-deny:cloud-metadata" {
		t.Errorf("命中规则 = %q，期望 default-deny:cloud-metadata", denied.Decision.Rule)
	}
}

// TestDialChecksEveryResolvedCandidate 验证多地址主机名的每个候选都被单独判定。
//
// 攻击形态：一个主机名同时解析出一个合法地址和一个元数据地址，
// 指望实现只检查第一个就放过后面的。
func TestDialChecksEveryResolvedCandidate(t *testing.T) {
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	// 第一个是元数据（必须被跳过），第二个不在 allow 内（也必须被拒）。
	p.resolver = &fakeResolver{addrs: []netip.Addr{
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("8.8.8.8"),
	}}

	_, err := p.DialContext(context.Background(), "tcp", "mixed.example.com:80")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("所有候选都不合法时应当返回 ErrDenied，得到 %v", err)
	}
}

// TestDialUsesResolvedLiteralNotHostname 是防 DNS 重绑定的核心断言。
//
// 它证明拨号用的是**已判定的 IP 字面量**而不是原始主机名 ——
// 因为没有第二次解析，resolve 与 dial 之间就不存在可被利用的时间窗。
//
// 做法：让 resolver 返回一个可用的回环地址，起一个真实监听器，
// 然后断言 resolver 只被调用了一次（若实现把 host 交给 net.Dialer，
// 系统会再解析一次，但那次不经过我们的 fakeResolver —— 所以我们改为
// 断言连接确实落在我们预期的那个字面量上）。
func TestDialUsesResolvedLiteralNotHostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		c.Close()
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	wantAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))

	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	r := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	p.resolver = r

	conn, err := p.DialContext(context.Background(), "tcp",
		net.JoinHostPort("resolves-to-loopback.example.com", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("合法目标应当拨通：%v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("监听器没有收到连接")
	}

	if r.calls != 1 {
		t.Errorf("resolver 被调用 %d 次，期望恰好 1 次（多于一次说明存在第二个解析窗口）", r.calls)
	}
	// 连接的远端必须是那个字面量。
	if got := conn.RemoteAddr().String(); got != wantAddr {
		t.Errorf("远端 = %s，期望 %s", got, wantAddr)
	}
}

// TestDialWithIPLiteralSkipsResolution 确认目标本就是 IP 时不做 DNS 查询。
func TestDialWithIPLiteralSkipsResolution(t *testing.T) {
	p := mustPolicy(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	r := &fakeResolver{}
	p.resolver = r

	// 目标不在 allow 内，会被拒；重点是不该触发解析。
	_, _ = p.DialContext(context.Background(), "tcp", "8.8.8.8:53")
	if r.calls != 0 {
		t.Errorf("IP 字面量不该触发 DNS 解析，却调用了 %d 次", r.calls)
	}
}

func TestDialRejectsMalformedTarget(t *testing.T) {
	p := mustPolicy(t, DefaultConfig())
	for _, bad := range []string{"no-port", "host:notaport", "host:99999", ""} {
		if _, err := p.DialContext(context.Background(), "tcp", bad); err == nil {
			t.Errorf("目标 %q 应当被拒", bad)
		}
	}
}

func TestIPNetworkMapping(t *testing.T) {
	for in, want := range map[string]string{
		"tcp": "ip", "udp": "ip",
		"tcp4": "ip4", "udp4": "ip4",
		"tcp6": "ip6", "udp6": "ip6",
	} {
		if got := ipNetwork(in); got != want {
			t.Errorf("ipNetwork(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestDeniedTargetIsShownInItsCanonicalForm(t *testing.T) {
	// 这句拒绝原因会原样传到控制台给用户看（经 agent 的 target_denied）。
	// 若 Target 用 IPv4-in-IPv6 映射形式，同一句话里就会出现
	// [::ffff:127.0.0.1] 与 127.0.0.1 两种写法 —— 用户会以为是两个地址。
	//
	// 这是 e2e 补「拨号期否决」用例时从日志里看出来的。
	p, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}})
	if err != nil {
		t.Fatal(err)
	}

	// localhost 在双栈机器上常解析出 ::ffff:127.0.0.1。
	_, err = p.DialContext(context.Background(), "tcp", "localhost:9")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("应当被策略拒绝，得到 %#v", err)
	}
	if strings.Contains(denied.Target, "::ffff:") {
		t.Errorf("拒绝原因里的地址应当规范化，实际：%s", denied.Target)
	}
	if strings.Contains(denied.Error(), "::ffff:") {
		t.Errorf("整句拒绝原因不该出现映射形式，实际：%s", denied.Error())
	}
}

func TestResolveAllowedAppliesTheSameVerdictAsDialContext(t *testing.T) {
	// UDP 路径用 ResolveAllowed 而不是 DialContext（它要 *net.UDPConn）。
	// 两者若判定不一致，攻击者只要把隧道的 l4 从 tcp 改成 udp 就能穿过
	// SSRF 防线 —— 一道防线有两份实现，等于迟早只剩一份是对的。
	p, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 云元数据地址在两条路上都必须被拒，且都给出 *ErrDenied。
	const metadata = "169.254.169.254:80"
	if _, err := p.ResolveAllowed(ctx, "udp", metadata); err == nil {
		t.Fatal("ResolveAllowed 必须拒绝云元数据地址")
	} else {
		var denied *ErrDenied
		if !errors.As(err, &denied) {
			t.Fatalf("应当是 *ErrDenied，实际 %#v", err)
		}
	}
	if _, err := p.DialContext(ctx, "tcp", metadata); err == nil {
		t.Fatal("DialContext 必须拒绝云元数据地址")
	}

	// 允许的地址应当原样返回字面量，供调用方直接拨。
	ap, err := p.ResolveAllowed(ctx, "udp", "127.0.0.1:5004")
	if err != nil {
		t.Fatalf("回环地址应当被允许：%v", err)
	}
	if ap.String() != "127.0.0.1:5004" {
		t.Fatalf("返回的应当是已判定的字面量，实际 %s", ap)
	}
}

func TestResolveAllowedReturnsALiteralNotAHostname(t *testing.T) {
	// 返回主机名会让调用方再解析一次 —— 那正是 DNS 重绑定的时间窗。
	p, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}

	ap, err := p.ResolveAllowed(context.Background(), "udp", "localhost:5004")
	if err != nil {
		t.Fatalf("localhost 应当被允许：%v", err)
	}
	if !ap.Addr().IsLoopback() {
		t.Fatalf("返回的应当是解析后的回环地址，实际 %s", ap)
	}
	// 必须是一个真正的 IP 字面量，而不是任何形式的名字。
	if _, err := netip.ParseAddrPort(ap.String()); err != nil {
		t.Fatalf("返回值必须能被当作字面量解析：%v", err)
	}
}
