package acmecert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// knownHosts 是 HostChecker 的测试实现。
type knownHosts map[string]bool

func (k knownHosts) KnowsHost(name string) bool { return k[name] }

func newManager(t *testing.T, mutate func(*Config)) *Manager {
	t.Helper()

	cfg := Config{
		Enabled:    true,
		Email:      "ops@example.com",
		StorageDir: t.TempDir(),
		Hosts:      knownHosts{"web.example.com": true, "api.example.com": true},
		Log:        quiet(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("装配 ACME 失败：%v", err)
	}
	if m == nil {
		t.Fatal("Enabled=true 时不该返回 nil")
	}
	return m
}

func TestDisabledReturnsNilManagerNotAnError(t *testing.T) {
	// 未启用是**正常状态**（默认就是），不是错误。返回错误会让调用方
	// 要么忽略它、要么在启动时报一个假故障。
	m, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatalf("未启用时不该报错：%v", err)
	}
	if m != nil {
		t.Fatal("未启用时应当返回 nil manager")
	}
}

func TestNewRefusesConfigurationsThatWouldBurnTheRateLimit(t *testing.T) {
	base := func() Config {
		return Config{
			Enabled: true, Email: "ops@example.com",
			StorageDir: t.TempDir(), Hosts: knownHosts{}, Log: quiet(),
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		why    string
	}{
		{"缺邮箱", func(c *Config) { c.Email = "" },
			"CA 用邮箱发到期提醒；没有它，续期失败时没有任何人会知道"},
		{"缺存储目录", func(c *Config) { c.StorageDir = "" },
			"certmagic 的默认路径在容器里（HOME 为空）会退化成当前工作目录，" +
				"重建容器即丢证书，下次启动全量重签，直奔速率限制"},
		{"缺域名判断依据", func(c *Config) { c.Hosts = nil },
			"没有依据时会对任意 SNI 申请证书 —— 那正是 CA 速率限制存在的原因"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatalf("这个配置应当被拒：%s", tc.why)
			}
		})
	}
}

func TestDefaultCAIsStagingNotProduction(t *testing.T) {
	// **刻意反 certmagic 的默认**（它默认生产环境）。
	//
	// 调试时误打生产配额是不可逆的：Let's Encrypt 的 failed-validation
	// 按小时计、重复证书按周计。让生产成为**显式**选择。
	m := newManager(t, nil)
	if !m.IsStaging() {
		t.Fatalf("默认 CA 应当是 staging，实际 %s", m.cfg.CA)
	}
}

func TestDecisionRejectsNamesThatCanNeverGetAPublicCert(t *testing.T) {
	// certmagic 内部只调**宽松版** SubjectQualifiesForCert，那个函数不检查 IP。
	// 而空 SNI 时它会拿**本地连接 IP** 当域名去签发
	//（getNameFromClientHello → localIPFromConn）。
	//
	// 本产品场景二的扫端口机器人与「ESP32 只认裸 IPv4」都会命中这条路径，
	// 所以这道闸门必须自己调严格版。
	m := newManager(t, nil)
	ctx := context.Background()

	cases := []struct{ name, why string }{
		{"203.0.113.9", "IPv4 字面量 —— 空 SNI 时 certmagic 会拿它去签"},
		{"2001:db8::1", "IPv6 字面量"},
		{"localhost", "本地名，公网 CA 不会签"},
		{"relay.local", ".local 是 mDNS 保留"},
		{"box.internal", ".internal 是内部保留（RFC 8375 之后正式化）"},
		{"a.home.arpa", ".home.arpa 是家庭网络保留"},
	}
	for _, c := range cases {
		err := m.decide(ctx, c.name)
		if err == nil {
			t.Errorf("%s 必须被拒（%s）", c.name, c.why)
			continue
		}
		if !errors.Is(err, ErrUnqualified) {
			t.Errorf("%s 应当以「不合资格」被拒，实际：%v", c.name, err)
		}
	}
	if got := m.Stats().DeniedUnqualified.Load(); got != int64(len(cases)) {
		t.Errorf("不合资格计数应为 %d，实际 %d", len(cases), got)
	}
	// 这些不该被记成「不在路由表」—— 两者的处置完全不同
	//（前者是背景噪声，后者可能是有人在扫）。
	if got := m.Stats().DeniedUnknownHost.Load(); got != 0 {
		t.Errorf("不合资格不该被记成未知域名，实际 %d", got)
	}
}

func TestDecisionRejectsDomainsThatAreNotOurBusiness(t *testing.T) {
	// certmagic 会为**任何**握手里出现的名字申请证书。任何人拿我们的 IP
	// 发一个带随机 SNI 的握手，就能让我们去找 CA 要一张证书 ——
	// 几百次之后 CA 把我们限速，真域名也签不出来。
	m := newManager(t, nil)
	ctx := context.Background()

	err := m.decide(ctx, "attacker-chosen.example.net")
	if err == nil {
		t.Fatal("不在路由表里的域名必须被拒")
	}
	if !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("应当以「不在路由表」被拒，实际：%v", err)
	}
	if got := m.Stats().DeniedUnknownHost.Load(); got != 1 {
		t.Errorf("未知域名计数应为 1，实际 %d", got)
	}

	// 在路由表里的照常通过。
	if err := m.decide(ctx, "web.example.com"); err != nil {
		t.Fatalf("已注册域名不该被拒：%v", err)
	}
}

func TestPerNameBudgetStopsRepeatedIssuanceOfTheSameDomain(t *testing.T) {
	// 映射 CA 的重复证书限制（LE 是 5 次/周/精确域名集合）。
	// 我们的预算要**比它更紧**，这样撞到的是我们自己的闸门
	//（可观测、错误信息可解释），而不是 CA 的（不可观测、恢复期以周计）。
	m := newManager(t, func(c *Config) {
		c.PerNameIssuances = 3
		c.PerNameWindow = time.Hour
	})
	ctx := context.Background()

	for i := range 3 {
		if err := m.decide(ctx, "web.example.com"); err != nil {
			t.Fatalf("第 %d 次不该被拒：%v", i+1, err)
		}
	}
	err := m.decide(ctx, "web.example.com")
	if err == nil {
		t.Fatal("第 4 次应当撞上预算")
	}
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("应当以「撞预算」被拒，实际：%v", err)
	}
	// 错误信息要说清「多少次 / 多长窗口」，否则用户不知道等多久。
	if !contains(err.Error(), "3") {
		t.Errorf("错误信息应当给出用量，实际：%v", err)
	}

	// **别的**域名不受影响：预算是 per-name 的。
	if err := m.decide(ctx, "api.example.com"); err != nil {
		t.Fatalf("另一个域名不该被牵连：%v", err)
	}
}

func TestGlobalBudgetStopsABroadSweepAcrossManyDomains(t *testing.T) {
	// per-name 预算挡不住「每个域名只签一次，但有一千个域名」——
	// 而那正好是 CA 的账户级限制会撞上的形态。
	hosts := knownHosts{}
	names := make([]string, 0, 10)
	for i := range 10 {
		n := string(rune('a'+i)) + ".example.com"
		hosts[n] = true
		names = append(names, n)
	}
	m := newManager(t, func(c *Config) {
		c.Hosts = hosts
		c.PerNameIssuances = 5
		c.GlobalIssuances = 4
	})
	ctx := context.Background()

	var allowed int
	for _, n := range names {
		if err := m.decide(ctx, n); err == nil {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("全局预算 4，应当只放行 4 次，实际 %d", allowed)
	}
	if got := m.Stats().DeniedBudget.Load(); got != 6 {
		t.Errorf("撞预算计数应为 6，实际 %d", got)
	}
}

func TestBudgetCountsFailuresToo(t *testing.T) {
	// **失败也要扣配额。**
	//
	// CA 的 failed-validation 限制是按**尝试次数**算的，而 certmagic
	// 没有失败退避 —— 只在成功后记账等于让失败无限重试，
	// 那正是最容易烧掉配额的路径。
	//
	// 所以记账发生在 decide 里（放行时），而不是签发成功之后。
	m := newManager(t, func(c *Config) { c.PerNameIssuances = 2 })
	ctx := context.Background()

	// 两次「放行」——无论后续签发成败，配额都已扣掉。
	for range 2 {
		if err := m.decide(ctx, "web.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.decide(ctx, "web.example.com"); !errors.Is(err, ErrBudget) {
		t.Fatalf("放行过 2 次后应当撞预算（无论那两次是否签成），实际：%v", err)
	}

	used, _, _ := m.Budget()
	if used["web.example.com"] != 2 {
		t.Errorf("用量应为 2，实际 %d", used["web.example.com"])
	}
}

func TestFailureCooldownStopsARetryStormOnAMisconfiguredDomain(t *testing.T) {
	// certmagic 没有失败负缓存：一个被 CA 拒掉的域名，下一次握手会原样重试。
	// 而一个 DNS 没指过来的域名会**每次握手都失败**——
	// 浏览器自动重试几次就能把 failed-validation 配额烧掉。
	m := newManager(t, func(c *Config) {
		c.PerNameIssuances = 100 // 排除预算的干扰
		c.FailureCooldown = time.Hour
	})
	ctx := context.Background()

	if err := m.decide(ctx, "web.example.com"); err != nil {
		t.Fatal(err)
	}
	m.NoteFailure("web.example.com")

	err := m.decide(ctx, "web.example.com")
	if err == nil {
		t.Fatal("刚失败过的域名应当在静默期内被拒")
	}
	if !errors.Is(err, ErrRecentFailure) {
		t.Fatalf("应当以「刚失败过」被拒，实际：%v", err)
	}
	// 错误信息要说还剩多久，否则用户只知道「又不行」。
	if !contains(err.Error(), "还剩") {
		t.Errorf("应当告知剩余静默时间，实际：%v", err)
	}
	if got := m.Stats().DeniedRecentFailure.Load(); got != 1 {
		t.Errorf("静默期拒绝计数应为 1，实际 %d", got)
	}

	// 别的域名不受牵连。
	if err := m.decide(ctx, "api.example.com"); err != nil {
		t.Fatalf("一个域名失败不该影响另一个：%v", err)
	}
}

func TestBudgetAndFailureTablesDoNotGrowWithoutBound(t *testing.T) {
	// 这两张表的键是**握手里出现的域名** —— 也就是说，键由任何能连上
	// 443 的人指定。不清理就是一个可被外部驱动的内存泄漏，
	// 而中继是长期运行的进程。
	hosts := knownHosts{}
	for i := range 50 {
		hosts[string(rune('a'+i%26))+string(rune('a'+i/26))+".example.com"] = true
	}
	m := newManager(t, func(c *Config) {
		c.Hosts = hosts
		c.PerNameWindow = 50 * time.Millisecond
		c.FailureCooldown = 50 * time.Millisecond
		c.GlobalIssuances = 1000
		c.PerNameIssuances = 1000
	})
	ctx := context.Background()

	for n := range hosts {
		_ = m.decide(ctx, n)
		m.NoteFailure(n)
	}
	if got := len(m.issued); got == 0 {
		t.Fatal("测试前置条件不成立：没有记录任何签发")
	}

	// 等窗口过去，再触发一次清理。
	time.Sleep(120 * time.Millisecond)
	_ = m.decide(ctx, "web.example.com")

	m.mu.Lock()
	issued, failed := len(m.issued), len(m.failed)
	m.mu.Unlock()

	// 只剩刚刚那一次（web.example.com 不在 hosts 里所以会被拒，
	// 但清理已经跑过了）。
	if issued > 2 {
		t.Errorf("过期的签发记录应当被清掉，还剩 %d 条", issued)
	}
	if failed > 2 {
		t.Errorf("过期的失败记录应当被清掉，还剩 %d 条", failed)
	}
}

func TestBudgetReportsUsageForTheConsole(t *testing.T) {
	// 控制台要能显示「还剩几次」。撞上限时用户的第一个问题是
	// 「我还能签几次、什么时候恢复」——没有这个数字就只能猜。
	m := newManager(t, func(c *Config) { c.GlobalIssuances = 7 })
	ctx := context.Background()

	_ = m.decide(ctx, "web.example.com")
	_ = m.decide(ctx, "api.example.com")

	perName, globalUsed, globalLimit := m.Budget()
	if perName["web.example.com"] != 1 || perName["api.example.com"] != 1 {
		t.Errorf("per-name 用量不对：%v", perName)
	}
	if globalUsed != 2 || globalLimit != 7 {
		t.Errorf("全局用量应为 2/7，实际 %d/%d", globalUsed, globalLimit)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestStaticHostsMatchesExactlyAndCaseInsensitively(t *testing.T) {
	// turns: 的域名不是隧道，查不到网关路由表 —— 但它同样需要一张可信证书
	//（客户端会校验，自签直接握手失败）。
	h := StaticHosts{"turn.example.com", "Alt.Example.COM."}

	cases := []struct {
		name string
		want bool
		why  string
	}{
		{"turn.example.com", true, "逐字命中"},
		{"TURN.example.com", true, "DNS 域名大小写无关"},
		{"turn.example.com.", true, "根点是合法写法，certmagic 可能带也可能不带"},
		{"alt.example.com", true, "配置里带了大小写与根点，也该匹配上"},
		{"evil-turn.example.com", false,
			"必须精确匹配 —— 后缀匹配会让 evil-example.com 命中 example.com"},
		{"a.turn.example.com", false, "子域不算"},
		{"", false, "空 SNI"},
	}
	for _, c := range cases {
		if got := h.KnowsHost(c.name); got != c.want {
			t.Errorf("KnowsHost(%q)=%v，想要 %v（%s）", c.name, got, c.want, c.why)
		}
	}
}

func TestAnyOfUnionsSourcesAndSkipsNils(t *testing.T) {
	// 调用方常有「TURN 没启用所以没有 turns: 域名」这种情形。
	// 让 nil 在这里被吸收，比让每个调用点自己判空更不容易漏 ——
	// 漏一个的后果是 nil 接口调用直接 panic 在 TLS 握手里。
	both := AnyOf(knownHosts{"a.example.com": true}, nil, StaticHosts{"b.example.com"})
	for _, n := range []string{"a.example.com", "b.example.com"} {
		if !both.KnowsHost(n) {
			t.Errorf("%s 应当被认识", n)
		}
	}
	if both.KnowsHost("c.example.com") {
		t.Error("没有任何来源认识 c.example.com")
	}

	// 全 nil 也不能 panic，且必须一律不认（安全默认）。
	if AnyOf(nil, nil).KnowsHost("a.example.com") {
		t.Error("没有任何来源时必须一律不认")
	}
}

func TestNilHostCheckerInAnyOfStillRefusesEverything(t *testing.T) {
	// New 会拒绝 Hosts=nil，但 AnyOf(nil) 返回的是一个**非 nil** 接口值，
	// 于是它能通过 New 的判空。那必须仍然是「一律拒」而不是「一律放」。
	m, err := New(Config{
		Enabled: true, Email: "ops@example.com",
		StorageDir: t.TempDir(), Hosts: AnyOf(), Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.decide(context.Background(), "web.example.com"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("空的域名来源必须一律拒，实际：%v", err)
	}
}

func TestGateDenialsDoNotOpenTheFailureCooldown(t *testing.T) {
	// 闸门自己的拒绝**不是**签发失败：那些请求根本没打到 CA。
	//
	// 记成失败的后果是静默期被无限续期 —— 每次握手都被闸门拒 →
	// 每次都刷新 failed[name] → 永远出不来。而且它会把「我们主动拒了」
	// 写成「CA 拒了我们」，那是两种完全不同的处置。
	m := newManager(t, nil)

	cases := []struct {
		name string
		err  error
	}{
		{"ip-literal", fmt.Errorf("certificate is not allowed for server name 203.0.113.9: "+
			"decision func: %w", ErrUnqualified)},
		{"unknown-host", fmt.Errorf("wrapped: %w", ErrUnknownHost)},
		{"budget", fmt.Errorf("wrapped: %w", ErrBudget)},
		{"already-cooling", fmt.Errorf("wrapped: %w", ErrRecentFailure)},
	}
	for _, c := range cases {
		m.noteIfIssuanceFailure("web.example.com", c.err)
	}

	m.mu.Lock()
	n := len(m.failed)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("闸门拒绝不该进负缓存表，实际留下 %d 条", n)
	}
	if got := m.Stats().IssueFailed.Load(); got != 0 {
		t.Errorf("闸门拒绝不该记成签发失败，实际 %d", got)
	}
}

func TestRealIssuanceFailureOpensTheFailureCooldown(t *testing.T) {
	// 反面：CA 真的拒了我们，配额已经扣掉了，必须开静默期。
	// 不开的话每次握手都会再打一次 CA —— 而记账发生在放行时，
	// 刷几下页面就够 5 次，该域名 7 天的预算在几秒内烧光。
	m := newManager(t, nil)

	m.noteIfIssuanceFailure("web.example.com",
		errors.New("acme: authorization error: urn:ietf:params:acme:error:dns"))

	if got := m.Stats().IssueFailed.Load(); got != 1 {
		t.Fatalf("真失败应当记 1 次，实际 %d", got)
	}
	if err := m.decide(context.Background(), "web.example.com"); !errors.Is(err, ErrRecentFailure) {
		t.Fatalf("真失败之后该域名应当在静默期内，实际：%v", err)
	}
}

func TestEmptySNIDoesNotPopulateTheFailureTable(t *testing.T) {
	// 负缓存表的键是外部可指定的。空 SNI 时 certmagic 自己会回落到
	// **本地连接 IP**，那个名字必然被闸门①拒掉、永远不该进表 ——
	// 否则场景二那些用裸 IP 直连的设备会持续往这张表里塞条目。
	m := newManager(t, nil)

	m.noteIfIssuanceFailure(nameFromHello(&tls.ClientHelloInfo{ServerName: ""}),
		errors.New("some real failure"))
	m.noteIfIssuanceFailure(nameFromHello(nil), errors.New("some real failure"))

	m.mu.Lock()
	n := len(m.failed)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("空 SNI 不该在负缓存表里留下条目，实际 %d 条", n)
	}
}

func TestServerNameIsNormalizedBeforeUse(t *testing.T) {
	// 大小写与根点都是合法写法。不归一化的话
	// "WEB.example.com." 与 "web.example.com" 会各占一份预算与一份静默期,
	// 于是攻击者靠大小写变体就能把 per-name 预算绕成无限。
	for _, in := range []string{"WEB.Example.COM.", "web.example.com", "Web.Example.Com"} {
		if got := nameFromHello(&tls.ClientHelloInfo{ServerName: in}); got != "web.example.com" {
			t.Errorf("nameFromHello(%q)=%q，想要 web.example.com", in, got)
		}
	}
}

func TestPerNameBudgetCannotBeBypassedWithNameVariants(t *testing.T) {
	// certmagic 的 normalizedName 只做 ToLower + TrimSpace，**不去根点**
	//（核实过 handshake.go:954-956）。预算若跟着它分桶，
	// 攻击者靠加一个点就能多拿一份 5 次配额。
	// 用 StaticHosts 而不是 knownHosts：后者是精确 map 查找，
	// 会让「大小写变体被闸门②拦下」与「变体被归一化成同一个预算键」
	// 这两件事混在一起 —— 那样测试就说不清它到底在验哪个。
	m := newManager(t, func(c *Config) {
		c.PerNameIssuances = 2
		c.Hosts = StaticHosts{"web.example.com"}
	})
	ctx := context.Background()

	variants := []string{"web.example.com", "web.example.com.", "WEB.example.com", " web.example.com "}
	var allowed int
	for _, v := range variants {
		if err := m.decide(ctx, v); err == nil {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("四个写法是同一个域名，总共只该放行 2 次，实际 %d", allowed)
	}

	used, _, _ := m.Budget()
	if len(used) != 1 {
		t.Fatalf("预算表里只该有一个键，实际 %d 个：%v", len(used), used)
	}
	if used["web.example.com"] != 2 {
		t.Errorf("键应当是归一化后的名字，实际：%v", used)
	}
}
