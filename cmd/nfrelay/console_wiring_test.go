package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/console"
)

// TestConsoleOptionsCarryEveryFlag 钉住「flag 真的到了 Options」。
//
// # 为什么这条测试必须存在
//
// 本轮修的那个 bug 就是这一步漏了一个字段：`Options.Secure` **从来没有被赋过值**，
// 于是 __Host- 前缀、Cookie 的 Secure 属性、HSTS 三样全是死代码 —— 而
// internal/console 那边的测试全绿，因为它们自己构造 Options、自己把 Secure 设成
// true。也就是说「中间件行为对」与「中间件被正确装配」是两件事，
// 而只测前者会让后者静默缺席。
//
// 逐字段断言而不是「构造一次看看不报错」：漏掉一个字段与写对一个字段
// 在编译器眼里长得一模一样。
func TestConsoleOptionsCarryEveryFlag(t *testing.T) {
	rt := newTestRuntime(t)
	cfg := consoleConfig{
		addr:      "127.0.0.1:19443",
		hosts:     "relay.example.com, alt.example.com",
		behindTLS: true,
	}
	got := consoleOptions(cfg, nil, rt, nil, quietLog())

	if got.BindAddr != cfg.addr {
		t.Errorf("BindAddr = %q，期望 %q", got.BindAddr, cfg.addr)
	}
	if !got.Secure {
		t.Error("Secure 没被赋值 —— 这正是本轮修的那个 bug：" +
			"__Host- 前缀与 Cookie 的 Secure 属性会全部变成死代码，" +
			"而 internal/console 的测试照样全绿（它们自己设 Secure）")
	}
	if want := []string{"relay.example.com", "alt.example.com"}; !slices.Equal(got.AllowedHosts, want) {
		t.Errorf("AllowedHosts = %v，期望 %v（逗号分隔且要去空白）", got.AllowedHosts, want)
	}
	if got.Snapshot == nil {
		t.Error("Snapshot 没接上 —— 控制台会看不到任何运行时状态")
	}
	if got.Settings == nil {
		t.Error("Settings 没接上 —— 设置页会空")
	}
	if got.Log == nil {
		t.Error("Log 没接上")
	}

	// 反面：默认不加固。默认就加固会让明文 loopback 形态直接登不上去
	//（浏览器不保存带 Secure 的 Cookie）。
	if consoleOptions(consoleConfig{addr: "127.0.0.1:9443"}, nil, rt, nil, quietLog()).Secure {
		t.Error("默认必须**不**加固 —— 默认形态是明文 loopback，" +
			"无条件加 Secure 会让浏览器不保存 Cookie，也就是登不上去")
	}
}

// TestHardeningSettingIsVisibleInTheSupportBundle 钉住那个键名决定。
//
// 断言**实际产出的设置项**，不是一个写死的字符串字面量：写死字面量的测试
// 在有人把 probe.go 里的键改名之后照样绿（实测过，是一次真实的假绿）。
//
// 为什么这一项必须在支持包里可见：它是「登录返回 200 但下一个请求 401」
// 这个现象唯一的诊断依据（Cookie 带了 Secure 而实际是明文传输，
// 浏览器于是根本不保存它，而两侧日志都显示成功）。支持包按键名脱敏，
// 键里含 cookie/key/token 就会变成「（已脱敏）」—— 最需要它的那次排障恰好看不到。
func TestHardeningSettingIsVisibleInTheSupportBundle(t *testing.T) {
	rt := newTestRuntime(t)
	rt.consoleHardened = true

	var found *console.SettingItem
	for _, g := range rt.Settings() {
		for i, it := range g.Items {
			// 按**语义**找它，不按键名 —— 键名正是被测的对象。
			if g.Group == "auth" && it.SourceRef == "-console-behind-tls-proxy" {
				found = &g.Items[i]
			}
		}
	}
	if found == nil {
		t.Fatal("设置页里没有报告控制台加固状态的项 —— " +
			"「登录 200 随后 401」这个现象就没有任何诊断依据了")
	}
	if console.IsSensitiveSettingKey(found.Key) {
		t.Errorf("加固状态的键名 %q 会被支持包脱敏成「（已脱敏）」—— "+
			"换一个不含 secret/key/token/password/credential/cookie 的名字。"+
			"这一项是纯诊断，没有任何秘密。", found.Key)
	}
	if found.Value == "" {
		t.Error("值不能为空 —— 空值在界面上与「读不到」无法区分")
	}
}

// TestValidateListenAddrRejectsWhatSilentlyBecomesPort80 钉住一条最阴的输入。
//
// http.Server 与 net.Listen 对空 Addr 的默认是 **":80"**。也就是说
// `-console ""` 不是「关掉控制台」，而是把控制台开到 80 端口上：
// 它会与 -acme-http 抢端口（报错文案指向 ACME），而 warnConsoleExposure
// 那条暴露告警**一条都不会打**（空串既不是 loopback 也解析不出主机），
// 日志里毫无线索。而 80 通常对公网开放。
//
// 本仓没有「关闭控制台」的开关，所以空串一定是笔误。
func TestValidateListenAddrRejectsWhatSilentlyBecomesPort80(t *testing.T) {
	for _, bad := range []string{"", "   ", "0.0.0.0", "127.0.0.1", "relay.example.com"} {
		err := ValidateListenAddr("-console", bad)
		if err == nil {
			t.Errorf("%q 应当被拒 —— 标准库会把它回落成 \":80\"，而那不是「关闭」", bad)
			continue
		}
		if !strings.Contains(err.Error(), "-console") {
			t.Errorf("错误信息里必须出现是哪个 flag 出的问题：%v", err)
		}
	}
	for _, ok := range []string{"127.0.0.1:9443", "0.0.0.0:9443", ":9443", "[::1]:9443"} {
		if err := ValidateListenAddr("-console", ok); err != nil {
			t.Errorf("%q 是合法的，不该被拒：%v", ok, err)
		}
	}
}

// TestValidatePortRangeRejectsSilentTruncation 钉住 uint16 强转那一处。
//
// flag.Uint 收下的值被强转成 uint16 送进 TURN 配置。写 70000 会静默变成 4464
// —— 于是中继端口落在一个你没预期、防火墙也没放通的低号段，
// 现象是「分配成功但媒体不通」，而启动日志一切正常。
func TestValidatePortRangeRejectsSilentTruncation(t *testing.T) {
	for _, c := range []struct{ lo, hi uint }{
		{70000, 70100}, // 超 uint16 → 会被截断
		{0, 49400},     // 0 会静默退回默认
		{49160, 65536}, // 上界超界
		{49400, 49160}, // 下界大于上界
	} {
		if err := ValidatePortRange("TURN 端口", c.lo, c.hi); err == nil {
			t.Errorf("(%d,%d) 应当被拒", c.lo, c.hi)
		}
	}
	if err := ValidatePortRange("TURN 端口", 49160, 49400); err != nil {
		t.Errorf("默认范围不该被拒：%v", err)
	}
}
