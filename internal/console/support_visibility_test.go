package console

import (
	"log/slog"
	"strings"
	"testing"
)

// TestDiagnosticSettingsSurviveRedaction 钉住一条容易被脱敏层意外吃掉的诊断项。
//
// # 为什么单独为它写一条测试
//
// 支持包按**键名**脱敏：键里含 secret/key/token/password/credential/cookie 的项，
// 值一律换成「（已脱敏）」。那道白名单是对的（它挡的是「将来某处不小心把密钥
// 塞进设置视图」），但它有一个反作用：一个名字里带 cookie 的**纯诊断项**
// 也会被吃掉。
//
// 具体到本仓：`console_session_hardening` 报告控制台有没有按「前置 TLS 反代」
// 加固。它是「登录返回 200 但下一个请求 401」这个现象**唯一**的诊断依据
// （Cookie 带了 Secure 而实际是明文传输，浏览器于是根本不保存它，
// 而两侧日志都显示成功）。如果它在支持包里显示成「（已脱敏）」，
// 那么最需要它的那次排障恰好看不到它。
//
// 所以这个键刻意**不叫** console_cookie_secure。这条测试守的就是那个命名决定 ——
// 否则下一个人会为了「读起来更准确」把它改成含 cookie 的名字，
// 而 make check 全绿。
func TestDiagnosticSettingsSurviveRedaction(t *testing.T) {
	// 这些是必须在支持包里**可见**的诊断项。
	for _, key := range []string{
		"console_session_hardening",
		"console_bind",
		"agent_handshake",
	} {
		if isSensitiveKey(key) {
			t.Errorf("%q 被脱敏层吃掉了 —— 它是纯诊断项，"+
				"在支持包里变成「（已脱敏）」会让最需要它的那次排障看不到它。"+
				"换一个不含 secret/key/token/password/credential/cookie 的名字。", key)
		}
	}

	// 反面：真正该被脱敏的必须仍然被脱敏 —— 上面那条不能靠削弱白名单来满足。
	for _, key := range []string{
		"turn_secret", "session_key", "enrol_token", "admin_password",
		"agent_credential", "csrf_cookie",
	} {
		if !isSensitiveKey(key) {
			t.Errorf("%q 没被脱敏 —— 白名单被削弱了", key)
		}
	}

	// 端到端确认一次：脱敏之后诊断项的值还在。
	got := redactSettings([]SettingsGroup{{
		Group: "auth",
		Items: []SettingItem{
			{Key: "console_session_hardening", Value: "已加固（会话 Cookie 带 Secure）"},
			{Key: "turn_secret", Value: "super-secret-value"},
		},
	}})
	if len(got) != 1 || len(got[0].Items) != 2 {
		t.Fatalf("脱敏改变了结构：%+v", got)
	}
	if !strings.Contains(got[0].Items[0].Value, "已加固") {
		t.Errorf("诊断项的值被吃掉了：%q", got[0].Items[0].Value)
	}
	if strings.Contains(got[0].Items[1].Value, "super-secret") {
		t.Errorf("敏感项没被脱敏：%q", got[0].Items[1].Value)
	}
}

// TestWarnRedactedDiagnosticsOnlyFlagsWhatWeControl 钉住这条启动自检的判据。
//
// 它必须**只**报「名字由我们自己控制的项」。provenance=console 的项是控制台
// 写入的值，可能真的含密钥，被脱敏是正确的 —— 对它们告警就是狼来了，
// 而一条会误报的告警一周之后就被所有人忽略。
func TestWarnRedactedDiagnosticsOnlyFlagsWhatWeControl(t *testing.T) {
	var buf strings.Builder
	s, _ := newTestServerWith(t, func(o *Options) {
		o.Log = newTextLogger(&buf)
	})

	s.WarnRedactedDiagnostics([]SettingsGroup{{
		Group: "auth",
		Items: []SettingItem{
			// 该报：命令行定义的、名字里带 cookie 的纯诊断项。
			{Key: "console_cookie_secure", Value: "已加固", Provenance: ProvenanceEnv},
			// 不该报：名字干净。
			{Key: "console_session_hardening", Value: "已加固", Provenance: ProvenanceEnv},
			// 不该报：控制台写入的密钥，被脱敏是正确的。
			{Key: "turn_secret", Value: "xxx", Provenance: ProvenanceConsole},
		},
	}})

	out := buf.String()
	if !strings.Contains(out, "console_cookie_secure") {
		t.Errorf("命令行定义的、会被脱敏的诊断项必须被报出来：%q", out)
	}
	if strings.Contains(out, "console_session_hardening") {
		t.Errorf("名字干净的项不该被报：%q", out)
	}
	if strings.Contains(out, "turn_secret") {
		t.Errorf("控制台写入的密钥被脱敏是正确的，不该告警（狼来了）：%q", out)
	}
}

// newTextLogger 给需要断言日志内容的测试用。
func newTextLogger(w *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn}))
}
