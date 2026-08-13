package console

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func supportFixture(t *testing.T) (*Server, *store.DB, func(*http.Request) *http.Request) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(Options{DB: db, Log: quiet, Snapshot: &fakeSnapshot{}, Turn: &fakeTurn{}})
	if err != nil {
		t.Fatal(err)
	}
	return s, db, setupAndLogin(t, s)
}

func TestSupportBundleIsNotA404File(t *testing.T) {
	// 在实现之前，前端那个按钮（Diagnostics.tsx 的 <a download>）指向一条
	// **不存在**的路由 —— 于是用户下载到一个内容为 `404 page not found`
	// 的文件，并且很可能把它贴进 issue。
	// 一个假文件比一个明确的「未实现」更糟。
	s, _, auth := supportFixture(t)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/diagnostics/support-bundle", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("支持包端点应当返回 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type 应当是 JSON，实际 %q", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".json") {
		t.Errorf("应当作为附件下发，实际 %q", cd)
	}

	var b SupportBundle
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("支持包必须是合法 JSON：%v\n前 200 字节：%s",
			err, w.Body.String()[:min(200, w.Body.Len())])
	}
	if b.FormatVersion == 0 {
		t.Error("必须带格式版本 —— 将来的解析方要能判断自己认不认识这份文件")
	}
	if b.GeneratedAt == "" {
		t.Error("必须带生成时间")
	}
	if b.Interfaces == nil {
		t.Error("必须报告哪几个可选接口装上了 —— " +
			"「有按钮但接口没装」与「接口装了但报错」的处置完全不同")
	}
}

func TestSupportBundleNeverContainsSecrets(t *testing.T) {
	// 支持包是要**发给别人看**的：贴进 issue、发给同事、丢进工单系统。
	// 所以它的信任边界与数据库快照完全相反 ——
	// store.Backup 刻意不接进这条路径，因为库里有 agent 密钥的**明文**
	//（HMAC 校验需要密钥本身）、argon2id 口令哈希、会话与 CSRF 令牌、
	// 入网令牌哈希、TURN 长期密钥。一份 DB 快照就是这台中继的完整沦陷。
	s, db, auth := supportFixture(t)
	ctx := t.Context()

	// 造一个真实的入网令牌（明文只在签发时出现一次）与一个 agent。
	plainToken, err := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "support-test")
	if err != nil {
		t.Fatal(err)
	}
	agentID, agentKey, err := db.RedeemEnrolToken(ctx, plainToken,
		&store.Agent{Hostname: "home-nas", OS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	// 故意把一个令牌写进事件消息 —— 将来任何一处 AppendEvent 都可能
	// 不小心这样做，而键名白名单挡不住它。
	if err := db.AppendEvent(ctx, store.Event{
		Kind: store.KindAgentEnrolled, Level: store.LevelInfo,
		Subject: agentID,
		Message: "用令牌 " + plainToken + " 入网，密钥 " + agentKey,
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/diagnostics/support-bundle", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d：%s", w.Code, w.Body.String())
	}
	body := w.Body.String()

	// 逐项断言。每一条都是一个具体的泄露路径。
	for _, secret := range []struct{ what, value string }{
		{"入网令牌明文", plainToken},
		{"agent 密钥明文", agentKey},
	} {
		if secret.value == "" {
			continue
		}
		if strings.Contains(body, secret.value) {
			t.Errorf("支持包里出现了%s —— 它是要发给别人看的文件", secret.what)
		}
	}
	// 脱敏标记必须出现：说明脱敏真的跑了，而不是「恰好没有秘密」。
	if !strings.Contains(body, redactedMark) {
		t.Error("事件消息里塞了令牌，支持包里却看不到脱敏标记 —— " +
			"那说明形状匹配没有生效（键名白名单挡不住自由文本里的令牌）")
	}
}

func TestSupportBundleRedactsSensitiveSettingKeys(t *testing.T) {
	// 两道都要：键名匹配挡「spki_pin / secret / token」这类字段，
	// 形状匹配挡「值里恰好带了一个令牌」。少任何一道都会漏。
	if !isSensitiveKey("agent_secret") || !isSensitiveKey("TURN_Key") ||
		!isSensitiveKey("session_cookie") {
		t.Error("键名白名单漏了明显的敏感键")
	}
	if isSensitiveKey("bind") || isSensitiveKey("listeners") {
		t.Error("键名白名单把普通配置项也吃掉了")
	}

	// 形状匹配：入网令牌与长十六进制串。
	for _, in := range []string{
		"用 nf_enrol_deadbeefcafe1234 入网",
		"会话 3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a 过期",
	} {
		if out := redactSecrets(in); !strings.Contains(out, redactedMark) {
			t.Errorf("形状匹配没有脱掉：%q → %q", in, out)
		}
	}
	// 而普通文本不该被吃掉 —— 过度脱敏会让支持包变得没用。
	for _, in := range []string{
		"端口 8443 被占用", "隧道 web-api 状态 active", "127.0.0.1:5004",
	} {
		if out := redactSecrets(in); out != in {
			t.Errorf("正常文本被误脱敏：%q → %q", in, out)
		}
	}
}

func TestSupportBundleFilenameCannotInjectHeaders(t *testing.T) {
	// 版本串来自构建期的 ldflags，理论上可以是任意内容 ——
	// 一个带引号或换行的版本号会把响应头撕开（HTTP 头注入）。
	for _, in := range []string{
		`v1"; evil="`, "v1\r\nX-Evil: 1", "v1/../../etc/passwd", "",
	} {
		got := safeFilenamePart(in)
		if strings.ContainsAny(got, "\"\r\n/;") {
			t.Errorf("safeFilenamePart(%q) = %q —— 仍然含能撕开响应头的字符", in, got)
		}
		if got == "" {
			t.Errorf("safeFilenamePart(%q) 返回空串，会生成一个没有名字的附件", in)
		}
	}
}

func TestSupportBundleExplainsWhatIsMissing(t *testing.T) {
	// 空着一段而不解释，读的人无法区分「这台中继没有这个」与
	// 「导出的时候出错了」—— 而那两者的下一步完全不同。
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "console.db"), Log: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// 刻意**不装** Snapshot / Settings / Turn。
	s, err := New(Options{DB: db, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/diagnostics/support-bundle", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("即使可选接口都没装，支持包也该能生成：%d %s", w.Code, w.Body.String())
	}
	var b SupportBundle
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Omitted) == 0 {
		t.Fatal("三个可选接口都没装，omitted 必须逐条说明为什么 —— " +
			"空着一段不解释，读的人无法区分「没有」与「出错了」")
	}
	for _, want := range []string{"settings", "turn"} {
		found := false
		for _, o := range b.Omitted {
			if strings.Contains(o, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("omitted 里应当说明 %s 为什么缺席：%v", want, b.Omitted)
		}
	}
}

func TestSupportBundleDownloadIsAudited(t *testing.T) {
	// 支持包是**外发**动作，与签发 TURN 凭据同类：
	// 「谁在什么时候导出了一份」必须可追溯。
	s, db, auth := supportFixture(t)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/diagnostics/support-bundle", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d", w.Code)
	}

	evs, err := db.ListEvents(t.Context(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Kind == store.KindSupportBundle {
			if e.Actor == "" {
				t.Error("必须记下是谁导出的")
			}
			return
		}
	}
	t.Fatal("下载支持包必须留痕 —— 它是一次外发，与签发 TURN 凭据同类")
}
