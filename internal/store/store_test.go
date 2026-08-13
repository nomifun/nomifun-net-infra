package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func open(t *testing.T) *DB {
	t.Helper()
	// 测试里静音迁移日志：每个子测试都建一个新库，否则输出被
	// 几十行「迁移完成」淹没，真正的失败信息就看不见了。
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	// 用文件库而不是内存库：内存库的 cache=shared 语义在两个 sql.DB 之间
	// 有微妙差异，而我们要测的正是「写句柄写进去、读池读得到」。
	db, err := Open(Options{Path: filepath.Join(t.TempDir(), "test.db"), Log: quiet})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkTunnel(slug string, port uint16) *tunnel.Tunnel {
	tn := &tunnel.Tunnel{
		ID:         "t-" + slug,
		Slug:       slug,
		ListenPort: port,
		Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	tn.Complete()
	return tn
}

func TestMigrationsRunAndAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.db")

	db, err := Open(Options{Path: path, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("首次 Open: %v", err)
	}
	v1, err := db.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v1 == 0 {
		t.Fatal("迁移后 schema 版本不应为 0")
	}
	db.Close()

	// 再开一次：迁移必须幂等，不能报错也不能重复建表。
	db2, err := Open(Options{Path: path, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("二次 Open（迁移应幂等）: %v", err)
	}
	defer db2.Close()
	v2, _ := db2.SchemaVersion()
	if v2 != v1 {
		t.Errorf("二次打开后版本变为 %d，期望仍是 %d", v2, v1)
	}
}

func TestTunnelRoundTripPreservesEverything(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	enabled := false
	orig := &tunnel.Tunnel{
		ID:         "t-full",
		Slug:       "full-featured",
		Kind:       tunnel.KindService,
		TLS:        tunnel.TLSGateway,
		Exposure:   tunnel.ExposureShared,
		L4:         tunnel.L4TCP,
		AgentID:    "agent-1",
		ListenPort: 0,
		Router: &tunnel.Router{
			Kind:        tunnel.RouterHTTP,
			Domains:     []string{"api.example.com", "*.dev.example.com"},
			Locations:   []string{"/v1", "/v2/deep"},
			HostRewrite: "127.0.0.1:8080",
		},
		Policy: &tunnel.Policy{
			AllowCIDRs:       []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			MaxConns:         42,
			BytesPerSecond:   1 << 20,
			PacketsPerSecond: 5000,
		},
		Backend:     tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		StateReason: "",
		Enabled:     &enabled,
	}
	orig.Complete()

	if err := db.PutTunnel(ctx, orig); err != nil {
		t.Fatalf("PutTunnel: %v", err)
	}

	got, err := db.GetTunnel(ctx, "t-full")
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}

	// 逐字段比对 —— 一个静默丢字段的存储层会让用户「保存了但没生效」。
	if got.Slug != orig.Slug || got.Kind != orig.Kind || got.TLS != orig.TLS ||
		got.Exposure != orig.Exposure || got.L4 != orig.L4 || got.AgentID != orig.AgentID {
		t.Errorf("标量字段不一致：\ngot  %+v\nwant %+v", got, orig)
	}
	if got.Router == nil {
		t.Fatal("Router 丢失")
	}
	if got.Router.HostRewrite != "127.0.0.1:8080" {
		t.Errorf("HostRewrite = %q，期望 127.0.0.1:8080（接入 nomifun-tauri 必需的字段）",
			got.Router.HostRewrite)
	}
	if len(got.Router.Domains) != 2 || got.Router.Domains[1] != "*.dev.example.com" {
		t.Errorf("Domains = %v", got.Router.Domains)
	}
	if len(got.Router.Locations) != 2 || got.Router.Locations[1] != "/v2/deep" {
		t.Errorf("Locations = %v", got.Router.Locations)
	}
	if got.Policy == nil {
		t.Fatal("Policy 丢失")
	}
	if got.Policy.MaxConns != 42 || got.Policy.PacketsPerSecond != 5000 {
		t.Errorf("Policy 数值字段不一致：%+v", got.Policy)
	}
	if len(got.Policy.AllowCIDRs) != 1 || got.Policy.AllowCIDRs[0].String() != "203.0.113.0/24" {
		t.Errorf("AllowCIDRs = %v", got.Policy.AllowCIDRs)
	}
	// 三态 bool 必须保真：nil / true / false 三者不可混淆。
	if got.Enabled == nil {
		t.Fatal("Enabled 从 false 变成了 nil —— 三态语义被破坏")
	}
	if *got.Enabled != false {
		t.Error("Enabled 应为 false")
	}
}

func TestEnabledTriStateSurvivesRoundTrip(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	tr, fa := true, false
	// slug 只允许小写字母数字与连字符，所以这里用 ASCII 键名 ——
	// 校验是对的，不该为了测试方便放宽它。
	cases := []struct {
		name string
		val  *bool
	}{
		{"unset", nil},
		{"true", &tr},
		{"false", &fa},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tn := mkTunnel("tri-"+tc.name, 0)
			tn.ID = "t-tri-" + tc.name
			tn.Enabled = tc.val
			if err := db.PutTunnel(ctx, tn); err != nil {
				t.Fatal(err)
			}
			got, err := db.GetTunnel(ctx, tn.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.val == nil && got.Enabled != nil:
				t.Error("nil 变成了非 nil")
			case tc.val != nil && got.Enabled == nil:
				t.Error("非 nil 变成了 nil")
			case tc.val != nil && *got.Enabled != *tc.val:
				t.Errorf("值变了：%v → %v", *tc.val, *got.Enabled)
			}
		})
	}
}

// TestDuplicateSlugIsConflictNotSilentOverwrite 是很重要的一条。
//
// frp 的 store 按名字**静默覆盖**，那种沉默覆盖在排障时极难发现：
// 用户以为自己新建了一条，实际把旧的改掉了。这里必须是 409。
func TestDuplicateSlugIsConflictNotSilentOverwrite(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	a := mkTunnel("same-slug", 1001)
	a.ID = "t-a"
	if err := db.PutTunnel(ctx, a); err != nil {
		t.Fatal(err)
	}

	b := mkTunnel("same-slug", 1002) // 不同 ID、不同端口、相同 slug
	b.ID = "t-b"
	err := db.PutTunnel(ctx, b)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("重复 slug 应返回 ErrConflict（→HTTP 409），得到 %v", err)
	}

	// 原记录必须完好无损。
	got, err := db.GetTunnel(ctx, "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenPort != 1001 {
		t.Errorf("原记录被改动了：ListenPort = %d，期望 1001", got.ListenPort)
	}
}

// TestDuplicateListenPortIsConflict 验证端口冲突被数据库挡住。
//
// 两条隧道监听同一端口时，第二个 net.Listen 会失败 —— 但那是运行时才发现。
// 在存储层就挡住，用户在控制台点保存时就得到 409 而不是保存成功后隧道起不来。
func TestDuplicateListenPortIsConflict(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	a := mkTunnel("port-a", 2001)
	a.ID = "t-pa"
	if err := db.PutTunnel(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := mkTunnel("port-b", 2001)
	b.ID = "t-pb"
	if err := db.PutTunnel(ctx, b); !errors.Is(err, ErrConflict) {
		t.Fatalf("重复入口端口应返回 ErrConflict，得到 %v", err)
	}
}

// TestZeroListenPortAllowsMultiple 确认 0（由中继分配）不受唯一约束限制。
func TestZeroListenPortAllowsMultiple(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	for i := range 3 {
		tn := mkTunnel(fmt.Sprintf("auto-%d", i), 0)
		tn.ID = fmt.Sprintf("t-auto-%d", i)
		if err := db.PutTunnel(ctx, tn); err != nil {
			t.Fatalf("第 %d 条 listen_port=0 的隧道应当允许：%v", i, err)
		}
	}
}

func TestPutTunnelUpdatesSameID(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	tn := mkTunnel("updatable", 3001)
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatal(err)
	}
	tn.Backend.Addr = "127.0.0.1:9999"
	tn.TLS = tunnel.TLSGateway
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatalf("同 ID 更新应当成功：%v", err)
	}
	got, err := db.GetTunnel(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Backend.Addr != "127.0.0.1:9999" || got.TLS != tunnel.TLSGateway {
		t.Errorf("更新未生效：%+v", got)
	}
}

func TestListTunnelsIsSorted(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	// 故意乱序插入。
	for i, slug := range []string{"zebra", "alpha", "middle"} {
		tn := mkTunnel(slug, uint16(4000+i))
		tn.ID = "t-" + slug
		if err := db.PutTunnel(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	list, err := db.ListTunnels(ctx, tunnel.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("返回 %d 条，期望 3", len(list))
	}
	// 顺序必须确定：不确定的顺序会让「下发给 agent 的期望集合」diff 产生假变更。
	for i, want := range []string{"alpha", "middle", "zebra"} {
		if list[i].Slug != want {
			t.Errorf("第 %d 条 = %q，期望 %q（必须按 slug 排序）", i, list[i].Slug, want)
		}
	}
}

// TestSetTunnelStateDoesNotClobberConfig 验证状态上报不会覆盖配置。
//
// 这是一个真实的竞态：agent 上报「被本地策略否决」的同时，
// 管理员刚在控制台改了后端地址。若状态更新走整行覆盖，管理员的改动会被冲掉。
func TestSetTunnelStateDoesNotClobberConfig(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	tn := mkTunnel("stateful", 5001)
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatal(err)
	}

	if err := db.SetTunnelState(ctx, tn.ID,
		tunnel.StateRejectedByAgent, "目标命中云元数据黑名单"); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetTunnel(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != tunnel.StateRejectedByAgent {
		t.Errorf("State = %q", got.State)
	}
	if got.StateReason != "目标命中云元数据黑名单" {
		t.Errorf("StateReason = %q —— 拒绝原因必须保留并展示给用户", got.StateReason)
	}
	// 配置字段必须不受影响。
	if got.Backend.Addr != "127.0.0.1:8080" || got.ListenPort != 5001 {
		t.Errorf("状态更新覆盖了配置字段：%+v", got)
	}
}

func TestGetMissingTunnelIsNotFound(t *testing.T) {
	db := open(t)
	if _, err := db.GetTunnel(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v，期望 ErrNotFound", err)
	}
}

func TestDeleteTunnel(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	tn := mkTunnel("deletable", 6001)
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteTunnel(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteTunnel(ctx, tn.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("重复删除应返回 ErrNotFound，得到 %v", err)
	}
}

func TestPutTunnelRejectsInvalidDefinition(t *testing.T) {
	db := open(t)
	tn := &tunnel.Tunnel{ID: "t-bad", Slug: "Bad Slug!"}
	tn.Complete()
	if err := db.PutTunnel(context.Background(), tn); err == nil {
		t.Fatal("非法隧道定义不该被写入 —— 校验必须在存储层之前生效")
	}
}

// ── Agent 与入网令牌 ────────────────────────────────────────────────────────

// TestEnrolTokenIsSingleUse 是入网安全的核心断言。
func TestEnrolTokenIsSingleUse(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, err := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "测试")
	if err != nil {
		t.Fatal(err)
	}

	id1, key1, err := db.RedeemEnrolToken(ctx, plain, &Agent{Hostname: "h1", OS: "linux"})
	if err != nil {
		t.Fatalf("首次兑换应当成功：%v", err)
	}
	if id1 == "" || key1 == "" {
		t.Fatal("兑换应返回非空 ID 与密钥")
	}

	if _, _, err := db.RedeemEnrolToken(ctx, plain, nil); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("二次兑换必须被拒为 ErrTokenUsed，得到 %v", err)
	}
}

func TestEnrolTokenExpires(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	// 先用正常 TTL 创建，再把时钟推到过期之后。
	plain, err := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	orig := now
	now = func() int64 { return orig() + 10 }
	defer func() { now = orig }()

	if _, _, err := db.RedeemEnrolToken(ctx, plain, nil); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("过期令牌应被拒为 ErrTokenExpired，得到 %v", err)
	}
}

func TestEnrolTokenRequiresPositiveTTL(t *testing.T) {
	db := open(t)
	// 一个永不过期的入网令牌本质上是长期主密钥，必须拒绝。
	if _, err := db.CreateEnrolToken(context.Background(), tunnel.DefaultTenantID, 0, ""); err == nil {
		t.Fatal("TTL 为 0 的入网令牌应被拒绝")
	}
}

func TestUnknownEnrolTokenIsNotFound(t *testing.T) {
	db := open(t)
	if _, _, err := db.RedeemEnrolToken(context.Background(), "nf_enrol_bogus", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v，期望 ErrNotFound", err)
	}
}

// TestAgentSecretIsRetrievableForHMAC 确认密钥能取回明文。
//
// 这不是疏忽而是必需：握手证明是 HMAC，中继必须用同一个密钥重算 MAC。
func TestAgentSecretIsRetrievableForHMAC(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, err := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := db.RedeemEnrolToken(ctx, plain, nil)
	if err != nil {
		t.Fatal(err)
	}

	secret, ok := db.AgentSecret(ctx, id)
	if !ok {
		t.Fatal("应当能取回 agent 密钥（HMAC 校验需要它）")
	}
	if len(secret) != 32 {
		t.Errorf("密钥长度 = %d，期望 32 字节", len(secret))
	}
}

// TestRevokeAgentTakesEffectImmediately 验证撤销立即生效。
func TestRevokeAgentTakesEffectImmediately(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, _ := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "")
	id, _, err := db.RedeemEnrolToken(ctx, plain, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !db.AgentExists(ctx, id) {
		t.Fatal("撤销前应当存在")
	}
	if err := db.RevokeAgent(ctx, id); err != nil {
		t.Fatal(err)
	}
	if db.AgentExists(ctx, id) {
		t.Error("撤销后 AgentExists 应返回 false")
	}
	if _, ok := db.AgentSecret(ctx, id); ok {
		t.Error("撤销后不该还能取回密钥 —— 撤销必须立即生效")
	}
	// 重复撤销是 ErrNotFound（已经撤销过了）。
	if err := db.RevokeAgent(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("重复撤销应返回 ErrNotFound，得到 %v", err)
	}
}

// TestRevokedAgentIsStillListed 确认撤销是 UPDATE 而不是 DELETE。
//
// 审计需要知道「这个 ID 曾经存在过」。
func TestRevokedAgentIsStillListed(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, _ := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "")
	id, _, _ := db.RedeemEnrolToken(ctx, plain, &Agent{Hostname: "gone"})
	db.RevokeAgent(ctx, id)

	list, err := db.ListAgents(ctx, tunnel.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range list {
		if a.ID == id {
			found = true
			if !a.Revoked {
				t.Error("列表里应标记为已撤销")
			}
		}
	}
	if !found {
		t.Error("已撤销的 agent 仍应出现在列表里（审计需要）")
	}
}

func TestTouchAgentUpdatesProfile(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, _ := db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, time.Hour, "")
	id, _, _ := db.RedeemEnrolToken(ctx, plain, nil)

	if err := db.TouchAgent(ctx, &Agent{
		ID: id, Hostname: "home-desktop", OS: "linux", Arch: "arm64", Version: "1.2.3",
	}); err != nil {
		t.Fatal(err)
	}

	list, _ := db.ListAgents(ctx, tunnel.DefaultTenantID)
	for _, a := range list {
		if a.ID != id {
			continue
		}
		if a.Hostname != "home-desktop" || a.Arch != "arm64" || a.Version != "1.2.3" {
			t.Errorf("画像未更新：%+v", a)
		}
		if a.LastSeenAt.IsZero() {
			t.Error("LastSeenAt 应被更新")
		}
		return
	}
	t.Fatal("找不到该 agent")
}

// ── 事件 ────────────────────────────────────────────────────────────────────

func TestEventsAreNewestFirst(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	for i := range 5 {
		if err := db.AppendEvent(ctx, Event{
			Kind:    KindTunnelCreated,
			Message: fmt.Sprintf("第 %d 条", i),
			Actor:   "admin",
		}); err != nil {
			t.Fatal(err)
		}
	}

	list, err := db.ListEvents(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 5 {
		t.Fatalf("返回 %d 条，期望 5", len(list))
	}
	if list[0].Message != "第 4 条" {
		t.Errorf("首条 = %q，期望最新的「第 4 条」", list[0].Message)
	}
	if list[0].Actor != "admin" {
		t.Error("actor 必须保留 —— 审计要能回答「谁改的」")
	}
}

func TestListEventsCapsLimit(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	for range 3 {
		db.AppendEvent(ctx, Event{Kind: "x", Message: "y"})
	}
	// 传一个荒谬的 limit，必须被夹到上限而不是照做。
	list, err := db.ListEvents(ctx, 1_000_000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Errorf("返回 %d 条", len(list))
	}
}

func TestPruneEvents(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	old := time.Unix(1000, 0)
	db.AppendEvent(ctx, Event{At: old, Kind: "old", Message: "旧"})
	db.AppendEvent(ctx, Event{Kind: "new", Message: "新"})

	n, err := db.PruneEvents(ctx, time.Unix(2000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("删除 %d 条，期望 1", n)
	}
	list, _ := db.ListEvents(ctx, 10, 0)
	if len(list) != 1 || list[0].Kind != "new" {
		t.Errorf("剩余事件不对：%+v", list)
	}
}

// ── 时序 ────────────────────────────────────────────────────────────────────

// TestRecordSampleAccumulatesWithinBucket 验证同一桶内多次上报是累加而非覆盖。
func TestRecordSampleAccumulatesWithinBucket(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	base := int64(1_700_000_000)
	base -= base % 60

	for range 3 {
		if err := db.RecordSample(ctx, Sample{
			TunnelID: "t1", Bucket: base + 5, // 桶内不同秒，应归入同一桶
			BytesIn: 100, BytesOut: 200, ConnsOK: 1, Samples: 1,
			RTTMaxUS: 5000,
		}); err != nil {
			t.Fatal(err)
		}
	}

	samples, err := db.QuerySamples(ctx, "t1", time.Unix(base-60, 0), time.Unix(base+120, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("应当只有 1 个桶，得到 %d 个", len(samples))
	}
	s := samples[0]
	if s.BytesIn != 300 || s.BytesOut != 600 || s.ConnsOK != 3 || s.Samples != 3 {
		t.Errorf("累加不正确：%+v", s)
	}
	// 最大值取较大者而不是相加。
	if s.RTTMaxUS != 5000 {
		t.Errorf("RTTMaxUS = %d，期望 5000（最大值不该被累加）", s.RTTMaxUS)
	}
}

// TestQuantileFromHistogram 是「存桶而非存 p95」这个决策的回报验证。
//
// 分位数不能被平均：把每分钟的 p95 再平均成每小时的 p95 是算术错误。
// 存累积直方图之后，任意时间范围、任意分位数都能正确算出。
func TestQuantileFromHistogram(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)

	// 构造一个分布：90 次 1ms，10 次 500ms。
	// p50 应落在 1ms 桶，p95 应落在 500ms 桶。
	for range 90 {
		if err := db.RecordRTT(ctx, "t1", at, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	for range 10 {
		if err := db.RecordRTT(ctx, "t1", at, 500*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}

	from, to := at.Add(-time.Hour), at.Add(time.Hour)

	p50, err := db.Quantile(ctx, "t1", from, to, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if p50 != time.Millisecond {
		t.Errorf("p50 = %v，期望 1ms（90%% 的观测在这个桶）", p50)
	}

	p95, err := db.Quantile(ctx, "t1", from, to, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if p95 != 500*time.Millisecond {
		t.Errorf("p95 = %v，期望 500ms（尾部 10%% 在这里）", p95)
	}

	// 无数据时返回 0 而不是报错或编一个数字。
	zero, err := db.Quantile(ctx, "no-such-tunnel", from, to, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if zero != 0 {
		t.Errorf("无数据应返回 0，得到 %v", zero)
	}
}

func TestQuantileRejectsBadP(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	for _, p := range []float64{0, -0.5, 1.5} {
		if _, err := db.Quantile(ctx, "t", time.Unix(0, 0), time.Now(), p); err == nil {
			t.Errorf("p=%v 应被拒绝", p)
		}
	}
}

// TestRollupWeightsLossBySamples 验证上卷时丢包率按样本数加权。
//
// 简单平均是错的：一个只有 1 个样本的桶不该与 1000 个样本的桶等权。
func TestRollupWeightsLossBySamples(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	// 桶时间必须落在留存窗口内（1m 表保留 48h），否则 Rollup 的清理步骤
	// 会把刚上卷出来的数据当成过期数据删掉。
	// 第一版测试用了 2023 年的固定时间戳，结果 5m 表恒为空 —— 那不是 SQL 错，
	// 而是「测试数据比留存窗口还老」。
	base := time.Now().Unix() - 3600
	base -= base % 300 // 对齐到 5 分钟边界

	// 桶 A：1000 个样本、丢包 0
	if err := db.RecordSample(ctx, Sample{
		TunnelID: "t1", Bucket: base, Samples: 1000, LossPPM: 0,
	}); err != nil {
		t.Fatal(err)
	}
	// 桶 B：1 个样本、丢包 100%（1e6 ppm）。与 A 同属一个 5m 桶。
	if err := db.RecordSample(ctx, Sample{
		TunnelID: "t1", Bucket: base + 60, Samples: 1, LossPPM: 1_000_000,
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Rollup(ctx); err != nil {
		t.Fatal(err)
	}

	var loss, samples int64
	err := db.read.QueryRowContext(ctx,
		`SELECT loss_ppm, samples FROM tunnel_sample_5m WHERE tunnel_id='t1' AND bucket=?`,
		base).Scan(&loss, &samples)
	if err != nil {
		t.Fatalf("查询 5m 桶失败：%v", err)
	}
	if samples != 1001 {
		t.Errorf("samples = %d，期望 1001", samples)
	}
	// 加权平均：(0*1000 + 1e6*1) / 1001 ≈ 999 ppm。
	// 简单平均会得到 500000 ppm —— 差了 500 倍。
	if loss > 2000 {
		t.Errorf("loss_ppm = %d，期望约 999（按样本数加权）；"+
			"若接近 500000 说明用了简单平均", loss)
	}
}

// TestRollupPrunesDataOlderThanRetention 验证留存策略真的会删老数据。
//
// 这条测试是上面那个失败的副产品：我原本把「数据没出现在 5m 表」误判为
// SQL 错误，实际是留存清理正确地删掉了过老的桶。既然这个行为是对的，
// 就该有一条测试把它固定下来。
func TestRollupPrunesDataOlderThanRetention(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	// 一个 3 天前的桶：超出 1m 表的 48h 留存。
	old := time.Now().Unix() - 3*24*3600
	old -= old % 60
	if err := db.RecordSample(ctx, Sample{TunnelID: "t1", Bucket: old, Samples: 1}); err != nil {
		t.Fatal(err)
	}
	// 一个 1 小时前的桶：在留存内。
	recent := time.Now().Unix() - 3600
	recent -= recent % 60
	if err := db.RecordSample(ctx, Sample{TunnelID: "t1", Bucket: recent, Samples: 1}); err != nil {
		t.Fatal(err)
	}

	if err := db.Rollup(ctx); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := db.read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tunnel_sample_1m WHERE bucket = ?`, old).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("超出 48h 留存的 1m 桶应被清理")
	}
	if err := db.read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tunnel_sample_1m WHERE bucket = ?`, recent).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("留存窗口内的桶不该被清理")
	}
}

func TestBackupCreatesUsableSnapshot(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	tn := mkTunnel("backed-up", 7001)
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "snap.db")
	if err := db.Backup(ctx, dest); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// 快照必须是一个可用的数据库，且含刚写入的数据。
	snap, err := Open(Options{Path: dest, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("打开快照失败：%v", err)
	}
	defer snap.Close()

	got, err := snap.GetTunnel(ctx, tn.ID)
	if err != nil {
		t.Fatalf("快照里读不到数据：%v", err)
	}
	if got.Slug != "backed-up" {
		t.Errorf("快照数据不对：%+v", got)
	}
}

func TestBackupRefusesExistingTarget(t *testing.T) {
	db := open(t)
	dest := filepath.Join(t.TempDir(), "exists.db")
	if err := db.Backup(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	// 第二次必须拒绝，否则会静默覆盖一份可能是唯一的备份。
	if err := db.Backup(context.Background(), dest); err == nil {
		t.Fatal("目标已存在时应当拒绝，避免静默覆盖备份")
	}
}

func TestEscapeSQLLiteral(t *testing.T) {
	for in, want := range map[string]string{
		"plain":     "plain",
		"it's":      "it''s",
		"''":        "''''",
		"a'b'c":     "a''b''c",
		"/tmp/x.db": "/tmp/x.db",
	} {
		if got := escapeSQLLiteral(in); got != want {
			t.Errorf("escapeSQLLiteral(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestShortIDIsAllocatedOncePerTunnelAndNeverCollides(t *testing.T) {
	// 短标识进 UDP 数据报帧头，两条隧道共用一个值会让流量串到错误的后端 ——
	// 那是数据泄露级别的故障，不是显示错误。
	db := open(t)
	ctx := context.Background()

	seen := make(map[uint16]string)
	for i := range 5 {
		tn := &tunnel.Tunnel{
			ID:      fmt.Sprintf("t-%d", i),
			Slug:    fmt.Sprintf("svc-%d", i),
			Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		}
		if err := db.PutTunnel(ctx, tn); err != nil {
			t.Fatalf("建隧道 %d 失败：%v", i, err)
		}
		if tn.ShortID == 0 {
			t.Fatalf("隧道 %d 没有分到短标识", i)
		}
		if other, dup := seen[tn.ShortID]; dup {
			t.Fatalf("短标识 %d 被 %s 与 %s 共用", tn.ShortID, other, tn.ID)
		}
		seen[tn.ShortID] = tn.ID
	}

	// 更新一条隧道不该改动它的短标识：agent 那边正用着这个值。
	first, err := db.GetTunnel(ctx, "t-0")
	if err != nil {
		t.Fatal(err)
	}
	want := first.ShortID
	first.StateReason = "改点别的"
	if err := db.PutTunnel(ctx, first); err != nil {
		t.Fatal(err)
	}
	again, err := db.GetTunnel(ctx, "t-0")
	if err != nil {
		t.Fatal(err)
	}
	if again.ShortID != want {
		t.Fatalf("更新后短标识从 %d 变成了 %d —— agent 会开始往错误的隧道发包", want, again.ShortID)
	}
}

// TestPutTunnelBackfillsAShortIDOfZeroInsteadOfReallocatingForever 钉住
// UPDATE 子句里那个 CASE 表达式。
//
// short_id 刻意**不在**无条件更新的列里：改号会让在途的 UDP 数据报
// （帧头带的是旧号）被当成未知隧道丢掉。但「一律不写」留下一个死角：
// 一行的号若真的是 0，PutTunnel 每次都会分配一个新号、每次都写不进去，
// 于是那条隧道永远带着 0 —— 而 Tunnel=0 的数据报解复用直接错位，
// 静默把流量送到别处。这比拒绝启动糟得多。
//
// 所以子句写成「只在库里是 0 时才回填」。这条路径不可能从公开 API 走到
// （PutTunnel 会先补上号），只能直接改库造出来 —— 而它正是升级路径上
// 可能出现的形态，所以必须有一条测试守着。
func TestPutTunnelBackfillsAShortIDOfZeroInsteadOfReallocatingForever(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	tn := &tunnel.Tunnel{
		ID:      "t-zero",
		Slug:    "zero",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	if err := db.PutTunnel(ctx, tn); err != nil {
		t.Fatal(err)
	}

	// 造出「库里是 0」这个形态（模拟一次没回填干净的升级）。
	if _, err := db.write.ExecContext(ctx,
		`UPDATE tunnels SET short_id = 0 WHERE id = ?`, "t-zero"); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetTunnel(ctx, "t-zero")
	if err != nil {
		t.Fatal(err)
	}
	if got.ShortID != 0 {
		t.Fatalf("前置不成立：库里应当是 0，实际 %d", got.ShortID)
	}

	// 下一次写入必须把号补上并**落库**。
	got.StateReason = "随便改点什么触发一次写入"
	if err := db.PutTunnel(ctx, got); err != nil {
		t.Fatal(err)
	}
	after, err := db.GetTunnel(ctx, "t-zero")
	if err != nil {
		t.Fatal(err)
	}
	if after.ShortID == 0 {
		t.Fatal("库里的短标识仍然是 0 —— 每次写入都会重新分配一个号又扔掉，" +
			"而这条隧道的 UDP 数据报会一直带着 Tunnel=0，解复用错位")
	}
	if after.ShortID != got.ShortID {
		t.Errorf("返回的号 %d 与落库的号 %d 不一致", got.ShortID, after.ShortID)
	}
}

func TestShortIDReusesHolesLeftByDeletedTunnels(t *testing.T) {
	// 「最小可用」而不是「最大值 +1」：反复增删的部署下后者会很快爬到 65535。
	db := open(t)
	ctx := context.Background()

	ids := make([]uint16, 0, 3)
	for i := range 3 {
		tn := &tunnel.Tunnel{
			ID:      fmt.Sprintf("t-%d", i),
			Slug:    fmt.Sprintf("svc-%d", i),
			Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		}
		if err := db.PutTunnel(ctx, tn); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tn.ShortID)
	}

	// 挖掉中间那个。
	if err := db.DeleteTunnel(ctx, "t-1"); err != nil {
		t.Fatal(err)
	}

	fresh := &tunnel.Tunnel{
		ID: "t-new", Slug: "svc-new",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	if err := db.PutTunnel(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.ShortID != ids[1] {
		t.Fatalf("新隧道应当复用空洞 %d，实际拿到 %d", ids[1], fresh.ShortID)
	}
}
