package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// fakeObserver 是一个可控的 SourceObserver，装到测试用的 snapshot 上。
type fakeObserver struct {
	*fakeSnapshot
	byTunnel map[string]LearnedSources
	declined []string
}

func (f *fakeObserver) ObservedSources(id string) (LearnedSources, bool) {
	got, ok := f.byTunnel[id]
	return got, ok
}

func (f *fakeObserver) DeclineLearnedSources(id string) {
	f.declined = append(f.declined, id)
}

// learnRig 起一台带观测能力的控制台，并建好一条隧道。
func learnRig(t *testing.T, sources ...LearnedSource) (
	*Server, func(*http.Request) *http.Request, string, *fakeObserver,
) {
	t.Helper()
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("learnable", 9490, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("建隧道失败：%s", w.Body.String())
	}
	id := listTunnels(t, db)["learnable"].ID

	obs := &fakeObserver{
		fakeSnapshot: s.snapshot.(*fakeSnapshot),
		byTunnel:     map[string]LearnedSources{},
	}
	if len(sources) > 0 {
		obs.byTunnel[id] = LearnedSources{
			TunnelID: id, Sources: sources, ObservedFrom: time.Now().Add(-time.Hour),
		}
	}
	s.snapshot = obs
	return s, auth, id, obs
}

func postJSON(t *testing.T, s *Server, auth func(*http.Request) *http.Request,
	path string, body any,
) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, path, body)))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestApplyLearnedRefusesAnExplicitlyEmptySelection 是这一组里最要紧的一条。
//
// # 真机验证抓到的行为
//
// 请求体 `{"cidrs":[]}` 当时回了 200，并把**观测到的全部前缀**写进了
// allow_cidrs。原因是 Go 里 []string 分不开「字段缺席」与「空数组」——
// 两者 len 都是 0，而代码把 len==0 解释成「全选」。
//
// 为什么这条很危险：学习窗口里（allow_cidrs 为空、放行一切）扫描器的地址与
// 真客户端的地址**混在一起**，中继分不开。界面因此刻意不提供「一键全选」。
// 而一个算出空选集的界面 / 脚本，会在这个口子上把撞门的人一键请进允许列表 ——
// 恰好是这个功能想解决的问题的反面。
func TestApplyLearnedRefusesAnExplicitlyEmptySelection(t *testing.T) {
	s, auth, id, _ := learnRig(t,
		LearnedSource{CIDR: "203.0.113.7/32", Hits: 40},
		LearnedSource{CIDR: "198.51.100.66/32", Hits: 1}, // 扫描器
	)

	code, body := postJSON(t, s, auth, "/api/tunnels/"+id+":apply-learned",
		map[string]any{"cidrs": []string{}})
	if code == http.StatusOK {
		t.Fatalf("空数组被当成「全选」接受了（%d %v）—— "+
			"那会把只命中过一次的扫描器一起写进允许列表", code, body)
	}
	if got := body["code"]; got != "nothing_selected" {
		t.Errorf("错误码 = %v，期望 nothing_selected", got)
	}
	// 文案必须说清「空数组不是全选」，否则调用方会以为是自己少传了什么。
	if msg, _ := body["message"].(string); !strings.Contains(msg, "省略") {
		t.Errorf("文案里应当说明「要全选请省略字段」，实际 %q", msg)
	}
}

// TestApplyLearnedWithNoBodyAppliesEverythingObserved 钉住另一半。
//
// 「缺席 = 全部」是给 curl 与脚本留的便利。它与上面那条**必须**分得开，
// 否则要么便利没了，要么空选集变成全选。
func TestApplyLearnedWithNoBodyAppliesEverythingObserved(t *testing.T) {
	s, auth, id, _ := learnRig(t,
		LearnedSource{CIDR: "203.0.113.7/32", Hits: 40},
		LearnedSource{CIDR: "203.0.113.8/32", Hits: 9},
	)

	code, body := postJSON(t, s, auth, "/api/tunnels/"+id+":apply-learned", nil)
	if code != http.StatusOK {
		t.Fatalf("省略请求体应当应用全部，实际 %d %v", code, body)
	}
	got := allowCIDRsOf(t, s, auth, id)
	if len(got) != 2 {
		t.Errorf("allow_cidrs = %v，期望两条都写进去", got)
	}
}

// TestApplyLearnedRejectsPrefixesThatWereNeverObserved 钉住端点的边界。
//
// 这个端点叫 apply-learned，不是「写任意 CIDR」——后者是 PUT 的活。
// 接受一个没观测过的前缀会让它变成第二条写策略的路径，
// 而两条路径迟早会在校验上分叉。
func TestApplyLearnedRejectsPrefixesThatWereNeverObserved(t *testing.T) {
	s, auth, id, _ := learnRig(t, LearnedSource{CIDR: "203.0.113.7/32", Hits: 5})

	code, body := postJSON(t, s, auth, "/api/tunnels/"+id+":apply-learned",
		map[string]any{"cidrs": []string{"8.8.8.8/32"}})
	if code != http.StatusBadRequest {
		t.Fatalf("状态 %d，期望 400：%v", code, body)
	}
	if got := body["code"]; got != "not_observed" {
		t.Errorf("错误码 = %v，期望 not_observed", got)
	}
	if got := allowCIDRsOf(t, s, auth, id); len(got) != 0 {
		t.Errorf("被拒的请求却改了策略：%v", got)
	}
}

// TestApplyLearnedMergesInsteadOfReplacing 钉住并集语义。
//
// 覆盖会把运维手填的网段悄悄删掉，而那些网段覆盖的可能正是还没露面的客户端。
// 一个「收窄」动作把别的白名单删掉，是这条路径上最容易造成失联的形态。
func TestApplyLearnedMergesInsteadOfReplacing(t *testing.T) {
	s, auth, id, _ := learnRig(t, LearnedSource{CIDR: "203.0.113.7/32", Hits: 5})

	// 先手工写一条网段（模拟运维已经配过）。
	base := svcTunnel("learnable", 9490, "127.0.0.1:8080")
	base.Policy = &tunnel.Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPut, "/api/tunnels/"+id, base)))
	if w.Code != http.StatusOK {
		t.Fatalf("前置更新失败：%s", w.Body.String())
	}

	code, body := postJSON(t, s, auth, "/api/tunnels/"+id+":apply-learned",
		map[string]any{"cidrs": []string{"203.0.113.7/32"}})
	if code != http.StatusOK {
		t.Fatalf("状态 %d：%v", code, body)
	}

	got := allowCIDRsOf(t, s, auth, id)
	var sawOld, sawNew bool
	for _, c := range got {
		switch c {
		case "10.0.0.0/8":
			sawOld = true
		case "203.0.113.7/32":
			sawNew = true
		}
	}
	if !sawOld {
		t.Errorf("手工填的 10.0.0.0/8 被覆盖掉了（现在是 %v）—— "+
			"一个「收窄」动作删掉了别的白名单，覆盖的客户端会全部失联", got)
	}
	if !sawNew {
		t.Errorf("观测到的前缀没写进去：%v", got)
	}
}

// TestApplyLearnedRefusesWhenNothingWasObserved 钉住「没有观测」这一支。
//
// 这里最坏的实现是「照做」：把空列表写成 allow_cidrs。那不是收窄 ——
// 空 allow_cidrs 的语义是**放行一切**（tunnel.SourceAllowed 的第一行），
// 而界面会显示操作成功。用户于是以为自己刚刚收紧了一条隧道。
func TestApplyLearnedRefusesWhenNothingWasObserved(t *testing.T) {
	s, auth, id, _ := learnRig(t) // 一条观测都没有

	code, body := postJSON(t, s, auth, "/api/tunnels/"+id+":apply-learned", nil)
	if code == http.StatusOK {
		t.Fatalf("没有任何观测时却报成功（%v）—— "+
			"写空的 allow_cidrs 等于放行一切，而界面会说收窄成功", body)
	}
	if got := body["code"]; got != "nothing_learned" {
		t.Errorf("错误码 = %v，期望 nothing_learned", got)
	}
}

// TestLearnedSourcesTellsApartNotObservingFromNothingObserved 钉住 501。
//
// 一台不观测的中继回空列表，会被界面读成「没人连过这条隧道」——
// 而真相是「这台中继不看」。两者的下一步动作完全不同。
func TestLearnedSourcesTellsApartNotObservingFromNothingObserved(t *testing.T) {
	// ── 不实现 SourceObserver 的中继 ──
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("plain", 9491, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("建隧道失败：%s", w.Body.String())
	}
	id := listTunnels(t, db)["plain"].ID

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet,
		"/api/tunnels/"+id+"/learned-sources", nil)))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("不观测的中继应当回 501，实际 %d %s —— "+
			"回空列表会被读成「没人连过」", w.Code, w.Body.String())
	}

	// ── 观测但还什么都没看到 ──
	s2, auth2, id2, _ := learnRig(t)
	w = httptest.NewRecorder()
	s2.Handler().ServeHTTP(w, auth2(req(http.MethodGet,
		"/api/tunnels/"+id2+"/learned-sources", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("有观测能力时应当 200，实际 %d", w.Code)
	}
	// sources 必须是 []，不能是 null —— 前端 .map 会在 null 上炸。
	if body := w.Body.String(); !strings.Contains(body, `"sources":[]`) {
		t.Errorf("空结果的 sources 应当是 []（不是 null，前端会在 null 上炸）：%s", body)
	}

	// ── 观测方交出一条「有记录、但 Sources 为 nil」的结果 ──
	//
	// 这是上面那条**测不到**的形态：没有记录时处理器自己造了一个带空数组的
	// 结果，所以那条断言对 nil 守卫一无所知。而一个真实的观测方（比如
	// 某条隧道只被 decline 过、还没观测到任何来源）交出来的正是这种结果。
	s3, auth3, id3, obs3 := learnRig(t)
	obs3.byTunnel[id3] = LearnedSources{TunnelID: id3, Sources: nil, Declined: true}
	w = httptest.NewRecorder()
	s3.Handler().ServeHTTP(w, auth3(req(http.MethodGet,
		"/api/tunnels/"+id3+"/learned-sources", nil)))
	if body := w.Body.String(); !strings.Contains(body, `"sources":[]`) {
		t.Errorf("观测方交出 nil 时应当归一成 []，实际 %s —— "+
			"前端对这个字段直接 .map，null 会让整页白屏", body)
	}
}

// TestDeclineLearnedDoesNotTouchThePolicy 钉住「保持开放」只是一个标记。
func TestDeclineLearnedDoesNotTouchThePolicy(t *testing.T) {
	s, auth, id, obs := learnRig(t, LearnedSource{CIDR: "203.0.113.7/32", Hits: 5})

	code, _ := postJSON(t, s, auth, "/api/tunnels/"+id+":decline-learned", nil)
	if code != http.StatusOK {
		t.Fatalf("状态 %d", code)
	}
	if len(obs.declined) != 1 || obs.declined[0] != id {
		t.Errorf("拒绝没有被记下来：%v", obs.declined)
	}
	if got := allowCIDRsOf(t, s, auth, id); len(got) != 0 {
		t.Errorf("「保持开放」改了策略：%v —— 它只该记一个标记", got)
	}
}

// ── 小工具 ──────────────────────────────────────────────────────────────────

func allowCIDRsOf(t *testing.T, s *Server, auth func(*http.Request) *http.Request,
	id string,
) []string {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodGet, "/api/tunnels/"+id, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("读隧道失败：%d %s", w.Code, w.Body.String())
	}
	var got tunnel.Tunnel
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Policy == nil {
		return nil
	}
	out := make([]string, 0, len(got.Policy.AllowCIDRs))
	for _, p := range got.Policy.AllowCIDRs {
		out = append(out, p.String())
	}
	return out
}
