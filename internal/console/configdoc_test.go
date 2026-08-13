package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// docOf 把若干条隧道包成前端提交的那个形状：{"doc": "<JSON 文本>"}。
//
// 两层是刻意的（见 decodeConfigDoc）：前端给的是一个可粘贴的编辑框内容，
// 而那段内容完全可能不是合法 JSON。测试必须走同一条路径，
// 否则「文本解析失败」那半边代码一行都没被覆盖。
func docOf(t *testing.T, version int, tunnels ...*tunnel.Tunnel) map[string]string {
	t.Helper()
	inner := map[string]any{"version": version, "tunnels": tunnels}
	if tunnels == nil {
		// 明确写出空数组：nil 会序列化成 null，而那正是「删掉所有隧道」
		// 这条最危险的路径的输入形状，不该被测试悄悄换成别的东西。
		inner["tunnels"] = []*tunnel.Tunnel{}
	}
	b, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"doc": string(b)}
}

func rawDoc(text string) map[string]string { return map[string]string{"doc": text} }

// postDoc 发一次请求并解出 ConfigDiff。
func postDoc(t *testing.T, s *Server, auth func(*http.Request) *http.Request,
	path string, body any,
) (int, ConfigDiff, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, path, body)))
	var diff ConfigDiff
	// 忽略解码错误：错误响应（APIError）解不成 ConfigDiff，
	// 那时调用方看的是原始 body。
	_ = json.Unmarshal(w.Body.Bytes(), &diff)
	return w.Code, diff, w.Body.String()
}

func svcTunnel(slug string, port uint16, backend string) *tunnel.Tunnel {
	return &tunnel.Tunnel{
		Slug: slug, ListenPort: port,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend},
	}
}

// listTunnels 直接读库 —— 断言副作用必须绕开被测的那个端点。
func listTunnels(t *testing.T, db *store.DB) map[string]*tunnel.Tunnel {
	t.Helper()
	all, err := db.ListTunnels(t.Context(), tunnel.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]*tunnel.Tunnel, len(all))
	for _, x := range all {
		out[x.Slug] = x
	}
	return out
}

// TestValidateConfigWritesNothing 是这个端点存在的全部理由。
//
// validate 的用途就是「按下 apply 之前先看看」。如果它有任何副作用，
// 那么每一次「我只是想看看」都是一次真实的配置替换 ——
// 而这个操作能删隧道。
func TestValidateConfigWritesNothing(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	// 先建一条，这样文档里的「删除」不是空集 —— 空集下什么都不写是平凡的。
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("keep-me", 9400, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}
	before := listTunnels(t, db)

	// 一份「删掉 keep-me、新建 fresh」的文档。
	code, diff, body := postDoc(t, s, auth, "/api/config:validate",
		docOf(t, 1, svcTunnel("fresh", 9401, "127.0.0.1:8081")))
	if code != http.StatusOK {
		t.Fatalf("合法文档应当 200，实际 %d %s", code, body)
	}
	if !diff.OK {
		t.Fatalf("合法文档应当 ok=true：%s", body)
	}
	if !slices.Equal(diff.Create, []string{"fresh"}) {
		t.Errorf("应当报告新建 fresh，实际 %v", diff.Create)
	}
	if !slices.Equal(diff.Delete, []string{"keep-me"}) {
		t.Errorf("必须逐条列出将被删除的 slug —— 那是这个操作唯一不可逆的部分。实际 %v",
			diff.Delete)
	}

	after := listTunnels(t, db)
	if len(after) != len(before) {
		t.Fatalf("validate 必须是纯干跑：库里从 %d 条变成 %d 条", len(before), len(after))
	}
	if _, ok := after["keep-me"]; !ok {
		t.Fatal("validate 把 keep-me 删了 —— 它只该报告「将会删」")
	}
	if _, ok := after["fresh"]; ok {
		t.Fatal("validate 把 fresh 建出来了 —— 它只该报告「将会建」")
	}
}

// TestApplyConfigConvergesToTheDocument 验证声明式语义的三个方向。
//
// 「对齐一份清单」意味着新建、更新、**删除**三件事都要发生。
// 只做前两件的实现看起来能用（导入不报错、新东西出现了），
// 但它其实是增量合并 —— 而用户按声明式的直觉操作时会以为自己清掉了旧配置。
func TestApplyConfigConvergesToTheDocument(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	for _, tn := range []*tunnel.Tunnel{
		svcTunnel("gone", 9410, "127.0.0.1:8080"),
		svcTunnel("changed", 9411, "127.0.0.1:8081"),
		svcTunnel("same", 9412, "127.0.0.1:8082"),
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels", tn)))
		if w.Code != http.StatusOK {
			t.Fatalf("前置创建 %s 失败：%s", tn.Slug, w.Body.String())
		}
	}
	before := listTunnels(t, db)
	oldChangedID, oldChangedShort := before["changed"].ID, before["changed"].ShortID

	code, diff, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1,
		svcTunnel("changed", 9411, "127.0.0.1:9999"), // 后端改了
		svcTunnel("same", 9412, "127.0.0.1:8082"),    // 一模一样
		svcTunnel("added", 9413, "127.0.0.1:8083"),   // 新的
		// gone 不在清单里 → 删
	))
	if code != http.StatusOK {
		t.Fatalf("合法文档应当 200，实际 %d %s", code, body)
	}
	if !slices.Equal(diff.Create, []string{"added"}) {
		t.Errorf("Create 应为 [added]，实际 %v", diff.Create)
	}
	if !slices.Equal(diff.Update, []string{"changed"}) {
		t.Errorf("Update 应为 [changed]，实际 %v", diff.Update)
	}
	if !slices.Equal(diff.Delete, []string{"gone"}) {
		t.Errorf("Delete 应为 [gone]，实际 %v", diff.Delete)
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged 应为 1（same 一个字段都没变），实际 %d", diff.Unchanged)
	}

	after := listTunnels(t, db)
	if _, ok := after["gone"]; ok {
		t.Error("不在清单里的隧道必须被删掉 —— 否则这是增量合并而不是声明式对齐")
	}
	if _, ok := after["added"]; !ok {
		t.Error("清单里的新隧道没建出来")
	}
	if got := after["changed"].Backend.Addr; got != "127.0.0.1:9999" {
		t.Errorf("changed 的后端应当被更新，实际 %q", got)
	}

	// 更新必须**原地**改而不是删了重建。
	if after["changed"].ID != oldChangedID {
		t.Errorf("更新不该换 ID：%q → %q —— 换了说明它被当成新隧道，"+
			"而旧记录还在库里时 slug 唯一约束会直接把写入顶回来",
			oldChangedID, after["changed"].ID)
	}
	if after["changed"].ShortID != oldChangedShort {
		t.Errorf("更新不该换短标识：%d → %d —— 短标识重新分配意味着在途的 "+
			"UDP 数据报会串到别的隧道去", oldChangedShort, after["changed"].ShortID)
	}
	// 没变的那条连 ID 都不该动。
	if after["same"].ID != before["same"].ID {
		t.Error("unchanged 的隧道不该被重写")
	}
}

// TestApplyConfigIsIdempotent 是「重跑是安全的」这句话的证据。
//
// 部分失败时回执让用户重跑同一份文档 —— 如果第二遍会做出不同的事
// （比如把每条都当成更新、或者换掉短标识），那句话就是假的，
// 而用户会照着它把配置搞坏。
func TestApplyConfigIsIdempotent(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	doc := docOf(t, 1,
		svcTunnel("a", 9420, "127.0.0.1:8080"),
		svcTunnel("b", 9421, "127.0.0.1:8081"),
	)

	code, first, body := postDoc(t, s, auth, "/api/config:apply", doc)
	if code != http.StatusOK {
		t.Fatalf("第一遍应当 200，实际 %d %s", code, body)
	}
	if len(first.Create) != 2 {
		t.Fatalf("第一遍应当新建 2 条，实际 %v", first.Create)
	}
	afterFirst := listTunnels(t, db)

	code, second, body := postDoc(t, s, auth, "/api/config:apply", doc)
	if code != http.StatusOK {
		t.Fatalf("第二遍应当 200，实际 %d %s", code, body)
	}
	if len(second.Create) != 0 || len(second.Update) != 0 || len(second.Delete) != 0 {
		t.Errorf("同一份文档跑第二遍应当什么都不做，实际 create=%v update=%v delete=%v",
			second.Create, second.Update, second.Delete)
	}
	if second.Unchanged != 2 {
		t.Errorf("第二遍应当报 2 条未变，实际 %d", second.Unchanged)
	}

	afterSecond := listTunnels(t, db)
	for slug, was := range afterFirst {
		now, ok := afterSecond[slug]
		if !ok {
			t.Fatalf("第二遍把 %s 弄丢了", slug)
		}
		if now.ID != was.ID || now.ShortID != was.ShortID {
			t.Errorf("%s 的身份在第二遍变了：ID %q→%q，短标识 %d→%d",
				slug, was.ID, now.ID, was.ShortID, now.ShortID)
		}
	}
}

// TestSameTunnelNoticesEveryFieldTheAPIExposes 防的是一类静默失败。
//
// sameTunnel 决定一条隧道算不算「未变」。它漏掉哪个字段，那个字段的改动
// 就会被报成 unchanged 而 apply 什么都不做 —— 现象是「我改了配置，
// 它说成功了，但没生效」，而库里的记录确实没动，无从查起。
//
// 逐字段列举而不是信任实现：实现用的是 JSON 比较，
// 这条测试要在**有人把它改成逐字段比较**时抓住漏项。
func TestSameTunnelNoticesEveryFieldTheAPIExposes(t *testing.T) {
	base := func() *tunnel.Tunnel {
		x := svcTunnel("x", 9430, "127.0.0.1:8080")
		x.Complete()
		return x
	}
	yes := true

	cases := []struct {
		field  string
		mutate func(*tunnel.Tunnel)
	}{
		{"slug", func(x *tunnel.Tunnel) { x.Slug = "y" }},
		{"kind", func(x *tunnel.Tunnel) { x.Kind = tunnel.KindReverse }},
		{"tls", func(x *tunnel.Tunnel) { x.TLS = tunnel.TLSGateway }},
		{"exposure", func(x *tunnel.Tunnel) { x.Exposure = tunnel.ExposureShared }},
		{"l4", func(x *tunnel.Tunnel) { x.L4 = tunnel.L4UDP }},
		{"agent_id", func(x *tunnel.Tunnel) { x.AgentID = "a1" }},
		{"listen_port", func(x *tunnel.Tunnel) { x.ListenPort = 9999 }},
		{"short_id", func(x *tunnel.Tunnel) { x.ShortID = 7 }},
		{"backend.addr", func(x *tunnel.Tunnel) { x.Backend.Addr = "127.0.0.1:1" }},
		{"backend.kind", func(x *tunnel.Tunnel) { x.Backend.Kind = tunnel.BackendUnix }},
		{"router", func(x *tunnel.Tunnel) {
			x.Router = &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{"a.example.com"}}
		}},
		{"policy", func(x *tunnel.Tunnel) {
			x.Policy = &tunnel.Policy{BytesPerSecond: 1 << 20}
		}},
		{"enabled", func(x *tunnel.Tunnel) { x.Enabled = &yes }},
		{"id", func(x *tunnel.Tunnel) { x.ID = "t-other" }},
	}
	for _, c := range cases {
		a, b := base(), base()
		c.mutate(b)
		if sameTunnel(a, b) {
			t.Errorf("%s 变了却被判成「未变」—— 那个字段的改动会被静默丢掉，"+
				"现象是「我改了配置，它说成功了，但没生效」", c.field)
		}
	}

	// 反面：一模一样必须判成未变。否则每次导入都会重写全部隧道，
	// 而每次重写都会触发一次 ApplyTunnels（重建监听器 = 掐断现有连接）。
	if !sameTunnel(base(), base()) {
		t.Error("完全相同的两条隧道必须判成「未变」")
	}

	// 状态是**观测**而不是期望：它变了不算配置变了。
	// 算的话，一条隧道从 draft 变成 active 就会让下一次导入把它重写一遍。
	withState := base()
	withState.State, withState.StateReason = tunnel.StateActive, "已监听"
	if !sameTunnel(base(), withState) {
		t.Error("状态是运行时观测，不该参与「变了没有」的判断")
	}
}

// TestApplyConfigRefusesTheWholeDocumentOnAnySingleError 是那道全量的门。
//
// 边校验边写的话，中间失败会留下**半个**配置 —— 用户既不知道哪些生效了，
// 也不知道该从哪里接着来。而这份文档里坏的那条排在最后，
// 所以「顺序写到坏的那条才发现」的实现会先把前面几条写进去。
func TestApplyConfigRefusesTheWholeDocumentOnAnySingleError(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	bad := svcTunnel("Bad Slug!", 9441, "127.0.0.1:8081")
	code, diff, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1,
		svcTunnel("good-one", 9440, "127.0.0.1:8080"),
		bad,
	))
	if code != http.StatusBadRequest {
		t.Fatalf("含一条不合法隧道的文档应当 400，实际 %d %s", code, body)
	}
	if diff.OK {
		t.Error("有校验错误时 ok 必须是 false")
	}
	if len(diff.Errors) != 1 {
		t.Fatalf("应当报告 1 条错误，实际 %d：%s", len(diff.Errors), body)
	}
	if diff.Errors[0].Index != 1 {
		t.Errorf("必须指出是第几条出错（前端要能定位），实际 index=%d", diff.Errors[0].Index)
	}
	if len(diff.Errors[0].Fields) == 0 {
		t.Error("必须给出逐字段错误 —— 只说「不合法」用户不知道改哪里")
	}

	if got := listTunnels(t, db); len(got) != 0 {
		t.Fatalf("一条不合法就该整份拒绝、什么都不写，实际库里有 %d 条：%v",
			len(got), slices.Collect(maps_keys(got)))
	}
}

// TestApplyConfigRejectsDuplicateSlugsInTheDocument 防的是一个歧义输入。
//
// 同一个 slug 出现两次时，「期望状态」是哪一条？后写的赢是任意选择，
// 而用户多半是复制粘贴时改漏了一个字段 —— 静默取一条会让另一条的设置
// 凭空消失，而导入本身报成功。
func TestApplyConfigRejectsDuplicateSlugsInTheDocument(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	code, diff, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1,
		svcTunnel("dup", 9450, "127.0.0.1:8080"),
		svcTunnel("dup", 9451, "127.0.0.1:8081"),
	))
	if code != http.StatusBadRequest {
		t.Fatalf("重复 slug 应当 400，实际 %d %s", code, body)
	}
	if len(diff.Errors) != 1 || diff.Errors[0].Slug != "dup" {
		t.Fatalf("应当指名是 dup 重复了：%s", body)
	}
	if !strings.Contains(diff.Errors[0].Detail, "两次") {
		t.Errorf("错误信息应当说清是「出现了两次」，实际 %q", diff.Errors[0].Detail)
	}
	if got := listTunnels(t, db); len(got) != 0 {
		t.Errorf("歧义文档不该写入任何东西，实际 %d 条", len(got))
	}
}

// TestApplyConfigIgnoresIDsSuppliedForNewTunnels 防的是一条越权路径。
//
// 接受文档里给的 ID 意味着一份文档可以指定「覆盖 t-xxxxxx」，
// 而那条隧道的 slug 可能完全不同 —— 结果是改掉一条用户没在文档里提到的隧道，
// 而 diff 里只会显示「新建 <文档里的 slug>」。
func TestApplyConfigIgnoresIDsSuppliedForNewTunnels(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("victim", 9460, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}
	victimID := listTunnels(t, db)["victim"].ID

	// 一条新隧道，却带着 victim 的 ID。
	attacker := svcTunnel("innocent-looking", 9461, "127.0.0.1:6666")
	attacker.ID = victimID
	// 顺带把 victim 留在文档里，这样它不会因为「不在清单里」被删 ——
	// 那条路径是合法的，会掩盖这里要测的东西。
	code, _, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1,
		svcTunnel("victim", 9460, "127.0.0.1:8080"), attacker))
	if code != http.StatusOK {
		t.Fatalf("这份文档本身是合法的，应当 200：%d %s", code, body)
	}

	after := listTunnels(t, db)
	v, ok := after["victim"]
	if !ok {
		t.Fatal("victim 被顶掉了 —— 文档里的 ID 被当真了")
	}
	if v.Backend.Addr != "127.0.0.1:8080" || v.ID != victimID {
		t.Errorf("victim 被改写了：%+v", v)
	}
	if got := after["innocent-looking"]; got == nil {
		t.Fatal("新隧道没建出来")
	} else if got.ID == victimID {
		t.Errorf("新隧道拿到了文档里指定的 ID %q —— ID 必须由中继分配", got.ID)
	}
}

// TestApplyConfigNeverTakesShortIDForAnExistingTunnel 钉住**更新**路径上的
// 短标识。
//
// TestApplyConfigIgnoresIDsSuppliedForNewTunnels 只覆盖了新建那一支，
// 而更新那一支曾经写着 `if t.ShortID == 0 { t.ShortID = old.ShortID }` ——
// 一份带非 0 short_id 的文档能把号改掉。两种后果：
//
//   - 撞上别的隧道 → 唯一索引顶回写入 → 一份合法文档变成 partial_apply，
//     而错误指向存储层，看不出是 short_id。
//   - 没撞上 → **静默改号**。UDP 数据报按短标识解复用，改号之后在途的包
//     会被当成未知隧道丢掉 —— 现象是「导入了一次配置，UDP 就断了几秒」，
//     而配置本身看起来毫无问题。
//
// 这条测试同时覆盖两种：一个已被占用的号，与一个空闲的号。
func TestApplyConfigNeverTakesShortIDForAnExistingTunnel(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	for _, spec := range []struct {
		slug string
		port uint16
	}{{"alpha", 9470}, {"beta", 9471}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
			svcTunnel(spec.slug, spec.port, "127.0.0.1:8080"))))
		if w.Code != http.StatusOK {
			t.Fatalf("前置创建 %s 失败：%s", spec.slug, w.Body.String())
		}
	}
	before := listTunnels(t, db)
	alphaShort, betaShort := before["alpha"].ShortID, before["beta"].ShortID
	if alphaShort == 0 || betaShort == 0 || alphaShort == betaShort {
		t.Fatalf("前置不成立：短标识应当各自非零且不同（%d / %d）", alphaShort, betaShort)
	}

	// 一份想把 alpha 的短标识改成 beta 的（撞号），
	// 同时把 beta 的改成一个大概率空闲的号（不撞号）。
	docAlpha := svcTunnel("alpha", 9470, "127.0.0.1:8080")
	docAlpha.ShortID = betaShort
	docBeta := svcTunnel("beta", 9471, "127.0.0.1:8080")
	docBeta.ShortID = 60001

	code, _, body := postDoc(t, s, auth, "/api/config:apply",
		docOf(t, 1, docAlpha, docBeta))
	if code != http.StatusOK {
		t.Fatalf("这份文档除了 short_id 之外完全合法，应当 200（short_id 该被忽略而不是"+
			"顶回整份导入）：%d %s", code, body)
	}

	// 库里的号不能变。
	//
	// **注意这一半单独测不出问题**：存储层的 UPDATE 子句本来就不含 short_id，
	// 所以哪怕代码把文档里的号一路带下去，库里也不会变 —— 这条断言在缺陷
	// 存在时同样为真。它留在这里是为了守住存储层那道防线（万一有人给
	// UPDATE 子句加上 short_id，UDP 就会在每次改配置时断一下）。
	after := listTunnels(t, db)
	if got := after["alpha"].ShortID; got != alphaShort {
		t.Errorf("alpha 的库内短标识被文档改成了 %d（原本 %d）—— "+
			"在途的 UDP 数据报会被当成未知隧道丢掉", got, alphaShort)
	}
	if got := after["beta"].ShortID; got != betaShort {
		t.Errorf("beta 的库内短标识被文档改成了 %d（原本 %d）", got, betaShort)
	}

	// **这一半才是真正的判据。**
	//
	// 缺陷的可见形态在**返回给用户的对象**上：库拦住了写入，但那个带着
	// 文档指定号的对象会顺着 diff / 响应体流出去。用户手里于是有一份
	// 「short_id=60001」的记录，而库里是 2 —— 他照那个号去对数据报帧头
	// 就永远对不上，而两边都没有任何错误。
	//
	// 重新 GET 一次就能看到权威值：它们必须与库一致。
	for _, tc := range []struct {
		slug string
		want uint16
	}{{"alpha", alphaShort}, {"beta", betaShort}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, auth(req(http.MethodGet,
			"/api/tunnels/"+after[tc.slug].ID, nil)))
		if w.Code != http.StatusOK {
			t.Fatalf("读 %s 失败：%d %s", tc.slug, w.Code, w.Body.String())
		}
		var got tunnel.Tunnel
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("解析 %s 失败：%v", tc.slug, err)
		}
		if got.ShortID != tc.want {
			t.Errorf("GET %s 回的短标识是 %d，库里是 %d —— "+
				"接口交出了一个从未落库的号", tc.slug, got.ShortID, tc.want)
		}
	}
}

// TestUpdatingATunnelNeverHandsBackAShortIDThatWasNeverStored 钉住 PUT 响应。
//
// 这是同一个缺陷在**手工编辑**路径上的形态，而它比声明式导入那条更常撞上：
// 控制台的 PUT 请求体里根本没有 short_id（前端不发），于是对象带着 0 进
// PutTunnel，旧代码看到 0 就去 allocShortID **分配一个新号**。UPDATE 子句
// 不写这一列，所以库里没变 —— 但响应体里那个号是一个当时**空闲**的号。
//
// 后果是延迟发生的：下一条新建的隧道会真的拿到那个号，于是用户手里那份
// 响应在事后变成了**另一条隧道**的标识。没有任何一步会报错。
func TestUpdatingATunnelNeverHandsBackAShortIDThatWasNeverStored(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("solo", 9480, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}
	created := listTunnels(t, db)["solo"]
	want := created.ShortID

	// 改一下后端地址（前端就是这么发的：不带 short_id）。
	upd := svcTunnel("solo", 9480, "127.0.0.1:9090")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPut, "/api/tunnels/"+created.ID, upd)))
	if w.Code != http.StatusOK {
		t.Fatalf("更新失败：%d %s", w.Code, w.Body.String())
	}
	var got tunnel.Tunnel
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ShortID != want {
		t.Errorf("PUT 响应里的短标识是 %d，库里是 %d —— "+
			"那是一个从未落库的空闲号，下一条新建的隧道会真的拿到它，"+
			"于是这份响应在事后变成别人的标识", got.ShortID, want)
	}
	if after := listTunnels(t, db)["solo"].ShortID; after != want {
		t.Errorf("库内短标识被改成了 %d（原本 %d）", after, want)
	}
}

// TestApplyConfigDeletesBeforeCreating 钉住写入顺序。
//
// 「把 8080 从 a 换到 b」是一份完全合法的文档。先建后删的话，
// 写 b 时 a 还占着那个端口，唯一约束会把它顶回来 ——
// 用户看到的是一次莫名其妙的 500，而文档本身没有任何问题。
func TestApplyConfigDeletesBeforeCreating(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("old-owner", 9470, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}

	// 同一个端口换给另一条 slug：old-owner 要删，new-owner 要建。
	code, _, body := postDoc(t, s, auth, "/api/config:apply",
		docOf(t, 1, svcTunnel("new-owner", 9470, "127.0.0.1:8080")))
	if code != http.StatusOK {
		t.Fatalf("把端口从一条隧道换到另一条是合法的，应当 200，实际 %d %s", code, body)
	}
	after := listTunnels(t, db)
	if _, gone := after["old-owner"]; gone {
		t.Error("old-owner 应当被删掉")
	}
	if got := after["new-owner"]; got == nil {
		t.Fatal("new-owner 没建出来")
	} else if got.ListenPort != 9470 {
		t.Errorf("new-owner 的端口应当是 9470，实际 %d", got.ListenPort)
	}
}

// TestConfigDocRejectsMalformedInput 覆盖解码那一层的每条拒绝路径。
//
// 这些都是**用户会真的打出来**的输入：粘漏了、粘重了、拼错了键、
// 忘了版本号。每一条的错误信息都要能让人知道自己打错了什么。
func TestConfigDocRejectsMalformedInput(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	cases := []struct {
		name string
		body any
		want string // 错误信息里必须出现的片段
		why  string
	}{
		{"空文档", rawDoc("   "), "空的",
			"编辑框还没填就按了按钮 —— 这不该是一个解析错误"},
		{"不是 JSON", rawDoc("这不是 JSON"), "解析失败",
			"要说清是文档本身解析失败，而不是请求格式不对"},
		{"缺版本号", rawDoc(`{"tunnels":[]}`), "version",
			"版本号是将来格式变更的唯一识别依据，缺了必须拒"},
		{"版本号不对", rawDoc(`{"version":2,"tunnels":[]}`), "version",
			"未来的格式用当前代码解会静默丢字段"},
		{"拼错的键", rawDoc(`{"version":1,"tunels":[]}`), "解析失败",
			"静默忽略拼错的键会让用户以为自己设置了那一项"},
		{"后面多粘了一段", rawDoc(`{"version":1,"tunnels":[]}{"version":1}`), "之后还有内容",
			"只取第一个对象会让用户以为后面那些也生效了"},
	}
	for _, c := range cases {
		for _, path := range []string{"/api/config:validate", "/api/config:apply"} {
			t.Run(c.name+path, func(t *testing.T) {
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, auth(req(http.MethodPost, path, c.body)))
				if w.Code != http.StatusBadRequest {
					t.Fatalf("应当 400（%s），实际 %d %s", c.why, w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), c.want) {
					t.Errorf("错误信息里应当出现 %q（%s），实际 %s", c.want, c.why, w.Body.String())
				}
			})
		}
	}

	if got := listTunnels(t, db); len(got) != 0 {
		t.Errorf("坏输入不该写入任何东西，实际 %d 条", len(got))
	}
}

// TestApplyEmptyDocumentDeletesEverythingAndSaysSo 是最危险的那条路径。
//
// 一份 tunnels: [] 的文档意味着「删掉全部」。它必须**能**工作
// （否则声明式语义有一个说不清的例外），但也必须在 diff 里逐条列出来 ——
// 那是用户在按下 apply 之前唯一的刹车。
func TestApplyEmptyDocumentDeletesEverythingAndSaysSo(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	for i, slug := range []string{"one", "two", "three"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
			svcTunnel(slug, uint16(9480+i), "127.0.0.1:8080"))))
		if w.Code != http.StatusOK {
			t.Fatalf("前置创建 %s 失败：%s", slug, w.Body.String())
		}
	}

	// 先干跑：必须逐条列出三条 —— 只回一个 ok 的 validate 让用户
	// 在按下 apply 之前无从知道自己要删什么。
	_, diff, body := postDoc(t, s, auth, "/api/config:validate", docOf(t, 1))
	if !slices.Equal(diff.Delete, []string{"one", "three", "two"}) {
		t.Fatalf("干跑必须按字典序逐条列出将被删除的 slug，实际 %v（%s）", diff.Delete, body)
	}

	code, applied, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1))
	if code != http.StatusOK {
		t.Fatalf("空文档是合法的（= 清空），应当 200，实际 %d %s", code, body)
	}
	if len(applied.Delete) != 3 {
		t.Errorf("应当删掉 3 条，实际 %v", applied.Delete)
	}
	if got := listTunnels(t, db); len(got) != 0 {
		t.Errorf("清空之后库里应当没有隧道，实际 %d 条", len(got))
	}
}

// TestApplyConfigLeavesAnAuditTrail 钉住留痕。
//
// 这是本仓库唯一一个能一次删掉多条隧道的入口。事后必须能回答
// 「谁在什么时候把配置整体换掉了、换掉了多少」—— 逐条记
// tunnel.deleted 会把一次整体替换拆成一串看起来互不相关的事件。
func TestApplyConfigLeavesAnAuditTrail(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	code, _, body := postDoc(t, s, auth, "/api/config:apply",
		docOf(t, 1, svcTunnel("audited", 9490, "127.0.0.1:8080")))
	if code != http.StatusOK {
		t.Fatalf("应当 200，实际 %d %s", code, body)
	}

	events, err := db.ListEvents(t.Context(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	idx := slices.IndexFunc(events, func(e store.Event) bool {
		return e.Kind == store.KindConfigApplied
	})
	if idx < 0 {
		t.Fatalf("应用配置必须留痕（%s），实际事件：%+v", store.KindConfigApplied, events)
	}
	e := events[idx]
	if e.Actor != "admin" {
		t.Errorf("必须记下是谁做的，实际 actor=%q", e.Actor)
	}
	if e.Level != store.LevelWarn {
		t.Errorf("这条事件含「删掉了 N 条」，级别应当是 warn，实际 %q", e.Level)
	}
	if !strings.Contains(e.Message, "新建 1") {
		t.Errorf("必须记下改了多少，实际 %q", e.Message)
	}

	// validate 不该留痕：它什么都没做，而每次「我看看」都写一条事件
	// 会把事件流冲成噪声。
	_, _, _ = postDoc(t, s, auth, "/api/config:validate", docOf(t, 1))
	events, err = db.ListEvents(t.Context(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range events {
		if e.Kind == store.KindConfigApplied {
			n++
		}
	}
	if n != 1 {
		t.Errorf("干跑不该留痕，config_applied 事件数 = %d，期望 1", n)
	}
}

// TestApplyConfigSyncsTheRuntime 钉住「存了就生效」。
//
// 不调 ApplyTunnels 的话，导入之后隧道躺在库里但没有任何监听器 ——
// 控制台显示一切正常，而实际上什么都不通。用户下一步会去重启中继，
// 然后以为「重启修好了」。
func TestApplyConfigSyncsTheRuntime(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)
	fake := s.snapshot.(*fakeSnapshot)

	before := fake.applied
	code, _, body := postDoc(t, s, auth, "/api/config:apply",
		docOf(t, 1, svcTunnel("synced", 9500, "127.0.0.1:8080")))
	if code != http.StatusOK {
		t.Fatalf("应当 200，实际 %d %s", code, body)
	}
	if fake.applied == before {
		t.Fatal("apply 之后必须让运行时生效 —— 否则隧道躺在库里但没有监听器，" +
			"控制台显示正常而实际上什么都不通")
	}

	// 干跑绝不能碰运行时。
	was := fake.applied
	_, _, _ = postDoc(t, s, auth, "/api/config:validate",
		docOf(t, 1, svcTunnel("synced", 9500, "127.0.0.1:8080")))
	if fake.applied != was {
		t.Error("validate 是干跑，不该触发运行时重建（那会掐断现有连接）")
	}
}

// TestApplyConfigReportsRuntimeFailureWithoutLying 钉住那条最容易撒谎的路。
//
// 端口被本进程之外的东西占着时，配置已经落盘但监听器起不来。
// 回 200 是撒谎；回 500 也不对（配置确实存了，用户重试会得到同样结果）。
// 必须是 409 + 说明，并且带上 diff 告诉用户存进去了什么。
func TestApplyConfigReportsRuntimeFailureWithoutLying(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)
	fake := s.snapshot.(*fakeSnapshot)
	fake.applyErr = fmt.Errorf("listen tcp :9510: bind: address already in use")

	code, res, body := postDoc(t, s, auth, "/api/config:apply",
		docOf(t, 1, svcTunnel("blocked", 9510, "127.0.0.1:8080")))
	if code != http.StatusConflict {
		t.Fatalf("运行时应用失败应当 409，实际 %d %s", code, body)
	}
	if res.OK {
		t.Error("失败回执里的 ok 必须是 false —— 留着 true 会让前端把一次" +
			"「存了但没起来」渲染成成功，而那正是用户之后无从下手的原因")
	}
	if !strings.Contains(body, "已保存") || !strings.Contains(body, "address already in use") {
		t.Errorf("必须同时说清「存了」与「为什么没起来」，实际 %s", body)
	}
	// 回执必须仍然带着 diff：用户要知道「存进去了什么」才能判断下一步。
	if len(res.Create) != 1 {
		t.Errorf("失败回执里也要带 diff（存了什么），实际 create=%v", res.Create)
	}
	// 配置确实要留在库里 —— 回滚要再做一遍同样可能失败的写入，
	// 而用户看到 409 之后的下一步是去解决端口冲突然后重试。
	if _, ok := listTunnels(t, db)["blocked"]; !ok {
		t.Error("运行时失败不该把已保存的配置回滚掉 —— 回执说的是「已保存」")
	}
}

// TestApplyConfigNeverTakesStateFromTheDocument 钉住「状态是观测而不是期望」。
//
// 这条曾经是**假绿**的：sameTunnel 会把状态清零再比较，所以一条只有状态
// 不同的隧道被判成「未变」、压根不会被写 —— 于是「不从文档里接受状态」
// 那行代码删掉之后测试照样通过。
//
// 真正的漏洞要**另一个字段同时改了**才暴露：那时隧道走 Update 分支被整条
// 写回去，而写进去的状态来自文档。后果是控制台把一条根本没在监听的隧道
// 显示成「运行中」，而用户会去查后端为什么不通 —— 查错了地方。
func TestApplyConfigNeverTakesStateFromTheDocument(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("running", 9520, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}
	id := listTunnels(t, db)["running"].ID
	if err := db.SetTunnelState(t.Context(), id, tunnel.StateActive, "已监听 9520"); err != nil {
		t.Fatal(err)
	}

	// 文档里改了后端（强制走 Update，整条写回），并且**谎报**状态是 draft。
	lying := svcTunnel("running", 9520, "127.0.0.1:9999")
	lying.State = tunnel.StateDraft
	lying.StateReason = "文档说的"
	// 同时新建一条，谎报它已经在跑了。
	fresh := svcTunnel("brand-new", 9521, "127.0.0.1:8081")
	fresh.State = tunnel.StateActive
	fresh.StateReason = "文档说的"

	code, _, body := postDoc(t, s, auth, "/api/config:apply", docOf(t, 1, lying, fresh))
	if code != http.StatusOK {
		t.Fatalf("这份文档本身合法，应当 200，实际 %d %s", code, body)
	}

	after := listTunnels(t, db)
	if got := after["running"]; got.State != tunnel.StateActive {
		t.Errorf("既有隧道的状态被文档改成了 %q（原因 %q）—— 状态是运行时观测，"+
			"文档改不动它。控制台会因此显示一条与现实不符的状态",
			got.State, got.StateReason)
	}
	if got := after["running"]; got.Backend.Addr != "127.0.0.1:9999" {
		t.Errorf("后端应当被更新（否则这条测试没走到 Update 分支），实际 %q", got.Backend.Addr)
	}
	if got := after["brand-new"]; got.State != tunnel.StateDraft {
		t.Errorf("新隧道的状态应当是 draft，实际 %q —— 一条刚建出来、"+
			"还没有任何监听器的隧道被显示成「运行中」", got.State)
	}
}

// TestRejectedDocumentGetsNoFabricatedPreview 钉住一条真机验证才暴露的问题。
//
// 逐条校验遇到坏条目是跳过它，所以「期望集合」里只剩碰巧合法的那些。
// 拿它算 diff，算出来的是「这份文档合法的那一部分会做什么」——
// 而那是中继永远不会进入的状态（校验是全量的门，整份会被拒）。
//
// 具体的现象：一份只有一条隧道拼错了 slug 的文档，回执里赫然写着
// delete: ["web"]（因为 web 不在「合法的那一部分」里）。用户读到的是
// 「它要删掉 web」，而实际上它什么都不会做。凭空造出来的预览
// 比没有预览糟得多 —— 用户会照着它做决定。
func TestRejectedDocumentGetsNoFabricatedPreview(t *testing.T) {
	s, db := newTestServer(t)
	auth := setupAndLogin(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth(req(http.MethodPost, "/api/tunnels",
		svcTunnel("web", 9530, "127.0.0.1:8080"))))
	if w.Code != http.StatusOK {
		t.Fatalf("前置创建失败：%s", w.Body.String())
	}

	// 文档里想留下 web，但那一条的 slug 拼错了 —— 于是它进不了期望集合。
	for _, path := range []string{"/api/config:validate", "/api/config:apply"} {
		code, diff, body := postDoc(t, s, auth, path,
			docOf(t, 1, svcTunnel("Bad Slug!", 9530, "127.0.0.1:8080")))
		if code != http.StatusBadRequest {
			t.Fatalf("%s 应当 400，实际 %d %s", path, code, body)
		}
		if len(diff.Errors) == 0 {
			t.Errorf("%s 必须给出错误，实际 %s", path, body)
		}
		if len(diff.Delete) != 0 || len(diff.Create) != 0 || len(diff.Update) != 0 {
			t.Errorf("%s 对一份被拒的文档给出了预览 create=%v update=%v delete=%v —— "+
				"整份文档会被拒，这些事一件都不会发生，而用户会照着它做决定",
				path, diff.Create, diff.Update, diff.Delete)
		}
		if diff.Unchanged != 0 {
			t.Errorf("%s 被拒的文档不该报「未变 %d」—— 那暗示它做过一次比较",
				path, diff.Unchanged)
		}
	}

	if _, ok := listTunnels(t, db)["web"]; !ok {
		t.Fatal("web 被删了 —— 被拒的文档不该动任何东西")
	}
}

// TestConfigEndpointsRequireAuth 是最基本的那道闸。
//
// 这两个端点一个能读出全部隧道配置、一个能删掉全部隧道。
// 漏挂 requireAuth 的后果不需要解释。
func TestConfigEndpointsRequireAuth(t *testing.T) {
	s, _ := newTestServer(t)
	_ = setupAndLogin(t, s) // 让首启完成，否则 401 可能来自「还没初始化」

	for _, path := range []string{"/api/config:validate", "/api/config:apply"} {
		w := httptest.NewRecorder()
		// 不带 Cookie、不带 CSRF 头。
		s.Handler().ServeHTTP(w, req(http.MethodPost, path, docOf(t, 1)))
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s 未鉴权时应当 401/403，实际 %d %s", path, w.Code, w.Body.String())
		}
	}
}

// maps_keys 避免为一行断言引入 maps 包的导入。
func maps_keys[K comparable, V any](m map[K]V) func(func(K) bool) { //nolint:revive // 测试内联工具
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
