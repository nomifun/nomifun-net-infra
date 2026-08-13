package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 整份配置的声明式导入。
//
// # 为什么单条 CRUD 不够
//
// 单条 CRUD 回答不了「把这台中继变成我想要的样子」：迁移、灾后重建、
// 把测试环境的配置搬到生产 —— 都是「我有一份完整清单，请对齐它」。
// 一条一条地建，中间任何一步失败都会留下**半个**配置，
// 而那时用户既不知道哪些生效了、也不知道该从哪里接着来。
//
// # 为什么 validate 与 apply 必须是两个端点
//
// 「先看看会发生什么」与「去做」是两个动作。合成一个（带 dry_run 标志）
// 会让「手滑漏了一个参数」变成一次真实的配置替换 —— 而这个操作能删隧道。

// ConfigDoc 是一份完整的配置文档。
//
// **只含隧道。** agent 是被动入网的（凭据由中继签发、令牌一次性），
// 而管理员口令与 TURN 密钥都不该出现在一份会被粘贴、被存进 git 的文档里。
type ConfigDoc struct {
	// Version 让将来的格式变更能被识别。当前只接受 1。
	Version int `json:"version"`

	// Tunnels 是**期望的完整集合**。
	//
	// 不在这份清单里的现存隧道会被**删除** —— 那正是「声明式」的含义，
	// 也是这个端点最需要被谨慎对待的地方。所以 validate 的结果里
	// 逐条列出将被删掉的 slug，而不是只回一个 ok。
	Tunnels []tunnel.Tunnel `json:"tunnels"`
}

// ConfigDiff 是一次 validate 的结果，也是 apply 的回执。
//
// # 为什么必须给出「将被删除」的清单
//
// 声明式导入会删掉不在清单里的东西。一个只回 {"ok":true} 的 validate
// 让用户无法在按下 apply 之前知道自己要删什么 ——
// 而那是这个操作唯一不可逆的部分。
type ConfigDiff struct {
	OK bool `json:"ok"`

	// Create / Update / Delete 是 slug 列表，按字典序（顺序必须稳定，
	// 否则同一份文档两次 validate 的输出会不一样，用户无法比对）。
	Create []string `json:"create"`
	Update []string `json:"update"`
	Delete []string `json:"delete"`

	// Unchanged 只给计数：把没变的东西列出来是噪声，
	// 而它存在的意义只是让用户确认「其余的都没动」。
	Unchanged int `json:"unchanged"`

	// Errors 是逐条隧道的校验错误。非空时 OK 必为 false。
	Errors []ConfigDocError `json:"errors,omitempty"`
}

// ConfigDocError 指明是**哪一条**隧道出了什么问题。
//
// 带 index 而不是只带 slug：一条连 slug 都没填的隧道无从指认，
// 而「第 3 条」用户总能数出来。
type ConfigDocError struct {
	Index  int          `json:"index"`
	Slug   string       `json:"slug,omitempty"`
	Fields []FieldError `json:"fields,omitempty"`
	Detail string       `json:"detail,omitempty"`
}

// ConfigApplyResult 是 apply 的回执。
//
// **内嵌** ConfigDiff 而不是把它放在一个 "diff" 键下面：这样 apply 与
// validate 的响应是同一个形状，前端用同一段代码渲染两者 ——
// 而两套渲染代码里总有一套会漏掉「将被删除」那一栏。
type ConfigApplyResult struct {
	ConfigDiff
	// Applied 是**已经落盘**的条数（删 + 写）。
	//
	// 部分失败时它是用户唯一的定位信息。成功时它等于
	// len(Create)+len(Update)+len(Delete)。
	Applied int `json:"applied"`

	// Code / Message 只在失败时出现，与 APIError 的字段名一致。
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// maxConfigDocBytes 是文档大小上限。
//
// 1 MiB 够放几千条隧道。设上限是因为这个端点会把整份文档读进内存再解析两遍。
const maxConfigDocBytes = 1 << 20

// decodeConfigDoc 解出前端提交的文档。
//
// 前端提交的是 {"doc": "<文本>"}（一个可粘贴的编辑框），所以要**两层**解码。
// 这样做而不是直接 POST 文档本身：编辑框里的内容可能压根不是合法 JSON，
// 而那时的错误信息应当指出解析在哪里失败，而不是一个空壳 400。
func decodeConfigDoc(w http.ResponseWriter, r *http.Request) (*ConfigDoc, bool) {
	var wrap struct {
		Doc string `json:"doc"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigDocBytes)).Decode(&wrap); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return nil, false
	}
	text := strings.TrimSpace(wrap.Doc)
	if text == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "配置文档是空的")
		return nil, false
	}

	var doc ConfigDoc
	dec := json.NewDecoder(strings.NewReader(text))
	// 拒绝未知字段：一个拼错的键静默被忽略，用户会以为自己设置了那一项。
	// 与 decodeTunnel 同一条原则。
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_doc", "配置文档解析失败："+err.Error())
		return nil, false
	}
	// 必须确认文档到此结束。DisallowUnknownFields 管不到「一个合法对象后面
	// 又跟了一坨东西」—— 那种输入通常是粘贴时多带/重复了一段，
	// 静默只取第一个对象会让用户以为后面那些也生效了。
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_doc",
			"配置文档在第一个 JSON 对象之后还有内容 —— 多半是粘贴时多带了一段")
		return nil, false
	}
	if doc.Version != 1 {
		writeError(w, http.StatusBadRequest, "invalid_doc",
			fmt.Sprintf("只支持 version: 1，收到 %d", doc.Version))
		return nil, false
	}
	return &doc, true
}

// diffConfigDoc 算出一份文档相对当前状态的差异，并逐条校验。
//
// **除了读一次现状之外没有副作用**：validate 与 apply 共用它，
// 从而保证「validate 说会发生什么」与「apply 真的做了什么」不会漂开 ——
// 两处各写一遍 diff 是这类端点最经典的 bug 来源。
//
// 返回的 want/have 都按 slug 索引，apply 直接用它们而不再查一遍库
// （那一遍查询会带来一个 TOCTOU 的缝：diff 说要删 a，重查时 a 已经不在了）。
//
// 文档不合法时 want 为 nil 且 diff 里只有 Errors —— 理由见函数体里那段注释。
// 调用方本来就必须在 diff.OK 为 false 时提前返回，所以 nil 是安全的。
func (s *Server) diffConfigDoc(
	r *http.Request, doc *ConfigDoc,
) (diff *ConfigDiff, want, have map[string]*tunnel.Tunnel, err error) {
	existing, err := s.db.ListTunnels(r.Context(), tunnel.DefaultTenantID)
	if err != nil {
		return nil, nil, nil, err
	}
	have = make(map[string]*tunnel.Tunnel, len(existing))
	for _, t := range existing {
		have[t.Slug] = t
	}

	// 三个列表都初始化成空切片而不是 nil：它们会被序列化给前端，
	// 而 null 与 [] 在 TS 那边是两种类型，前端得为此多写一次判空。
	diff = &ConfigDiff{OK: true, Create: []string{}, Update: []string{}, Delete: []string{}}
	want = make(map[string]*tunnel.Tunnel, len(doc.Tunnels))

	for i := range doc.Tunnels {
		t := doc.Tunnels[i] // 值拷贝：不改调用方的文档
		if t.Slug == "" {
			diff.OK = false
			diff.Errors = append(diff.Errors, ConfigDocError{Index: i,
				Detail: "缺少 slug —— 声明式导入按 slug 对齐，" +
					"没有它无从判断这是新建还是更新"})
			continue
		}
		if _, dup := want[t.Slug]; dup {
			diff.OK = false
			diff.Errors = append(diff.Errors, ConfigDocError{Index: i, Slug: t.Slug,
				Detail: "同一个 slug 在文档里出现了两次 —— 那时无从判断哪一条是期望状态"})
			continue
		}

		t.TenantID = tunnel.DefaultTenantID
		if old, ok := have[t.Slug]; ok {
			// 沿用既有隧道的 ID 与短标识。**必须这样做**，否则一次导入会把
			// 每条隧道都当成新的：旧记录还在库里，slug 的唯一约束会把写入
			// 直接顶回来；而就算顶不回来，短标识重新分配意味着在途的 UDP
			// 数据报会串到别的隧道去（那是本仓修过的一个真实缺陷）。
			t.ID = old.ID
			// 短标识**无条件**沿用既有值，文档里带的号一概不认。
			//
			// 这里此前写的是 `if t.ShortID == 0 { t.ShortID = old.ShortID }`，
			// 于是一份带非 0 short_id 的文档能把那个号带进后续流程。
			//
			// **库拦得住**（store.PutTunnel 现在无条件用库里那个号，
			// 而 UPDATE 子句只回填 0、绝不改号），所以这一行不是最后一道防线，
			// 也不是唯一一道 —— 它存在的理由是让这一层自己说得通：
			// 上面那段注释声称短标识由中继决定，那这里就不该有一个「除非
			// 客户端指定了」的分支。两处都对的时候，将来任何一处松动都还有
			// 另一处兜着；而只要有一处写着「除非」，读代码的人就会以为
			// 客户端指定是被支持的。
			t.ShortID = old.ShortID
			// 状态是**观测**而不是期望，绝不从文档里接受 ——
			// 否则一份从别处拷来的文档会把 active 写进来，
			// 控制台会把一条根本没在监听的隧道显示成「运行中」。
			t.State, t.StateReason = old.State, old.StateReason
		} else {
			// 新隧道：文档里带的 ID / 短标识 / 状态一概不认。
			//
			// ID 由中继分配 —— 接受外来 ID 意味着一份文档可以指定
			// 「覆盖 t-xxxxxx」，而那条隧道的 slug 可能完全不同：
			// 结果是改掉一条用户没提到的隧道。短标识同理，
			// 只有存储层看得见哪些号已经用掉了。
			t.ID, t.ShortID = "", 0
			t.State, t.StateReason = "", ""
		}

		t.Complete()
		if err := t.Validate(); err != nil {
			diff.OK = false
			diff.Errors = append(diff.Errors, ConfigDocError{
				Index: i, Slug: t.Slug, Fields: fieldErrors(err),
			})
			continue
		}
		want[t.Slug] = &t
	}

	// 文档有错就**不给 diff**，只给错误。
	//
	// 上面的循环遇到坏条目是 continue，所以 want 里只剩「碰巧合法的那些」。
	// 拿它算出来的 diff 描述的是「这份文档合法的那一部分会做什么」——
	// 而那是一个中继永远不会进入的状态（校验是全量的门，整份会被拒）。
	//
	// 这一条是真机验证抓出来的：一份只有一条隧道拼错了 slug 的文档，
	// 回执里赫然写着 delete: ["web"] —— 因为 web 不在「合法的那一部分」里。
	// 用户读到的是「它要删掉 web」，而实际上它什么都不会做。
	// 一个凭空造出来的预览比没有预览糟得多。
	if !diff.OK {
		return diff, nil, have, nil
	}

	for slug, t := range want {
		old, ok := have[slug]
		switch {
		case !ok:
			diff.Create = append(diff.Create, slug)
		case sameTunnel(old, t):
			diff.Unchanged++
		default:
			diff.Update = append(diff.Update, slug)
		}
	}
	for slug := range have {
		if _, keep := want[slug]; !keep {
			diff.Delete = append(diff.Delete, slug)
		}
	}
	slices.Sort(diff.Create)
	slices.Sort(diff.Update)
	slices.Sort(diff.Delete)
	return diff, want, have, nil
}

// sameTunnel 判断两条隧道的**期望状态**是否相同。
//
// 比较序列化结果而不是逐字段：逐字段比较会在每次新增字段时默认漏掉它，
// 于是一次真实的改动被报成 unchanged 而 apply 什么都不做 ——
// 那种 bug 的现象是「我改了配置，它说成功了，但没生效」。
func sameTunnel(a, b *tunnel.Tunnel) bool {
	// 顶层字段的值拷贝就够：下面只清零标量，不碰 Router/Policy 指针的指向。
	x, y := *a, *b
	// 状态是观测而不是期望。diffConfigDoc 已经对齐过它，
	// 这里再清一次是为了让这个函数单独看也是对的。
	x.State, y.State = "", ""
	x.StateReason, y.StateReason = "", ""
	ja, err1 := json.Marshal(x)
	jb, err2 := json.Marshal(y)
	if err1 != nil || err2 != nil {
		// 序列化失败时报「不同」：宁可多做一次无谓的更新，
		// 也不要把一次真实改动漏掉。
		return false
	}
	return string(ja) == string(jb)
}

// handleValidateConfig 是**真正的干跑**：只算差异，一个字节都不写。
func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request, _ *session) {
	doc, ok := decodeConfigDoc(w, r)
	if !ok {
		return
	}
	diff, _, _, err := s.diffConfigDoc(r, doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "读取现状失败："+err.Error())
		return
	}
	code := http.StatusOK
	if !diff.OK {
		code = http.StatusBadRequest
	}
	writeJSON(w, code, diff)
}

// handleApplyConfig 把一份文档落成期望状态。
//
// # 为什么校验是一道全量的门
//
// 一条一条地边校验边写，中间失败会留下**半个**配置 ——
// 用户既不知道哪些生效了，也不知道该从哪里接着来。
// 所以任何一条不合法就整份拒绝，什么都不动。
//
// # 写入本身不是原子的，以及为什么可以接受
//
// store 没有跨多条隧道的事务口子，所以写入是逐条的。写到一半失败会留下
// 部分应用的状态 —— 那时回执里的 applied 指明「已生效几条」，
// 而**重跑同一份文档是安全的**（声明式：它描述终态而不是增量）。
// 这一点如实写在 README 里，不假装它是原子的。
func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request, sess *session) {
	doc, ok := decodeConfigDoc(w, r)
	if !ok {
		return
	}
	diff, want, have, err := s.diffConfigDoc(r, doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "读取现状失败："+err.Error())
		return
	}
	if !diff.OK {
		// 全量的门：一条不合法就整份拒绝，什么都不动。回的是同一个 diff
		// 结构，于是前端能用同一段代码渲染 validate 与 apply 的失败。
		writeJSON(w, http.StatusBadRequest, diff)
		return
	}

	applied := 0
	fail := func(status int, code, msg string) {
		// OK 置为 false。
		//
		// 走到这里时文档本身是合法的（diff.OK 曾是 true），但**这次请求
		// 没做到它说的事**。留着 true 会让前端把一次部分失败渲染成成功 ——
		// 而那正是用户之后无从下手的原因。
		out := ConfigApplyResult{ConfigDiff: *diff, Applied: applied, Code: code, Message: msg}
		out.OK = false
		writeJSON(w, status, out)
	}
	failWrite := func(what, slug string, err error) {
		s.log.Error("应用配置文档失败", "阶段", what, "隧道", slug, "已生效", applied, "err", err)
		fail(http.StatusInternalServerError, "partial_apply",
			fmt.Sprintf("%s隧道 %s 失败：%v —— 已生效 %d 条。"+
				"这份文档描述的是终态，直接重跑它是安全的。", what, slug, err, applied))
	}

	// 先删再建。
	//
	// 反过来的话，一次「把 8080 从 a 换到 b」的导入会在写 b 时撞上
	// a 还占着的端口唯一约束 —— 而那份文档本身完全合法。
	for _, slug := range diff.Delete {
		if err := s.db.DeleteTunnel(r.Context(), have[slug].ID); err != nil {
			failWrite("删除", slug, err)
			return
		}
		applied++
	}
	for _, slug := range slices.Concat(diff.Create, diff.Update) {
		t := want[slug]
		if t.ID == "" {
			id, err := randomToken(6)
			if err != nil {
				failWrite("创建", slug, err)
				return
			}
			t.ID = "t-" + id
		}
		if err := s.db.PutTunnel(r.Context(), t); err != nil {
			failWrite("写入", slug, err)
			return
		}
		applied++
	}

	// Warn 而不是 Info：这条事件里含「删掉了 N 条」，
	// 而这是本仓库唯一一个能一次删掉多条隧道的入口。
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindConfigApplied, Level: store.LevelWarn, Actor: sess.Username,
		Message: fmt.Sprintf("应用配置文档：新建 %d、更新 %d、删除 %d、未变 %d",
			len(diff.Create), len(diff.Update), len(diff.Delete), diff.Unchanged),
	})

	// 运行时应用失败不回滚，只如实报出来 —— 与 putTunnel 一致：
	// 配置已经落盘了，回滚要再做一遍同样可能失败的写入。
	// 报 conflict 让用户知道「存了但没起来」，diff 告诉他存了什么。
	if s.snapshot != nil {
		if err := s.snapshot.ApplyTunnels(); err != nil {
			s.log.Error("应用配置文档后同步运行时失败", "err", err)
			fail(http.StatusConflict, "apply_failed",
				"配置已保存，但运行时应用失败："+err.Error()+
					"（通常是端口被本进程之外的东西占了）")
			return
		}
	}
	writeJSON(w, http.StatusOK, ConfigApplyResult{ConfigDiff: *diff, Applied: applied})
}
