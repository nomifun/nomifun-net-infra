package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 学习模式的两个端点。
//
// 承诺是「一键收窄暴露面」：一条隧道刚建好时 allow_cidrs 通常为空
// （放行一切），而运维手上没有真实客户端的地址。这里把中继**实际观测到**
// 的来源交给他，让他据此收窄。
//
// 此前这个承诺只交付了一半 —— 前端有 client 方法与类型，两个端点都不存在，
// 于是那个面板一旦渲染出来就只会 404。
//
// # 三条必须守住的性质
//
//  1. **空集合绝不写下去。** allow_cidrs 为空的语义是「放行一切」
//     （tunnel.SourceAllowed 的第一行），所以把一个空的学习结果应用下去
//     不是「收窄」而是**保持全开**，而界面会显示成功。必须拒绝。
//  2. **只能应用真的观测到的前缀。** 这个端点叫 apply-learned，
//     不是「写任意 CIDR」——后者是 PUT /api/tunnels/{id} 的活。
//     客户端送来一个没在观测列表里的前缀就是它误解了这个端点，报错比接受好。
//  3. **与既有 allow_cidrs 取并集，不覆盖。** 覆盖会把运维手填的网段
//     悄悄删掉（那些网段可能覆盖的是还没露面的客户端）——
//     一个「收窄」动作把别的白名单删掉，是这条路径上最容易造成失联的形态。
const maxApplyLearnedBody = 16 << 10

// applyLearnedRequest 是 :apply-learned 的可选请求体。
//
// # 为什么 CIDRs 是指针
//
// 必须区分「字段缺席」与「字段是空数组」，而 []string 做不到 ——
// 两者的 len 都是 0。
//
//	缺席 / null → 应用全部观测到的前缀（curl 顺手用的形态）
//	[]         → **拒绝**，回 nothing_selected
//
// 合并这两种是一个真实的坑：界面或脚本算出一个空选集时，本该什么都不做，
// 却会变成「应用全部」—— 而学习窗口里扫描器的地址与真客户端混在一起，
// 那一下就是把撞门的人一键请进允许列表。这正是这个功能想解决的问题的反面。
//
// 真机验证抓出来的：`{"cidrs":[]}` 当时回了 200 并把观测到的全部写了下去。
type applyLearnedRequest struct {
	CIDRs *[]string `json:"cidrs"`
}

// handleLearnedSources 处理 GET /api/tunnels/{id}/learned-sources。
func (s *Server) handleLearnedSources(w http.ResponseWriter, r *http.Request, _ *session) {
	id := r.PathValue("id")
	if _, err := s.db.GetTunnel(r.Context(), id); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	obs, ok := s.snapshot.(SourceObserver)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不观测来源地址")
		return
	}

	got, ok := obs.ObservedSources(id)
	if !ok {
		// 没有记录 ≠ 空列表。回一个 sources 为空数组、observed_from 为零值的
		// 结果，界面据此显示「还没观测到任何来源」而不是「没人连过」。
		got = LearnedSources{TunnelID: id, Sources: []LearnedSource{}}
	}
	if got.Sources == nil {
		got.Sources = []LearnedSource{}
	}
	writeJSON(w, http.StatusOK, got)
}

// applyLearnedSources 处理 POST /api/tunnels/{id}:apply-learned。
func (s *Server) applyLearnedSources(w http.ResponseWriter, r *http.Request, sess *session, id string) {
	t, err := s.db.GetTunnel(r.Context(), id)
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	obs, ok := s.snapshot.(SourceObserver)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不观测来源地址")
		return
	}

	var req applyLearnedRequest
	// 空请求体是合法的（表示「全部应用」），所以解析失败只在**有内容**
	// 却解不出来时才算错误。
	if r.ContentLength != 0 {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxApplyLearnedBody))
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request",
				"请求体不是合法 JSON："+err.Error())
			return
		}
	}

	got, has := obs.ObservedSources(id)
	if !has || len(got.Sources) == 0 {
		writeError(w, http.StatusConflict, "nothing_learned",
			"这条隧道还没观测到任何来源地址，没有可应用的内容。"+
				"注意：把空列表写成 allow_cidrs 等于**放行一切**，所以这里拒绝而不是照做。")
		return
	}

	observed := make(map[string]bool, len(got.Sources))
	for _, srcEntry := range got.Sources {
		observed[srcEntry.CIDR] = true
	}

	// 选出要应用的前缀。
	var want []string
	switch {
	case req.CIDRs == nil:
		// 字段缺席：应用全部观测到的。
		want = make([]string, 0, len(got.Sources))
		for _, srcEntry := range got.Sources {
			want = append(want, srcEntry.CIDR)
		}
	case len(*req.CIDRs) == 0:
		// 显式的空数组：什么都不做，而且要说清为什么不是「全部」。
		writeError(w, http.StatusBadRequest, "nothing_selected",
			"cidrs 是空数组 —— 那表示「一条都不选」，本端点不会把它当成「全选」。"+
				"要应用全部观测到的来源请省略 cidrs 字段。"+
				"（顺带：空的 allow_cidrs 语义是放行一切，写空不是收窄。）")
		return
	default:
		want = *req.CIDRs
	}

	chosen := make([]netip.Prefix, 0, len(want))
	var unknown []string
	for _, raw := range want {
		c := strings.TrimSpace(raw)
		if !observed[c] {
			unknown = append(unknown, raw)
			continue
		}
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			// 观测侧生成的字符串解不回来说明两边的表示不一致，
			// 那是缺陷而不是用户输入错误。
			writeError(w, http.StatusInternalServerError, "internal",
				fmt.Sprintf("观测到的前缀 %q 解析失败：%v", c, perr))
			return
		}
		chosen = append(chosen, p)
	}
	if len(unknown) > 0 {
		writeError(w, http.StatusBadRequest, "not_observed",
			fmt.Sprintf("这些前缀不在观测列表里：%s。"+
				"本端点只能应用观测到的来源；要写任意网段请用 PUT /api/tunnels/{id}。",
				strings.Join(unknown, ", ")))
		return
	}
	if len(chosen) == 0 {
		// 走到这里意味着上面两条闸门都没拦住一个空集合 —— 不该发生，
		// 但**绝不能**继续：空 allow_cidrs 的语义是放行一切，
		// 而这条路径的名字叫「收窄」。
		writeError(w, http.StatusBadRequest, "nothing_selected",
			"没有选出任何前缀。空的允许列表等于放行一切，所以这里拒绝而不是照做。")
		return
	}

	// 与既有白名单取并集。
	if t.Policy == nil {
		t.Policy = &tunnel.Policy{}
	}
	before := len(t.Policy.AllowCIDRs)
	merged := slices.Clone(t.Policy.AllowCIDRs)
	for _, p := range chosen {
		if !slices.Contains(merged, p) {
			merged = append(merged, p)
		}
	}
	t.Policy.AllowCIDRs = merged
	added := len(merged) - before

	// 一次都没加上：全部已在白名单里。据实回报而不是假装改了 ——
	// 「点了按钮、什么都没变、界面说成功」会让人以为功能坏了。
	if added == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"tunnel":  t,
			"added":   0,
			"message": "观测到的来源已经全部在允许列表里，没有需要新增的。",
		})
		return
	}

	// 走与手工编辑同一条落库 + 应用路径：校验、PutTunnel、ApplyTunnels、
	// 审计事件、SSE。**不复制那套逻辑** —— 复制出来的第二条路径迟早会
	// 漏掉其中一步（本仓已经在隧道状态上吃过两次这种苦）。
	s.putTunnel(w, r, t, sess, store.KindTunnelUpdated,
		fmt.Sprintf("学习模式收窄来源：新增 %d 个允许前缀（共 %d 个）", added, len(merged)))
}

// declineLearnedSources 处理 POST /api/tunnels/{id}:decline-learned。
//
// 只记一个「不用再提示了」的标记，不改任何配置。它与观测数据同生命周期
// （重启即忘）：重启之后观测列表本身也空了，再提示一次是对的。
func (s *Server) declineLearnedSources(w http.ResponseWriter, r *http.Request, _ *session, id string) {
	if _, err := s.db.GetTunnel(r.Context(), id); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	obs, ok := s.snapshot.(SourceObserver)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不观测来源地址")
		return
	}
	obs.DeclineLearnedSources(id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "declined": true})
}
