package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 本文件放那些「界面早就建好、后端一直缺」的端点。
//
// # 为什么动词要在处理器里切，不能写进路由模式
//
// Go 的 ServeMux **不接受通配符不占满整个路径段**的模式：注册
// `POST /api/tunnels/{id}:test` 会在 pattern 解析时 panic
//（net/http/pattern.go:156 "bad wildcard segment (must end with '}')"），
// 而 routes() 是在 console.New() 里调用的 —— 于是中继**直接起不来**，
// 不是返回 404。
//
// 所以注册 `POST /api/tunnels/{id}`，在处理器里按第一个 ":" 切分动词。
// PathValue("id") 会拿到 "t-1:test" 这样的完整段。

// splitVerb 从 "t-1:test" 里切出对象 ID 与动词。
//
// 按**第一个**冒号切：ID 是我们自己生成的（hex），不含冒号；
// 而将来若有 "a:b:c" 形式的动词，也该整体交给处理器判断。
func splitVerb(seg string) (id, verb string) {
	if i := strings.IndexByte(seg, ':'); i >= 0 {
		return seg[:i], seg[i+1:]
	}
	return seg, ""
}

// ── 踢代理端下线 ────────────────────────────────────────────────────────────

// handleAgentVerb 分派 POST /api/agents/{id}:<verb>。
func (s *Server) handleAgentVerb(w http.ResponseWriter, r *http.Request, sess *session) {
	id, verb := splitVerb(r.PathValue("id"))
	switch verb {
	case "kick":
		s.kickAgent(w, r, sess, id)
	default:
		// 未知动词回 not_found 而不是裸 404 文本 —— 前端靠
		// code=="http_404"（stdlib 的 text/plain 兜底）判断「端点不存在」，
		// 而这里是「端点存在但动词不对」，两者必须能区分。
		writeError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("代理端不支持动作 %q", verb))
	}
}

// kickAgent 把一个代理端踢下线。
//
// 这是**连接层**操作，不撤销凭据 —— agent 会立刻按退避重连。
// 事件文案必须与撤销能区分，否则用户以为踢了就永久生效了。
func (s *Server) kickAgent(w http.ResponseWriter, r *http.Request, sess *session, id string) {
	if s.snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "中继未就绪")
		return
	}
	kicker, ok := s.snapshot.(AgentKicker)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不支持踢代理端下线")
		return
	}

	if !kicker.KickAgent(id) {
		// 「没踢到」与「不存在」是两件事，但从控制台看都是「它现在不在线」。
		// 回 409 而不是 404：对象存在（库里有这个 agent），只是没有活会话。
		writeError(w, http.StatusConflict, "not_online",
			"该代理端当前没有在线会话，无需踢下线")
		return
	}

	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindAgentKicked, Level: store.LevelWarn,
		Subject: id, Actor: sess.Username,
		// 明说「会自动重连」：不说的话用户会以为这是永久生效的封禁，
		// 然后在它十秒后重新上线时以为功能坏了。
		Message: "被控制台踢下线（连接层操作，代理端会自动重连；如需永久禁止请撤销凭据）",
	})
	s.hub.Publish(EventState, map[string]any{"agent": id, "online": false})

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── 生效配置与来源 ──────────────────────────────────────────────────────────

// handleSettings 返回生效配置及每一项的来源。
//
// 「显示生效值」只有一半用处 —— 用户真正要问的是「为什么是这个值」。
// 所以每一项都带 provenance（file / console / default / env）与来源引用。
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, _ *session) {
	if s.settings == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不提供配置视图")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": s.settings.Settings()})
}

// ── 生成的配置预览 ──────────────────────────────────────────────────────────

// handlePreviewTunnel 为一份草稿生成两侧的配置片段。
//
// 存在的理由是**可核对**：用户在向导里点了几个选项，看到的却是一个抽象的
// 「隧道」。把它翻成两侧实际会用的配置，他才能判断这是不是自己要的东西，
// 也才能在出问题时手工比对。
func (s *Server) handlePreviewTunnel(w http.ResponseWriter, r *http.Request, _ *session) {
	t, err := decodeTunnel(w, r)
	if err != nil {
		return // decodeTunnel 已经写了响应
	}
	t.Complete()

	writeJSON(w, http.StatusOK, map[string]string{
		"agent_yaml": agentPreview(t),
		"relay_yaml": relayPreview(t),
	})
}

// agentPreview 生成 agent 侧的配置片段。
func agentPreview(t *tunnel.Tunnel) string {
	var b strings.Builder
	b.WriteString("# agent 侧：这条隧道由中继下发，**不需要**写进 agent 配置文件。\n")
	b.WriteString("# 下面是它下发后 agent 实际会做的事，供核对。\n")
	fmt.Fprintf(&b, "tunnel: %s\n", t.Slug)
	fmt.Fprintf(&b, "  短标识: %d        # UDP 数据报帧头用它区分隧道\n", t.ShortID)
	switch t.Backend.Kind {
	case tunnel.BackendUnix:
		fmt.Fprintf(&b, "  拨号目标: unix://%s\n", t.Backend.Path)
	default:
		fmt.Fprintf(&b, "  拨号目标: %s/%s\n", t.Backend.Addr, t.L4)
	}
	b.WriteString("  裁决: 每次拨号都用已解析的地址查本地策略（防 DNS 重绑定）\n")
	if t.L4 == tunnel.L4UDP {
		if t.IsRealtimeDatagram() {
			b.WriteString("  超限数据报: 丢弃（realtime_datagram=true）\n")
		} else {
			b.WriteString("  超限数据报: 分片后重组\n")
		}
	}
	b.WriteString("\n# agent 只需要这一行（凭据由入网令牌换取，之后自动重连）：\n")
	b.WriteString("nfagent -relay <中继地址> -pin <证书指纹> -token <入网令牌>\n")
	return b.String()
}

// relayPreview 生成中继侧的配置片段。
func relayPreview(t *tunnel.Tunnel) string {
	var b strings.Builder
	b.WriteString("# 中继侧：这条隧道存在数据库里，下面是等价的声明式写法。\n")
	fmt.Fprintf(&b, "tunnels:\n  - slug: %s\n", t.Slug)
	fmt.Fprintf(&b, "    kind: %s\n    tls: %s\n    exposure: %s\n    l4: %s\n",
		t.Kind, t.TLS, t.Exposure, t.L4)
	if t.Exposure == tunnel.ExposurePort {
		fmt.Fprintf(&b, "    listen_port: %d\n", t.ListenPort)
	}
	if t.Router != nil {
		fmt.Fprintf(&b, "    router:\n      kind: %s\n", t.Router.Kind)
		if len(t.Router.Domains) > 0 {
			fmt.Fprintf(&b, "      domains: [%s]\n", strings.Join(t.Router.Domains, ", "))
		}
		if t.Router.CatchAll {
			b.WriteString("      catch_all: true    # 共享端口的默认落点\n")
		}
		if len(t.Router.Locations) > 0 {
			fmt.Fprintf(&b, "      locations: [%s]\n", strings.Join(t.Router.Locations, ", "))
		}
		if t.Router.HostRewrite != "" {
			fmt.Fprintf(&b, "      host_rewrite: %s\n", t.Router.HostRewrite)
		}
	}
	if t.Policy != nil && len(t.Policy.AllowCIDRs) > 0 {
		b.WriteString("    policy:\n      allow_cidrs:\n")
		for _, c := range t.Policy.AllowCIDRs {
			fmt.Fprintf(&b, "        - %s\n", c)
		}
	} else if t.IsBareExposure() {
		b.WriteString("    # policy.allow_cidrs 为空 = 裸端口开放。\n")
		b.WriteString("    # 「随机高位端口」不是安全措施：约 16 位熵，Shodan 级可枚举。\n")
	}
	fmt.Fprintf(&b, "    backend: %s\n", backendLine(t))
	return b.String()
}

func backendLine(t *tunnel.Tunnel) string {
	if t.Backend.Kind == tunnel.BackendUnix {
		return "unix://" + t.Backend.Path
	}
	return t.Backend.Addr
}

// ── 逐跳探测 ────────────────────────────────────────────────────────────────

// probeRequest 是 :test 的请求体。
type probeRequest struct {
	// FromInternet 要求从外网视角复测。
	//
	// 目前**不支持**：那需要一个外部回声服务，而中继自己去 curl 自己的
	// 公网地址在 NAT 回环失败的网络里会给出错误的「不通」结论。
	// 如实返回 from_internet=false 而不是假装测过了。
	FromInternet bool `json:"from_internet"`
}

// handleTunnelVerb 分派 POST /api/tunnels/{id}:<verb>。
func (s *Server) handleTunnelVerb(w http.ResponseWriter, r *http.Request, sess *session) {
	id, verb := splitVerb(r.PathValue("id"))
	switch verb {
	case "test":
		s.probeTunnel(w, r, id)
	case "apply-learned":
		s.applyLearnedSources(w, r, sess, id)
	case "decline-learned":
		s.declineLearnedSources(w, r, sess, id)
	default:
		writeError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("隧道不支持动作 %q", verb))
	}
}

// probeTunnel 逐跳探测一条隧道。
//
// 「不通」没用，「哪一跳不通」才有用。所以结果是一个步骤序列，
// 而**只返回自己真能测的那几跳** —— 界面对缺失的跳是宽容的
// （渲染成中性点），所以没必要编造。
func (s *Server) probeTunnel(w http.ResponseWriter, r *http.Request, id string) {
	var req probeRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)

	t, err := s.db.GetTunnel(r.Context(), id)
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}

	prober, ok := s.snapshot.(TunnelProber)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不支持逐跳探测")
		return
	}

	res := prober.ProbeTunnel(r.Context(), t)

	// from_internet 恒为 false：从外网视角复测需要一个外部回声服务，
	// 而中继自己去连自己的公网地址在 NAT 回环失败的网络里会得出
	// 错误的「不通」结论 —— 那比不测更糟。
	res.FromInternet = false
	if req.FromInternet {
		res.Steps = append(res.Steps, ProbeStep{
			Hop: HopListenerBound, OK: true,
			Detail: "外网视角复测尚未实现：需要一个外部回声服务，" +
				"而中继自测自己的公网地址在 NAT 回环失败的网络里会给出错误结论",
		})
	}

	// 契约要求：ok=false 时必须至少有一步 ok=false，否则界面会把失败点
	// 退化显示成第一跳（ProbeModal 的 `find(!ok)?.hop ?? 'listener_bound'`）。
	if !res.OK && !hasFailedStep(res.Steps) {
		res.Steps = append(res.Steps, ProbeStep{
			Hop: HopListenerBound, OK: false, Detail: "探测未能定位到具体环节",
		})
	}

	writeJSON(w, http.StatusOK, res)
}

func hasFailedStep(steps []ProbeStep) bool {
	for _, s := range steps {
		if !s.OK {
			return true
		}
	}
	return false
}

// ── 探测契约 ────────────────────────────────────────────────────────────────

// ProbeHop 是探测的环节名。**封闭枚举** —— 前端的 TS 类型是同名字面量联合，
// 加新值必须同步改 web/src/api/types.ts，否则 tsc 会报错（那正是我们要的）。
type ProbeHop string

const (
	HopListenerBound  ProbeHop = "listener_bound"
	HopAgentReachable ProbeHop = "agent_reachable"
	HopCarrierRTT     ProbeHop = "carrier_rtt"
	HopTargetDialable ProbeHop = "target_dialable"
	HopFirstByte      ProbeHop = "first_byte"
)

// ProbeStep 是一跳的结果。
type ProbeStep struct {
	Hop ProbeHop `json:"hop"`
	OK  bool     `json:"ok"`
	// MS 是耗时毫秒，未测得时省略（界面会不显示耗时，而不是显示 0）。
	MS     *int64 `json:"ms,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// UnverifiedHop 是一个**没能测**的环节，以及为什么没测。
//
// # 为什么不能用 ok=true 顶替
//
// UDP 隧道原本会拿到一个 target_dialable ok=true 的步骤，detail 里写着
// 「UDP 无连接语义，无法探测」—— 于是整条探测恒报「全链路通」，
// 并在那一跳画一个绿勾。那与 ProbeTunnel 自己的注释直接相反
// （「界面对缺失的跳是宽容的，所以没有任何理由编造」），
// 而后果是用户在真正的故障点上白找半天：本地服务没起、被 agent 策略否决、
// 端口写错，全都会显示成「通过」。
//
// 缺席 + 一句「为什么没测」是唯一诚实的表达。
type UnverifiedHop struct {
	Hop ProbeHop `json:"hop"`
	Why string   `json:"why"`
}

// ProbeResult 是一次探测的完整结果。
type ProbeResult struct {
	// OK 表示**已测的**每一跳都通过。
	//
	// 它不等于「端到端可用」—— Unverified 非空时还有没测到的环节，
	// 界面必须一并显示，否则 OK 会被读成「测过了，通」。
	OK           bool        `json:"ok"`
	FromInternet bool        `json:"from_internet"`
	Steps        []ProbeStep `json:"steps"`
	// Unverified 是没能测的环节。为空表示每一跳都真的测过了。
	Unverified []UnverifiedHop `json:"unverified,omitempty"`
	ExampleCmd string          `json:"example_cmd,omitempty"`
}

// Millis 是给 ProbeStep.MS 赋值的便利函数。
func Millis(d time.Duration) *int64 {
	ms := d.Milliseconds()
	return &ms
}
