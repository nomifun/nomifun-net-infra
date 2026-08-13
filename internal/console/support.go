package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 支持包。
//
// # 它是一份脱敏后的 JSON 摘要，**不是数据库快照**
//
// store.Backup 存在，而它**刻意不接**进这条路径：库里有
//   - agent 密钥的**明文**（不是哈希 —— HMAC 校验需要密钥本身，
//     见 migrations/00001_init.sql 里 secret 列的注释）
//   - argon2id 口令哈希、会话与 CSRF 令牌、入网令牌哈希
//   - TURN 长期密钥（server_secrets）
//
// 一份 DB 快照就是这台中继的**完整沦陷**。而支持包的用途恰恰是发给别人看 ——
// 贴进 issue、发给同事、丢进工单系统。两件事的信任边界完全相反。
//
// # 脱敏的判据是「白名单」而不是「黑名单」
//
// 逐字段挑要放进去的东西，而不是「导出全部再删掉几个」。后者在每次新增字段时
// 都默认泄露 —— 而新增字段是最经常发生的事。

// SupportBundleEvents 是支持包里带的近期事件条数。
//
// 200 条：足够覆盖一次故障前后的上下文，又不会让文件大到没法贴。
const SupportBundleEvents = 200

// SupportBundle 是支持包的顶层结构。
type SupportBundle struct {
	// FormatVersion 让将来的解析方能判断自己认不认识这份文件。
	FormatVersion int    `json:"format_version"`
	GeneratedAt   string `json:"generated_at"`
	RelayVersion  string `json:"relay_version"`

	// SchemaVersion 缺席表示读取失败。**不填 0** —— 0 会被读成
	// 「schema 版本是 0」，而那是一个合法值（迁移一条都没跑）。
	SchemaVersion *int64 `json:"schema_version,omitempty"`

	Totals   *SnapshotTotals    `json:"totals,omitempty"`
	Shared   *SharedEntryStatus `json:"shared,omitempty"`
	Agents   []SupportAgent     `json:"agents"`
	Tunnels  []SupportTunnel    `json:"tunnels"`
	Settings []SettingsGroup    `json:"settings,omitempty"`
	Turn     *SupportTurn       `json:"turn,omitempty"`
	Events   []SupportEvent     `json:"events"`

	// Interfaces 报告哪几个可选接口装上了。
	//
	// 排障时第一个要问的往往是「你这个版本有没有那个功能」——
	// 而「有按钮但接口没装」与「接口装了但报错」的处置完全不同。
	Interfaces map[string]bool `json:"interfaces"`

	// Omitted 逐条说明**为什么**某一段没有内容。
	//
	// 空着一段而不解释，读的人无法区分「这台中继没有这个」与
	// 「导出的时候出错了」。而那两者的下一步完全不同。
	Omitted []string `json:"omitted,omitempty"`
}

// SupportAgent 是一个 agent 的摘要。**不含**密钥、machine_id。
type SupportAgent struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Online   bool   `json:"online"`
	Revoked  bool   `json:"revoked"`
	Rung     string `json:"rung,omitempty"`
	// Reported 是 agent 自报的计数器（不含任何地址）。
	Reported *AgentReportedMetrics `json:"reported,omitempty"`
}

// SupportTunnel 是一条隧道的摘要。
//
// **含**后端地址与域名：那些是排障必需的，而且它们是用户自己填的配置，
// 不是凭据。**不含**任何运行时观测到的客户端地址。
type SupportTunnel struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	Kind       string   `json:"kind"`
	TLS        string   `json:"tls"`
	Exposure   string   `json:"exposure"`
	L4         string   `json:"l4"`
	ListenPort uint16   `json:"listen_port,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	ShortID    uint16   `json:"short_id,omitempty"`
	Backend    string   `json:"backend,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	State      string   `json:"state"`
	Reason     string   `json:"reason,omitempty"`
	// Runtime 缺席表示这条隧道当前没有入口在跑。
	// **缺席而不是一堆 0** —— 0 会被读成「测过，是零」。
	Runtime *TunnelStatus `json:"runtime,omitempty"`
}

// SupportTurn 只放**计数**，绝不放分配明细。
//
// 分配明细里有真实的对端地址与用户名（用户名含租户标识）——
// 那些是运行时观测到的第三方信息，不该出现在一份要发给别人的文件里。
type SupportTurn struct {
	Allocations int `json:"allocations"`
}

// SupportEvent 是一条脱敏后的事件。
type SupportEvent struct {
	At      string `json:"at"`
	Level   string `json:"level"`
	Kind    string `json:"kind"`
	Subject string `json:"subject,omitempty"`
	Actor   string `json:"actor,omitempty"`
	Message string `json:"message"`
}

// handleSupportBundle 生成并下发支持包。
//
// 当前行为若不实现是**下载到一个内容为 `404 page not found` 的文件** ——
// 前端那个按钮（Diagnostics.tsx）直接指向这个路径。一个假文件比一个明确的
// 「未实现」更糟：用户会把它贴进 issue。
func (s *Server) handleSupportBundle(w http.ResponseWriter, r *http.Request, sess *session) {
	b := SupportBundle{
		FormatVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Interfaces:    map[string]bool{},
		Agents:        []SupportAgent{},
		Tunnels:       []SupportTunnel{},
		Events:        []SupportEvent{},
	}
	omit := func(why string) { b.Omitted = append(b.Omitted, why) }

	b.Interfaces["snapshot"] = s.snapshot != nil
	b.Interfaces["settings"] = s.settings != nil
	b.Interfaces["turn"] = s.turn != nil
	if s.snapshot != nil {
		_, ok := s.snapshot.(AgentKicker)
		b.Interfaces["agent_kicker"] = ok
		_, ok = s.snapshot.(TunnelProber)
		b.Interfaces["tunnel_prober"] = ok
	}

	if v, err := s.db.SchemaVersion(); err == nil {
		b.SchemaVersion = &v
	} else {
		omit("schema_version：读取失败：" + err.Error())
	}

	// 运行时快照。
	var snap *Snapshot
	if s.snapshot != nil {
		got := s.snapshot.Snapshot()
		snap = &got
		b.RelayVersion = got.RelayVersion
		b.Totals = &got.Totals
		b.Shared = got.Shared
		for _, a := range got.Agents {
			b.Agents = append(b.Agents, SupportAgent{
				// Hostname 由 agent 自报（Hello 帧里的一个字符串），
				// 中继对它的内容没有任何控制 —— 过一遍形状匹配。
				ID: a.ID, Hostname: redactSecrets(a.Hostname), OS: a.OS, Arch: a.Arch,
				Version: a.Version, Online: a.Online, Revoked: a.Revoked,
				Rung: a.Rung, Reported: a.Reported,
			})
		}
	} else {
		omit("totals / shared / agents：中继运行时未装配（snapshot 接口缺席）")
	}

	// 生效配置及来源，逐项脱敏。
	if s.settings != nil {
		b.Settings = redactSettings(s.settings.Settings())
	} else {
		omit("settings：本中继版本不提供配置视图")
	}

	// 隧道定义 + 运行时计数。
	if tuns, err := s.db.ListTunnels(r.Context(), tunnel.DefaultTenantID); err == nil {
		byID := map[string]*TunnelStatus{}
		if snap != nil {
			for i := range snap.Tunnels {
				byID[snap.Tunnels[i].ID] = &snap.Tunnels[i]
			}
		}
		for _, t := range tuns {
			st := SupportTunnel{
				ID: t.ID, Slug: t.Slug, Kind: string(t.Kind), TLS: string(t.TLS),
				Exposure: string(t.Exposure), L4: string(t.L4),
				ListenPort: t.ListenPort, AgentID: t.AgentID, ShortID: t.ShortID,
				State: string(t.State),
				// Reason 是**自由文本**：它装的可能是 agent 上报的否决原因、
				// 也可能是将来某处随手拼进去的诊断串。所以它与事件 message
				// 同类，必须过形状匹配。
				Reason: redactSecrets(t.StateReason),
			}
			if t.Backend.Kind == tunnel.BackendUnix {
				st.Backend = "unix://" + t.Backend.Path
			} else {
				st.Backend = t.Backend.Addr
			}
			if t.Router != nil {
				st.Domains = t.Router.Domains
			}
			st.Runtime = byID[t.ID]
			b.Tunnels = append(b.Tunnels, st)
		}
	} else {
		omit("tunnels：读取失败：" + err.Error())
	}

	if s.turn != nil {
		b.Turn = &SupportTurn{Allocations: len(s.turn.Allocations())}
	} else {
		omit("turn：本中继未启用 TURN")
	}

	if evs, err := s.db.ListEvents(r.Context(), SupportBundleEvents, 0); err == nil {
		for _, e := range evs {
			b.Events = append(b.Events, SupportEvent{
				At: e.At.UTC().Format(time.RFC3339), Level: string(e.Level),
				Kind: e.Kind, Subject: e.Subject, Actor: e.Actor,
				Message: redactSecrets(e.Message),
			})
		}
	} else {
		omit("events：读取失败：" + err.Error())
	}

	// 先编码到内存再写响应头。
	//
	// 两个理由：① Content-Length 能给出来，浏览器的下载进度条才准；
	// ② encode 失败时还能干净地回一个 JSON 错误 —— 直接往 w 里 encode
	// 的话头已经发出去了，只能给用户一个截断的文件。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "生成支持包失败")
		return
	}

	// 留痕。支持包是要外发的，与签发 TURN 凭据同类。
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindSupportBundle, Level: store.LevelInfo,
		Actor: sess.Username,
		Message: fmt.Sprintf("下载支持包（%d 条事件、%d 条隧道、%d 个代理端）",
			len(b.Events), len(b.Tunnels), len(b.Agents)),
	})

	name := fmt.Sprintf("nomirelay-support-%s-%s.json",
		safeFilenamePart(b.RelayVersion), time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// redactSettings 深拷贝并脱敏配置视图。
//
// **深拷贝是必需的**：Settings() 返回的可能是运行时持有的切片，
// 就地改会污染控制台自己看到的配置 —— 那种 bug 的现象是「打开过支持包之后
// 设置页显示的值变了」，而没人会把两件事联系起来。
func redactSettings(groups []SettingsGroup) []SettingsGroup {
	out := make([]SettingsGroup, 0, len(groups))
	for _, g := range groups {
		items := make([]SettingItem, 0, len(g.Items))
		for _, it := range g.Items {
			if isSensitiveKey(it.Key) {
				it.Value = redactedMark
			} else {
				it.Value = redactSecrets(it.Value)
			}
			items = append(items, it)
		}
		out = append(out, SettingsGroup{Group: g.Group, Items: items})
	}
	return out
}

// redactedMark 是脱敏占位。
//
// 用一个显眼的标记而不是空串：空串会被读成「这一项没配」，
// 而那与「配了但不给你看」是两件事。
const redactedMark = "（已脱敏）"

// isSensitiveKey 判断一个配置项的值该不该出现在支持包里。
//
// **白名单式的思路反过来用**：这里列的是「一定要脱掉的」，
// 而下面 redactSecrets 会再对所有值做一次形状匹配 —— 两道都要，
// 因为键名匹配挡不住「值里恰好带了一个令牌」的情况。
// IsSensitiveSettingKey 报告一个配置项的键名是否会让它的值被支持包脱敏。
//
// # 为什么它是导出的
//
// cmd/nfrelay 那边定义了绝大多数配置项，而其中有几项是**纯诊断**的
// （比如控制台加固状态：它是「登录返回 200 但下一个请求 401」唯一的诊断依据）。
// 那些项一旦不小心取了个含 cookie/key/token 的名字，就会在支持包里变成
// 「（已脱敏）」—— 最需要它的那次排障恰好看不到它。
//
// 导出它让定义配置项的那一侧能写判据（cmd/nfrelay/console_wiring_test.go），
// 而不是靠人记得这条规则。
func IsSensitiveSettingKey(key string) bool { return isSensitiveKey(key) }

// WarnRedactedDiagnostics 检查一组配置项里有没有**纯诊断项**会被支持包脱敏掉，
// 并对每一处打一条告警。启动时跑一次。
//
// # 为什么要在启动时查，而不是等人导出支持包
//
// 支持包按键名脱敏，而一个名字里恰好带 cookie/key/token 的**纯诊断项**也会被
// 吃掉 —— 那种项往往正是排障要看的东西。本仓的实例：
// `console_session_hardening` 报告控制台有没有按前置 TLS 反代加固，
// 它是「登录返回 200 但下一个请求 401」这个现象**唯一**的诊断依据
// （Cookie 带了 Secure 而实际是明文传输，浏览器于是根本不保存它，
// 而两侧日志都显示成功）。它要是叫 console_cookie_secure，
// 就会在最需要它的那次排障里显示成「（已脱敏）」。
//
// 等到某人真的导出支持包才发现这件事，已经是在排障的最坏时刻了。
//
// 判据里跳过 provenance=console 的项：那些是控制台写入的值，可能真的含密钥，
// 被脱敏是**正确**的；而代码与命令行定义的项，名字由我们自己控制。
func (s *Server) WarnRedactedDiagnostics(groups []SettingsGroup) {
	for _, g := range groups {
		for _, it := range g.Items {
			if it.Provenance == ProvenanceConsole || !IsSensitiveSettingKey(it.Key) {
				continue
			}
			s.log.Warn("配置项的键名会让它在支持包里被脱敏；若它是纯诊断项请改名",
				"组", g.Group, "键", it.Key, "来源", it.Provenance)
		}
	}
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, bad := range []string{
		"secret", "key", "token", "password", "passwd", "credential", "cookie",
	} {
		if strings.Contains(k, bad) {
			return true
		}
	}
	return false
}

// 本仓库自己签发的凭据形状。脱敏靠**前缀**而不是熵值判断 ——
// 后者会把正常的 base64 配置值也一起吃掉。
var secretPatterns = []*regexp.Regexp{
	// 入网令牌。
	regexp.MustCompile(`nf_enrol_[0-9a-fA-F]{8,}`),
	// 十六进制的长串（会话令牌、CSRF 令牌、密钥的十六进制形式）。
	regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`),
}

// redactSecrets 把一段文本里长得像凭据的部分替换掉。
//
// 事件消息是自由文本，将来任何一处 AppendEvent 都可能不小心把令牌写进去。
// 键名白名单挡不住那个 —— 所以自由文本要再过一遍形状匹配。
//
// # 它覆盖哪些字段（这一段必须与调用点一致）
//
// 事件的 message、配置项的 value、隧道的 state_reason、agent 的 hostname。
// 判据是「这段文本的内容不由用户直接决定」：那种字段里出现凭据是
// **将来某次改动**的副作用，而不是用户自己填的。
//
// **不覆盖**用户自己配的值：后端地址、域名、slug。它们是排障必需的原文，
// 而且用户知道自己往里填了什么。这一条与 SupportTunnel 的注释同源
// （「那些是用户自己填的配置，不是凭据」）。
//
// 此前这段注释写的是「对所有外发文本」，而实际只有两个调用点 ——
// 注释比代码走得远，于是文档照它写、读的人以为覆盖是全的。
func redactSecrets(text string) string {
	for _, re := range secretPatterns {
		text = re.ReplaceAllString(text, redactedMark)
	}
	return text
}

// safeFilenamePart 把一段文本清洗成能安全放进 Content-Disposition 的形式。
//
// 版本串来自构建期的 ldflags，理论上可以是任意内容 ——
// 一个带引号或换行的版本号会让响应头被撕开（HTTP 头注入）。
func safeFilenamePart(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
