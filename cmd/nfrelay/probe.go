package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/acmecert"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// KickAgent 关掉一个代理端的活会话（实现 console.AgentKicker）。
//
// **连接层**操作：不撤销凭据，agent 会立刻按退避重连。
// 用途是「它状态不对，让它重连一次」，不是封禁。
func (rt *runtime) KickAgent(agentID string) bool {
	s, ok := rt.sessions.Get(agentID)
	if !ok || !s.Alive() {
		return false
	}
	s.Close("被控制台踢下线")
	// 状态要立刻跟着变，否则控制台会在下一次快照前继续显示「运行中」。
	rt.RefreshStates()
	return true
}

// ProbeTunnel 逐跳探测一条隧道（实现 console.TunnelProber）。
//
// # 只测自己真能测的那几跳
//
// 界面对缺失的跳是宽容的（渲染成中性点），所以**没有任何理由编造**。
// 编一跳「看起来通过了」的结果，会让用户在真正的故障点上白找半天 ——
// 那比少一跳信息糟糕得多。
//
// 具体来说：listener_bound 与 agent_reachable 是中继自己知道的事实；
// carrier_rtt 目前测不到（carrier.RTT() 返回 0，需要控制面 Ping/Pong，
// 见 README 缺口）；target_dialable 与 first_byte 要真的开一条流到 agent
// 并让它拨本地目标 —— 那是**真实**的端到端探测，也是这个功能的价值所在。
func (rt *runtime) ProbeTunnel(ctx context.Context, t *tunnel.Tunnel) console.ProbeResult {
	res := console.ProbeResult{Steps: make([]console.ProbeStep, 0, 4)}

	// ── listener_bound：入口在不在 ──
	bound, detail := rt.entryBound(t)
	res.Steps = append(res.Steps, console.ProbeStep{
		Hop: console.HopListenerBound, OK: bound, Detail: detail,
	})
	if !bound {
		res.ExampleCmd = exampleCmd(t)
		return res
	}

	// ── agent_reachable：承载在不在 ──
	if t.AgentID == "" {
		res.Steps = append(res.Steps, console.ProbeStep{
			Hop: console.HopAgentReachable, OK: false,
			Detail: "这条隧道还没有绑定代理端（等代理端上线后会自动绑定）",
		})
		res.ExampleCmd = exampleCmd(t)
		return res
	}
	sess, online := rt.SessionFor(t.AgentID)
	res.Steps = append(res.Steps, console.ProbeStep{
		Hop: console.HopAgentReachable, OK: online,
		Detail: agentDetail(t.AgentID, online),
	})
	if !online {
		res.ExampleCmd = exampleCmd(t)
		return res
	}

	// ── carrier_rtt：有观测就报，没有就如实说没有 ──
	//
	// 承载 RTT 现在由控制流 Ping/Pong 测（relay/rtt.go），每 5 秒一个样本。
	// 刚上线的会话还没有观测 —— 那时报一个 0 毫秒会被读成「延迟极低」，
	// 那是编造，所以如实记进 Unverified。
	if rtt := sess.LastRTT(); rtt > 0 {
		res.Steps = append(res.Steps, console.ProbeStep{
			Hop: console.HopCarrierRTT, OK: true, MS: console.Millis(rtt),
			Detail: "控制流往返（含重传与对端调度延迟，比链路 RTT 偏大）",
		})
	} else {
		res.Unverified = append(res.Unverified, console.UnverifiedHop{
			Hop: console.HopCarrierRTT,
			Why: "这条会话还没有 RTT 观测（Ping 每 5 秒一次，刚上线时会这样）",
		})
	}

	// ── target_dialable + first_byte：真的开一条流 ──
	rt.probeThroughTunnel(ctx, t, sess, &res)

	res.ExampleCmd = exampleCmd(t)
	// OK 只表示「已测的每一跳都通过」。Unverified 非空时界面必须一并显示 ——
	// 否则 OK 会被读成「测过了，通」，而那正是这次要修掉的谎。
	res.OK = allOK(res.Steps)
	return res
}

// entryBound 报告这条隧道的入口是否已经在监听。
func (rt *runtime) entryBound(t *tunnel.Tunnel) (bool, string) {
	if !t.IsEnabled() {
		return false, "隧道已停用"
	}
	rt.mu.RLock()
	el := rt.entries[t.ID]
	de := rt.dgrams[t.ID]
	sh := rt.shared
	rt.mu.RUnlock()

	switch {
	case el != nil:
		return true, "TCP 入口 " + el.Addr().String()
	case de != nil:
		return true, "UDP 入口 " + de.Addr().String()
	case t.Exposure == tunnel.ExposureShared:
		if sh == nil {
			return false, "这条隧道用共享入口，但中继没有启用 -shared"
		}
		return true, "共享入口 " + sh.ln.Addr().String()
	default:
		return false, "入口未就绪（端口被占用？看隧道状态里的原因）"
	}
}

func agentDetail(agentID string, online bool) string {
	if online {
		return "代理端 " + agentID + " 在线"
	}
	return "代理端 " + agentID + " 不在线"
}

// probeThroughTunnel 真的开一条流到 agent 并让它拨本地目标。
//
// 这是整个探测里唯一**不能靠读内存状态回答**的部分，也正是它的价值：
// 「入口在、agent 在线」之后仍然不通的原因，几乎总在这一段
// （本地服务没起、被 agent 策略否决、端口写错）。
func (rt *runtime) probeThroughTunnel(
	ctx context.Context, t *tunnel.Tunnel, sess *relay.Session, res *console.ProbeResult,
) {
	// UDP 没有「连上了」这个概念：开一条流的语义只对 TCP 成立。
	//
	// **记进 Unverified，不要给一个 ok=true 的步骤。** 旧版本那样做的后果是
	// 整条探测恒报「全链路通」并在这一跳画绿勾 —— 与本函数注释里
	// 「界面对缺失的跳是宽容的，所以没有任何理由编造」直接相反。
	// 本地服务没起、被 agent 策略否决、端口写错，全都会显示成「通过」。
	if t.L4 == tunnel.L4UDP {
		res.Unverified = append(res.Unverified,
			console.UnverifiedHop{
				Hop: console.HopTargetDialable,
				Why: "UDP 无连接语义，无法在不发业务数据的前提下探测目标可达性；" +
					"看隧道详情里的丢弃分项计数（会话表满 / 每源配额 / 回包无对应会话）",
			},
			console.UnverifiedHop{
				Hop: console.HopFirstByte,
				Why: "同上；首字节要真的发业务数据，而我们不知道这条隧道后面是什么协议",
			})
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, relay.StreamSetupTimeout)
	defer cancel()

	start := time.Now()
	// 源地址用中继自己：这是一次探测，不是真实用户连接。
	// agent 侧的日志里能看出「这是控制台探的」。
	ts, err := relay.DialTunnelStream(dialCtx, sess, probeOpen(t), relay.StreamSetupTimeout)
	elapsed := time.Since(start)

	if err != nil {
		step := console.ProbeStep{
			Hop: console.HopTargetDialable, OK: false,
			MS: console.Millis(elapsed), Detail: err.Error(),
		}
		// agent 的结构化拒绝要原样呈现：那是用户可行动的信息
		//（比如「目标被本地策略否决」意味着改策略，而不是重启服务）。
		var rej *relay.StreamRejectedError
		if errors.As(err, &rej) {
			step.Detail = fmt.Sprintf("代理端拒绝了这条流：%s（%s）", rej.Message, rej.Code)
		}
		res.Steps = append(res.Steps, step)
		return
	}
	defer ts.Close()

	res.Steps = append(res.Steps, console.ProbeStep{
		Hop: console.HopTargetDialable, OK: true, MS: console.Millis(elapsed),
		Detail: "代理端已连上 " + t.Backend.Addr,
	})

	// first_byte 需要真的发业务数据，而我们不知道这条隧道后面是什么协议 ——
	// 往一个未知协议的服务上发探测字节可能让它记一条错误日志，甚至断开
	// 真实客户端。所以这一跳如实**不测**，而不是画一个绿勾。
	res.Unverified = append(res.Unverified, console.UnverifiedHop{
		Hop: console.HopFirstByte,
		Why: "已建立到目标的连接但未发送任何业务字节 —— " +
			"探测不该往一个未知协议的服务上灌数据；用下面那条命令自己复核",
	})
}

// probeOpen 造探测用的 StreamOpen。
func probeOpen(t *tunnel.Tunnel) proto.StreamOpen {
	return proto.StreamOpen{
		TunnelID: t.ID,
		SrcAddr:  "127.0.0.1",
		SrcPort:  0,
		DstAddr:  "127.0.0.1",
		DstPort:  t.ListenPort,
	}
}

func allOK(steps []console.ProbeStep) bool {
	for _, s := range steps {
		if !s.OK {
			return false
		}
	}
	return true
}

// exampleCmd 给出一条用户可以自己复制执行的等价命令。
//
// 「我们测过了，通/不通」很难让人信服；给一条他能自己跑的命令，
// 他就能自己复核 —— 而且在我们的探测有盲区时（比如 first_byte），
// 那条命令恰好能补上。
func exampleCmd(t *tunnel.Tunnel) string {
	switch {
	case t.Exposure == tunnel.ExposureShared && t.Router != nil && len(t.Router.Domains) > 0:
		return fmt.Sprintf("curl -v https://%s/", t.Router.Domains[0])
	case t.L4 == tunnel.L4UDP:
		return fmt.Sprintf("# UDP 没有通用探测命令；用你自己的客户端打 <中继地址>:%d",
			t.ListenPort)
	case t.ListenPort != 0:
		return fmt.Sprintf("curl -v http://<中继地址>:%d/    # 或 nc -vz <中继地址> %d",
			t.ListenPort, t.ListenPort)
	default:
		return ""
	}
}

// ── 生效配置与来源 ──────────────────────────────────────────────────────────

// Settings 返回生效配置及每一项的来源（实现 console.SettingsSource）。
//
// # 为什么每一项都要带来源
//
// 「显示生效值」只回答了一半。用户真正要问的是「**为什么**是这个值」——
// 是我在控制台改的？是配置文件写的？还是代码默认？
// 不给来源，一个「监听地址是 0.0.0.0」的显示就无法判断该去改哪里。
//
// v1 没有配置文件（一切在库里 + 命令行参数），所以 provenance 只会是
// env（命令行参数）与 default。如实这样报，而不是为了让界面好看
// 编一个 file 来源。
func (rt *runtime) Settings() []console.SettingsGroup {
	env := console.ProvenanceEnv
	def := console.ProvenanceDefault

	listeners := []console.SettingItem{
		{Key: "bind", Value: rt.bindAddr, Provenance: env,
			SourceRef: "-bind", Editable: false},
	}
	rt.mu.RLock()
	sh := rt.shared
	dgramCount := len(rt.dgrams)
	entryCount := len(rt.entries)
	rt.mu.RUnlock()

	if sh != nil {
		listeners = append(listeners, console.SettingItem{
			Key: "shared", Value: sh.ln.Addr().String(), Provenance: env,
			SourceRef: "-shared", Editable: false,
		})
	} else {
		listeners = append(listeners, console.SettingItem{
			Key: "shared", Value: "未启用", Provenance: def,
			SourceRef: "-shared 未指定；共享入口要占 443，是个需要明确同意的决定",
			Editable:  false,
		})
	}
	listeners = append(listeners,
		console.SettingItem{Key: "tcp_entries", Value: strconv.Itoa(entryCount),
			Provenance: console.ProvenanceConsole,
			SourceRef:  "由隧道定义派生", Editable: false},
		console.SettingItem{Key: "udp_entries", Value: strconv.Itoa(dgramCount),
			Provenance: console.ProvenanceConsole,
			SourceRef:  "由隧道定义派生", Editable: false},
	)

	tlsItems := []console.SettingItem{
		{Key: "agent_cert", Value: "自签（指纹绑定）", Provenance: def,
			SourceRef: "承载证书必须指纹稳定 —— 换证书等于全机队掉线，所以刻意不接 ACME",
			Editable:  false},
		{Key: "gateway_cert", Value: gatewayCertValue(sh, rt.acme), Provenance: def,
			SourceRef: gatewayCertSource(rt.acme), Editable: false},
		{Key: "spki_pin", Value: rt.pin, Provenance: def,
			SourceRef: "从证书公钥算出；agent 用 -pin 绑定它", Editable: false},
	}
	tlsItems = append(tlsItems, acmeItems(rt.acme, env, def)...)

	auth := []console.SettingItem{
		// SourceRef 只写**真的存在**的东西。初版这里写着「非 loopback 时拒绝
		// 空凭据启动」，而那道检查从来没实现过（规格 §8.2 规定了它，v1 走的是
		// 另一条路）—— 把一条不存在的保护当作生效配置展示给运维看，
		// 比缺这道检查更坏：他会据此判断这台中继能不能公网暴露。
		{Key: "console_bind", Value: "见 -console", Provenance: env,
			SourceRef: "-console；Host 白名单见 -console-hosts", Editable: false},
		{Key: "agent_handshake", Value: "HMAC-SHA256 + 信道绑定 + 重放账本",
			Provenance: def, SourceRef: "规格 §7", Editable: false},
		{Key: "console_session_hardening", Value: hardeningValue(rt.consoleHardened),
			Provenance: env, SourceRef: "-console-behind-tls-proxy", Editable: false},
	}

	retention := []console.SettingItem{
		{Key: "sample_retention", Value: "1m 桶 48 小时", Provenance: def,
			SourceRef: "internal/store 的 rollup 与剪枝", Editable: false},
	}

	return []console.SettingsGroup{
		{Group: "listeners", Items: listeners},
		{Group: "tls", Items: tlsItems},
		{Group: "auth", Items: auth},
		{Group: "retention", Items: retention},
	}
}

func gatewayCertValue(sh *shareState, acme *acmecert.Manager) string {
	switch {
	case sh == nil:
		return "不适用（共享入口未启用）"
	case !sh.tlsOn:
		return "无（只能做 SNI 透传路由）"
	case acme == nil:
		return "自签（浏览器会报证书错误）"
	case acme.IsStaging():
		// 必须显著区分 staging 与生产：staging 签出的证书浏览器**不信**。
		// 只写「ACME」会让用户以为接好了，然后对着证书错误页找半天。
		return "ACME / staging（浏览器不信任）"
	default:
		return "ACME"
	}
}

func gatewayCertSource(acme *acmecert.Manager) string {
	if acme == nil {
		return "-acme 未启用；用自签证书，浏览器会报证书错误"
	}
	return "-acme；按需签发，只对**逐字注册过**的域名生效（通配路由拿不到证书）"
}

// acmeItems 报告 ACME 的预算用量。
//
// 撞上限时用户的第一个问题是「我还能签几次、什么时候恢复」——
// 不给这个数字他只能猜，而 CA 侧的配额是看不见的。
func acmeItems(acme *acmecert.Manager, env, def console.Provenance) []console.SettingItem {
	if acme == nil {
		return nil
	}
	used, globalUsed, globalLimit := acme.Budget()
	items := []console.SettingItem{
		{Key: "acme_budget", Value: fmt.Sprintf("全局 %d/%d", globalUsed, globalLimit),
			Provenance: def,
			SourceRef: "预算比 CA 的限制更紧，这样撞到的是我们自己的闸门（可观测）" +
				"而不是 CA 的（恢复期以周计）", Editable: false},
	}
	if len(used) > 0 {
		parts := make([]string, 0, len(used))
		for name, n := range used {
			parts = append(parts, fmt.Sprintf("%s=%d", name, n))
		}
		sort.Strings(parts) // 顺序稳定，否则每次刷新界面上都在跳
		items = append(items, console.SettingItem{
			Key: "acme_per_name", Value: strings.Join(parts, " "),
			Provenance: def, SourceRef: "窗口内各域名的签发次数（失败也计入）",
			Editable: false,
		})
	}
	if acme.IsStaging() {
		items = append(items, console.SettingItem{
			Key: "acme_ca", Value: "staging", Provenance: env,
			SourceRef: "-acme-ca 未指定；staging 签出的证书浏览器不信任，" +
				"确认流程无误后指向生产环境",
			Editable: false,
		})
	}
	return items
}

// 保证 runtime 满足这三个可选接口 —— 少一个方法就会退化成
// 「控制台如实回未实现」，而那时没有任何编译错误提示我们漏了装配。
var (
	_ console.AgentKicker    = (*runtime)(nil)
	_ console.SettingsSource = (*runtime)(nil)
	_ console.TunnelProber   = (*runtime)(nil)
)

// hardeningValue 把控制台加固状态说成人话。
//
// 不写「true / false」：运维要的是「这意味着什么」。而这一项存在的唯一理由是
// 诊断「登录返回 200 但下一个请求 401」—— 那个现象的成因是 Cookie 带了 Secure
// 而实际传输是明文，浏览器于是根本不保存它，而两侧日志都显示成功。
func hardeningValue(on bool) string {
	if on {
		return "已加固（会话 Cookie 带 Secure 与 __Host- 前缀；要求经 HTTPS 访问）"
	}
	return "未加固（明文 HTTP 形态；Cookie 不带 Secure）"
}
