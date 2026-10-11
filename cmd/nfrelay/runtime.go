package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/acmecert"
	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/limiter"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// runtime 是中继的运行时状态与协调中心。
//
// 它同时实现 relay.TunnelLookup（供入口监听器找会话）与
// console.SnapshotSource（供控制台读状态、签发令牌、应用变更），
// 从而把「存储层的期望状态」与「进程内的观测状态」缝在一起。
type runtime struct {
	db  *store.DB
	log *slog.Logger

	version   string
	startedAt time.Time

	// bindAddr 是 agent 承载监听地址，用于生成入网命令。
	bindAddr string

	// desktopBusinessURL 是最终交给 Mobile 的稳定 HTTP(S) 业务入口。
	//
	// v1 保留裸端口探测；v2 每个邀请绑定自己的共享 HTTPS 业务地址，
	// 该值只作为控制台的建议值。v2 的就绪探测使用真正的业务入口。
	desktopBusinessURL  string
	desktopBootstrapURL string
	desktopDevInsecure  bool
	desktopEnrolTTL     time.Duration
	desktopInviteMu     sync.Mutex

	// consoleHardened 记录控制台是否按「前置 TLS 反代」加固。
	//
	// 只为了在设置页把它显示出来。这一项**必须可见**：它是「登录返回 200
	// 但下一个请求 401」这个现象唯一的诊断依据（Cookie 带了 Secure 而
	// 实际是明文传输，浏览器就不保存它）。而支持包会把键名含 cookie/key/token
	// 的项脱敏掉，所以这个键刻意叫 console_session_hardening 而不是
	// console_cookie_secure —— 后者会在支持包里变成「（已脱敏）」，
	// 于是唯一能诊断那个现象的东西恰好看不见。
	consoleHardened bool
	// pin 是本中继证书的 SPKI 指纹（base64），入网命令里要带。
	pin string

	// acme 为 nil 表示未启用 ACME（共享入口退回自签证书）。
	//
	// 只被 Settings() 读来如实报告状态，不参与请求路径 —— 请求路径上
	// ACME 是通过 tls.Config.GetCertificate 接进去的，与 runtime 无关。
	acme *acmecert.Manager

	sessions *relay.SessionManager
	guard    *proto.ReplayGuard

	// hub 用于向控制台推事件。可以为 nil（未启用控制台时）。
	hub *console.Server

	mu      sync.RWMutex
	tunnels map[string]*tunnel.Tunnel
	byPort  map[uint16]*tunnel.Tunnel
	entries map[string]*relay.EntryListener

	// dgrams 是 UDP 入口，与 entries 分开存。
	//
	// 不合并成一张表：两者的生命周期一样但**类型不同**，合并就得到处
	// 做类型断言，而 UDP 与 TCP 的背压、丢弃语义没有一处相同。
	dgrams map[string]*relay.DatagramEntry

	// shared 是共享入口（gateway / SNI 路由），未启用时为 nil。
	//
	// 与 entries / dgrams 分开：那两者是「一隧道一监听器」，
	// 而共享入口是「一监听器服务任意多条隧道」——
	// 隧道增删只改路由表，不动监听器。
	shared *shareState

	// dgramRouter 按隧道短标识把回向数据报分发到对应入口。
	//
	// 只能有一个：数据报在 QUIC 上是**连接级**的流，若每个入口各自去
	// ReceiveDatagram 就会互相抢包，各自只拿到属于别人的帧。
	dgramRouter *relay.DatagramRouter

	// rejections 记录 agent 上报的否决原因，控制台要展示它。
	rejections map[string]string

	// routeErrors 记录共享入口拒绝的路由及原因。
	//
	// 必须单独记：refreshStates 从零重算状态（active / pending / degraded），
	// 它不知道路由被拒过，会把 applyShared 刚写的 error 覆盖掉 ——
	// 表现是「控制台显示 active，而请求 404」。
	// agent 侧的否决用 rejections 规避同一个问题，这里照同一个模式。
	routeErrors map[string]string

	// entryErrors 是入口绑定失败的原因（tunnelID → 原因）。
	//
	// 与 routeErrors 同一个理由：refreshStates 从零重算状态、不知道谁绑
	// 失败过，于是它会把「端口被占，error」覆盖成「端口已监听，等待代理端
	// 上线」——那句话本身是假的，端口根本没有监听。
	entryErrors map[string]string

	// agentMetrics 是各 agent 最近一次上报的计数器（agentID → 快照）。
	//
	// 只保留最新一份：曲线由控制台按差分自己画（前端已有环形缓冲），
	// 中继侧存历史等于把同一份数据存两遍。
	agentMetrics map[string]agentMetricSample

	// deniedSeen 给拨号期否决事件去重：键是 tunnelID|code。
	//
	// 必须去重。一条配置错了的隧道会让**每一条**用户连接都被拒一次，
	// 一个刷新不停的页面就能几秒钟写进上千条一模一样的事件，
	// 把真正有用的事件挤出可视范围 —— 事件流的价值在于信噪比。
	deniedSeen map[string]time.Time

	// observed 是学习模式的观测存储：中继实际看到过的来源地址。
	//
	// **只在内存里**（见 observed.go 顶部的说明）—— 这些是第三方地址，
	// 而库会被备份、事件表会被支持包外发。
	observed *observedSources

	ctx context.Context
}

// streamDeniedDedupWindow 是同一隧道同一错误码的事件最小间隔。
//
// 一分钟：足够压住风暴，又不至于让「我改了策略，再试一次」的用户
// 等太久才看到新事件。
const streamDeniedDedupWindow = time.Minute

// noteStreamDenied 把一次拨号期否决落进事件流（同隧道同码一分钟一条）。
func (rt *runtime) noteStreamDenied(tunnelID, code, message string) {
	slug := tunnelID
	if t, ok := rt.TunnelByID(tunnelID); ok {
		slug = t.Slug
	}

	key := tunnelID + "|" + code
	now := time.Now()

	rt.mu.Lock()
	last, seen := rt.deniedSeen[key]
	if seen && now.Sub(last) < streamDeniedDedupWindow {
		rt.mu.Unlock()
		return
	}
	rt.deniedSeen[key] = now
	// 顺手清掉过期条目，免得这张表随隧道与错误码的组合无界增长。
	for k, ts := range rt.deniedSeen {
		if now.Sub(ts) > 10*streamDeniedDedupWindow {
			delete(rt.deniedSeen, k)
		}
	}
	rt.mu.Unlock()

	_ = rt.db.AppendEvent(rt.ctx, store.Event{
		Kind: store.KindStreamDenied, Level: store.LevelWarn,
		Subject: slug, Message: message,
	})
	// 同时推给控制台，让正开着页面的用户立刻看到，不必等下一次轮询。
	rt.publish(console.EventState, map[string]any{
		"kind": store.KindStreamDenied, "tunnel": slug, "code": code, "detail": message,
	})
}

func newRuntime(ctx context.Context, db *store.DB, log *slog.Logger, version, bindAddr, pin string) *runtime {
	return &runtime{
		db:              db,
		log:             log,
		version:         version,
		startedAt:       time.Now(),
		bindAddr:        bindAddr,
		pin:             pin,
		desktopEnrolTTL: console.DefaultEnrolTTL,
		sessions:        relay.NewSessionManager(log),
		guard:           proto.NewReplayGuard(0, 0),
		tunnels:         make(map[string]*tunnel.Tunnel),
		byPort:          make(map[uint16]*tunnel.Tunnel),
		entries:         make(map[string]*relay.EntryListener),
		dgrams:          make(map[string]*relay.DatagramEntry),
		dgramRouter:     relay.NewDatagramRouter(log),
		rejections:      make(map[string]string),
		routeErrors:     make(map[string]string),
		entryErrors:     make(map[string]string),
		agentMetrics:    make(map[string]agentMetricSample),
		deniedSeen:      make(map[string]time.Time),
		observed:        newObservedSources(),
		ctx:             ctx,
	}
}

func (rt *runtime) setDesktopBusinessURL(raw string) {
	rt.desktopBusinessURL = strings.TrimRight(strings.TrimSpace(raw), "/")
}

func (rt *runtime) attachConsole(c *console.Server) { rt.hub = c }

func (rt *runtime) publish(eventType string, data any) {
	if rt.hub != nil {
		rt.hub.Hub().Publish(eventType, data)
	}
}

// ── relay.TunnelLookup ──────────────────────────────────────────────────────

// TunnelByID 返回当前的隧道定义（实现 relay.TunnelLookup）。
func (rt *runtime) TunnelByID(id string) (*tunnel.Tunnel, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	t, ok := rt.tunnels[id]
	return t, ok
}

func (rt *runtime) TunnelByListenPort(port uint16) (*tunnel.Tunnel, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	t, ok := rt.byPort[port]
	return t, ok
}

func (rt *runtime) SessionFor(agentID string) (*relay.Session, bool) {
	// 空 agentID **只**表示「中继自己拨号」（场景二的无代理端路径），
	// 不再被解释为「任意在线 agent」。
	//
	// 第一版把空值当作单 agent 部署的便利，结果同一个空值有了两种含义：
	// 数据库里存空值，控制台按规格把它渲染成「中继直拨」，
	// 而运行时却悄悄派给了某个 agent —— 界面与实际行为对不上。
	// 这是浏览器验证时看截图发现的。
	//
	// 现在隐式绑定在 ApplyTunnels 里完成并**回写数据库**，
	// 所以到这里的空值一定是真的要中继直拨。
	if agentID == "" {
		return nil, false
	}
	s, ok := rt.sessions.Get(agentID)
	if !ok || !s.Alive() {
		return nil, false
	}
	return s, true
}

// ── console.SnapshotSource ──────────────────────────────────────────────────

func (rt *runtime) Snapshot() console.Snapshot {
	// 隧道的期望状态**从库里读**，不读内存副本。
	//
	// 这是手工验证抓出来的缺陷：我原本让 Snapshot 读 rt.tunnels，
	// 而那份副本是在 ApplyTunnels 里赋值的、状态还是 draft；
	// 之后 SetTunnelState 只更新了数据库。结果入口明明已就绪，
	// 控制台却一直显示 draft —— 同一份数据有了两个真相源。
	//
	// 库是唯一真相源；内存里只保留**观测状态**（入口计数器、会话、否决原因）。
	tunnels, err := rt.db.ListTunnels(rt.ctx, tunnel.DefaultTenantID)
	if err != nil {
		rt.log.Warn("快照读取隧道失败", "err", err)
	}

	rt.mu.RLock()
	entries := make(map[string]*relay.EntryListener, len(rt.entries))
	for k, v := range rt.entries {
		entries[k] = v
	}
	dgrams := make(map[string]*relay.DatagramEntry, len(rt.dgrams))
	for k, v := range rt.dgrams {
		// 跳过占位的 nil（bindDatagramEntry 正在建它）。
		if v != nil {
			dgrams[k] = v
		}
	}
	rejections := make(map[string]string, len(rt.rejections))
	for k, v := range rt.rejections {
		rejections[k] = v
	}
	routeErrors := make(map[string]string, len(rt.routeErrors))
	for k, v := range rt.routeErrors {
		routeErrors[k] = v
	}
	entryErrors := make(map[string]string, len(rt.entryErrors))
	for k, v := range rt.entryErrors {
		entryErrors[k] = v
	}
	rt.mu.RUnlock()

	// 活会话按 agentID 索引一次，供下面取承载级属性（数据报 MTU）。
	//
	// 在循环外做：一台中继上几十条隧道共享同一个 agent，
	// 在循环里逐条 SessionFor 会把一次快照变成几十次加锁查找。
	sessions := make(map[string]*relay.Session)
	for _, sess := range rt.sessions.List() {
		if sess.Alive() {
			sessions[sess.AgentID] = sess
		}
	}

	snap := console.Snapshot{
		RelayVersion: rt.version,
		StartedAt:    rt.startedAt,
		Agents:       rt.agentStatuses(),
		Tunnels:      make([]console.TunnelStatus, 0, len(tunnels)),
		Shared:       rt.sharedStatus(),
	}

	for _, t := range tunnels {
		ts := console.TunnelStatus{
			ID:           t.ID,
			Slug:         t.Slug,
			State:        string(t.State),
			Reason:       t.StateReason,
			BareExposure: t.IsBareExposure(),
		}
		// agent 上报的否决原因优先于库里的状态：它更新鲜。
		if reason, ok := rejections[t.ID]; ok {
			ts.State = string(tunnel.StateRejectedByAgent)
			ts.Reason = reason
		}
		// 共享入口的路由错误同理。
		if reason, ok := routeErrors[t.ID]; ok {
			ts.State = string(tunnel.StateError)
			ts.Reason = reason
		}
		// 入口绑定失败同理，而且比上面两个更靠前：端口没绑上的话，
		// 其它一切都是空谈。
		if reason, ok := entryErrors[t.ID]; ok {
			ts.State = string(tunnel.StateError)
			ts.Reason = reason
		}
		// 承载 RTT。会话级的数，同一个 agent 名下所有隧道是同一条曲线 ——
		// 那是规格的展示粒度，不是两次独立测量。
		if t.AgentID != "" {
			if sess, live := rt.SessionFor(t.AgentID); live {
				p50, p95, p99 := sess.RTTPercentiles()
				// **0 表示还没测到，不是 0 毫秒。** 只有真的有观测时才填，
				// 否则界面必须显示「—」。
				if p50 > 0 {
					ts.RTTP50US = p50.Microseconds()
					ts.RTTP95US = p95.Microseconds()
					ts.RTTP99US = p99.Microseconds()
				}
			}
		}

		if el, ok := entries[t.ID]; ok {
			st := el.Stats()
			// **活跃**数而不是累计接受数。
			//
			// 填 Accepted 是一个真实存在过的谎：那是只增不减的累计值，
			// 于是一条早就没人用的隧道会显示「活跃会话 1523」。
			// 规格 §8.4 要的是「活跃会话」与「新会话/秒」两项 ——
			// 后者由控制台对 SessionsTotal 做差分得出。
			ts.Sessions = st.Active.Load()
			ts.SessionsTotal = st.Accepted.Load()
			ts.BytesIn = st.BytesUp.Load()
			ts.BytesOut = st.BytesDown.Load()
			ts.DeniedCIDR = st.DeniedCIDR.Load()
			ts.NoSession = st.NoSession.Load()
			ts.OpenFailed = st.OpenFailed.Load()
			ts.RateLimited = st.RateLimited.Load()
		}
		// UDP 入口的计数器也要读。
		//
		// 漏了这一段的后果是**静默错误**：UDP 隧道明明在传数据，控制台上
		// 的流量却永远是 0。而 README 自己写着「0 会被读成『测过，是零』」——
		// 用户会去查客户端，而问题根本不在那里。
		//
		// 字段语义与 TCP 对齐：Sessions 用活跃流数（UDP 没有连接，
		// 一条「流」就是一个五元组会话），DeniedCIDR / NoSession 同名同义，
		// 而 OpenFailed 在 UDP 上对应「承载不支持数据报」，
		// RateLimited 对应「建流速率超限」——都是「在哪一道闸丢的」。
		if de, ok := dgrams[t.ID]; ok {
			st := de.Stats()
			ts.Sessions = st.Flows.Load()
			// UDP 的「新会话/秒」同理由累计建流数差分。
			ts.SessionsTotal = st.FlowsAdmitted.Load()
			ts.BytesIn = st.BytesIn.Load()
			ts.BytesOut = st.BytesOut.Load()
			ts.DeniedCIDR = st.DeniedCIDR.Load()
			ts.NoSession = st.NoSession.Load()
			ts.OpenFailed = st.NoDatagram.Load()
			ts.RateLimited = st.RateLimited.Load()
			ts.PacketsIn = st.PacketsIn.Load()
			ts.PacketsOut = st.PacketsOut.Load()
			ts.DroppedTableFull = st.TableFull.Load()
			ts.DroppedPerIPQuota = st.PerIPQuota.Load()
			ts.DroppedUnknownFlow = st.UnknownFlow.Load()
			ts.DroppedWrongAgent = st.WrongAgent.Load()
			ts.DroppedCarrier = st.DroppedCarrier.Load()
			// 「表满」在这套流表里不产生任何拒绝（它淘汰最旧而不是拒绝新流），
			// 所以必须读淘汰数 —— 否则界面上那一格恒为 0。
			ts.FlowsEvicted = de.FlowsEvicted()
			ts.RateLimitedBytes = st.RateLimitedBytes.Load()

			// 重组失败要把**超时**也算进去。
			//
			// ReasmDropped 只在 Reassembler.Push 返回错误时递增，而超时
			// 不是错误 —— 分片是被后台回收掉的，Push 那时早就返回过
			// 「还没齐」了。于是「丢一个分片」这个**最常见**的重组失败
			// 在界面上一个数字都没有：用户看到「大 UDP 报文收不到」，
			// 而分阶段拒绝那一整排全是 0。
			rs := de.ReassemblyStats()
			ts.DroppedReassembly = st.ReasmDropped.Load() + rs.TimedOut.Load()
			ts.Fragments = rs.Fragments.Load()
			ts.Reassembled = rs.Completed.Load()
			ts.ReasmOverlapping = rs.Overlapping.Load()

			// 数据报 MTU 从**承载**上取（每 agent 一条 QUIC 连接），
			// 所以同一个 agent 名下所有 UDP 隧道是同一个值 ——
			// 与承载 RTT 同一个道理：那是链路的属性，不是隧道的。
			if sess, ok := sessions[t.AgentID]; ok && sess.Carrier != nil {
				ts.DgramMTU = sess.Carrier.MaxDatagramPayload()
			}
		}
		snap.Tunnels = append(snap.Tunnels, ts)

		if ts.State == string(tunnel.StateActive) {
			snap.Totals.TunnelsUp++
		} else {
			snap.Totals.TunnelsDown++
		}
		snap.Totals.BytesIn += ts.BytesIn
		snap.Totals.BytesOut += ts.BytesOut
		snap.Totals.Sessions += int(ts.Sessions)
	}

	for _, a := range snap.Agents {
		if a.Online {
			snap.Totals.AgentsOnline++
		}
	}
	return snap
}

// agentStatuses 合并数据库里的注册信息与进程内的在线状态。
//
// 两者都要：库里有历史与撤销标记，进程内才知道现在是否在线、走哪个梯级。
func (rt *runtime) agentStatuses() []console.AgentStatus {
	registered, err := rt.db.ListAgents(rt.ctx, tunnel.DefaultTenantID)
	if err != nil {
		rt.log.Warn("读取 agent 列表失败", "err", err)
	}

	live := make(map[string]*relay.Session)
	for _, s := range rt.sessions.List() {
		if s.Alive() {
			live[s.AgentID] = s
		}
	}

	rt.mu.RLock()
	reported := make(map[string]agentMetricSample, len(rt.agentMetrics))
	for k, v := range rt.agentMetrics {
		reported[k] = v
	}
	rt.mu.RUnlock()

	out := make([]console.AgentStatus, 0, len(registered))
	for _, a := range registered {
		st := console.AgentStatus{
			ID: a.ID, Hostname: a.Hostname, OS: a.OS, Arch: a.Arch,
			Version: a.Version, Revoked: a.Revoked, LastSeenAt: a.LastSeenAt,
		}
		if s, ok := live[a.ID]; ok {
			st.Online = true
			st.Rung = s.Carrier.Rung().String()
			st.SupportsDgram = s.SupportsDatagrams()
			st.ConnectedAt = s.ConnectedAt
			// 数据报发送队列的计量。
			//
			// 只在真的建过发送器时报（DatagramSender 是惰性创建的），
			// 否则会给一整排 0 —— 而 0 会被读成「测过，是零」。
			// 队列满与超限必须分开：前者要加带宽 / 降码率，
			// 后者要等 PMTUD 学到新值，两个动作方向相反。
			if s.HasDatagramSender() {
				ds := s.DatagramSendStats()
				st.Datagram = &console.DatagramCarrierStats{
					Sent:       ds.Sent.Load(),
					Bytes:      ds.Bytes.Load(),
					QueueFull:  ds.QueueFull.Load(),
					TooLarge:   ds.TooLarge.Load(),
					Failed:     ds.Failed.Load(),
					Fragmented: ds.Fragmented.Load(),
				}
			}
		}
		if sample, ok := reported[a.ID]; ok {
			st.Reported = &console.AgentReportedMetrics{
				AtUnix:        sample.at.Unix(),
				UptimeSeconds: sample.m.UptimeSeconds,
				UDP:           sample.m.UDP,
			}
		}
		out = append(out, st)
	}
	return out
}

// IssueEnrolToken 签发入网令牌并返回可直接复制的安装命令。
func (rt *runtime) IssueEnrolToken(ttl time.Duration, note string) (string, string, error) {
	token, err := rt.db.CreateEnrolToken(rt.ctx, tunnel.DefaultTenantID, ttl, note)
	if err != nil {
		return "", "", err
	}
	cmd := fmt.Sprintf("nfagent -relay %s -pin %s -token %s", rt.bindAddr, rt.pin, token)
	return token, cmd, nil
}

// CreateDesktopPairingInvite 创建管理员可交给 Desktop 的一次性 bootstrap
// bearer。目标地址由服务端固定，调用方只能选择业务入口端口与短时 TTL。
func (rt *runtime) CreateDesktopPairingInvite(
	ctx context.Context, ttl time.Duration, listenPort uint16, note string,
) (console.DesktopPairingInviteResponse, error) {
	if rt.desktopBootstrapURL == "" {
		return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：请配置 -desktop-bootstrap-url；管理浏览器地址不能用作 Desktop 配对地址", console.ErrDesktopPrecondition)
	}
	backend := tunnel.Backend{
		Kind: tunnel.BackendAddr,
		Addr: console.DesktopBackendAddr,
	}
	publicHost, _, _ := net.SplitHostPort(rt.bindAddr)
	token, invite, err := rt.db.CreatePairingInvite(ctx, store.PairingInviteSpec{
		TenantID:       tunnel.DefaultTenantID,
		Scopes:         []string{console.DesktopBootstrapScope},
		Backend:        backend,
		PublicHostname: publicHost,
		PublicPort:     listenPort,
		TLS:            tunnel.TLSPassthrough,
		TTL:            ttl,
		Note:           note,
	})
	if err != nil {
		return console.DesktopPairingInviteResponse{}, err
	}
	return console.DesktopPairingInviteResponse{
		ID:           invite.ID,
		Token:        token,
		Relay:        rt.bindAddr,
		Pin:          rt.pin,
		ListenPort:   listenPort,
		ExpiresAt:    invite.ExpiresAt,
		BootstrapURL: strings.TrimSuffix(rt.desktopBootstrapURL, "/v2"),
	}, nil
}

// BootstrapDesktop 兑换一次性 invite，并创建短时 enrol token 与一条显式
// 绑定到预期 agent ID 的 Desktop 隧道。
//
// 注意：invite 消费、enrol token 与隧道写入目前是三个串行存储操作，不是
// 一个跨对象事务。若后两步失败，invite 已消费，管理员需要重新创建 invite。
// 这条失败边界必须保持可见，不能声称该流程具备原子回滚。
func (rt *runtime) BootstrapDesktop(
	ctx context.Context, inviteToken string,
) (console.DesktopBootstrapResponse, error) {
	backend := tunnel.Backend{
		Kind: tunnel.BackendAddr,
		Addr: console.DesktopBackendAddr,
	}
	invite, err := rt.db.RedeemPairingInvite(ctx, inviteToken, store.PairingInviteRedeemRequest{
		TenantID: tunnel.DefaultTenantID,
		Scopes:   []string{console.DesktopBootstrapScope},
		Backend:  backend,
		UsedBy:   "desktop-bootstrap",
	})
	if err != nil {
		return console.DesktopBootstrapResponse{}, err
	}

	const enrolTTL = console.DefaultEnrolTTL
	enrolToken, err := rt.db.CreateEnrolToken(ctx, tunnel.DefaultTenantID, enrolTTL,
		"Desktop bootstrap "+invite.ID)
	if err != nil {
		return console.DesktopBootstrapResponse{}, err
	}
	agentID := store.EnrolAgentID(enrolToken)
	suffix := strings.TrimPrefix(invite.ID, "pinv-")
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	t := &tunnel.Tunnel{
		ID:         "t-desktop-" + suffix,
		Slug:       "desktop-" + suffix,
		TenantID:   tunnel.DefaultTenantID,
		Kind:       tunnel.KindService,
		TLS:        invite.TLS,
		Exposure:   tunnel.ExposurePort,
		L4:         tunnel.L4TCP,
		AgentID:    agentID,
		ListenPort: invite.PublicPort,
		Backend:    invite.Backend,
	}
	if err := rt.db.PutTunnel(ctx, t); err != nil {
		return console.DesktopBootstrapResponse{}, err
	}
	if err := rt.ApplyTunnels(); err != nil {
		// 配置已经保存，且 enrol token 只有这次响应能交给 Desktop。
		// 返回凭据并让隧道的 error 状态说明运行时失败，比吞掉凭据导致
		// 一次性 invite 永久作废更可恢复。
		rt.log.Warn("Desktop bootstrap 已保存配置，但运行时应用未完全成功",
			"invite_id", invite.ID, "tunnel_id", t.ID, "err", err)
	}
	if fresh, err := rt.db.GetTunnel(ctx, t.ID); err == nil {
		t = fresh
	}

	cmd := fmt.Sprintf("nfagent -relay %s -pin %s -token %s",
		rt.bindAddr, rt.pin, enrolToken)
	probeURL := desktopTunnelURL(invite.PublicHostname, t.ListenPort)
	businessURL := rt.desktopBusinessURL
	if businessURL == "" {
		businessURL = probeURL
	}
	return console.DesktopBootstrapResponse{
		InviteID:       invite.ID,
		Relay:          rt.bindAddr,
		BusinessURL:    businessURL,
		ProbeURL:       probeURL,
		Pin:            rt.pin,
		EnrolToken:     enrolToken,
		EnrolExpiresAt: time.Now().Add(enrolTTL),
		InstallCmd:     cmd,
		Tunnel:         t,
	}, nil
}

func desktopTunnelURL(host string, port uint16) string {
	if host == "" || port == 0 {
		return ""
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// ApplyTunnels 把存储层的期望状态同步到运行时。
//
// # 零停机的关键
//
// 只关被移除的监听器、只绑新增的，**已建立的连接不受影响**。
// frp 的服务端根本没有 reload（只有客户端有），配置变更要重启，
// 而重启会断掉所有隧道。
func (rt *runtime) ApplyTunnels() error {
	desired, err := rt.db.ListTunnels(rt.ctx, tunnel.DefaultTenantID)
	if err != nil {
		return fmt.Errorf("读取隧道失败：%w", err)
	}

	byID := make(map[string]*tunnel.Tunnel, len(desired))
	byPort := make(map[uint16]*tunnel.Tunnel, len(desired))
	for _, t := range desired {
		byID[t.ID] = t
		if t.ListenPort != 0 {
			byPort[t.ListenPort] = t
		}
	}

	// 绑定唯一在线 agent **必须在发布之前**做。
	//
	// 它会写 t.AgentID，而 rt.tunnels = byID 一旦发布，数据面就开始通过
	// TunnelByID 拿到同一批指针并每包读 t.AgentID —— 那是一个真实的
	// data race（-race 下会在任何「入口打流 + agent 上线」重叠的测试里报出来，
	// 而发布构建没有 race 检测器，表现会是偶发的错误路由）。
	//
	// 挪顺序而不是加锁：这些对象在发布之前**只有这一个协程**看得到，
	// 那是最便宜也最不容易写错的独占方式。
	rt.bindUnassigned(desired)

	// 为 listen_port=0 的端口型隧道分配一个端口，并**回写库**。
	//
	// 与 bindUnassigned 同一个位置、同一个理由：这里要写 t.ListenPort，
	// 而 rt.tunnels 一发布数据面就开始读这些指针。放在发布之前，
	// 对象只有这一个协程看得到。
	rt.assignPorts(desired, byPort)

	rt.mu.Lock()
	current := make(map[string]*relay.EntryListener, len(rt.entries))
	for k, v := range rt.entries {
		current[k] = v
	}
	rt.tunnels = byID
	rt.byPort = byPort
	rt.mu.Unlock()

	// 丢掉已不存在隧道的学习模式观测。
	//
	// 不丢的话，一条被删掉又重建的隧道（新 ID）不会继承旧记录，
	// 但那些旧记录会**一直留在内存里**：第三方地址无限期驻留，
	// 而且没有任何界面能看到它们（隧道已经不在了）。
	live := make(map[string]bool, len(byID))
	for id := range byID {
		live[id] = true
	}
	rt.observed.retain(live)

	// 关掉不再需要的入口。
	for id, el := range current {
		t, keep := byID[id]
		// 端口变了也要重建 —— 监听地址不能原地改。
		//
		// L4 变了同样要关：把一条已上线的端口型隧道从 tcp 改成 udp 之后，
		// 下面的绑定循环会去建 UDP 入口，而这里若不认 L4，**旧的 TCP 监听器
		// 会一直留着并继续把连接代理到后端**。用户以为自己换了协议，
		// 实际是同一个端口上多了一条没人知道的 TCP 通路。
		if !keep || !t.IsEnabled() || t.Exposure != tunnel.ExposurePort ||
			t.ListenPort == 0 || t.L4 != tunnel.L4TCP {
			_ = el.Close()
			rt.mu.Lock()
			delete(rt.entries, id)
			rt.mu.Unlock()
			continue
		}
		if addrPort(el.Addr()) != t.ListenPort {
			_ = el.Close()
			rt.mu.Lock()
			delete(rt.entries, id)
			rt.mu.Unlock()
		}
	}

	// 关掉不再需要的 UDP 入口。与 TCP 同一套判据。
	rt.mu.Lock()
	currentDgrams := make(map[string]*relay.DatagramEntry, len(rt.dgrams))
	for k, v := range rt.dgrams {
		currentDgrams[k] = v
	}
	rt.mu.Unlock()

	for id, de := range currentDgrams {
		if de == nil {
			// 占位：另一次调用正在建它，别去动。
			continue
		}
		t, keep := byID[id]
		stale := !keep || !t.IsEnabled() || t.Exposure != tunnel.ExposurePort ||
			t.ListenPort == 0 || t.L4 != tunnel.L4UDP ||
			addrPort(de.Addr()) != t.ListenPort ||
			de.ShortID() != t.ShortID
		if !stale {
			continue
		}
		// 按身份注销，不能按短标识。
		//
		// 并发的另一次 ApplyTunnels 可能已经用同一个短标识注册了**新**入口
		//（改端口就是这个形状：先关旧的再建新的，短标识不变）。
		// 按短标识删会把新入口的注册一起删掉，于是这条隧道从此单向：
		// 上行照常，回向全被 Dispatch 当 unrouted 丢掉。
		rt.dgramRouter.UnregisterEntry(de)
		_ = de.Close()
		rt.mu.Lock()
		delete(rt.dgrams, id)
		rt.mu.Unlock()
	}

	// 绑新增的入口。
	//
	// entryErrs 收集绑定失败的原因。**必须与 routeErrors 一样单独记住**：
	// refreshStates 从零重算状态、不知道谁绑失败过，于是它会把
	// 「端口被占，error」覆盖成「端口已监听，等待代理端上线」——
	// 那句话本身是假的，端口根本没有监听。
	entryErrs := make(map[string]string)
	var errs []error
	for _, t := range desired {
		if !t.IsEnabled() || t.Exposure != tunnel.ExposurePort || t.ListenPort == 0 {
			continue
		}
		if t.L4 == tunnel.L4UDP {
			if err := rt.bindDatagramEntry(t); err != nil {
				entryErrs[t.ID] = err.Error()
				errs = append(errs, err)
			}
			continue
		}

		rt.mu.RLock()
		el, exists := rt.entries[t.ID]
		rt.mu.RUnlock()
		if exists {
			// 已经在跑：**把 policy 的变化应用上去**，而不是什么都不做。
			//
			// 此前这里直接 continue，而入口的限速器与信号量都固化在构造期。
			// 于是在一条已上线隧道上把 1 Mbps 改成 100 Kbps 之后，进程重启前
			// 一个字节都不会变 —— 而详情页照常显示「已设置」。
			// entry.go 的注释还写着「改限速值走重建入口」，那句话是假的。
			//
			// 带宽原地改（不掉线）；并发上限做不到原地改（信号量容量固定），
			// 只能重建 —— 而重建会掐断这条隧道上所有在飞连接，所以只在那两个
			// 数字**真的变了**时才做。
			el.SetLimits(limitsOfTunnel(t))
			wantConns, wantPerIP := desiredConnCaps(t)
			if gotConns, gotPerIP := el.LimitsSpec(); gotConns != wantConns || gotPerIP != wantPerIP {
				rt.log.Info("隧道的并发上限变了，重建入口（在飞连接会被掐断）",
					"隧道", t.Slug, "max_conns", wantConns, "max_conns_per_ip", wantPerIP)
				_ = el.Close()
				rt.mu.Lock()
				delete(rt.entries, t.ID)
				rt.mu.Unlock()
				// 落到下面的绑定逻辑重建它。
			} else {
				continue
			}
		}

		el, err := relay.NewEntryListener(
			net.JoinHostPort("0.0.0.0", fmt.Sprint(t.ListenPort)), t, rt,
			relay.EntryOptions{
				Log: rt.log, OnReject: rt.noteStreamDenied,
				OnSession: rt.noteSession,
			})
		if err != nil {
			// 端口被进程外的东西占了之类。把原因记下来，
			// 用户在控制台就能看到，而不是只看到「不通」。
			entryErrs[t.ID] = err.Error()
			errs = append(errs, err)
			continue
		}

		rt.mu.Lock()
		rt.entries[t.ID] = el
		rt.mu.Unlock()

		go func(t *tunnel.Tunnel, el *relay.EntryListener) {
			if err := el.Serve(rt.ctx); err != nil {
				rt.log.Error("入口服务退出", "隧道", t.Slug, "err", err)
			}
		}(t, el)

		rt.log.Info("入口已就绪", "隧道", t.Slug,
			"监听", el.Addr().String(), "目标", t.Backend.Addr)
	}

	// 统一刷新状态。
	//
	// **必须独立于绑定循环**：那个循环对已存在的监听器 continue 跳过，
	// 状态就更新不到 —— 表现为「agent 已绑定、流量已通，但控制台还显示
	// pending」。这是浏览器验证时抓出来的第二个状态不一致。
	// 共享入口的路由表全量重建。必须在 refreshStates 之前 ——
	// 它会因路由冲突把隧道标成 error，而那个状态要能被下面读到。
	rt.applyShared(desired)

	rt.mu.Lock()
	rt.entryErrors = entryErrs
	rt.mu.Unlock()

	rt.refreshStates(desired)

	// 把新的期望集合下发给所有在线 agent。
	for _, s := range rt.sessions.List() {
		if s.Alive() {
			rt.pushTunnels(s)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// bindUnassigned 把未指定 agent 的隧道绑到唯一在线 agent。
//
// 只在**恰好一个** agent 在线时自动绑定：多于一个时无法判断用户意图，
// 少于一个时无从绑定。两种情况都把原因写进隧道状态，
// 让用户在控制台看到「为什么这条隧道不通」而不是对着一个静默失败发呆。
//
// # 为什么它**不再**跳过 kind=reverse
//
// 原本这里跳过 reverse，注释写的是「kind=reverse 且无 agent 是合法且有意的
// 形态（中继自己拨号），不要去动它」。那句话是**假的**：中继直拨在数据面
// 根本不存在（三个入口都调 SessionFor，返回 false 就放弃，没有任何回落），
// 所以一条无 agent 的 reverse 隧道不是「另一种形态」，
// 而是一条每个连接都被静默关掉的坏隧道。
//
// 跳过它的后果是它连自愈的机会都没有：service 隧道在唯一 agent 上线时会被
// 自动绑上，而 reverse 永远停在那里，同时还在控制台上显示绿点。
// 现在两者同路 —— 这也让 probe.go 那句「等代理端上线后会自动绑定」
// 对 reverse 第一次成为真话。
func (rt *runtime) bindUnassigned(desired []*tunnel.Tunnel) {
	var live []*relay.Session
	for _, s := range rt.sessions.List() {
		if s.Alive() {
			live = append(live, s)
		}
	}

	for _, t := range desired {
		if t.AgentID != "" {
			continue
		}
		switch len(live) {
		case 0:
			// 状态由入口绑定那一步统一设置（见 ApplyTunnels），
			// 这里不重复写，否则会被后面覆盖掉，白做一次写库。
		case 1:
			t.AgentID = live[0].AgentID
			if err := rt.db.PutTunnel(rt.ctx, t); err != nil {
				rt.log.Warn("回写隧道的代理端绑定失败", "隧道", t.Slug, "err", err)
				continue
			}
			rt.log.Info("隧道已绑定到唯一在线代理端",
				"隧道", t.Slug, "agent", t.AgentID)
		default:
			// 多个 agent 在线：中继无从判断该用哪个，不猜。
			//
			// **状态不在这里写。** 这里写完之后，同一次 ApplyTunnels 里的
			// refreshStates 会看到 t.AgentID 仍然为空，落到
			// 「pending：端口已监听，等待代理端上线」把它覆盖掉 ——
			// 而那句话是**假的**：agent 已经在线，只是有两个。
			// 用户看到的是一条永远停在 pending 的隧道，
			// 以及一条永远不会实现的承诺。
			//
			// 上面 case 0 的注释早就点出了这个陷阱（「这里不重复写，
			// 否则会被后面覆盖掉」），default 分支落进了同一个坑。
			// 判据现在归 refreshStates 一处，见那里的 len(online) > 1。
		}
	}
}

// assignPorts 给 listen_port=0 的端口型隧道分配一个端口并回写库。
//
// # 为什么必须回写
//
// 不回写的话重启后会换一个端口，而 exposure=port 的客户端是拿端口号硬配的
// （场景二的设备写在固件里）—— 换端口等于让所有客户端同时失联。
// 「由中继分配」的意思是「你不用挑，但挑定了就不再变」。
//
// # 这里有一个 TOCTOU 窗口，如实说明
//
// 做法是 bind :0 拿到内核分配的端口、立刻 Close、然后回写。在 Close 与
// 后面绑定循环真正 bind 之间，那个端口理论上会被别的进程抢走。
// 抢走的后果是这一轮绑定失败并把原因写进隧道状态（用户看得到
// 「端口被占」），下一次 ApplyTunnels 会重试 —— 而**不是**静默失败。
//
// 不用「bind 之后把 listener 留着交给绑定循环」的做法，是因为那要求
// relay.NewEntryListener 接受一个已有的 listener，而那个口子会让
// 「监听器由谁拥有、谁负责关」变得含糊 —— 这条路径每年只走一次，
// 不值得为它把所有权模型搞复杂。
func (rt *runtime) assignPorts(desired []*tunnel.Tunnel, byPort map[uint16]*tunnel.Tunnel) {
	for _, t := range desired {
		if !t.IsEnabled() || t.Exposure != tunnel.ExposurePort || t.ListenPort != 0 {
			continue
		}
		network := "tcp"
		if t.L4 == tunnel.L4UDP {
			network = "udp"
		}
		port, err := probeFreePort(network)
		if err != nil {
			rt.log.Warn("为隧道分配端口失败", "隧道", t.Slug, "err", err)
			continue
		}
		t.ListenPort = port
		byPort[port] = t
		if err := rt.db.PutTunnel(rt.ctx, t); err != nil {
			// 回写失败就把内存里的改动**撤销**：留着它会让运行时用一个
			// 库里没有的端口，而控制台按库渲染 —— 那正是「同一份数据两个
			// 真相源」的形状，本仓库为它付过代价。
			rt.log.Warn("回写分配的端口失败", "隧道", t.Slug, "端口", port, "err", err)
			delete(byPort, port)
			t.ListenPort = 0
			continue
		}
		rt.log.Info("已为隧道分配入口端口", "隧道", t.Slug, "端口", port, "协议", network)
	}
}

// probeFreePort 让内核挑一个空闲端口。
//
// 绑 :0 再立刻关。返回的端口在极短窗口内可能被别人抢走 ——
// 调用方必须能处理「随后 bind 失败」，见 assignPorts 的说明。
func probeFreePort(network string) (uint16, error) {
	switch network {
	case "udp":
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return 0, err
		}
		defer c.Close()
		return uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
	default:
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return uint16(l.Addr().(*net.TCPAddr).Port), nil
	}
}

// noteSession 把一次会话开/关推给控制台（实现 relay.SessionSink）。
//
// # 为什么这些帧是「可牺牲的」
//
// 它们的速率由**外部输入**（用户连接）决定，而控制台的事件队列是共享且有界的。
// 冲垮它意味着把 1Hz 的权威快照挤掉 —— 那时界面会停在旧数据上，
// 用户看到的是「一个正在被扫的中继看起来风平浪静」。
//
// 所以入口那边已经有令牌桶，而这里 Publish 满了就丢。返回值告诉入口
// 「这一帧发出去了吗」，它据此决定关闭时要不要再发一帧 ——
// 只发了 open 没发 close 会留下一条永不消失的幽灵行。
//
// # 为什么 Peer 只推送不落库
//
// 它是运行时观测到的第三方地址，而事件表会被**支持包外发**。
// 会话网格是实时视图，看完就没了；把地址写进库等于让它进到一份要发给别人的
// 文件里。
func (rt *runtime) noteSession(ev relay.SessionEvent) bool {
	// 学习模式的观测点之一。
	//
	// **只记开启帧**（Delta > 0）：关闭帧的地址与开启帧一样，记两遍会让
	// 命中次数虚高一倍，而命中次数正是运维用来区分「真客户端」与
	// 「扫了一次的人」的依据。
	//
	// 这一步在 hub 为 nil（没开控制台）时也要做：学习不依赖有人在看，
	// 而「只在有人开着页面时才学」恰恰是这个功能最没用的形态。
	if ev.Delta > 0 {
		rt.observeSessionPeer(ev.TunnelID, ev.Peer)
	}
	if rt.hub == nil {
		return false
	}
	return rt.hub.PublishSession(console.SessionFrame{
		TunnelID:      ev.TunnelID,
		Delta:         ev.Delta,
		Sessions:      ev.Active,
		SessionsTotal: ev.Total,
		Peer:          ev.Peer,
		Path:          ev.Path,
	})
}

// observeSessionPeer 把一条会话的对端地址记进学习模式。
//
// peer 是 "host:port" 形式（netip.AddrPort.String()）。解析失败就不记 ——
// 一个解不出来的地址推荐给运维毫无用处，而编一个更糟。
func (rt *runtime) observeSessionPeer(tunnelID, peer string) {
	if tunnelID == "" || peer == "" {
		return
	}
	ap, err := netip.ParseAddrPort(peer)
	if err != nil {
		// 也接受不带端口的写法，将来若有别的观测点直接送地址进来。
		addr, aerr := netip.ParseAddr(peer)
		if aerr != nil {
			return
		}
		rt.observed.note(tunnelID, addr)
		return
	}
	rt.observed.note(tunnelID, ap.Addr())
}

// ObservedSources 实现 console.SourceObserver。
func (rt *runtime) ObservedSources(tunnelID string) (console.LearnedSources, bool) {
	return rt.observed.ObservedSources(tunnelID)
}

// DeclineLearnedSources 实现 console.SourceObserver。
func (rt *runtime) DeclineLearnedSources(tunnelID string) {
	rt.observed.DeclineLearnedSources(tunnelID)
}

// RefreshStates 从库里读一遍隧道并刷新状态。
//
// agent 上下线不改变隧道**定义**，所以没必要走完整的 ApplyTunnels
// （那会去 diff 监听器），但状态必须跟着变 —— 否则 agent 掉线后
// 控制台还显示「运行中」，而实际连接会被干净拒掉。
func (rt *runtime) RefreshStates() {
	desired, err := rt.db.ListTunnels(rt.ctx, tunnel.DefaultTenantID)
	if err != nil {
		rt.log.Warn("刷新状态时读取隧道失败", "err", err)
		return
	}
	// 共享入口的路由表全量重建。必须在 refreshStates 之前 ——
	// 它会因路由冲突把隧道标成 error，而那个状态要能被下面读到。
	rt.applyShared(desired)

	rt.refreshStates(desired)
}

// datagramCapable 报告某个 agent 的会话能否走不可靠数据报。
func (rt *runtime) datagramCapable(agentID string) bool {
	s, ok := rt.sessions.Get(agentID)
	return ok && s.Alive() && s.SupportsDatagrams()
}

// refreshStates 让隧道状态如实反映**可用性**，而不只是「端口绑上了」。
//
// 端口在监听 ≠ 隧道能用：没有 agent 承载时打进来的连接会被干净地拒掉。
// 第一版无条件写 active，控制台就显示一条「运行中」但实际不通的隧道 ——
// 那是在撒谎。
func (rt *runtime) refreshStates(desired []*tunnel.Tunnel) {
	online := make(map[string]bool)
	for _, s := range rt.sessions.List() {
		if s.Alive() {
			online[s.AgentID] = true
		}
	}

	for _, t := range desired {
		// 由 agent 本地策略否决的隧道，原因更权威，不要覆盖。
		rt.mu.RLock()
		_, rejected := rt.rejections[t.ID]
		_, routeBad := rt.routeErrors[t.ID]
		entryErr, entryBad := rt.entryErrors[t.ID]
		sharedOn := rt.shared != nil
		rt.mu.RUnlock()
		if rejected || routeBad {
			// 这两种状态由别处写入且更具体，不该被这里的通用判定覆盖。
			continue
		}
		if entryBad {
			// 入口压根没绑上。这个原因比下面任何通用判定都具体，
			// 而覆盖它会让控制台说「端口已监听」——那句话是假的。
			if t.State != tunnel.StateError || t.StateReason != entryErr {
				if err := rt.db.SetTunnelState(rt.ctx, t.ID, tunnel.StateError, entryErr); err != nil {
					rt.log.Warn("更新隧道状态失败", "隧道", t.Slug, "err", err)
				}
			}
			continue
		}

		state, reason := tunnel.StateActive, ""
		switch {
		case !t.IsEnabled():
			state, reason = tunnel.StateStopped, ""
		case t.Exposure == tunnel.ExposurePort && t.ListenPort == 0:
			// 走到这里意味着**分配也失败了**（assignPorts 连一个空闲端口都
			// 拿不到，或回写库失败）。那时确实一个监听器都没有，
			// 而它原本会被报成 active。
			state, reason = tunnel.StateError,
				"中继未能为这条隧道分配入口端口（系统无空闲端口，或状态回写失败）"
		case t.Exposure == tunnel.ExposureShared && !sharedOn:
			// 共享入口没启用。同样是「一个监听器都没有」，
			// 而原本它会被报成 active —— curl 过去直接连不上。
			state, reason = tunnel.StateError,
				"这条隧道用共享入口，但中继没有启用 -shared"
		case t.L4 == tunnel.L4UDP && t.ShortID == 0:
			// 短标识是 UDP 解复用的前提，为 0 就没法上线。
			// 正常路径下不会发生（存储层落库时分配），
			// 但如实报出来比让它静默失效好。
			state, reason = tunnel.StateError, "隧道缺少短标识，无法承载 UDP"
		case t.L4 == tunnel.L4UDP && t.AgentID != "" && online[t.AgentID] &&
			!rt.datagramCapable(t.AgentID):
			// 承载不支持不可靠数据报（例如将来降级到 TLS/smux 梯级）。
			// 必须如实告知，**绝不**悄悄把 UDP 塞进一条可靠流让用户
			// 以为自己拿到了低延迟通道 —— frp 就是那样做的。
			state, reason = tunnel.StateDegraded, "代理端承载不支持不可靠数据报，UDP 暂不可用"
		// 下面两条**不按 kind 分流**。
		//
		// 原本它们都带 `t.Kind == KindService &&` 前置，理由是「reverse 走中继
		// 自己拨号，不需要 agent」。而那条路径**在数据面根本不存在**：
		// 三个入口（internal/relay/entry.go、internal/gateway/gateway.go、
		// internal/relay/udpentry.go）全都调 SessionFor(t.AgentID)，返回 false
		// 就直接放弃，没有任何一处回落到「中继自己拨」；而 SessionFor("")
		// 无条件返回 false。
		//
		// 于是 reverse 隧道恒落到本 switch 的初值 StateActive —— 一条每个连接
		// 都被静默关掉的隧道在控制台上显示**绿点**。实测过：三条隧道挂同一个
		// 不存在的 agent，reverse 报 active、service 报 degraded，
		// 而两者 curl 过去都是 connection reset。
		//
		// 运维因此拿不到任何故障信号，而这正是本仓最在意的那类缺陷：
		// 界面上一切正常，实际什么都不通。
		case t.AgentID == "" && len(online) > 1:
			// 未绑定，而在线 agent 不止一个 —— 中继无从判断该用哪个。
			//
			// **必须与「一个都没在线」分开报。** 合并成 pending 的话，
			// 用户看到的是「等待代理端上线」，而 agent 已经在线、
			// 只是有两个：那条隧道会永远停在 pending，
			// 而界面给出的下一步动作（等）永远不会奏效。
			// 正确的下一步是「去隧道配置里挑一个」，所以文案必须这么说。
			state, reason = tunnel.StateError,
				fmt.Sprintf("有 %d 个代理端在线，请在隧道配置里显式指定一个", len(online))
		case t.AgentID == "":
			state, reason = tunnel.StatePending, "端口已监听，等待代理端上线"
		case !online[t.AgentID]:
			state, reason = tunnel.StateDegraded, "代理端不在线"
		}

		// 只在真的变了时才写库，避免每秒一次无谓的写。
		if t.State == state && t.StateReason == reason {
			continue
		}
		if err := rt.db.SetTunnelState(rt.ctx, t.ID, state, reason); err != nil {
			rt.log.Warn("更新隧道状态失败", "隧道", t.Slug, "err", err)
		}
	}
}

// addrPort 从一个监听地址里取端口。
//
// **必须同时认 TCP 与 UDP。** 只认 TCPAddr 的版本让 UDP 入口的「端口变了吗」
// 判据恒为真（拿到 0，永远不等于配置的端口），于是每次 ApplyTunnels 都会把
// 所有 UDP 入口关掉重建 —— 活跃的音视频流全断、计数器归零、端口还有一个
// 未绑定的窗口在丢包。真实进程验证时靠「UDP 入口已就绪」打了两遍才发现。
func addrPort(a net.Addr) uint16 {
	switch v := a.(type) {
	case *net.TCPAddr:
		return uint16(v.Port)
	case *net.UDPAddr:
		return uint16(v.Port)
	default:
		return 0
	}
}

// bindDatagramEntry 为一条 UDP 隧道绑定入口并登记到解复用器。
func (rt *runtime) bindDatagramEntry(t *tunnel.Tunnel) error {
	// 存在性检查与登记必须在**同一把写锁**里。
	//
	// ApplyTunnels 会被并发调用（控制台改配置、agent 上线各走一次），
	// 先 RLock 查、再 Lock 写的话两边都能通过检查，于是绑两个 socket 到
	// 同一个端口 —— 第二个要么失败要么抢走流量，都是随机现象。
	rt.mu.Lock()
	if _, exists := rt.dgrams[t.ID]; exists {
		rt.mu.Unlock()
		return nil
	}
	// 先占位再建，防止同时进来的第二次调用重复建。
	rt.dgrams[t.ID] = nil
	rt.mu.Unlock()

	de, err := relay.NewDatagramEntry(
		net.JoinHostPort("0.0.0.0", fmt.Sprint(t.ListenPort)), t, rt,
		relay.DatagramOptions{
			Log: rt.log,
			// 学习模式观测点：每条**新准入**的 UDP 流记一次（不是每个包）。
			OnSource: rt.observed.note,
		})
	if err != nil {
		// 建失败要把占位撤掉，否则这条隧道再也不会被重试。
		rt.mu.Lock()
		delete(rt.dgrams, t.ID)
		rt.mu.Unlock()
		return err
	}

	rt.mu.Lock()
	rt.dgrams[t.ID] = de
	rt.mu.Unlock()
	// 先登记再开始收包：反过来的话，最初几个回包会因为找不到入口而
	// 被记成 unrouted —— 一个只在启动瞬间出现、极难复现的怪现象。
	rt.dgramRouter.Register(de)

	go func() {
		if err := de.Serve(rt.ctx); err != nil {
			rt.log.Error("UDP 入口退出", "隧道", t.Slug, "err", err)
		}
	}()

	rt.log.Info("UDP 入口已就绪", "隧道", t.Slug,
		"监听", de.Addr().String(), "短标识", t.ShortID, "目标", t.Backend.Addr)
	return nil
}

// DatagramRouter 返回解复用器，供 agent 上线时启动接收循环。
func (rt *runtime) DatagramRouter() *relay.DatagramRouter { return rt.dgramRouter }

// pushTunnels 把隧道集合下发给一个 agent，并收下它的否决回执。
func (rt *runtime) pushTunnels(sess *relay.Session) {
	rt.mu.RLock()
	list := make([]*tunnel.Tunnel, 0, len(rt.tunnels))
	for _, t := range rt.tunnels {
		// 只下发**明确属于**这个 agent 的隧道。绑定已由 bindUnassigned
		// 完成并回写，所以这里不做任何隐式归属。
		if t.AgentID == sess.AgentID {
			list = append(list, t.Clone())
		}
	}
	rt.mu.RUnlock()

	ctx, cancel := context.WithTimeout(rt.ctx, 10*time.Second)
	defer cancel()

	st, err := sess.Carrier.OpenStream(ctx)
	if err != nil {
		rt.log.Warn("下发隧道集合失败：开流", "agent", sess.AgentID, "err", err)
		return
	}
	defer st.Close()

	if err := proto.NewWriter(st).WriteMessage(proto.TypeTunnelSet, 0, 0, list); err != nil {
		rt.log.Warn("下发隧道集合失败：写入", "agent", sess.AgentID, "err", err)
		return
	}

	_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
	fr, err := proto.NewReader(st).ReadFrame()
	if err != nil {
		return
	}
	if fr.Header.Type != proto.TypeTunnelRejected {
		rt.log.Info("隧道集合已下发", "agent", sess.AgentID, "条数", len(list))
		return
	}

	var rejects map[string]string
	if err := proto.Decode(fr, &rejects); err != nil {
		return
	}

	rt.mu.Lock()
	// 先清掉这个 agent 之前的否决记录，否则一条已修好的隧道会永远显示被否决。
	for id := range rt.rejections {
		if t, ok := rt.tunnels[id]; ok && t.AgentID == sess.AgentID {
			delete(rt.rejections, id)
		}
	}
	for id, reason := range rejects {
		rt.rejections[id] = reason
	}
	rt.mu.Unlock()

	for id, reason := range rejects {
		rt.log.Warn("隧道被代理端本地策略否决", "隧道", id, "原因", reason)
		_ = rt.db.SetTunnelState(rt.ctx, id, tunnel.StateRejectedByAgent, reason)
		_ = rt.db.AppendEvent(rt.ctx, store.Event{
			Kind: store.KindTunnelRejected, Level: store.LevelWarn,
			Subject: id, Message: reason, Actor: sess.AgentID,
		})
	}
	rt.publish(console.EventState, map[string]any{"rejections": rejects})
	rt.log.Info("隧道集合已下发", "agent", sess.AgentID, "条数", len(list), "否决", len(rejects))
}

// ── agent 鉴权（对接存储层）─────────────────────────────────────────────────

// LookupKey 实现 relay.AgentAuthenticator。
func (rt *runtime) LookupKey(agentID string) ([]byte, bool) {
	return rt.db.AgentSecret(rt.ctx, agentID)
}

// RedeemEnrolToken 实现 relay.AgentAuthenticator。
func (rt *runtime) RedeemEnrolToken(token string, p relay.AgentProfile) (string, []byte, error) {
	// 画像必须一并落库：否则控制台的节点清单里 OS 与架构是空的，
	// 而那正是用户最想看的两列。（这是手工验证抓出来的缺陷。）
	id, _, err := rt.db.RedeemEnrolToken(rt.ctx, token, &store.Agent{
		MachineID: p.MachineID,
		Hostname:  p.Hostname,
		OS:        p.OS,
		Arch:      p.Arch,
		Version:   p.Version,
	})
	if err != nil {
		return "", nil, err
	}
	// 存储层返回 hex，握手层要密钥字节本身（HMAC 需要）。
	key, ok := rt.db.AgentSecret(rt.ctx, id)
	if !ok {
		return "", nil, fmt.Errorf("兑换后取不回密钥（agent %s）", id)
	}
	return id, key, nil
}

// touchProfile 在 agent（重）连时刷新库里的设备画像。
func (rt *runtime) touchProfile(agentID string, p relay.AgentProfile) {
	if err := rt.db.TouchAgent(rt.ctx, &store.Agent{
		ID:        agentID,
		MachineID: p.MachineID,
		Hostname:  p.Hostname,
		OS:        p.OS,
		Arch:      p.Arch,
		Version:   p.Version,
	}); err != nil {
		rt.log.Warn("刷新 agent 画像失败", "agent", agentID, "err", err)
	}
}

// closeEntries 关闭全部入口监听器（停止接受新连接）。
func (rt *runtime) closeEntries() {
	rt.mu.RLock()
	entries := make([]*relay.EntryListener, 0, len(rt.entries))
	for _, e := range rt.entries {
		entries = append(entries, e)
	}
	// UDP 入口也要关。
	//
	// 漏了它的后果：优雅关闭时 UDP 端口仍在监听、仍在收包，而这些包
	// 会被送给一个正在断开的会话 —— 用户看到的是「关机过程中包被吞了」
	// 而不是干净的连接拒绝。而且端口不释放会让紧接着的重启绑定失败。
	dgrams := make([]*relay.DatagramEntry, 0, len(rt.dgrams))
	for _, e := range rt.dgrams {
		if e != nil {
			dgrams = append(dgrams, e)
		}
	}
	rt.mu.RUnlock()

	for _, e := range entries {
		_ = e.Close()
	}
	for _, e := range dgrams {
		rt.dgramRouter.Unregister(e.ShortID())
		_ = e.Close()
	}
}

// startMaintenance 起一个后台循环做上卷与清理。
func (rt *runtime) startMaintenance() (stop func()) {
	done := make(chan struct{})
	go func() {
		// 每分钟一次：与 1m 桶粒度一致。
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-rt.ctx.Done():
				return
			case <-ticker.C:
				if err := rt.db.Rollup(rt.ctx); err != nil {
					rt.log.Warn("时序上卷失败", "err", err)
				}
				if _, err := rt.db.PruneSessions(rt.ctx); err != nil {
					rt.log.Warn("清理过期会话失败", "err", err)
				}
				// 事件保留 30 天。
				if _, err := rt.db.PruneEvents(rt.ctx, time.Now().AddDate(0, 0, -30)); err != nil {
					rt.log.Warn("清理事件失败", "err", err)
				}
				rt.collectSamples()
			}
		}
	}()
	return func() { close(done) }
}

// collectSamples 把入口计数器的当前值差分成时序样本。
func (rt *runtime) collectSamples() {
	rt.mu.RLock()
	entries := make(map[string]*relay.EntryListener, len(rt.entries))
	for k, v := range rt.entries {
		entries[k] = v
	}
	dgrams := make(map[string]*relay.DatagramEntry, len(rt.dgrams))
	for k, v := range rt.dgrams {
		// 跳过占位的 nil（bindDatagramEntry 正在建它）。
		if v != nil {
			dgrams[k] = v
		}
	}
	rt.mu.RUnlock()

	bucket := time.Now().Unix()
	for id, el := range entries {
		st := el.Stats()
		// 计数器是单调累加的，所以要差分成增量 —— 直接写累计值会让
		// 时序图变成一条单调上升的线，看不出「现在的速率」。
		cur := counterSet{
			bytesIn:  st.BytesUp.Load(),
			bytesOut: st.BytesDown.Load(),
			connsOK:  st.Accepted.Load(),
			connsErr: st.OpenFailed.Load() + st.DeniedCIDR.Load() + st.RateLimited.Load(),
		}
		prev := rt.lastCounters(id)
		rt.setLastCounters(id, cur)

		delta := cur.sub(prev)
		if delta.isZero() {
			continue
		}
		if err := rt.db.RecordSample(rt.ctx, store.Sample{
			TunnelID: id, Bucket: bucket,
			BytesIn: delta.bytesIn, BytesOut: delta.bytesOut,
			ConnsOK: delta.connsOK, ConnsErr: delta.connsErr,
			Samples: 1,
		}); err != nil {
			rt.log.Warn("记录时序样本失败", "隧道", id, "err", err)
		}
	}

	rt.recordRTTSamples(bucket)
}

// recordRTTSamples 把每个会话的承载 RTT 写进它名下所有隧道的直方图。
//
// # 为什么一个 RTT 写进多条隧道
//
// 测的是**承载** RTT（规格 §8.4 的用词），而承载是每 agent 一条 ——
// 同一个 agent 名下所有隧道共享同一条链路，所以它们的承载 RTT 就是同一个数。
// 规格要求「每隧道 p50/p95/p99 承载 RTT」，那是**展示**粒度，不是测量粒度。
//
// 这一点必须在控制台上说清楚，否则用户会以为两条隧道的曲线是两次独立测量 ——
// 而它们其实是同一条。
//
// # 为什么写直方图而不是一列 p95
//
// 规格 §401：「RTT 必须存直方图桶（le_us）而不是 p95 列 —— p95 的 p95
// 在算术上是错的」。RecordRTT 写的正是累积直方图。
func (rt *runtime) recordRTTSamples(bucket int64) {
	// 先按 agent **排空**观测，再按隧道分发。
	//
	// 排空而不是「读最近一个」：ping 每 5 秒一次而本循环每分钟一次，
	// 只取最近一个等于把 12 个观测里的 11 个丢掉 —— 而直方图的价值恰恰在
	// 样本数，一分钟一个点算不出有意义的 p95。
	byAgent := make(map[string][]time.Duration)
	for _, sess := range rt.sessions.List() {
		if !sess.Alive() {
			continue
		}
		if rtts := sess.DrainRTT(); len(rtts) > 0 {
			byAgent[sess.AgentID] = rtts
		}
	}
	if len(byAgent) == 0 {
		return
	}

	rt.mu.RLock()
	tunnels := make([]*tunnel.Tunnel, 0, len(rt.tunnels))
	for _, t := range rt.tunnels {
		tunnels = append(tunnels, t)
	}
	rt.mu.RUnlock()

	at := time.Unix(bucket, 0)
	for _, t := range tunnels {
		rtts, ok := byAgent[t.AgentID]
		if !ok {
			continue
		}
		if err := rt.db.RecordRTT(rt.ctx, t.ID, at, rtts...); err != nil {
			rt.log.Warn("记录 RTT 样本失败", "隧道", t.Slug, "err", err)
		}
	}
}

type counterSet struct {
	bytesIn, bytesOut, connsOK, connsErr int64
}

func (c counterSet) sub(prev counterSet) counterSet {
	d := counterSet{
		bytesIn:  c.bytesIn - prev.bytesIn,
		bytesOut: c.bytesOut - prev.bytesOut,
		connsOK:  c.connsOK - prev.connsOK,
		connsErr: c.connsErr - prev.connsErr,
	}
	// 入口被重建时计数器归零，差分会变负数。夹到 0 而不是写入负增量。
	if d.bytesIn < 0 {
		d.bytesIn = 0
	}
	if d.bytesOut < 0 {
		d.bytesOut = 0
	}
	if d.connsOK < 0 {
		d.connsOK = 0
	}
	if d.connsErr < 0 {
		d.connsErr = 0
	}
	return d
}

func (c counterSet) isZero() bool {
	return c.bytesIn == 0 && c.bytesOut == 0 && c.connsOK == 0 && c.connsErr == 0
}

var (
	countersMu sync.Mutex
	counters   = make(map[string]counterSet)
)

func (rt *runtime) lastCounters(id string) counterSet {
	countersMu.Lock()
	defer countersMu.Unlock()
	return counters[id]
}

func (rt *runtime) setLastCounters(id string, c counterSet) {
	countersMu.Lock()
	defer countersMu.Unlock()
	counters[id] = c
}

// writePEM 把 DER 编码写成 PEM 文件。
func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("写 %s 失败：%w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("编码 %s 失败：%w", path, err)
	}
	return f.Sync()
}

// readAgentMetrics 在控制流上读 agent 的周期性计数器上报。
//
// # 为什么这些数字不能只留在 agent 里
//
// 中继只看得见自己那一侧。agent 侧有一整类丢弃它完全不知道：
// 拨本地目标失败、被本地策略否决、回向发送队列满、回向数据报超限、
// 回向分片重组失败。用户看到的症状是「下行统计都对，就是收不到回包」，
// 而在这条上报之前**没有任何数字**能告诉运维为什么。
//
// # 为什么未知帧类型只跳过
//
// proto.Reader 对未知类型是跳过而不是断连（前向兼容），所以一个更新的
// agent 发来我们不认识的帧不会把这条流搞坏。**绝不**因为一个坏帧就关会话：
// 那会把「计量上报有点问题」放大成「整条隧道断掉」。
func (rt *runtime) readAgentMetrics(rest io.Reader, sess *relay.Session) {
	// **必须用握手交出来的 rest，不能新建 Reader 读裸流。**
	//
	// 握手那个 Reader 内部是 16 KiB bufio，可能已经把 Hello 之后的字节吞了；
	// 新建一个就会从帧中间开始解析 → 版本不匹配 → 整条控制流死掉。
	// proto.Reader.Remainder 的注释把这条写成了硬要求。
	r := proto.NewReader(rest)
	for {
		fr, err := r.ReadFrame()
		if err != nil {
			// 会话结束时这里必然出错，不值得记日志。
			return
		}
		if fr.Header.Type == proto.TypePong {
			// 承载 RTT 的观测就在这里闭环：时间戳两次都由中继取，
			// agent 的时钟完全不参与（见 relay/rtt.go 的说明）。
			//
			// seq 不匹配时 NotePong 静默忽略 —— 一个陈旧的或伪造的 Pong
			// 不该被算成一次观测，那正是把 RTT 报成接近 0 的路径。
			sess.NotePong(fr.Header.CorrID, time.Now())
			continue
		}
		if fr.Header.Type != proto.TypeMetrics {
			continue
		}
		var m proto.AgentMetrics
		if err := json.Unmarshal(fr.Payload, &m); err != nil {
			rt.log.Debug("agent 计数器上报解析失败", "agent", sess.AgentID, "err", err)
			continue
		}
		rt.mu.Lock()
		rt.agentMetrics[sess.AgentID] = agentMetricSample{at: time.Now(), m: m}
		rt.mu.Unlock()
	}
}

// pingAgent 周期性在控制流上发 Ping，测承载 RTT。
//
// # 为什么这是必需的
//
// 规格 §8.4 要求「每隧道 p50/p95/p99 **承载** RTT」，而 store.RecordRTT
// 与直方图表（tunnel_rtt_hist_1m）早就写好了却**没有生产写入点** ——
// 于是控制台上那三个数字一直显示「—」。
//
// # 中继是控制流唯一的写者
//
// 握手之后中继不再往控制流写别的东西（下发隧道走新开的流），
// 所以这里不需要写锁。这个前提写出来，因为它不显然 ——
// 将来若有第二个写者，必须先加锁再动。
func (rt *runtime) pingAgent(ctrl carrier.Stream, sess *relay.Session) {
	w := proto.NewWriter(ctrl)
	ticker := time.NewTicker(rttPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sess.Carrier.Context().Done():
			return
		case <-rt.ctx.Done():
			return
		case <-ticker.C:
		}
		// 写期限：控制流卡住时不该让这个协程挂死。
		_ = ctrl.SetWriteDeadline(time.Now().Add(rttPingInterval))
		sent, err := sess.SendPing(w, time.Now())
		_ = ctrl.SetWriteDeadline(time.Time{})
		if err != nil {
			rt.log.Debug("发 Ping 失败（会话可能已结束）", "agent", sess.AgentID, "err", err)
			return
		}
		_ = sent // false 只是「上一个还在飞」，不是错误
	}
}

// rttPingInterval 是承载 RTT 的采样间隔。
//
// 5 秒：直方图是慢慢积累的，而 64 个样本的环形缓冲 @5 秒 ≈ 5 分钟窗口 ——
// 分位数要的是分布而不是历史。更密的采样只会让控制流上多一些没用的帧。
const rttPingInterval = 5 * time.Second

// agentMetricSample 是一份 agent 上报的计数器快照及其到达时刻。
//
// 记下到达时刻是必需的：控制台要能区分「这个 agent 刚报过」与
// 「它上报卡住了，你看到的是十分钟前的数」。不记的话第二种情况会被读成
// 「一切正常」——而那正是最需要被看见的状态。
type agentMetricSample struct {
	at time.Time
	m  proto.AgentMetrics
}

// limitsOfTunnel 从隧道策略里取带宽限速参数。
//
// 与 internal/relay 的 limitsOf 同形，但那个是包内的 —— 这里需要一份
// 能从 cmd 侧调用的。两处必须给同样的答案，否则「改了带宽」在两条路径上
// 表现不同。
func limitsOfTunnel(t *tunnel.Tunnel) limiter.Limits {
	if t.Policy == nil {
		return limiter.Limits{}
	}
	return limiter.Limits{
		BytesPerSecond:   t.Policy.BytesPerSecond,
		PacketsPerSecond: t.Policy.PacketsPerSecond,
	}
}

// desiredConnCaps 算出一条隧道期望的并发上限，与 relay.NewEntryListener 的
// 算法**逐字一致**（含 0 → 默认、以及每源配额被收敛到全局上限）。
//
// 不一致的后果是「每次 ApplyTunnels 都认为并发上限变了」→ 每秒重建一次入口
// → 所有连接被反复掐断，而配置一个字都没改。
func desiredConnCaps(t *tunnel.Tunnel) (maxConns, maxPerIP int) {
	maxConns = relay.DefaultMaxConns
	if t.Policy != nil && t.Policy.MaxConns > 0 {
		maxConns = t.Policy.MaxConns
	}
	if t.Policy != nil && t.Policy.MaxConnsPerIP > 0 {
		maxPerIP = min(t.Policy.MaxConnsPerIP, maxConns)
	}
	return maxConns, maxPerIP
}
