// Package console 实现中继的 Web 控制台后端：鉴权、隧道 CRUD、SSE 事件流、指标。
//
// # 为什么是独立监听器而不是与网关共用端口
//
// SSE 需要 HTTP/2 才能摆脱浏览器「每源约 6 连接」的限制（否则一个图表一个
// EventSource 就把仪表盘拖死），而场景二的 ESP32 只说明文 HTTP/1.1、不做 ALPN
// 协商，网关侧必须把入站钉在 HTTP/1。两个要求互斥，共用监听器做不到。
// 顺带的好处是管理面与数据面不共享端口，安全边界更清晰。
//
// # 相对 frp 控制台的关键修正
//
// frp 的 `webServer.port = 7500` 一行配置就能得到一个**监听 0.0.0.0 的无鉴权
// 控制台**：中间件在用户名密码双空时放行一切（pkg/util/net/http.go:48），
// 校验从不要求填凭据（validation/common.go:24-35），而 Complete() 又把地址
// 覆盖成 0.0.0.0（server.go:117），README 还教 admin/admin。
// 本实现拒绝在非 loopback 监听下使用空凭据启动。
// （`must_rotate` 字段与会话里的改密页都存在，但 v1 没有任何路径把它置 1
// ——「强制首次登录改密」当前不生效，见 docs/integration/03-api.md §3.4。）
package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// SessionCookieName 是会话 Cookie 名。
//
// `__Host-` 前缀是浏览器强制的加固：要求 Secure、Path=/、且**不允许 Domain
// 属性**，因此子域无法写入或覆盖它。这挡住了「子域接管」这一类会话固定攻击。
// 但它同时要求 HTTPS —— 所以 loopback 明文场景下退化为不带前缀的名字。
const (
	SessionCookieName         = "__Host-nfr_session"
	SessionCookieNameInsecure = "nfr_session"
	CSRFCookieName            = "nfr_csrf"
	CSRFHeaderName            = "X-NFR-CSRF"

	// APIContractVersion 是控制台接口的契约版本。
	//
	// **必须与 web/vite.config.ts 的 API_CONTRACT_VERSION 一致** ——
	// 有一条契约测试（TestAPIContractVersionMatchesTheFrontend）会解析那个
	// 文件并比对。
	//
	// 加字段不需要动它（前端对未知字段是宽容的）；**删字段或改语义**要加一。
	// 前端拿它与自己编译进去的值比对，不一致就横幅提示刷新 ——
	// 覆盖的是「中继升级了、浏览器还挂着旧前端」那段时间：
	// 界面看起来正常但数字不完整，而后端宽容、前端类型也宽容，
	// 没有任何一层会报错。
	APIContractVersion = 1
)

// SessionTTL 是会话有效期。
const SessionTTL = 12 * time.Hour

// Server 是控制台 HTTP 服务。
type Server struct {
	db  *store.DB
	log *slog.Logger

	// secure 表示会话 Cookie 是否带 Secure 与 __Host- 前缀。
	// 由是否走 HTTPS 决定。
	secure bool

	// allowedHosts 是允许的 Host 头取值。
	//
	// **DNS 重绑定防护**：不校验 Host 的话，攻击者可以让一个恶意页面
	// 用一个解析到 127.0.0.1 的域名访问 loopback 上的控制台，
	// 浏览器会带上 Cookie —— 一个只监听 loopback 的控制台就这样被接管了。
	// frp 完全没有这个检查。
	allowedHosts map[string]bool

	// events 是 SSE 订阅者集合。
	hub *eventHub

	// snapshot 提供运行时状态（在线 agent、隧道实时统计）。
	snapshot SnapshotSource

	mux *http.ServeMux

	// turn 可以为 nil（未启用 TURN）。
	turn TurnSource

	// settings 可以为 nil（不提供配置视图）。
	settings SettingsSource

	// guard 给未鉴权端点（登录、首启）按源 IP 限速。
	//
	// 全系统只有一把管理员口令、没有多因素、没有分权令牌 —— 那把口令就是全部，
	// 而这两个端点任何人都能打。argon2 并发闸关的是内存放大，这个关的是次数。
	guard *loginGuard
}

// SnapshotSource 让控制台读取运行时状态，而不必与中继核心耦合。
type SnapshotSource interface {
	// Snapshot 返回当前运行时快照。
	Snapshot() Snapshot
	// IssueEnrolToken 签发一个入网令牌并返回明文与安装命令。
	IssueEnrolToken(ttl time.Duration, note string) (token, installCmd string, err error)
	// ApplyTunnels 让中继重新加载隧道集合（增删入口监听器、下发给 agent）。
	ApplyTunnels() error
}

// DesktopBootstrapper 是可选的 Desktop 一键入网能力。
//
// 不把它塞进 SnapshotSource：已有的 fakeSnapshot、agent-only 嵌入方和
// 旧 runtime 都不需要 provisioning。实现方必须自己保证 invite 的一次性
// 消费、backend 约束与隧道应用；控制台只负责鉴权边界、请求大小与响应形状。
type DesktopBootstrapper interface {
	BootstrapDesktop(ctx context.Context, inviteToken string) (DesktopBootstrapResponse, error)
}

// DesktopPairingInviteIssuer 是管理员侧创建一次性 Desktop invite 的能力。
//
// 与 DesktopBootstrapper 分开，旧的 SnapshotSource 假实现不需要因为
// 增加 provisioning 能力而升级接口。
type DesktopPairingInviteIssuer interface {
	CreateDesktopPairingInvite(
		ctx context.Context, ttl time.Duration, listenPort uint16, note string,
	) (DesktopPairingInviteResponse, error)
}

// DesktopBootstrapScope 是 Desktop invite 的最小权限。
const DesktopBootstrapScope = "desktop:bootstrap"

// DesktopBackendAddr 是 Desktop WebUI 的固定本机后端。
//
// bootstrap 请求不接受 backend 字段，避免 bearer invite 被改造成 SSRF。
const DesktopBackendAddr = "127.0.0.1:25808"

// DesktopBootstrapResponse 是 Desktop 兑换 invite 后启动 nfagent 所需的
// 最小信息。EnrolToken 只在这次响应里出现，服务端不记录它。
type DesktopBootstrapResponse struct {
	InviteID       string         `json:"invite_id"`
	Relay          string         `json:"relay"`
	BusinessURL    string         `json:"business_url"`
	ProbeURL       string         `json:"probe_url"`
	Pin            string         `json:"pin"`
	EnrolToken     string         `json:"enrol_token"`
	EnrolExpiresAt time.Time      `json:"enrol_expires_at"`
	InstallCmd     string         `json:"install_cmd"`
	Tunnel         *tunnel.Tunnel `json:"tunnel"`
}

// DesktopPairingInviteResponse 是管理员创建 invite 后看到的一次性结果。
//
// Token 只出现在该响应中；数据库只保存 hash，日志与事件不得包含它。
type DesktopPairingInviteResponse struct {
	ID              string    `json:"id"`
	Token           string    `json:"token"`
	Relay           string    `json:"relay"`
	Pin             string    `json:"pin"`
	ListenPort      uint16    `json:"listen_port"`
	ExpiresAt       time.Time `json:"expires_at"`
	ProtocolVersion int       `json:"protocol_version,omitempty"`
	BootstrapURL    string    `json:"bootstrap_url,omitempty"`
	BusinessURL     string    `json:"business_url,omitempty"`
}

// AgentKicker 让控制台把代理端踢下线。
//
// 可选接口而不是塞进 SnapshotSource：那会逼出一堆空实现，也会让
// internal/console 的测试假实现每加一个能力就要改一次。
type AgentKicker interface {
	// KickAgent 关掉该代理端的活会话，返回是否真的踢到了。
	//
	// 这是**连接层**操作：不撤销凭据，agent 会立刻重连。
	KickAgent(agentID string) bool
}

// SettingsSource 让控制台读取生效配置及其来源。
type SettingsSource interface {
	Settings() []SettingsGroup
}

// TunnelProber 让控制台做逐跳探测。
type TunnelProber interface {
	ProbeTunnel(ctx context.Context, t *tunnel.Tunnel) ProbeResult
}

// SourceObserver 让控制台读取学习模式观测到的来源地址。
//
// 可选接口：不实现时两个端点回 501 而不是空列表 —— 一个空列表会被
// 界面读成「没人连过」，而真相是「这台中继不观测」。两者的下一步动作不同。
type SourceObserver interface {
	// ObservedSources 返回一条隧道观测到的来源。第二个返回值报告有没有记录
	//（没有记录 ≠ 空列表：前者是「还没观测到任何东西」）。
	ObservedSources(tunnelID string) (LearnedSources, bool)

	// DeclineLearnedSources 记下运维明确拒绝过这条隧道的推荐。
	DeclineLearnedSources(tunnelID string)
}

// LearnedSource 是一条被观测到的来源前缀。
type LearnedSource struct {
	CIDR string `json:"cidr"`
	// Hits 是这个前缀被观测到的次数。它是运维判断「这是真客户端还是扫描器」
	// 的主要依据 —— 一次性的单次命中与每天几百次命中，含义完全不同。
	Hits      uint64    `json:"hits"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// LearnedSources 是一条隧道的学习模式观测结果。
type LearnedSources struct {
	TunnelID string          `json:"tunnel_id"`
	Sources  []LearnedSource `json:"sources"`

	// ObservedFrom 是学习窗口的起点。**它是进程启动之后的某一刻** ——
	// 观测只在内存里，重启即清空（地址是第三方信息，绝不落库）。
	// 界面必须显示它，否则一份只攒了五分钟的列表会被当成完整的。
	ObservedFrom time.Time `json:"observed_from"`

	// Truncated 报告这份列表**曾经被上限截断**。
	//
	// 截断过的列表拿去一键收窄会写出一个不完整的白名单，把没上榜的真实
	// 客户端全部锁死，而现象是「我点了推荐按钮，然后一半客户端连不上了」。
	// 所以界面在这一位为真时换成警告，而不是推荐。
	Truncated bool `json:"truncated"`

	// Declined 表示运维已经明确拒绝过一次，界面不再主动提示。
	Declined bool `json:"declined"`
}

// Provenance 是一个配置项的来源。
//
// 「显示生效值」只有一半用处 —— 用户真正要问的是「为什么是这个值」。
type Provenance string

const (
	// ProvenanceFile 来自配置文件（source_ref 给出文件:行）。
	ProvenanceFile Provenance = "file"
	// ProvenanceConsole 由控制台写入（存库）。
	ProvenanceConsole Provenance = "console"
	// ProvenanceDefault 是代码里的默认值。
	ProvenanceDefault Provenance = "default"
	// ProvenanceEnv 来自环境变量或命令行参数。
	ProvenanceEnv Provenance = "env"
)

// SettingItem 是一个配置项的生效值与来源。
type SettingItem struct {
	Key        string     `json:"key"`
	Value      string     `json:"value"`
	Provenance Provenance `json:"provenance"`
	SourceRef  string     `json:"source_ref,omitempty"`
	// Editable 为 false 时界面禁止编辑，并把原因放进 tooltip（不是隐藏）——
	// 隐藏会让用户以为这一项不存在，然后去别处找。
	Editable bool `json:"editable"`
}

// SettingsGroup 是一组配置项。
//
// group 的取值是**规范性**的（规格 §8.1）：listeners / tls / auth /
// retention / backup / other。前端 locale 只翻了这几个，其他值会原样显示。
type SettingsGroup struct {
	Group string        `json:"group"`
	Items []SettingItem `json:"items"`
}

// TurnSource 让控制台读取 TURN 状态并签发凭据。
//
// 单独一个接口而不是塞进 SnapshotSource：TURN 是可选组件（没配公网地址
// 就不起），把它并进必需接口会逼出一堆空实现。为 nil 时相关端点如实回
// 「未启用」而不是假装成功 —— 静默省略比一个明确的错误更难排查。
type TurnSource interface {
	// Allocations 返回当前 TURN 分配明细。
	Allocations() []TurnAllocation
	// MintCredential 签发一对临时 TURN 凭据并拼出 iceServers。
	MintCredential(userID string, ttl time.Duration) (any, error)
}

// TurnAllocation 是「媒体中继」一屏里的一行。
//
// 在这里重新声明而不是 import internal/turnsrv：控制台不该依赖一个
// 可选组件的具体实现 —— 那会让 nfagent 之类不需要 TURN 的构建也拖上
// pion 的依赖树。字段与 web/src/api/types.ts 的 TurnAllocation 对应。
type TurnAllocation struct {
	ID                   string    `json:"id"`
	Username             string    `json:"username"`
	RelayedAddr          string    `json:"relayed_addr"`
	PeerCount            int       `json:"peer_count"`
	BytesRelayed         int64     `json:"bytes_relayed"`
	CredentialTTLSeconds int       `json:"credential_ttl_s"`
	CreatedAt            time.Time `json:"created_at"`
}

// Snapshot 是一次运行时状态快照。
type Snapshot struct {
	RelayVersion string         `json:"relay_version"`
	StartedAt    time.Time      `json:"started_at"`
	Agents       []AgentStatus  `json:"agents"`
	Tunnels      []TunnelStatus `json:"tunnels"`
	Totals       SnapshotTotals `json:"totals"`
	// Shared 是共享入口的计量，未启用 -shared 时缺席。
	//
	// **缺席而不是一堆 0**：0 会被读成「测过，是零」，
	// 而这里要表达的是「这个功能没开」。
	Shared *SharedEntryStatus `json:"shared,omitempty"`
}

// SnapshotTotals 是概览页的磁贴数据。
type SnapshotTotals struct {
	TunnelsUp    int   `json:"tunnels_up"`
	TunnelsDown  int   `json:"tunnels_down"`
	AgentsOnline int   `json:"agents_online"`
	Sessions     int   `json:"sessions"`
	BytesIn      int64 `json:"bytes_in"`
	BytesOut     int64 `json:"bytes_out"`
}

// AgentStatus 是一个 agent 的运行时状态。
type AgentStatus struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Online   bool   `json:"online"`
	Revoked  bool   `json:"revoked"`
	// Rung 是当前承载梯级（L0/QUIC 等），控制台要显示它 —— frp 无法回答
	// 「我现在走的是哪条通道」。
	Rung          string `json:"rung,omitempty"`
	SupportsDgram bool   `json:"supports_datagram"`
	// 数据报发送队列的计量。**只在支持数据报的会话上有意义**，
	// 其余情况为 nil（不是 0 —— 0 会被读成「测过，是零」）。
	//
	// 分原因是必需的：队列满意味着承载带宽不够（加带宽 / 降码率），
	// 超限意味着路径 MTU 比我们以为的小（等 PMTUD 学到新值）。
	// 两者的运维动作完全相反，合成一个「丢包数」等于不给信息。
	Datagram *DatagramCarrierStats `json:"datagram,omitempty"`

	// Reported 是这个 agent **自己上报**的计数器，没收到过则缺席。
	//
	// # 为什么必须与中继侧的数字分开
	//
	// 中继只看得见自己那一侧。agent 侧有一整类丢弃它完全不知道：
	// 拨本地目标失败、被本地策略否决、回向发送队列满、回向超限、回向重组失败。
	// 症状是「下行统计都对，就是收不到回包」——两侧数字放在同一栏里会让人
	// 以为它们是同一次测量的两个视角，而实际上一边是中继观测的、一边是
	// agent 自报的，可信度与新鲜度都不同。
	Reported    *AgentReportedMetrics `json:"reported,omitempty"`
	ConnectedAt time.Time             `json:"connected_at,omitzero"`
	LastSeenAt  time.Time             `json:"last_seen_at,omitzero"`
}

// SharedEntryStatus 是共享入口（-shared）的运行时计量。
//
// # 为什么这一屏必须存在
//
// 共享入口是**一个**监听器服务任意多条隧道，所以「这条隧道有多少流量」
// 回答不了「443 上到底发生了什么」。判别是分级 peek 的：专用端口 → PROXY
// → 首字节 → ALPN → SNI → 明文 Host。一次「域名打不开」可能停在其中任何
// 一级，而每一级对应完全不同的动作：
//   - SNI 未注册 → 域名没配上
//   - 明文命中但 502 → agent 那头不通
//   - AtCapacity → 并发上限太小
//   - DeniedCIDR → 自己的白名单挡住了自己
//
// 不报这份分布的话，用户只能看到「不通」，而这正是本产品声称要解决的问题。
type SharedEntryStatus struct {
	Addr string `json:"addr"`
	// TLSTermination 为 false 时只能做 SNI 透传路由（没有可信证书）。
	TLSTermination bool `json:"tls_termination"`
	// Routes 是当前注册的域名数。
	Routes int `json:"routes"`

	// 判别步骤分布。
	Dedicated     int64 `json:"dedicated"`
	ProxyProtocol int64 `json:"proxy_protocol"`
	SNIPassthru   int64 `json:"sni_passthru"`
	SNIGateway    int64 `json:"sni_gateway"`
	Cleartext     int64 `json:"cleartext"`
	ACME          int64 `json:"acme"`
	PortDefault   int64 `json:"port_default"`
	Rejected      int64 `json:"rejected"`
	DeniedCIDR    int64 `json:"denied_cidr"`
	AtCapacity    int64 `json:"at_capacity"`

	// CarrierALPN 是被认成 agent 承载（L2 梯级）的连接数。
	//
	// 它涨起来意味着有 agent 走在降级路径上（它的网络封了 UDP）。
	// 那条路上 UDP 隧道不可用，所以这个数字是解释「为什么某条 UDP 隧道
	// 一直 degraded」的第一现场 —— 少了它，运维只能去翻 agent 那台机器的日志。
	CarrierALPN int64 `json:"carrier_alpn"`

	// 网关（L7）计量。
	Requests   int64 `json:"requests"`
	NoRoute    int64 `json:"no_route"`
	BadGateway int64 `json:"bad_gateway"`
	Upgrades   int64 `json:"upgrades"`

	// 网关的两道**请求级**闸门，与上面那个连接级的 DeniedCIDR 是两回事。
	//
	// 判别器每**连接**判一次（按首个请求的 Host 或 TLS 的 SNI），而网关每
	// **请求**重查路由 —— 一条 keep-alive 连接上的第二个请求换一个 Host
	// 就会落到另一条隧道，而那条隧道的闸门在连接级从没被查过。
	// 两个数字必须分开报：连接级的涨说明「有人连上来就被挡了」，
	// 请求级的涨说明「有人在同一条连接上换 Host 试别的隧道」。
	//
	// 这两个计数器此前**没有任何读取点**：它们在网关里递增，而快照读的是
	// 判别器那份同名计数。于是这两道闸拦下的事情在计量上完全不可见。
	GatewayDeniedCIDR int64 `json:"gateway_denied_cidr"`

	// 每隧道限额（policy.max_conns / max_conns_per_ip）在共享入口上拒掉的次数。
	//
	// 与判别器那个 at_capacity 是两回事：那个是**整个共享端口**的并发上限
	//（保护中继不被压垮），这两个是**单条隧道**的配额（保护其他隧道与其他来源
	// 不被一条隧道挤掉）。混在一起的话，「加中继容量」与「提这条隧道的上限」
	// 这两个完全不同的动作就分不出来了。
	//
	// gateway_* 是网关（HTTP）路径上按**请求**算的；splice_* 是直通路径上按
	// **连接**算的。两条路径的语义不同（见 gateway.ServeHTTP 的注释），
	// 所以数字也分开报 —— 合成一个的话运维无法判断该看哪条路。
	GatewayDeniedMaxConns int64 `json:"gateway_denied_max_conns"`
	GatewayDeniedPerIP    int64 `json:"gateway_denied_per_ip"`
	SpliceDeniedMaxConns  int64 `json:"splice_denied_max_conns"`
	SpliceDeniedPerIP     int64 `json:"splice_denied_per_ip"`
	// DeniedPassthrough 是「明文降级绕过」被拦下的次数。它此前混进
	// NoRoute，与「域名没配上」这种日常噪声共用一个数字。
	DeniedPassthrough int64 `json:"denied_passthrough"`
}

// AgentReportedMetrics 是 agent 自报的计数器。
type AgentReportedMetrics struct {
	// AtUnix 是这份数据到达中继的时刻。
	//
	// **必须有**：控制台要能区分「刚报过」与「上报卡住了，你看到的是
	// 十分钟前的数」。没有它，第二种情况会被读成「一切正常」，
	// 而那正是最需要被看见的状态。
	AtUnix        int64 `json:"at_unix"`
	UptimeSeconds int64 `json:"uptime_seconds"`

	// UDP 是数据报路径的计数器，字段与 proto.AgentUDPMetrics 一一对应。
	UDP any `json:"udp"`
}

// SessionFrame 是一次会话开/关的推送帧（SSE 事件类型 `session`，规格 §406）。
//
// 与 web/src/api/types.ts 的 SessionFrame 逐字段对应。
//
// # 为什么带上活跃数与累计数，而不让前端自己累加
//
// 这些帧是**可牺牲的**（速率由外部输入决定，队列满了就丢），
// 而前端自己累加会在丢帧之后**永久偏移** —— 那种偏移不会自愈，
// 用户会一直看到一个错的数字，而没有任何迹象说明它错了。
// 每帧带上权威值，丢帧只影响曲线的分辨率。
type SessionFrame struct {
	TunnelID string `json:"tunnel_id"`
	// Delta 是 +1（开）或 -1（关）。
	Delta int `json:"delta"`
	// Sessions 是**当前活跃**数，SessionsTotal 是累计数。
	Sessions      int64 `json:"sessions"`
	SessionsTotal int64 `json:"sessions_total"`
	// Peer 是真实客户端地址。**只推送、绝不落库** ——
	// 事件表会被支持包外发，而这是运行时观测到的第三方信息。
	Peer string `json:"peer,omitempty"`
	// Path 在 v1 恒为 "relayed"：P2P 打洞是明确的非目标。
	Path string `json:"path,omitempty"`
}

// DatagramCarrierStats 是一个 agent 承载上数据报发送队列的计量。
type DatagramCarrierStats struct {
	Sent       int64 `json:"sent"`
	Bytes      int64 `json:"bytes"`
	QueueFull  int64 `json:"queue_full"`
	TooLarge   int64 `json:"too_large"`
	Failed     int64 `json:"failed"`
	Fragmented int64 `json:"fragmented"`
}

// TunnelStatus 是一条隧道的运行时统计。
type TunnelStatus struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Sessions 是**当前活跃**的会话数。
	//
	// 曾经这里填的是累计接受数（只增不减），于是一条早就没人用的隧道
	// 会显示「活跃会话 1523」。规格 §8.4 要的是两项，见下面 SessionsTotal。
	Sessions int64 `json:"sessions"`
	// SessionsTotal 是累计会话数，控制台对它差分得出「新会话/秒」。
	//
	// 两个数字都要：活跃数回答「现在有多少人在用」，
	// 累计数回答「流量在增长吗」——一条活跃数恒为 2 的隧道，
	// 累计数是 2 还是 20000 是完全不同的两种情况。
	SessionsTotal int64 `json:"sessions_total"`
	BytesIn       int64 `json:"bytes_in"`
	BytesOut      int64 `json:"bytes_out"`
	// 承载 RTT 分位数（微秒）。**0 或缺席表示还没测到，不是 0 毫秒。**
	//
	// 测的是承载（每 agent 一条 QUIC 连接）的往返，所以同一个 agent 名下
	// 所有隧道是**同一条曲线** —— 规格 §8.4 的「每隧道 RTT」是展示粒度，
	// 不是测量粒度。界面上要说清这一点，否则用户会以为是两次独立测量。
	RTTP50US int64 `json:"rtt_p50_us,omitempty"`
	RTTP95US int64 `json:"rtt_p95_us,omitempty"`
	RTTP99US int64 `json:"rtt_p99_us,omitempty"`

	// 分阶段拒绝计数。「拒了多少」没用，「在哪一道闸拒的」才告诉你该调什么。
	DeniedCIDR  int64 `json:"denied_cidr"`
	NoSession   int64 `json:"no_session"`
	OpenFailed  int64 `json:"open_failed"`
	RateLimited int64 `json:"rate_limited"`

	// 以下四项只对 UDP 隧道有意义（TCP 隧道恒为 0）。
	//
	// 包数与字节数都要：UDP 的病态流量是「大量小包」，只看字节数看不出来
	// （10 万 pps 的 64 字节包在字节图上是一条平线，在包数图上是一根尖峰）。
	PacketsIn  int64 `json:"packets_in"`
	PacketsOut int64 `json:"packets_out"`

	// DgramMTU 是承载**反应式学到**的数据报载荷上限（字节），0 = 还没学到。
	//
	// 它不是猜的：quic-go 在一次 SendDatagram 超限时回
	// *quic.DatagramTooLargeError，里面带着真实上限，承载层把它存下来、
	// 分片器拿它决定分不分片。也就是说这个值**已经在影响转发行为**。
	//
	// 此前它没有任何出口：控制台的 metric 帧里有个 dgram_mtu 字段，
	// 而中继发的是快照、根本不发那种帧，于是界面上恒为「—」。
	// README 的诚实清单因此把它与「丢包率测不到」并列 —— 而它其实测到了，
	// 只是没接线。0 与「学到了但恰好是 0」不需要区分：载荷上限为 0 不存在。
	DgramMTU int `json:"dgram_mtu,omitempty"`
	// DroppedTableFull / DroppedPerIPQuota 分别对应「加容量」与「提每源上限」
	// 这两个完全不同的运维动作，所以不能合并成一个「丢包数」。
	DroppedTableFull  int64 `json:"dropped_table_full"`
	DroppedPerIPQuota int64 `json:"dropped_per_ip_quota"`
	// DroppedUnknownFlow 是回向路径上 FlowID 查不到的包（会话已过期）。
	DroppedUnknownFlow int64 `json:"dropped_unknown_flow"`
	// DroppedReassembly 是回向分片重组失败（超时 / 表满 / 分片重叠）。
	DroppedReassembly int64 `json:"dropped_reassembly"`
	// Fragments / Reassembled 是回向分片数与重组成功数。
	//
	// 规格 §遥测要求展示分片率。分片率高说明当前路径 MTU 偏小，
	// 而分片放大丢包影响 —— 一个该让用户看见的性能信号。
	Fragments   int64 `json:"fragments"`
	Reassembled int64 `json:"reassembled"`
	// ReasmOverlapping 是分片范围重叠而被拒的分片数。
	//
	// **非零就该看一眼**：正常发送方按固定步长切片，不会重叠。
	// 重叠分片是 teardrop / rose 那类「把内容藏过检查设备」的手法。
	ReasmOverlapping int64 `json:"reasm_overlapping"`
	// RateLimited 是被**限速**丢掉/延迟的量。
	//
	// UDP 上它是被丢掉的数据报数；TCP 上限速表现为**变慢**而不是丢弃
	//（字节流丢中间一段就是把连接搞坏），所以 TCP 隧道这一格恒为 0，
	// 而那是正确的 —— 界面上要写清楚，否则用户会以为限速没生效。
	RateLimitedBytes int64 `json:"rate_limited_bytes"`
	// FlowsEvicted 是因会话表**超出容量**而被挤掉的流数。
	//
	// 与 DroppedTableFull 不是一回事：那一格是「这个包被拒了」，
	// 这一格是「别人的流被挤掉了」。流表刻意选择淘汰最旧而不是拒绝新流
	//（对实时流量是正确取舍），所以「表满」这件事**一个拒绝都不产生** ——
	// 没有这个数字，界面上那一格恒为 0，而真实情况是有人的流正在被静默挤掉。
	FlowsEvicted int64 `json:"flows_evicted"`
	// DroppedCarrier 是承载发送侧丢的包（队列满 / 超限 / 承载错误）。
	//
	// 细分原因在 agent 那一行（队列满要加带宽、超限要等 PMTUD 或降包长），
	// 这一格只回答「这条隧道丢了多少」—— 两个问题，两个层级。
	DroppedCarrier int64 `json:"dropped_carrier"`
	// DroppedWrongAgent 是「发这个包的 agent 不是这条隧道的 agent」。
	//
	// **非零就是安全事件**，与其他丢弃分项不是一类：其他项调参数，
	// 这一项吊销凭据。所以界面上必须单独一格并且标红 ——
	// 混进容量指标里等于把它藏起来。
	DroppedWrongAgent int64 `json:"dropped_wrong_agent"`

	// BareExposure 为 true 时控制台显示暴露风险标记。
	BareExposure bool `json:"bare_exposure"`
}

// Options 是构造控制台的参数。
type Options struct {
	DB       *store.DB
	Snapshot SnapshotSource
	Log      *slog.Logger

	// Turn 是可选的：没配 TURN 公网地址时为 nil，
	// 相关端点会如实回「未启用」。
	Turn TurnSource

	// Settings 是可选的配置视图来源。
	Settings SettingsSource

	// Secure 表示控制台经 HTTPS 提供。
	Secure bool

	// AllowedHosts 是允许的 Host 头。为空时只放行 loopback 与配置的绑定地址。
	AllowedHosts []string

	// BindAddr 是控制台监听地址，用于推导默认允许的 Host。
	BindAddr string
}

// New 构造控制台服务。
func New(opts Options) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("console: 缺少 DB")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	// allowedHosts 有**两个**消费者，改动它的构造要同时想到两处：
	//   1. withHostCheck —— 比对请求的 Host 头（DNS 重绑定防护）；
	//   2. originAllowed —— 比对 Origin 头（CSRF 防护）。
	// 两处都在查表**之前**剥掉端口，所以入表的键也必须是剥过端口的，
	// 否则 `-console-hosts relay.example.com:9443` 这种完全自然的写法会
	// 静默失效：键是带端口的、查的是不带端口的，永远匹配不上 ——
	// 运维以为自己配好了防护，实际上是把自己关在门外（实测两种 Host 写法都 421）。
	allowed := make(map[string]bool)
	for _, h := range opts.AllowedHosts {
		if k := normalizeHostKey(h); k != "" {
			allowed[k] = true
		}
	}
	// 总是放行 loopback 与实际绑定地址，否则本机运维直接被自己的防护挡在门外。
	allowed["localhost"] = true
	allowed["127.0.0.1"] = true
	allowed["[::1]"] = true
	allowed["::1"] = true
	if opts.BindAddr != "" {
		if host, _, err := net.SplitHostPort(opts.BindAddr); err == nil {
			if k := normalizeHostKey(host); k != "" {
				allowed[k] = true
			}
		}
	}

	s := &Server{
		db:           opts.DB,
		log:          log,
		secure:       opts.Secure,
		guard:        newLoginGuard(),
		allowedHosts: allowed,
		hub:          newEventHub(log),
		snapshot:     opts.Snapshot,
		mux:          http.NewServeMux(),

		turn:     opts.Turn,
		settings: opts.Settings,
	}
	s.routes()
	return s, nil
}

// Handler 返回带全局中间件的处理器。
//
// **注意它只覆盖控制台自己的路由。** 中继把 SPA 资源挂在同一个监听器的
// `/` 上（cmd/nfrelay/main.go 的 consoleHandler），那一层在这个返回值
// **外面** —— 所以安全头必须由最外层的 SecurityHeaders 再包一次，
// 不能只靠这里。历史上就是这么漏的：CSP 只装饰了 JSON，
// 而真正加载脚本、真正能被 iframe 套的 index.html 一个头都没有。
func (s *Server) Handler() http.Handler {
	// 顺序有意义：Host 校验最外层（在做任何事之前先确认请求是给我们的），
	// 然后是安全头，最后才是路由。
	//
	// 这里保留一次 SecurityHeaders 而不是「反正外层包了就删掉」：
	// Handler() 是本包的公开入口，console 自己的测试与任何只用 API 的
	// 嵌入方都直接拿它，删掉那些用法就裸奔了。
	// 重复设置是无害的 —— Header.Set 是覆盖写，两层写的是同一个值。
	//
	// 删掉它 TestSecurityHeadersArePresent 会红（实测过）。写下这句是因为
	// 初版注释在这里写的是「没有任何测试会红」—— 那是假的，
	// 而一条假的「这里没有护栏」注释会让下一个人放心地把护栏拆掉。
	return s.HostCheck(s.SecurityHeaders(s.mux))
}

// Hub 返回事件中心，供中继推送事件。
func (s *Server) Hub() *eventHub { return s.hub }

func (s *Server) sessionCookieName() string {
	if s.secure {
		return SessionCookieName
	}
	return SessionCookieNameInsecure
}

// normalizeHostKey 把一个配置项或绑定地址归一化成 allowedHosts 的键。
//
// 剥端口、去空白、小写，并**丢掉通配与未指定地址**。
//
// 丢掉 0.0.0.0 / :: / * 不是洁癖：`-console 0.0.0.0:9443` 会把 0.0.0.0 送进来，
// 而那不是任何客户端会发出的 Host。更糟的是 `-console-hosts=":9443"` 这种笔误
// 剥完端口是**空串** —— 一个空键会放行所有不带 Host 头的请求（HTTP/1.0 客户端、
// 手写的 socket），也就是在 DNS 重绑定防护上开一个不可见的洞。
func normalizeHostKey(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	// SplitHostPort 只在真的有端口时成功；没有端口时保持原样。
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else {
		// 没有端口的 IPv6 字面量常被写成带方括号的形式（`[2001:db8::1]`）——
		// 那是 URL 里的写法，而 Host 头里不带端口时**不带**方括号。
		// 不剥掉的话这条白名单条目永远匹配不上：入表的键是 `[2001:db8::1]`，
		// 而 HostCheck 剥完端口拿到的是 `2001:db8::1`。
		//
		// 症状具有误导性：同一份配置里的域名条目工作正常，
		// 看起来像「只有 IPv6 被歧视」。
		//
		// 默认白名单里同时放了 `[::1]` 与 `::1` 两种写法 —— 那是这个歧义
		// 早就存在的痕迹，只是当时用「两个都加」绕过去了，
		// 而用户给的条目没人替他绕。
		h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(h), "["), "]")
	}
	h = strings.ToLower(strings.TrimSpace(h))
	switch h {
	case "", "0.0.0.0", "::", "[::]", "*":
		return ""
	}
	return h
}

// ── 中间件 ──────────────────────────────────────────────────────────────────

// HostCheck 校验 Host 头，防 DNS 重绑定。
//
// 返回 421 Misdirected Request 而不是 400：语义上「这个请求发错了服务器」
// 正是 421 的含义，而且它不会被浏览器当作可重试的客户端错误。
//
// # 为什么它是导出的，以及为什么 SPA 也要过这道闸
//
// 控制台监听器上不只有本包的路由：`/` 是内嵌 SPA（cmd/nfrelay 的
// consoleHandler）。这道闸必须包在**整个** mux 外面，理由有两条：
//
//  1. 不包的话失败形态是「半开」——页面 200 载入正常，而所有 /api/* 421。
//     运维看到一个渲染完整却什么都点不动的控制台，界面上没有任何解释，
//     而真正的原因（Host 不在白名单里）只在中继日志里。要把这件事讲清楚
//     就得写一整套前端代码（错误类型 + 全局分支 + 双语文案）；而闸门包住
//     整个 mux 之后，这条解释由服务端直接渲染出来，前端零改动。
//  2. 给别名 Host 返回完整的 index.html 会泄露指纹：那份 HTML 里有
//     产品名与带哈希的资源名，足够确认「这是一台 NomiRelay」并推断版本。
//     没有任何理由把它交给一个我们判定为「发错了」的请求。
//
// # /healthz 刻意在闸外
//
// 编排系统的探针（k8s httpGet 默认拿 Pod IP 当 Host、Docker healthcheck 同理）
// 不可能知道运维配了什么 -console-hosts，而 421 会让它把一个健康的中继标成
// 不健康并反复重启。这**不削弱** DNS 重绑定防护：那类攻击的目的是借浏览器的
// Cookie 去调有副作用的接口，而 /healthz 不鉴权、无副作用、只回 {"ok":true}，
// 攻击者直连就能拿到同样的字节，绕过它拿不到任何新东西。
//
// 但只放行 GET/HEAD：写方法即使在一个「无副作用」的路径上也没有理由被放过，
// 而 ServeMux 的模式匹配不区分方法。
func (s *Server) HostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !s.allowedHosts[strings.ToLower(host)] {
			s.log.Warn("拒绝可疑 Host（DNS 重绑定防护）", "host", r.Host, "path", r.URL.Path)
			s.writeMisdirected(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeMisdirected 回一个**能自己解释怎么修**的 421。
//
// 分两种受众：浏览器导航要看得懂的文字，程序化调用要结构化的 JSON。
// 不这样分的话，二者必有一方拿到对它无用的东西 —— 而这条响应存在的全部意义
// 就是让人知道下一步该做什么（此前它只有一句「Host 不被允许」，
// 既没说哪个 Host、也没说去配什么）。
func (s *Server) writeMisdirected(w http.ResponseWriter, r *http.Request) {
	const hint = "请用 -console-hosts 把这个主机名加进白名单（逗号分隔可给多个），" +
		"或改用中继实际绑定的地址访问。这是 DNS 重绑定防护，不是鉴权失败。"
	msg := fmt.Sprintf("Host %q 不在控制台的白名单里。%s", r.Host, hint)

	// 浏览器导航（Accept 里要 HTML）给纯文本：它会直接显示在页面上，
	// 而一坨 JSON 对着一个正在排障的人是噪音。
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, msg+"\n")
		return
	}
	writeError(w, http.StatusMisdirectedRequest, "misdirected_host", msg)
}

// SecurityHeaders 给 next 的所有响应加上安全头。
//
// # 为什么它是导出的
//
// 控制台监听器上不只有本包的路由：`/` 是内嵌 SPA（cmd/nfrelay/main.go 的
// consoleHandler）。安全头必须包在**那个 mux 的外面**，否则 index.html ——
// 唯一一个真的加载脚本、也是唯一一个能被 iframe 套进去的响应 —— 拿不到
// CSP 与 frame-ancestors，而 JSON 响应上那套头是纯装饰。
//
// 另一条路是让 web.AssetHandler 自己设。不走那条：CSP 字符串会有第二份
// 拷贝，改一处忘一处的后果不是编译错误而是「某些路径没防护」；而且
// web 包不知道 s.secure，HSTS 无从判断。
//
// # 为什么 CSP 是这几条
//
// 前端构建产物里**没有内联 script**（web/index.html 的 theme-boot 刻意抽成
// 了外部 /theme-boot.js），也没有任何跨源资源（dist 的 CSS 里 url() 数为 0）。
// 所以 script 侧可以严格到只有 'self'：既不给 'unsafe-inline' 也不给
// 'unsafe-eval'。这是这条 CSP 真正值钱的部分。
//
// style 侧必须留 'unsafe-inline'，因为 index.html 里有一个 5 行的内联
// <style>（把 html/body/#root 撑满高度并铺上底色，删掉它首屏会先闪一屏白），
// 而 React 19 的资源提升路径也会 createElement("style")。
// 替代方案都更贵：写死 sha256 哈希会在**每次改那段 CSS 时静默白屏**
// —— 那是本仓最不愿意有的失败形态；per-request nonce 要求模板化 index.html，
// 与预压缩 .br/.gz 的静态发送路径直接冲突（没法往已 brotli 的字节里插 nonce）。
// 留 'unsafe-inline' 丢掉的是「CSS 注入/改版面」这一类，
// 换不到代码执行 —— 这个取舍是清楚的，写在这里免得被当成偷懒。
//
// base-uri / form-action / object-src 三条与 SPA 的运行毫无关系，
// 纯粹是白送的收窄：default-src 'self' 管不到 <base>，
// 一个注入的 <base href> 能把全部相对 URL 指到别处；
// form-action 不设时被注入的表单可以往外站 POST；
// object-src 若落回 'self' 仍然允许从本源加载插件内容。
func (s *Server) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// **每一个 Set 都必须在 next.ServeHTTP 之前。**
		//
		// net/http 在 WriteHeader 那一刻就把头发走了，之后往 Header() 里
		// 塞什么都被丢弃。把任何一行挪到 next 之后，线上就是一个安全头都
		// 没有 —— 而 httptest 的 ResponseRecorder.Header() 是那张**活的**
		// map，照样看得见，于是读 w.Header() 的测试会保持绿色。
		// 判据因此必须读 Result().Header（见 cmd/nfrelay/console_headers_test.go
		// 与 web/handler_test.go 里那条注释）。
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy 是控制台的 CSP。理由见 SecurityHeaders 的注释。
//
// 改动它之前先想清楚：这条头同时作用在 index.html 与 /assets/*.js 上，
// 而 CSP 出错的表现是**控制台白屏**，不是报错。
const contentSecurityPolicy = "default-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// session 是一次已认证的会话。
type session struct {
	Username  string
	CSRFToken string
}

// requireAuth 包装需要登录的处理器。
func (s *Server) requireAuth(fn func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "请先登录")
			return
		}
		// 状态变更动词必须过 CSRF 双提交 + Origin 校验。
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := s.checkCSRF(r, sess); err != nil {
				writeError(w, http.StatusForbidden, "csrf", err.Error())
				return
			}
		}
		fn(w, r, sess)
	}
}

func (s *Server) currentSession(r *http.Request) (*session, bool) {
	c, err := r.Cookie(s.sessionCookieName())
	if err != nil || c.Value == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(c.Value))
	username, csrf, ok := s.db.LookupSession(r.Context(), hex.EncodeToString(sum[:]))
	if !ok {
		return nil, false
	}
	return &session{Username: username, CSRFToken: csrf}, true
}

// checkCSRF 做双提交校验**加上** Origin/Referer 检查。
//
// 只做双提交是不够的：一个能写 Cookie 的子域攻击者可以同时设置两边。
// 加上 Origin 检查才形成有效防线。
func (s *Server) checkCSRF(r *http.Request, sess *session) error {
	got := r.Header.Get(CSRFHeaderName)
	if got == "" {
		return errors.New("缺少 CSRF 令牌")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
		return errors.New("CSRF 令牌不匹配")
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// 没有 Origin 时退化用 Referer。两者都没有则拒绝 ——
		// 现代浏览器对跨站写请求一定会带 Origin。
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return errors.New("缺少 Origin")
	}
	if !s.originAllowed(origin) {
		// 以中文开头：错误串不该以大写字母开头（staticcheck ST1005），
		// 而 "Origin" 是 HTTP 头名，改小写会让它变成另一个词。
		return fmt.Errorf("请求的 Origin %q 不被允许", origin)
	}
	return nil
}

func (s *Server) originAllowed(origin string) bool {
	// 手工取出 host 部分，避免为此引入 net/url 的完整解析开销与歧义。
	rest := origin
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		rest = h
	}
	return s.allowedHosts[strings.ToLower(rest)]
}

// ── 响应辅助 ────────────────────────────────────────────────────────────────

// APIError 是统一的错误响应体。
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Fields 用于表单校验：前端据此高亮每一个坏字段。
	Fields []FieldError `json:"fields,omitempty"`
}

// FieldError 是单个字段的校验错误。
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	// hash_busy 必须带 Retry-After，无论它从哪条路径写出来。
	//
	// 放在这里而不是各个处理器里：这个头是「可重试」的**唯一机器可读形式**，
	// 而它此前只在登录与改密两处手工设过 —— POST /api/setup 走 statusFor，
	// 于是首启脚本拿到一个没有 Retry-After 的 503，只能瞎猜等多久。
	// 一个「必须每处都记得设」的头迟早会在某一处被漏掉。
	if code == "hash_busy" && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, status, APIError{Code: code, Message: msg})
}

// statusFor 把存储层的哨兵错误映射到 HTTP 状态码。
//
// 集中在一处，处理器就不需要各自判断 —— frp 也是这么做的
// （client/http/controller.go:53-68），这是它少数值得直接抄的设计。
func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, ErrDesktopPrecondition):
		return http.StatusConflict, "precondition_failed"
	case errors.Is(err, store.ErrPairingInviteVersionMismatch):
		return http.StatusConflict, "pairing_version_mismatch"
	case errors.Is(err, store.ErrDesktopConnectionRevoked):
		return http.StatusGone, "connection_revoked"
	case errors.Is(err, store.ErrDesktopEnrolExpired):
		return http.StatusGone, "enrol_expired"
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, store.ErrTokenUsed):
		return http.StatusConflict, "token_used"
	case errors.Is(err, store.ErrTokenExpired):
		return http.StatusGone, "token_expired"
	case errors.Is(err, store.ErrPairingInviteUsed):
		return http.StatusConflict, "invite_used"
	case errors.Is(err, store.ErrPairingInviteExpired):
		return http.StatusGone, "invite_expired"
	case errors.Is(err, store.ErrPairingInviteScopeDenied),
		errors.Is(err, store.ErrPairingInviteBackendMismatch),
		errors.Is(err, store.ErrPairingInviteTenantMismatch):
		return http.StatusForbidden, "invite_denied"
	case errors.Is(err, store.ErrHashBusy):
		// 503 而不是 500：argon2 并发闸满是**暂时**做不了，重试就能成。
		//
		// 落在 500 "internal" 上的后果不是显示问题：首启脚本与自动化会把
		// internal 当成永久失败而放弃，于是一台正被并发探测的中继会在
		// 「本该重试就好」的时候把首启流程整个卡死。
		// 登录与改密两条路径早就单独处理了这个错误（503 + Retry-After），
		// 而 POST /api/setup 走的是这里 —— 三条路径必须给同一个答案。
		return http.StatusServiceUnavailable, "hash_busy"
	default:
		return http.StatusInternalServerError, "internal"
	}
}

// randomToken 生成一个 URL 安全的随机令牌。
func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
