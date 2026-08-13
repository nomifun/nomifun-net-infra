// Package tunnel 定义隧道的正交对象模型，两端共享。
//
// # 为什么是正交分解而不是 frp 的 8 种类型
//
// frp 的 8 种代理类型大部分是**假差异**（证据见 docs/research/05-frp-proxy-types-plugins.md）：
// 客户端侧 tcp/http/https/stcp/tcpmux 共用同一个实现
// （client/proxy/general_tcp.go:23-34），stcp 与 sudp 的服务端实现逐字节相同
// （server/proxy/{stcp,sudp}.go:43-46），8 个校验分支里 5 个是空的 return nil。
//
// 分解成正交维度之后，8 种类型收敛为 3 个枚举 + 1 个可选路由器，
// 并且**免费得到 frp 表达不出的组合** —— 例如 {exposure:port, l4:tcp, policy:{allowCIDRs}}
// 正是场景二要的「端口暴露 + 源 IP 白名单」，而 frp 的 tcp 类型压根没有 auth 字段
// （pkg/config/v1/proxy.go:264-268）。
package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Kind 是隧道的方向轴。
//
// 它与 TLSMode 是**两个正交的轴**，绝不共用 "mode" 这个标签 ——
// 一个词同时表示两件事，是配置演进时最容易出错的地方。
type Kind string

const (
	// KindService 对应场景一：外部客户端主动访问内网服务。
	KindService Kind = "service"

	// KindReverse 对应场景二：为一个只能填 IP+端口的设备提供固定入口。
	KindReverse Kind = "reverse"

	// KindPeer 为场景三预留：agent↔agent 的对等隧道。
	//
	// **v1 不实现**，但枚举位现在就必须占住：所有 v1 隧道都是
	// 「公网入口 → agent」，事后加一个方向就是一次 schema 迁移。
	KindPeer Kind = "peer"
)

// TLSMode 是「中继能否看见明文」这个轴。
type TLSMode string

const (
	// TLSPassthrough 表示中继只搬字节，不解密。
	//
	// 可以按 SNI 路由 —— SNI 是明文，读它不需要解密。
	// 但无法改写请求头、无法做路径路由、无法 ACME。
	TLSPassthrough TLSMode = "passthrough"

	// TLSGateway 表示中继终止 TLS，可做 Host/路径路由、ACME、注入鉴权。
	TLSGateway TLSMode = "gateway"
)

// Exposure 是「外部如何抵达」这个轴。
type Exposure string

const (
	// ExposurePort 独占一个入口端口。场景二的机器人走这条。
	ExposurePort Exposure = "port"

	// ExposureShared 共享端口，靠 SNI / Host / 路径分流。
	ExposureShared Exposure = "shared"

	// ExposurePrivate 不对公网开放，需要授权后才可达。
	ExposurePrivate Exposure = "private"

	// ExposureP2P 为 v2 的打洞预留，v1 不实现。
	ExposureP2P Exposure = "p2p"
)

// L4 是传输层协议。
type L4 string

const (
	L4TCP L4 = "tcp"
	L4UDP L4 = "udp"
)

// RouterKind 是共享端口的分流方式。
type RouterKind string

const (
	// RouterHTTP 按 Host + 路径前缀分流，需要 TLSGateway。
	RouterHTTP RouterKind = "http"

	// RouterTLSSNI 按 ClientHello 的 SNI 分流，**不解密**，配 TLSPassthrough。
	RouterTLSSNI RouterKind = "tls-sni"
)

// BackendKind 是目标的形态。
type BackendKind string

const (
	// BackendAddr 拨一个 host:port。
	BackendAddr BackendKind = "addr"

	// BackendUnix 拨一个 unix domain socket。
	BackendUnix BackendKind = "unix"

	// BackendHandler 为场景三预留：由 agent **自己终结**的能力型后端
	//（截图 / PTY / 键鼠注入），而不是拨号到一个 TCP 目标。
	//
	// **v1 不实现**，但枚举位现在占住 —— 事后加会破坏线协议。
	BackendHandler BackendKind = "handler"
)

// State 是隧道的观测状态。
type State string

const (
	StateDraft    State = "draft"
	StatePending  State = "pending"
	StateActive   State = "active"
	StateDegraded State = "degraded"
	StateStopped  State = "stopped"
	StateError    State = "error"

	// StateRejectedByAgent 表示 agent 的本地目标策略否决了这条隧道。
	//
	// 这个状态用于解决两种信任模型的冲突：中继拥有 Tunnel 记录，
	// 但目标地址的最终裁决权在 agent（否则被攻陷的控制台就是内网跳板）。
	// 拒绝原因必须上报并在控制台展示，否则用户只会看到一条「不通」的隧道
	// 而不知道是被自己的策略挡住的。
	StateRejectedByAgent State = "rejected_by_agent"
)

// Backend 描述隧道的目标。
type Backend struct {
	Kind BackendKind `json:"kind"`

	// Addr 在 Kind==BackendAddr 时有效，形如 "127.0.0.1:8080"。
	Addr string `json:"addr,omitempty"`

	// Path 在 Kind==BackendUnix 时有效。
	Path string `json:"path,omitempty"`
}

// Router 描述共享端口的分流规则。
type Router struct {
	Kind RouterKind `json:"kind"`

	// Domains 是自定义域名列表。
	Domains []string `json:"domains,omitempty"`

	// Locations 是路径前缀，仅 RouterHTTP 有效，按最长前缀匹配。
	Locations []string `json:"locations,omitempty"`

	// HostRewrite 是转发时要写入的 Host 头，仅 RouterHTTP 有效。
	//
	// 这个字段对接入 nomifun-tauri 是**必需**的：它的 host guard 挂在路由器之外，
	// 会 403 掉任何域名型 Host/Origin，只放行 IP 字面量与 localhost。
	HostRewrite string `json:"host_rewrite,omitempty"`

	// CatchAll 把这条隧道设为共享端口的**默认落点**：所有没有匹配到域名的
	// 请求都落到它。一个共享端口最多一条。
	//
	// # 为什么需要一个显式字段
	//
	// 场景二的设备只填「中继 IP + 端口」：它不发 SNI，Host 是一个 IP 字面量
	// 甚至缺失 —— 没有任何域名可匹配。网关早就为这种情况准备了 Fallback 分支，
	// 但没有任何配置能设置它。
	//
	// 用「域名列表为空」来暗示这个意图是**错的**：那让「忘了填域名」与
	// 「故意要接住全部」在配置里长得一模一样，而前者是配置错误、后者是
	// 一个把整个端口都暴露出去的决定。两者必须能被区分，
	// 所以校验仍然要求「要么有域名、要么显式声明 catch_all」。
	CatchAll bool `json:"catch_all,omitempty"`
}

// Policy 是隧道的访问控制与配额。
type Policy struct {
	// AllowCIDRs 为空表示不限来源 —— 即「裸端口开放」。
	//
	// 所有者已决定场景二接受裸端口，所以这里默认为空是合法的；
	// 但控制台必须对这种隧道打醒目风险标记，且**绝不**把
	// 「随机高位端口」当作安全措施展示（约 16 位熵，Shodan 级可枚举）。
	AllowCIDRs []netip.Prefix `json:"allow_cidrs,omitempty"`

	// MaxConns 是并发连接上限，0 表示用全局默认。
	MaxConns int `json:"max_conns,omitempty"`

	// MaxConnsPerIP 是**单个源 IP** 的并发上限，0 表示与 MaxConns 相同。
	//
	// # 为什么不能只有 MaxConns
	//
	// 只有全局上限时，一个源 IP 就能把它占满并把别人挤出去 ——
	// 而「最多 N 路」这个配置在用户看来是保护，实际上它保护的是**中继**
	// 不被压垮，不是保护其他用户不被挤掉。
	//
	// UDP 侧本来就有每源配额（udpflow 的 PerSourceIP），但它被收敛到会话表
	// 容量之内：用户一填 max_conns=32，容量变成 32、每源也变成 32，
	// 于是那道闸等于不存在。TCP 侧则压根没有每源限制，只有一个全局信号量。
	//
	// 这个字段让两侧都能表达「最多 N 路，且单个 IP 不超过其中 M 路」。
	//
	// 0 而不是「无限」作为默认：与 MaxConns 相同意味着「不额外限制」，
	// 与改动之前的行为一致 —— 一个新字段不该悄悄改变已有部署的行为。
	MaxConnsPerIP int `json:"max_conns_per_ip,omitempty"`

	// BytesPerSecond 是限速，0 表示不限。
	BytesPerSecond int64 `json:"bytes_per_second,omitempty"`

	// PacketsPerSecond 是数据报路径的包速率上限，0 表示不限。
	//
	// 必须与 BytesPerSecond **同时**存在：10 万 pps 的 64 字节小包是现实攻击，
	// 只看字节的限速器会放行它。
	PacketsPerSecond int64 `json:"packets_per_second,omitempty"`

	// RealtimeDatagram 表示这条 UDP 隧道是实时媒体，超限的数据报应当**丢弃**
	// 而不是分片。
	//
	// 分片放大丢包影响：任一片丢失整个数据报作废。而一帧迟到的音频等于
	// 丢了还白占带宽 —— 正确做法是让编码器降码率。
	//
	// 默认（false）是分片，因为默认要错向安全的一侧：一条本该丢弃的媒体流
	// 被分片只是多点延迟，而一条本该分片的批量流被丢弃是**静默数据丢失**。
	RealtimeDatagram bool `json:"realtime_datagram,omitempty"`
}

// Tunnel 是用户操作的核心对象，也是**期望状态**。
//
// 观测状态是 Session，两者是不同对象。frp 把配置与运行时混在一张表，
// 这才是它需要「清理离线」按钮的原因；Session 的消失绝不意味 Tunnel 被删除。
type Tunnel struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	TenantID string `json:"tenant_id"`

	Kind     Kind     `json:"kind"`
	TLS      TLSMode  `json:"tls"`
	Exposure Exposure `json:"exposure"`
	L4       L4       `json:"l4"`

	// AgentID 指明由哪个 agent 承载。
	//
	// **v1 里所有 kind 都必须有 agent。** 为空只表示「还没绑定」——
	// 中继会在恰好一个 agent 在线时自动绑上（cmd/nfrelay 的 bindUnassigned）。
	//
	// 这里原本写着「KindReverse 且中继自己拨号时为空」，那是假的：
	// 中继直拨在数据面不存在（三个入口都调 SessionFor，返回 false 即放弃）。
	// 真要做那条路径的话，中继侧必须自己实现与 agent 同一套目标策略，
	// 否则 SSRF 防线在那里是缺失的 —— 那是它没被实现的主要原因，
	// 也是 README 诚实清单里记着的一条。
	AgentID string `json:"agent_id,omitempty"`

	// ListenPort 在 Exposure==ExposurePort 时有效。
	//
	// 0 表示**由中继分配一个**，并把结果回写进这条记录 ——
	// 回写是必需的：不回写的话重启后会换一个端口，
	// 而 exposure=port 的客户端是拿端口号硬配的（场景二的设备写在固件里），
	// 换端口等于让所有客户端同时失联。
	ListenPort uint16 `json:"listen_port,omitempty"`

	// ShortID 是隧道的短标识，供 UDP 数据报帧头使用（0 表示未分配）。
	//
	// 数据报帧头只有 16 字节，装不下字符串 ID，而帧必须自己说明属于哪条隧道 ——
	// 否则一条承载上多个 UDP 隧道的流量就分不开。frp 正是把原始目的地址整个
	// 丢掉了（pkg/proto/udp/udp.go:64 传 nil），一条隧道因此只能承载一个
	// UDP 服务。
	//
	// 由中继在落库时分配，agent 通过隧道集合下发原样收到 —— 两侧必须用同一个值。
	ShortID uint16 `json:"short_id,omitempty"`

	Router  *Router `json:"router,omitempty"`
	Policy  *Policy `json:"policy,omitempty"`
	Backend Backend `json:"backend"`

	State State `json:"state"`

	// StateReason 在 State 为 error / rejected_by_agent 时说明原因，
	// 直接展示给用户。
	StateReason string `json:"state_reason,omitempty"`

	// Enabled 用 *bool 表达三态：nil（未设置，视为启用）/ true / false。
	//
	// 这是从 frp 的 Complete() 模式里抄来的好东西
	//（pkg/config/v1/proxy.go:124）—— 用 *bool 才能区分「没设置」与「设成 false」。
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled 报告隧道是否启用（nil 视为启用）。
func (t *Tunnel) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

// IsRealtimeDatagram 报告这条隧道的超限数据报应当丢弃而不是分片。
func (t *Tunnel) IsRealtimeDatagram() bool {
	return t.Policy != nil && t.Policy.RealtimeDatagram
}

// slugPattern 限制 slug 为小写字母、数字与连字符，且首尾必须是字母数字。
//
// slug 会出现在 URL 与日志里，所以必须限制字符集；不允许下划线与点，
// 避免与域名标签、文件名产生歧义。
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// 校验错误。
var (
	ErrInvalidSlug     = errors.New("tunnel: slug 非法")
	ErrUnsupportedKind = errors.New("tunnel: 该 kind 在 v1 未实现")
	ErrModeConflict    = errors.New("tunnel: 模式组合冲突")
	ErrMissingField    = errors.New("tunnel: 缺少必填字段")
)

// Complete 填充零值与派生字段。
//
// 三段式（Complete / Validate / Clone）严格分离：Complete 可变、幂等、无 I/O、不返错。
func (t *Tunnel) Complete() {
	if t.TenantID == "" {
		// v1 单租户；schema 保留该列，将来做多租户时不需要迁移。
		t.TenantID = DefaultTenantID
	}
	if t.Kind == "" {
		t.Kind = KindService
	}
	if t.L4 == "" {
		t.L4 = L4TCP
	}
	if t.Exposure == "" {
		t.Exposure = ExposurePort
	}
	if t.TLS == "" {
		// 默认透传：它是最少假设、最少信任的那个选项。
		// 用户要七层能力时再显式选 gateway，并在控制台看到「中继可见明文」的代价。
		t.TLS = TLSPassthrough
	}
	if t.Backend.Kind == "" {
		t.Backend.Kind = BackendAddr
	}
	if t.State == "" {
		t.State = StateDraft
	}
}

// DefaultTenantID 是 v1 单租户模式下的唯一租户标识。
const DefaultTenantID = "default"

// Validate 校验隧道定义，用 errors.Join 返回**所有**问题。
//
// 一次返回全部错误，控制台才能一次高亮所有坏字段；逐个返回会让用户
// 改一个、提交、再发现下一个，来回好几轮。
func (t *Tunnel) Validate() error {
	var errs []error

	if !slugPattern.MatchString(t.Slug) {
		errs = append(errs, fmt.Errorf("%w: %q 必须是小写字母数字与连字符、首尾为字母数字、不超过 63 字符",
			ErrInvalidSlug, t.Slug))
	}

	switch t.Kind {
	case KindService, KindReverse:
	case KindPeer:
		errs = append(errs, fmt.Errorf("%w: kind=peer 是为场景三预留的枚举位", ErrUnsupportedKind))
	default:
		errs = append(errs, fmt.Errorf("tunnel: 未知 kind %q", t.Kind))
	}

	switch t.Exposure {
	case ExposurePort, ExposureShared, ExposurePrivate:
	case ExposureP2P:
		errs = append(errs, fmt.Errorf("%w: exposure=p2p 是为 v2 打洞预留的枚举位", ErrUnsupportedKind))
	default:
		errs = append(errs, fmt.Errorf("tunnel: 未知 exposure %q", t.Exposure))
	}

	if t.L4 != L4TCP && t.L4 != L4UDP {
		errs = append(errs, fmt.Errorf("tunnel: 未知 l4 %q", t.L4))
	}
	if t.TLS != TLSPassthrough && t.TLS != TLSGateway {
		errs = append(errs, fmt.Errorf("tunnel: 未知 tls %q", t.TLS))
	}

	errs = append(errs, t.validateRouter()...)
	errs = append(errs, t.validateBackend()...)

	return errors.Join(errs...)
}

func (t *Tunnel) validateRouter() []error {
	var errs []error

	if t.Exposure == ExposureShared {
		if t.Router == nil {
			errs = append(errs, fmt.Errorf("%w: exposure=shared 必须配 router", ErrMissingField))
			return errs
		}
		if t.L4 != L4TCP {
			errs = append(errs, fmt.Errorf("%w: 共享端口分流只对 TCP 有意义，UDP 没有 SNI 或 Host 可读",
				ErrModeConflict))
		}
	} else if t.Router != nil {
		errs = append(errs, fmt.Errorf("%w: 只有 exposure=shared 才能配 router", ErrModeConflict))
		return errs
	}

	if t.Router == nil {
		return errs
	}

	switch t.Router.Kind {
	case RouterHTTP:
		// 七层路由必须能读明文。这不是可以放宽的限制，是物理事实。
		if t.TLS != TLSGateway {
			errs = append(errs, fmt.Errorf("%w: router=http 需要 tls=gateway —— "+
				"按 Host 与路径路由必须能读明文，透传模式读不到", ErrModeConflict))
		}
		if len(t.Router.Domains) == 0 && !t.Router.CatchAll {
			errs = append(errs, fmt.Errorf("%w: router=http 必须至少配一个域名，"+
				"或显式设 catch_all 把它作为端口默认落点", ErrMissingField))
		}
		if len(t.Router.Domains) > 0 && t.Router.CatchAll {
			// 两者同时给出是自相矛盾的意图：既要按域名精确匹配，
			// 又要接住所有没匹配上的？让用户拆成两条隧道，
			// 而不是替他猜一个优先级。
			errs = append(errs, fmt.Errorf("%w: catch_all 与域名列表不能同时指定 —— "+
				"若两种都要，请拆成两条隧道", ErrModeConflict))
		}
	case RouterTLSSNI:
		// SNI 是明文，所以透传也能路由；但既然透传就不该再终止 TLS。
		if t.TLS != TLSPassthrough {
			errs = append(errs, fmt.Errorf("%w: router=tls-sni 需要 tls=passthrough —— "+
				"若要终止 TLS 请改用 router=http", ErrModeConflict))
		}
		if len(t.Router.Domains) == 0 {
			errs = append(errs, fmt.Errorf("%w: router=tls-sni 必须至少配一个域名", ErrMissingField))
		}
		if t.Router.CatchAll {
			// SNI 路由的 catch-all 没有意义：不发 SNI 的客户端在第 2 步
			// （首字节判别）就被分到明文路径了，压根到不了 SNI 匹配。
			errs = append(errs, fmt.Errorf("%w: router=tls-sni 不支持 catch_all —— "+
				"不发 SNI 的客户端到不了 SNI 匹配这一步", ErrModeConflict))
		}
		if len(t.Router.Locations) > 0 {
			errs = append(errs, fmt.Errorf("%w: router=tls-sni 无法按路径分流（那要求解密）", ErrModeConflict))
		}
		if t.Router.HostRewrite != "" {
			errs = append(errs, fmt.Errorf("%w: router=tls-sni 无法改写 Host（那要求解密）", ErrModeConflict))
		}
	default:
		errs = append(errs, fmt.Errorf("tunnel: 未知 router.kind %q", t.Router.Kind))
	}

	for _, d := range t.Router.Domains {
		if d == "" || strings.ContainsAny(d, " /:") {
			errs = append(errs, fmt.Errorf("tunnel: 域名 %q 非法", d))
		}
	}
	for _, l := range t.Router.Locations {
		if !strings.HasPrefix(l, "/") {
			errs = append(errs, fmt.Errorf("tunnel: 路径前缀 %q 必须以 / 开头", l))
		}
	}
	return errs
}

func (t *Tunnel) validateBackend() []error {
	var errs []error
	switch t.Backend.Kind {
	case BackendAddr:
		if t.Backend.Addr == "" {
			errs = append(errs, fmt.Errorf("%w: backend.kind=addr 必须配 addr", ErrMissingField))
		}
	case BackendUnix:
		if t.Backend.Path == "" {
			errs = append(errs, fmt.Errorf("%w: backend.kind=unix 必须配 path", ErrMissingField))
		}
		if t.L4 == L4UDP {
			errs = append(errs, fmt.Errorf("%w: unix socket 后端不支持 UDP", ErrModeConflict))
		}
	case BackendHandler:
		errs = append(errs, fmt.Errorf("%w: backend.kind=handler 是为场景三预留的枚举位",
			ErrUnsupportedKind))
	default:
		errs = append(errs, fmt.Errorf("tunnel: 未知 backend.kind %q", t.Backend.Kind))
	}
	return errs
}

// Clone 深拷贝，供热重载先构候选再原子换。
func (t *Tunnel) Clone() *Tunnel {
	if t == nil {
		return nil
	}
	c := *t

	if t.Router != nil {
		r := *t.Router
		r.Domains = slices.Clone(t.Router.Domains)
		r.Locations = slices.Clone(t.Router.Locations)
		c.Router = &r
	}
	if t.Policy != nil {
		p := *t.Policy
		p.AllowCIDRs = slices.Clone(t.Policy.AllowCIDRs)
		c.Policy = &p
	}
	if t.Enabled != nil {
		v := *t.Enabled
		c.Enabled = &v
	}
	return &c
}

// IsBareExposure 报告这条隧道是否是「裸端口开放」——
// 独占端口且没有任何来源限制。
//
// 控制台用它决定是否显示风险标记。所有者已决定接受这种形态，
// 所以这里只是识别，不是拒绝。
func (t *Tunnel) IsBareExposure() bool {
	if t.Exposure != ExposurePort {
		return false
	}
	return t.Policy == nil || len(t.Policy.AllowCIDRs) == 0
}

// SourceAllowed 判断一个来源地址是否被本隧道的策略放行。
//
// 没有配 AllowCIDRs 时一律放行（裸端口语义）。
func (t *Tunnel) SourceAllowed(addr netip.Addr) bool {
	if t.Policy == nil || len(t.Policy.AllowCIDRs) == 0 {
		return true
	}
	// IPv4-in-IPv6 必须先规范化，否则 ::ffff:1.2.3.4 会绕过 IPv4 白名单。
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range t.Policy.AllowCIDRs {
		if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return true
		}
	}
	return false
}
