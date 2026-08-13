// Package policy 实现 agent 侧的本地目标策略。
//
// # 这一层为什么必须存在
//
// 中继拥有 Tunnel 记录（控制台可 CRUD），但**目标地址的最终裁决权在 agent**。
// 没有这一层，一个被攻陷的控制台就变成了内网与云元数据的跳板：中继下发
// 「转发到 169.254.169.254」，agent 照做，云凭据即外泄。
//
// frp 完全没有这一层：localIP 默认 127.0.0.1（pkg/config/v1/proxy.go:155），
// 而 TCP/UDP 代理的客户端校验是空实现，直接 return nil
// （pkg/config/v1/validation/proxy.go:129-135）—— 写 169.254.169.254 一路畅通。
// 在我们的产品里这个问题比在 frp 里更尖锐，因为**控制台会向 agent 推送隧道定义**。
//
// # 关键设计：检查已解析的地址，且每次拨号都检查
//
// 只在配置解析时校验主机名是无效的：DNS 可以在校验之后、拨号之前改变解析结果
// （DNS 重绑定）。所以 DialContext 是 agent 唯一的出网路径，它拨的是**已通过
// 检查的 netip.AddrPort 字面量**，而不是主机名 —— 这样 resolve 与 dial 之间
// 不存在时间窗，因为没有第二次解析。判定结果**绝不缓存**。
package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
)

// Decision 是一次目标检查的结论。
type Decision struct {
	// Allowed 是最终裁决。
	Allowed bool
	// Reason 面向人类，会通过 TunnelRejected 上报控制台并展示给用户。
	Reason string
	// Rule 标识命中的规则，便于排障（例如 "default-deny:cloud-metadata"）。
	Rule string
}

// Policy 是 agent 的本地目标策略。
//
// 零值不可用；请用 New 构造。
type Policy struct {
	allow []netip.Prefix
	deny  []netip.Prefix

	// allowPorts 为空表示不限端口。
	allowPorts []PortRange

	// resolver 可注入以便测试。
	resolver Resolver
}

// Resolver 抽象 DNS 解析，便于测试与将来替换。
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// PortRange 是一个闭区间端口范围。
type PortRange struct {
	Lo, Hi uint16
}

// Contains 报告 p 是否落在范围内。
func (r PortRange) Contains(p uint16) bool { return p >= r.Lo && p <= r.Hi }

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// defaultDeny 是**永远**生效的拒绝列表，用户的 allow 规则不能覆盖它。
//
// 这些地址一旦可达即等于凭据泄露或内网跳板，因此不接受「我知道我在做什么」。
// 若确实需要访问其中某个地址，正确做法是改代码并解释理由，而不是配一行 allow。
var defaultDeny = []struct {
	prefix netip.Prefix
	rule   string
	why    string
}{
	// 云元数据服务。这是最高价值目标：一次 SSRF 换一套云凭据。
	{netip.MustParsePrefix("169.254.169.254/32"), "cloud-metadata", "云元数据服务（AWS/GCP/Azure）"},
	{netip.MustParsePrefix("169.254.170.2/32"), "cloud-metadata", "ECS 任务元数据"},
	{netip.MustParsePrefix("100.100.100.200/32"), "cloud-metadata", "阿里云元数据服务"},
	{netip.MustParsePrefix("100.100.100.0/24"), "cloud-metadata", "阿里云内部服务段"},
	// 整个链路本地段 —— 上面两条 169.254.x 只是其中最出名的。
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local", "IPv4 链路本地"},
	{netip.MustParsePrefix("fe80::/10"), "link-local", "IPv6 链路本地"},
	// IPv6 形式的元数据地址。攻击者会用 IPv6 表示绕过只写了 IPv4 的黑名单。
	{netip.MustParsePrefix("fd00:ec2::254/128"), "cloud-metadata", "EC2 IPv6 元数据"},
	// 未指定地址与多播。
	{netip.MustParsePrefix("0.0.0.0/8"), "unspecified", "「本网络」保留段"},
	{netip.MustParsePrefix("::/128"), "unspecified", "IPv6 未指定地址"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast", "IPv4 多播"},
	{netip.MustParsePrefix("ff00::/8"), "multicast", "IPv6 多播"},
	{netip.MustParsePrefix("255.255.255.255/32"), "broadcast", "受限广播"},
}

// 配置错误。
var (
	// ErrAllowOverlapsDefaultDeny 表示用户的 allow 规则与永久拒绝段重叠。
	//
	// 这是**校验错误而不是静默忽略**：一个以为自己开通了某段的运维，
	// 必须当场知道那段里有一部分永远不会通，而不是等到线上排查半天。
	ErrAllowOverlapsDefaultDeny = errors.New("policy: allow 规则与永久拒绝段重叠")

	// ErrNoAllowRules 表示没有配置任何 allow 规则。
	// 默认拒绝一切是安全的默认值，但它必然导致所有隧道被否决，
	// 所以构造时就报错，而不是让用户对着一堆 rejected_by_agent 猜原因。
	ErrNoAllowRules = errors.New("policy: 未配置任何 allow 规则，所有目标都会被拒绝")
)

// Config 是策略的声明式配置，直接对应 agent.toml 的 [policy] 段。
type Config struct {
	// Allow 是允许的目标网段。为空则构造失败（见 ErrNoAllowRules）。
	Allow []netip.Prefix

	// Deny 是用户追加的拒绝网段，优先级高于 Allow。
	Deny []netip.Prefix

	// AllowPorts 为空表示不限端口。
	AllowPorts []PortRange

	// Resolver 覆盖 DNS 解析，nil 时用 net.DefaultResolver。
	//
	// 存在的理由是**可测**：「主机名解析很慢时会发生什么」是一个真实的
	// 故障模式（局域网 DNS 抖动），而它的后果曾经是一整条读循环被冻住
	// 5 秒。没有这个注入口的话，那条性质只能靠一个真的解析不出来的名字
	// 去撞 —— 而 NXDOMAIN 在多数机器上是毫秒级返回的，撞不出来。
	Resolver Resolver
}

// DefaultConfig 返回一个适合家庭/办公内网的默认策略：
// 放行回环与私有段，不限端口。
//
// 之所以默认放行私有段而不是仅回环：本产品的核心用途就是暴露内网服务，
// 只放行回环会让绝大多数用户第一步就撞墙。
//
// fc00::/7 里含有 EC2 的 IPv6 元数据地址 fd00:ec2::254，但这没关系 ——
// 判定时永久拒绝段优先（见 CheckAddr 的顺序），而 New 的重叠校验会识别出
// 「allow 真包含 deny」这种安全情形并放行（见 New 的文档）。
func DefaultConfig() Config {
	return Config{
		Allow: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("fc00::/7"), // IPv6 唯一本地地址
		},
	}
}

// New 校验并构造一个策略。
//
// # 重叠校验的两种情形
//
// allow 与永久拒绝段重叠有两种截然不同的含义，必须区别对待：
//
//   - **allow 真包含 deny**（例如 allow fc00::/7 ⊇ deny fd00:ec2::254/128）：
//     这是**正常且安全**的。用户想开通一个大段，其中恰好有个别高危地址被永久
//     拒绝；判定时拒绝段优先，结果正确。若把这种情形也报错，用户就被迫手工
//     切分 CIDR —— 那是极易算错的活（把 fc00::/7 减去一个 /32 需要十几条子段），
//     错了反而扩大暴露面。所以放行，但把「有例外」这件事说清楚是文档与控制台的责任。
//
//   - **deny 真包含 allow，或两者部分交叠**（例如 allow 169.254.0.0/15
//     与 deny 169.254.0.0/16）：这是**配置错误**。用户以为开通了某段，
//     而其中一整块永远不通。必须当场报错，而不是让人线上排查半天。
func New(cfg Config) (*Policy, error) {
	if len(cfg.Allow) == 0 {
		return nil, ErrNoAllowRules
	}

	for _, a := range cfg.Allow {
		for _, d := range defaultDeny {
			if !a.Overlaps(d.prefix) {
				continue
			}
			// allow 严格更宽（位数更小）即为「真包含」，安全放行。
			if a.Bits() < d.prefix.Bits() {
				continue
			}
			return nil, fmt.Errorf("%w: allow %s 与 %s（%s）交叠且未真包含它；"+
				"该段中有一部分永远不会被放行，请收窄 allow 规则",
				ErrAllowOverlapsDefaultDeny, a, d.prefix, d.why)
		}
	}

	for _, r := range cfg.AllowPorts {
		if r.Lo > r.Hi {
			return nil, fmt.Errorf("policy: 端口范围 %d-%d 的下界大于上界", r.Lo, r.Hi)
		}
		if r.Lo == 0 {
			return nil, errors.New("policy: 端口 0 不是有效目标")
		}
	}

	return &Policy{
		allow:      slices.Clone(cfg.Allow),
		deny:       slices.Clone(cfg.Deny),
		allowPorts: slices.Clone(cfg.AllowPorts),
		resolver:   resolverOr(cfg.Resolver),
	}, nil
}

func resolverOr(r Resolver) Resolver {
	if r != nil {
		return r
	}
	return net.DefaultResolver
}

// CheckAddr 对一个**已解析**的地址端口做裁决。
//
// 这是策略的唯一判定入口。它不接受主机名 —— 类型系统在此强制
// 「先解析、再判定、然后拨已判定的字面量」这个顺序。
func (p *Policy) CheckAddr(ap netip.AddrPort) Decision {
	addr := ap.Addr()

	// IPv4-in-IPv6（::ffff:a.b.c.d）必须先规范化，否则
	// ::ffff:169.254.169.254 会绕过所有 IPv4 前缀检查。
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	if !addr.IsValid() {
		return Decision{Reason: "地址无效", Rule: "invalid"}
	}

	// 1. 永久拒绝段优先于一切。
	for _, d := range defaultDeny {
		// 前缀与地址的族必须一致才比较，否则 Contains 恒为 false 却看不出原因。
		if d.prefix.Addr().Is4() == addr.Is4() && d.prefix.Contains(addr) {
			return Decision{
				Reason: fmt.Sprintf("目标 %s 命中永久拒绝段 %s（%s）", addr, d.prefix, d.why),
				Rule:   "default-deny:" + d.rule,
			}
		}
	}

	// 2. 用户 deny 优先于用户 allow。
	for _, d := range p.deny {
		if d.Addr().Is4() == addr.Is4() && d.Contains(addr) {
			return Decision{
				Reason: fmt.Sprintf("目标 %s 命中本地拒绝规则 %s", addr, d),
				Rule:   "deny:" + d.String(),
			}
		}
	}

	// 3. 端口。
	if len(p.allowPorts) > 0 {
		ok := false
		for _, r := range p.allowPorts {
			if r.Contains(ap.Port()) {
				ok = true
				break
			}
		}
		if !ok {
			return Decision{
				Reason: fmt.Sprintf("端口 %d 不在允许范围内", ap.Port()),
				Rule:   "port",
			}
		}
	}

	// 4. 必须命中某条 allow —— 默认拒绝。
	for _, a := range p.allow {
		if a.Addr().Is4() == addr.Is4() && a.Contains(addr) {
			return Decision{Allowed: true, Rule: "allow:" + a.String()}
		}
	}

	return Decision{
		Reason: fmt.Sprintf("目标 %s 不在任何允许网段内（默认拒绝）", addr),
		Rule:   "default-deny:no-match",
	}
}

// ErrDenied 包装一次被策略拒绝的拨号。
type ErrDenied struct {
	Target   string
	Decision Decision
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("policy: 拒绝拨号 %s：%s（规则 %s）", e.Target, e.Decision.Reason, e.Decision.Rule)
}

// DialContext 是 agent 的**唯一**出网路径。
//
// 流程：解析 → 逐个候选地址判定 → 拨**已判定的字面量**。
//
// 关键点：拨的是 netip.AddrPort 的字符串形式而不是原始 host，
// 所以不存在第二次 DNS 解析，也就不存在 DNS 重绑定的时间窗。
// frp 直接把配置里的 localIP/localPort 交给 libnet.Dial
// （client/proxy/proxy.go:216-219），中间没有任何判定。
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	candidates, port, err := p.resolve(ctx, network, address)
	if err != nil {
		return nil, err
	}

	// 每个候选都必须单独判定。一个主机名可以同时解析出一个合法地址和一个
	// 元数据地址（DNS rebinding 的常见形态），逐个判定才能挡住。
	var lastDenied *ErrDenied
	var lastDialErr error
	for _, addr := range candidates {
		ap := netip.AddrPortFrom(addr, port)
		if d := p.CheckAddr(ap); !d.Allowed {
			lastDenied = deniedFor(addr, port, d)
			continue
		}
		// 拨已判定的字面量，不再经过 host。
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, network, ap.String())
		if err != nil {
			lastDialErr = err
			continue
		}
		return conn, nil
	}

	if lastDenied != nil {
		return nil, lastDenied
	}
	return nil, fmt.Errorf("policy: 拨 %q 的所有候选地址均失败：%w", address, lastDialErr)
}

// ResolveAllowed 解析 address 并返回**第一个被允许**的地址字面量。
//
// 存在这个方法是为了让不走 net.Dialer 的路径（UDP 要 net.DialUDP 才能拿到
// *net.UDPConn）也**共用同一处判定**。若让 UDP 自己写一遍解析与裁决，
// 攻击者只要把隧道的 l4 从 tcp 改成 udp 就能穿过 SSRF 防线 ——
// 一道防线有两份实现，等于迟早只剩一份是对的。
//
// 返回的是已判定的字面量，调用方**必须**直接用它拨号，不得回头再用主机名：
// 那会重新打开 DNS 重绑定的时间窗。
func (p *Policy) ResolveAllowed(ctx context.Context, network, address string) (netip.AddrPort, error) {
	candidates, port, err := p.resolve(ctx, network, address)
	if err != nil {
		return netip.AddrPort{}, err
	}

	var lastDenied *ErrDenied
	for _, addr := range candidates {
		ap := netip.AddrPortFrom(addr, port)
		if d := p.CheckAddr(ap); !d.Allowed {
			lastDenied = deniedFor(addr, port, d)
			continue
		}
		return ap, nil
	}
	if lastDenied != nil {
		return netip.AddrPort{}, lastDenied
	}
	return netip.AddrPort{}, fmt.Errorf("policy: %q 没有可用的候选地址", address)
}

// resolve 把 address 拆成候选地址列表与端口。host 已是 IP 字面量时跳过解析。
func (p *Policy) resolve(ctx context.Context, network, address string) ([]netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, fmt.Errorf("policy: 目标 %q 格式非法：%w", address, err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("policy: 目标 %q 的端口非法：%w", address, err)
	}
	port := uint16(port64)

	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, port, nil
	}
	candidates, err := p.resolver.LookupNetIP(ctx, ipNetwork(network), host)
	if err != nil {
		return nil, 0, fmt.Errorf("policy: 解析 %q 失败：%w", host, err)
	}
	if len(candidates) == 0 {
		return nil, 0, fmt.Errorf("policy: %q 没有解析到任何地址", host)
	}
	return candidates, port, nil
}

// deniedFor 造一条拒绝错误，地址用规范形式。
//
// CheckAddr 内部已经 unmap 过，若这里仍用映射形式，同一句错误里就会出现
// [::ffff:127.0.0.1] 与 127.0.0.1 两种写法 —— 而这句话是**原样**呈现给
// 用户的（经 agent 的 target_denied 传到控制台）。
func deniedFor(addr netip.Addr, port uint16, d Decision) *ErrDenied {
	shown := netip.AddrPortFrom(addr, port)
	if addr.Is4In6() {
		shown = netip.AddrPortFrom(addr.Unmap(), port)
	}
	return &ErrDenied{Target: shown.String(), Decision: d}
}

// ipNetwork 把 "tcp"/"udp" 之类映射成 LookupNetIP 需要的 "ip"/"ip4"/"ip6"。
func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	default:
		return "ip"
	}
}
