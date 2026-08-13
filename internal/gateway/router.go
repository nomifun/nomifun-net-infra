package gateway

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 路由注册错误。
var (
	// ErrRouteConflict 表示同一个 (域名, 路径前缀) 已被别的隧道占用。
	//
	// 注册期就必须报错。frp 的「先到先得、无所有权概念」在多租户下是个坑：
	// frps 重启后所有域名重新抢占（docs/research/03-frp-l7-vhost.md §5）。
	ErrRouteConflict = errors.New("gateway: 路由冲突")

	// ErrModeConflict 表示同一端口同一域名上混用了透传与网关。
	//
	// 这是研究档案 15 §B1 的注册期不变量 (b)：一个域名在一个端口上只能有一种
	// TLS 处置方式，否则判别器在 SNI 命中后无法决定要不要解密。
	ErrModeConflict = errors.New("gateway: 同一域名不能同时是透传与网关")

	// ErrDuplicateDefault 表示一个端口上出现了第二个默认绑定。
	//
	// 不变量 (a)：IP 字面量流量没有任何判别信息，所以每个共享端口最多一个默认绑定。
	ErrDuplicateDefault = errors.New("gateway: 一个端口只能有一个默认绑定")
)

// Route 是一条已注册的路由。
type Route struct {
	// Domain 是注册时的域名，可能是 "*.b.c" 或 "*"。
	Domain string

	// Location 是路径前缀，"" 表示不限路径。
	Location string

	Tunnel *tunnel.Tunnel
}

// HostRouter 是手写的 Host 路由器：域名精确匹配 + 通配回落 + 最长路径前缀。
//
// # 为什么必须手写
//
// net/http 的 ServeMux 主机模式**只支持字面量**，不支持 *.example.com
// （spec §7.3 明确记了这一条）。多租户 vhost 需要
// `a.b.c` → `*.b.c` → `*` 的回落链，ServeMux 表达不出来。
//
// 结构照 frp 的 pkg/util/vhost/router.go:98-155：精确 host 查不到就逐层把最左
// label 换成 `*`，最后落到 `"*"` 兜底；两段域名（example.com）刻意**不**进入
// 通配走查，否则它会命中 `*.com` 这种明显不该被谁注册到的东西。
//
// **但不抄它的假 URL.Host**：frp 把路由键 base64 编进 req.URL.Host
// （vhost/http.go:81-85）只为借用 http.Transport 的连接池分桶。这里用真实的
// map 存路由、每条隧道一个 Transport 来做池隔离（见 gateway.go），
// 不往协议字段里塞编码数据。
type HostRouter struct {
	mu sync.RWMutex

	// byDomain 的每个 value 按 Location 长度**降序**，于是线性扫描的第一个
	// HasPrefix 命中就是最长前缀。
	byDomain map[string][]*Route
}

// NewHostRouter 创建一个空路由器。
func NewHostRouter() *HostRouter {
	return &HostRouter{byDomain: make(map[string][]*Route)}
}

// Add 注册一条路由。domain 允许 "*.b.c" 与 "*"；location 为空表示不限路径。
func (r *HostRouter) Add(domain, location string, t *tunnel.Tunnel) error {
	domain = normalizeHost(domain)
	if domain == "" {
		return fmt.Errorf("%w：域名不能为空", ErrRouteConflict)
	}
	if location != "" && !strings.HasPrefix(location, "/") {
		return fmt.Errorf("gateway: 路径前缀 %q 必须以 / 开头", location)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	routes := r.byDomain[domain]
	for _, ex := range routes {
		if ex.Location == location {
			return fmt.Errorf("%w：%s%s 已被隧道 %s 占用", ErrRouteConflict, domain, location, ex.Tunnel.Slug)
		}
		// 同域名混用透传与网关会让 SNI 命中后无法决定是否解密。
		if ex.Tunnel.TLS != t.TLS {
			return fmt.Errorf("%w：%s 上 %s 是 %s，新来的 %s 是 %s",
				ErrModeConflict, domain, ex.Tunnel.Slug, ex.Tunnel.TLS, t.Slug, t.TLS)
		}
	}

	routes = append(routes, &Route{Domain: domain, Location: location, Tunnel: t})
	slices.SortStableFunc(routes, func(a, b *Route) int {
		// 降序：更长（更具体）的前缀先被检查。
		return len(b.Location) - len(a.Location)
	})
	r.byDomain[domain] = routes
	return nil
}

// Remove 摘掉一条路由，并在域名下已无路由时删除整个条目。
//
// 最后那一步不能省：frp 的 Routers.Del 只清切片、留下空 map 条目
// （router.go:162-184），长期动态注册会缓慢泄漏 map 条目。
func (r *HostRouter) Remove(domain, location string) {
	domain = normalizeHost(domain)

	r.mu.Lock()
	defer r.mu.Unlock()

	routes := r.byDomain[domain]
	routes = slices.DeleteFunc(routes, func(x *Route) bool { return x.Location == location })
	if len(routes) == 0 {
		delete(r.byDomain, domain)
		return
	}
	r.byDomain[domain] = routes
}

// Len 返回已注册的域名数。
func (r *HostRouter) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDomain)
}

// HasExactDomain 报告一个域名是否被**逐字**注册过（不走通配回落）。
//
// # 为什么 ACME 要用这个而不是 MatchHost
//
// MatchHost 会做通配回落：a.b.example.com 命中已注册的 *.b.example.com。
// 那对**转发**是对的（用户注册通配就是要这个效果），但对**签证书**是错的：
// 任何人都能拿 <随机>.b.example.com 发一次握手，让我们去找 CA 要一张新证书。
// 每个名字只算一次 per-name 预算，可名字有无穷多个 —— 于是全局预算在
// 几十次握手里烧光，真域名之后也签不出来了。
//
// 通配域名的正解是 DNS-01 + 一张通配证书，而本产品刻意不支持 DNS-01
// （家庭/工厂部署多数没有 DNS API 权限，见 acmecert 包注释）。所以通配路由
// **拿不到 ACME 证书**，这是已知且如实记录的限制，不是可以靠放宽匹配修掉的。
func (r *HostRouter) HasExactDomain(domain string) bool {
	domain = normalizeHost(domain)

	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDomain[domain]) > 0
}

// Match 按 (host, path) 找最合适的路由：精确域名优先，然后通配回落，
// 每一级里按最长路径前缀命中。
func (r *HostRouter) Match(host, path string) (*Route, bool) {
	host = normalizeHost(host)
	if path == "" {
		path = "/"
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cand := range wildcardChain(host) {
		if rt, ok := r.matchLocked(cand, path); ok {
			return rt, true
		}
	}
	return nil, false
}

// MatchHost 只按域名匹配，忽略路径。
//
// SNI 判别（第 4 步）只能看到域名：TLS 还没解密，路径根本不存在。
// 所以那一步用这个方法决定「哪条隧道、要不要解密」，路径分流留到
// 解密之后的 L7 处理器里做（那时 Match 才有意义）。
func (r *HostRouter) MatchHost(host string) (*Route, bool) {
	host = normalizeHost(host)

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cand := range wildcardChain(host) {
		if routes := r.byDomain[cand]; len(routes) > 0 {
			return routes[0], true
		}
	}
	return nil, false
}

func (r *HostRouter) matchLocked(domain, path string) (*Route, bool) {
	for _, rt := range r.byDomain[domain] {
		if rt.Location == "" || strings.HasPrefix(path, rt.Location) {
			return rt, true
		}
	}
	return nil, false
}

// wildcardChain 返回一个 host 的匹配候选链：
// a.b.c → [a.b.c, *.b.c, *.c?, *]。
//
// 与 frp 一样，`len >= 3` 的限制让两段域名（example.com）不进入通配走查 ——
// 否则 example.com 会命中 `*.com`，等于让一个租户注册到整个顶级域。
func wildcardChain(host string) []string {
	if host == "" {
		return []string{"*"}
	}
	out := []string{host}

	labels := strings.Split(host, ".")
	for len(labels) >= 3 {
		labels[0] = "*"
		out = append(out, strings.Join(labels, "."))
		labels = labels[1:]
	}
	return append(out, "*")
}

// normalizeHost 把 Host 头或 SNI 规范化成路由键：去端口、去尾点、转小写。
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	// IPv6 字面量会带方括号，去掉后才好与注册值比较。
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.ToLower(host)
}

// ── 端口绑定表 ──────────────────────────────────────────────────────────────

// PortView 是一个端口绑定的只读快照。
//
// 判别器一次性拿走它，避免在判别过程中反复加锁、以及中途看到半张表。
// Hosts 本身是并发安全的，所以快照里放指针是安全的。
type PortView struct {
	// Dedicated 是专用端口绑定：判别顺序第 0 步，命中就**不 peek**。
	Dedicated *tunnel.Tunnel

	// Fallback 是端口默认绑定：没有 SNI、Host 是 IP 字面量、或首字节既非 TLS
	// 也非明文 HTTP 时的落点。
	Fallback *tunnel.Tunnel

	// TrustProxyProtocol 决定是否解析 PROXY 头。默认 false。
	TrustProxyProtocol bool

	Hosts *HostRouter
}

// Registry 是「端口 → 绑定」的注册表。
//
// 一个 Registry 覆盖整台中继：判别器按连接的本地端口取快照。
//
// 契约：**Registry 里有什么就服务什么**。它不看 Tunnel.State，也不看
// Tunnel.Enabled —— 「哪些隧道该被服务」是装配层（控制台 apply / 热重载 diff）
// 的决定，在这里再判一次只会制造两个真相源。停止服务一条隧道 =
// 把它的路由从 Registry 里摘掉，并调用 Gateway.Invalidate。
type Registry struct {
	// limits 是每隧道限额状态，按隧道 ID 索引。
	//
	// **ReplaceWith 刻意不碰它。** 见 limits.go 顶部：applyShared 每次都整体
	// 替换路由表，而它在每次 agent 上下线时都会跑 —— 把限额状态跟着换掉
	// 等于每次抖动都把令牌桶清零（桶初始满 → 白送一份突发额度），
	// 并让在飞计数与还开着的连接脱节。
	//
	// 放在 Registry 上而不是 Gateway 或 Discriminator 上：那两者持有的是
	// **同一个** *Registry 实例（它们必须看到同一份路由），所以它是唯一
	// 天然被两条路径共享、且生命周期与「这台中继的共享入口」一致的对象。
	limits *limitStore

	mu    sync.RWMutex
	ports map[uint16]*portBinding
}

type portBinding struct {
	dedicated          *tunnel.Tunnel
	fallback           *tunnel.Tunnel
	trustProxyProtocol bool
	hosts              *HostRouter
}

// NewRegistry 创建一个空注册表。
func NewRegistry() *Registry {
	return &Registry{
		ports:  make(map[uint16]*portBinding),
		limits: newLimitStore(),
	}
}

// ReplaceWith 原子地把本注册表的内容换成 other 的内容。
//
// # 为什么是「换内容」而不是「换指针」
//
// 判别器与网关持有的是**同一个** *Registry 实例（它们必须看到同一份路由，
// 否则会出现「判别器说走 gateway、网关说没这条路由」这种自相矛盾）。
// 所以配置变更时不能换指针，只能换内容。
//
// # 为什么是全量替换而不是增量 diff
//
// 路由表就是一份期望状态的投影，重建一次是纯内存操作（几十条路由）。
// 而增量 diff 要维护「哪条被改了」的判断，那正是最容易出
// 「界面显示已生效、实际还是旧路由」的地方 —— 本仓库在隧道状态上
// 已经吃过两次同类的苦。
func (r *Registry) ReplaceWith(other *Registry) {
	other.mu.RLock()
	fresh := make(map[uint16]*portBinding, len(other.ports))
	for k, v := range other.ports {
		fresh[k] = v
	}
	other.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ports = fresh
}

// limitsFor 取一条隧道的限额状态（不限额时为 nil）。
//
// 网关的请求路径与判别器的 splice 路径都走这一个入口 —— 两条路径分头维护
// 各自的状态就是漂移的开始，而这里的漂移意味着「换条路径就有一半限额不生效」。
func (r *Registry) limitsFor(t *tunnel.Tunnel) *tunnelLimits {
	return r.limits.for_(t)
}

// RetainLimits 丢掉已不存在隧道的限额状态。
//
// 由 applyShared 在同步完路由表之后调用。**不要**把它挂到 Invalidate 上：
// 那个每次 apply 都会对每条隧道调一遍，而 apply 在每次 agent 上下线时都跑 ——
// 等于每次抖动清零一次令牌桶。见 limits.go 顶部。
func (r *Registry) RetainLimits(live map[string]bool) {
	r.limits.retain(live)
}

// trackedLimits 报告当前跟踪着多少条隧道的限额状态。
//
// **刻意不导出。** 它只被本包的测试用到，而本仓的 reach-check 会把
// 「只有测试引用的导出符号」判成缺陷 —— 那条判据是对的：一个只为测试
// 存在的导出符号是把测试的需要伪装成 API。同包测试用小写就够了。
func (r *Registry) trackedLimits() int { return r.limits.tracked() }

func (r *Registry) bindingLocked(port uint16) *portBinding {
	b, ok := r.ports[port]
	if !ok {
		b = &portBinding{hosts: NewHostRouter()}
		r.ports[port] = b
	}
	return b
}

// SetTrustProxyProtocol 标记一个端口前面是否是我们自己的负载均衡器。
//
// 默认 false，且**必须**保持默认 false：对不可信来源解析 PROXY 头
// 等于把源 IP 伪造能力送给公网。
// EnsurePort 让一个端口在注册表里**存在**，即使它上面还没有任何路由。
//
// # 为什么「监听了」和「有路由」必须分开
//
// 判别器对 View 查不到的端口是立刻 close 的（那个默认是对的：不该为
// 一个我们没在听的端口去 peek ClientHello）。但共享入口的端口是我们**自己**
// 在听的 —— 上面没有路由只说明还没有隧道注册进来，不说明这个端口没用。
//
// 差别在 ACME 上会变成一个真故障：TLS-ALPN-01 的挑战按 RFC 8737 只走
// **443**，而 turns: 的域名不是隧道、永远不会在路由表里出现。于是一个
// 「只跑 turns:、还没建隧道」的中继会把挑战连接在 View 查不到时就关掉，
// 现象是签发超时 —— 而判别器与 ACME 两边的代码单看都对。
//
// 所以监听器一起来就调这个，把「端口存在」这件事登记下来。
func (r *Registry) EnsurePort(port uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindingLocked(port)
}

func (r *Registry) SetTrustProxyProtocol(port uint16, trust bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindingLocked(port).trustProxyProtocol = trust
}

// BindDedicated 把一个端口整条交给一条隧道（判别顺序第 0 步）。
//
// 场景二的 ESP32 走这条：它不发 SNI，Host 可能是 IP 字面量甚至缺失，
// 任何解析都是纯风险 —— 端口**就是**判别依据。
// # 为什么它**刻意**没有配置入口
//
// 这个方法实现了规格 §7.3 判别顺序的第 0 步（「专用端口绑定 → 立即拼接，
// 不 peek ← S2 的 ESP32 走这条」），而那一步的正确表达是
// **exposure: port 的独立监听器**，不是「把共享端口交给一条隧道」。
// 曾经加过一个 router.dedicated 字段，随后回退，三条理由都可核：
//
//  1. **能力为零，而且更弱。** relay.EntryListener 本来就是「整端口独占、
//     一个字节都不 peek」，而且它多出一样共享入口路径没有的东西：
//     7 个每隧道计数器。
//
//     这一条**曾经更强**：那时 internal/gateway 里没有任何限速器，
//     走判别器 splice 的连接完全不受限，而 policy.bytes_per_second 在界面上
//     显示「已设置」—— 正是本仓最在意的那类谎。现在限额三项在共享入口上
//     也生效了（见 limits.go），所以这条理由只剩计数器那一半。
//
//  2. **它能成功绑定的场合，恰好是 TLS-ALPN-01 静默死掉的场合。**
//     下面的检查只在「该端口已有域名路由或已有 fallback」时拒绝，
//     于是它成功的前提是「共享端口上没有别的隧道」—— 而一台
//     `-acme -turn` 只服务一台工厂设备的中继正是这个形状（证书是给 turns: 用的，
//     挑战走 TLS-ALPN-01 主路径）。判别器步骤 0 先于步骤 3，
//     所以挑战连接会被 splice 给设备的隧道：首签超时，或者更糟 ——
//     签成功、60 天后续签**静默**失败。Registry.EnsurePort 那段注释花了 14 行
//     讲「不登记端口会让 ACME 挑战被关掉」；给共享端口加独占开关，
//     等于从另一头把同一个洞挖回来。
//
//  3. **冲突赢家由 slug 字典序决定。** ListTunnels 是 ORDER BY slug，
//     而 applyShared 边遍历边绑。a-robot（独占）+ b-web（域名）→ robot 先绑成功、
//     web 被拒；把 robot 改名成 z-robot → 反过来。
//     **改一条隧道的名字改变了另一条隧道通不通**，这是最不能要的那种行为。
//     Validate() 是单条隧道的，它看不见同端口的其他隧道，压根拦不住这件事。
//
// 方法本身保留：它、PortView.Dedicated、StepDedicated、DiscriminatorStats.Dedicated
// 是规格 §7.3 第 0 步与 §7.2 的 ECH 兜底在同一张表里的表达，
// 删掉就是偏离规范性文档，而控制台已经在展示那个计数器。
func (r *Registry) BindDedicated(port uint16, t *tunnel.Tunnel) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.bindingLocked(port)
	if b.dedicated != nil && b.dedicated != t {
		return fmt.Errorf("%w：端口 %d 已被隧道 %s 独占", ErrRouteConflict, port, b.dedicated.Slug)
	}
	if b.hosts.Len() > 0 || b.fallback != nil {
		return fmt.Errorf("%w：端口 %d 已有共享绑定，不能再独占", ErrRouteConflict, port)
	}
	b.dedicated = t
	return nil
}

// BindDefault 设定一个端口的默认绑定（无判别信息时的落点）。
func (r *Registry) BindDefault(port uint16, t *tunnel.Tunnel) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.bindingLocked(port)
	if b.dedicated != nil {
		return fmt.Errorf("%w：端口 %d 已被独占", ErrRouteConflict, port)
	}
	if b.fallback != nil && b.fallback != t {
		return fmt.Errorf("%w：端口 %d 的默认绑定已是 %s", ErrDuplicateDefault, port, b.fallback.Slug)
	}
	b.fallback = t
	return nil
}

// AddShared 按隧道的 Router 定义在一个共享端口上注册域名与路径。
//
// 域名与路径来自 tunnel.Router，TLS 处置由 tunnel.TLS 决定 ——
// 这正是 spec §3.2 那两个正交轴：Router 说「怎么找到你」，
// TLS 说「中继要不要解密」，两者互不代表。
func (r *Registry) AddShared(port uint16, t *tunnel.Tunnel) error {
	if t.Router == nil {
		return fmt.Errorf("gateway: 隧道 %s 没有 router，不能注册到共享端口", t.Slug)
	}
	// 空域名列表必须报错，**绝不能**静默什么都不做。
	//
	// 下面那个双层循环在 Domains 为空时一次都不执行，于是这个函数会
	// 返回 nil 而注册了零条路由 —— 调用方以为成功了，用户建的隧道
	// 却永远匹配不到任何请求，而界面显示 active。
	// 「无域名」这个意图应当由调用方翻译成 BindDefault（端口默认落点），
	// 而不是在这里被吞掉。
	if len(t.Router.Domains) == 0 {
		// 最后那一句是给升级路径的：曾短暂存在过一个 router.dedicated 字段，
		// 而 Router 走 JSON 落库、encoding/json 默认忽略未知字段 ——
		// 所以一条已经写进库的 {"dedicated":true} 在回退之后会静默变成
		// 「shared + 无域名」并落到这里。不给指引的话用户会看到一条
		// 谁也看不懂的错误。
		return fmt.Errorf("gateway: 隧道 %s 的 router 没有域名；"+
			"若要把它当作端口默认落点，请用 catch_all；"+
			"若原本想要整端口独占，请改用 exposure: port（理由见 BindDedicated 的说明）",
			t.Slug)
	}

	r.mu.Lock()
	b := r.bindingLocked(port)
	dedicated := b.dedicated
	hosts := b.hosts
	r.mu.Unlock()

	if dedicated != nil {
		return fmt.Errorf("%w：端口 %d 已被隧道 %s 独占", ErrRouteConflict, port, dedicated.Slug)
	}

	locations := t.Router.Locations
	if len(locations) == 0 {
		locations = []string{""}
	}

	var errs []error
	for _, d := range t.Router.Domains {
		for _, loc := range locations {
			if err := hosts.Add(d, loc, t); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// 一次返回全部失败，控制台才能一次高亮所有坏字段（与 tunnel.Validate 同风格）。
	return errors.Join(errs...)
}

// View 取一个端口的绑定快照。
//
// 端口 0 是**通配端口**：找不到精确端口时回落到它。测试与「监听端口由系统分配」
// 的场景需要这条，否则每次换端口都要重新注册一遍路由。
func (r *Registry) View(port uint16) (PortView, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	b, ok := r.ports[port]
	if !ok {
		b, ok = r.ports[0]
	}
	if !ok {
		return PortView{}, false
	}
	return PortView{
		Dedicated:          b.dedicated,
		Fallback:           b.fallback,
		TrustProxyProtocol: b.trustProxyProtocol,
		Hosts:              b.hosts,
	}, true
}
