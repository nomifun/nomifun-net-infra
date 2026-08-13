// Package acmecert 用 certmagic 做按需证书签发，并补上它不提供的那道闸门。
//
// # 为什么必须自己写 DecisionFunc，一行都不能省
//
// certmagic 的 on-demand 模式会为**任何**握手里出现的名字去申请证书。
// 它内置了一个限速器（ratelimiter.go），但那是个**排队器不是闸门**：
// acmeclient.go 调的是 rl.Wait(ctx) 而不是 Allow()，粒度是「CA 目录 + 账户」
// 这种全局级别。后果是一大批未注册的 SNI 涌进来时，它们会在 TLS 握手里
// **排队等票**，既不会被拒、又会拖住握手协程。
//
// 更糟的是它**没有失败签发的负缓存**（grep failedIssuance / Backoff 为空）：
// 一个被 CA 拒掉的域名，下一次握手会原样重试。而 Let's Encrypt 的
// failed-validation 限制比成功签发的限制更容易撞上 —— 一个配错的域名
// 就能把整个中继的签发能力烧掉几个小时。
//
// 所以这里的四道闸门是**必需**的，不是加固：
//  1. 名字本身有没有资格（IP 字面量、localhost、.local 一律拒）
//  2. 这个域名在不在我们的路由表里（不在就不是我们的业务）
//  3. per-name 预算（映射 CA 的重复证书限制）
//  4. 全局预算 + 失败负缓存（失败也扣配额）
//
// # 空 SNI 是一条真实的攻击/误用路径
//
// certmagic 在 SNI 为空且 DefaultServerName 也空时，会拿**本地连接 IP**
// 当域名去签发（handshake.go 的 getNameFromClientHello → localIPFromConn）。
// 本产品场景二的扫端口机器人与「ESP32 只认裸 IPv4」都会命中这条路径。
//
// 而 SubjectQualifiesForPublicCert **不足以**挡住它。核实过源码
// （certificates.go:586）：它只调 SubjectIsInternal，而后者对 IP 只判
// **私有/回环**（isInternalIP）。一个**公网** IP 字面量能一路通过 ——
// 它压根不调 SubjectIsIP。
//
// 这一点与研究档案的记载相反（档案说那个函数「含 SubjectIsIP」），
// 是本包的测试抓出来的。所以第 1 道闸门要**显式**拒 IP 字面量。
package acmecert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
)

// HostChecker 报告一个域名是否属于本中继的某条隧道。
//
// 抽成接口而不是直接依赖 internal/gateway：ACME 也要服务 turns:，
// 而那条路径与网关路由表无关。
type HostChecker interface {
	// KnowsHost 报告这个域名是否已注册（隧道路由或 turns: 服务名）。
	KnowsHost(name string) bool
}

// StaticHosts 是一组写死的域名（比如 turns: 的服务名），实现 HostChecker。
//
// turns: 的域名不是隧道，所以查网关路由表查不到它 —— 但它同样需要一张
// 可信证书（客户端会校验，自签会直接握手失败）。
type StaticHosts []string

// KnowsHost 大小写无关地精确匹配。
//
// 精确匹配而非后缀匹配：后缀匹配会让 "evil-example.com" 命中 "example.com"。
func (h StaticHosts) KnowsHost(name string) bool {
	name = normalizeName(name)
	for _, want := range h {
		if normalizeName(want) == name {
			return true
		}
	}
	return false
}

// normalizeName 把一个域名归一化成比较用的形式。
//
// 与 gateway.normalizeHost 一致（小写 + 去根点 + 去空白）。两侧不一致的话
// 「闸门②认识它」与「预算按它分桶」会用不同的键，而那个缝正好是可以钻的：
// certmagic 的 normalizedName 只做 ToLower + TrimSpace，**不去根点**
// （handshake.go:954-956），所以加一个点就是一个新名字。
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// AnyOf 把多个来源并起来：任一认识即认识。
//
// nil 元素会被跳过（调用方常常有「TURN 没启用所以没有 turns: 域名」这种情形，
// 让它在这里被吸收比让每个调用点自己判空更不容易漏）。
func AnyOf(checkers ...HostChecker) HostChecker {
	kept := make([]HostChecker, 0, len(checkers))
	for _, c := range checkers {
		if c != nil {
			kept = append(kept, c)
		}
	}
	return anyOf(kept)
}

type anyOf []HostChecker

func (a anyOf) KnowsHost(name string) bool {
	for _, c := range a {
		if c.KnowsHost(name) {
			return true
		}
	}
	return false
}

// Stats 是签发决策的计量。
//
// 每个字段对应一个 nf_acme_* 指标。拒绝**必须**分原因：
// 「不合资格」是配置问题，「不在路由表」多半是有人在扫，
// 而「撞预算」意味着我们快要被 CA 限速了 —— 三者的处置完全不同。
type Stats struct {
	// Allowed 是通过全部闸门、真的去签发的次数。
	Allowed atomic.Int64

	// DeniedUnqualified 是名字本身没资格（IP 字面量、localhost、.local）。
	//
	// **这个数字在裸 IP 部署下会持续上涨且完全正常** —— 场景二的设备
	// 直接连 IP，没有 SNI。它不是告警，是背景噪声。
	DeniedUnqualified atomic.Int64

	// DeniedUnknownHost 是域名不在路由表里。
	//
	// 持续上涨值得看一眼：正常客户端不会对一个没配过的域名发起握手，
	// 所以它上涨通常意味着有人在拿我们的 IP 试各种域名。
	DeniedUnknownHost atomic.Int64

	// DeniedBudget 是撞上签发预算。
	//
	// 非零就该看：它意味着我们离 CA 的速率限制不远了。
	DeniedBudget atomic.Int64

	// DeniedRecentFailure 是这个域名刚失败过、在负缓存窗口内。
	DeniedRecentFailure atomic.Int64

	// IssueFailed 是**真的打到 CA 又失败**的次数（不含闸门自己的拒绝）。
	//
	// 与 Denied* 分开是因为处置完全不同：Denied* 是我们主动拦下来的，
	// 不消耗 CA 配额；IssueFailed 每一次都消耗了 CA 的 failed-validation
	// 配额，非零就说明有域名配错了（DNS 没指过来、80/443 不通）。
	IssueFailed atomic.Int64
}

// Config 是 ACME 的配置。
type Config struct {
	// Enabled 为 false 时 New 返回 nil manager（调用方据此退回自签）。
	Enabled bool

	// Email 是 ACME 账户邮箱。CA 用它发到期提醒，**必填**。
	Email string

	// CA 是 ACME 目录 URL。空则用 staging。
	//
	// 默认 staging 是**刻意反 certmagic 的默认**（它默认生产环境）：
	// 调试时误打生产配额是不可逆的 —— Let's Encrypt 的 failed-validation
	// 按小时计、重复证书按周计。让生产成为显式选择。
	CA string

	// StorageDir 是证书存储目录，**必须显式给**。
	//
	// certmagic 的默认是 XDG 路径，而 homeDir() 拿不到 HOME 时退化成 "."
	//（容器里 HOME 常为空）—— 于是证书落在当前工作目录，
	// 换 workdir 或重建容器即全丢，下次启动全量重签，直奔速率限制。
	StorageDir string

	// Hosts 判断域名是否属于本中继。为 nil 时**一切都拒**（安全默认）。
	Hosts HostChecker

	// PerNameIssuances 是单个域名在 PerNameWindow 内允许的签发次数。
	// 0 用 DefaultPerNameIssuances。
	PerNameIssuances int
	PerNameWindow    time.Duration

	// GlobalIssuances 是全局签发次数上限（同窗口）。0 用默认。
	GlobalIssuances int

	// FailureCooldown 是某个域名签发失败后的静默期。0 用默认。
	FailureCooldown time.Duration

	Log *slog.Logger
}

// 默认值。
//
// 数值依据 Let's Encrypt 的实际限制：重复证书 5 次/周/精确域名集合，
// failed validation 5 次/小时/账户/域名/挑战类型。
// 我们的预算要**比它更紧**，这样撞到的是我们自己的闸门（可观测、可解释），
// 而不是 CA 的（不可观测、恢复期长）。
const (
	DefaultPerNameIssuances = 5
	DefaultPerNameWindow    = 7 * 24 * time.Hour
	DefaultGlobalIssuances  = 50
	DefaultFailureCooldown  = time.Hour
)

// 决策错误。返回给 certmagic 的 DecisionFunc，非 nil 即拒签。
var (
	ErrUnqualified   = errors.New("acmecert: 名字不适合申请公网证书")
	ErrUnknownHost   = errors.New("acmecert: 域名不在本中继的路由表里")
	ErrBudget        = errors.New("acmecert: 撞上签发预算")
	ErrRecentFailure = errors.New("acmecert: 该域名刚签发失败过，在静默期内")
)

// Manager 是 ACME 证书管理器。
type Manager struct {
	cfg    Config
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer
	log    *slog.Logger
	stats  Stats

	mu sync.Mutex
	// issued 记录每个域名的签发时刻，用于 per-name 预算。
	issued map[string][]time.Time
	// failed 记录每个域名最近一次失败时刻，用于负缓存。
	failed map[string]time.Time
	// total 是窗口内的全局签发时刻。
	total []time.Time
}

// New 装配一个 ACME 管理器。Enabled 为 false 时返回 (nil, nil)。
func New(cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Email == "" {
		// CA 用邮箱发到期提醒。没有它，证书续期失败时没有任何人会知道。
		return nil, errors.New("acmecert: 启用 ACME 必须提供账户邮箱")
	}
	if cfg.StorageDir == "" {
		return nil, errors.New("acmecert: 必须指定证书存储目录（默认路径在容器里会丢证书）")
	}
	if cfg.Hosts == nil {
		// 安全默认：没有域名判断依据时一切都拒，而不是一切都放。
		return nil, errors.New("acmecert: 必须提供域名判断依据（否则会对任意 SNI 申请证书）")
	}
	if cfg.CA == "" {
		cfg.CA = certmagic.LetsEncryptStagingCA
	}
	if cfg.PerNameIssuances <= 0 {
		cfg.PerNameIssuances = DefaultPerNameIssuances
	}
	if cfg.PerNameWindow <= 0 {
		cfg.PerNameWindow = DefaultPerNameWindow
	}
	if cfg.GlobalIssuances <= 0 {
		cfg.GlobalIssuances = DefaultGlobalIssuances
	}
	if cfg.FailureCooldown <= 0 {
		cfg.FailureCooldown = DefaultFailureCooldown
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}

	m := &Manager{
		cfg:    cfg,
		log:    log,
		issued: make(map[string][]time.Time),
		failed: make(map[string]time.Time),
	}

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return m.magic, nil
		},
	})

	m.magic = certmagic.New(cache, certmagic.Config{
		// 必须显式给 Storage，理由见 Config.StorageDir 的说明。
		Storage: &certmagic.FileStorage{Path: cfg.StorageDir},
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: m.decide,
		},
	})

	m.issuer = certmagic.NewACMEIssuer(m.magic, certmagic.ACMEIssuer{
		CA:    cfg.CA,
		Email: cfg.Email,
		// 不设 DNS01Solver。
		//
		// 设了它会**静默禁掉** HTTP-01 与 TLS-ALPN-01
		//（acmeclient.go 是 if DNS01Solver == nil { 注册那两个 } else { 只注册 DNS01 }），
		// 不是「三种都试」。而本产品的用户是家庭/工厂部署，多数没有 DNS API 权限；
		// 给了凭据又过期的话，现象会是「证书签不出来」而不是「DNS 认证失败」。
	})
	m.magic.Issuers = []certmagic.Issuer{m.issuer}

	log.Info("ACME 已启用",
		"CA", cfg.CA, "邮箱", cfg.Email, "存储", filepath.Clean(cfg.StorageDir),
		"每域名预算", fmt.Sprintf("%d 次/%s", cfg.PerNameIssuances, cfg.PerNameWindow),
		"全局预算", cfg.GlobalIssuances,
		"失败静默期", cfg.FailureCooldown)
	if cfg.CA == certmagic.LetsEncryptStagingCA {
		// 必须显式说：staging 签出来的证书浏览器**不信**。
		// 不说的话用户会以为 ACME 接好了却仍然看到证书错误。
		log.Warn("ACME 用的是 staging 环境，签出的证书浏览器不会信任；" +
			"确认流程无误后用 -acme-ca 指向生产环境")
	}
	return m, nil
}

// Stats 返回计量指针。
func (m *Manager) Stats() *Stats { return &m.stats }

// GetCertificate 供 tls.Config 使用。
//
// **不要**直接用 certmagic 的 Config.TLSConfig()：它只设 GetCertificate 与
// NextProtos，会覆盖调用方原有的 NextProtos，而且不设 MinVersion。
//
// # 为什么失败要在这里记
//
// certmagic 不提供签发失败回调，而它自己**没有失败负缓存** —— 被 CA 拒掉的
// 域名下一次握手会原样重试。这个函数是失败唯一的可观测点，所以负缓存必须
// 从这里起。
//
// 不记的后果是具体的：运维把某个已注册域名的 DNS 或 80/443 配错时，
// 每次失败握手都真去打一次 CA，而记账发生在放行时（失败也扣配额），
// 于是刷几下页面就够 5 次 —— 该域名 7 天的预算在几秒内烧光。
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := m.magic.GetCertificate(hello)
	if err != nil {
		m.noteIfIssuanceFailure(nameFromHello(hello), err)
	}
	return cert, err
}

// noteIfIssuanceFailure 只对**真的签发失败**开负缓存。
//
// 闸门自己的拒绝不算：那些请求根本没打到 CA，把它们记成失败会让静默期
// 被无限续期（每次握手都被闸门拒 → 每次都刷新 failed[name] → 永远出不来），
// 而且会把「我们主动拒了」写成「CA 拒了我们」，那是两种完全不同的处置。
func (m *Manager) noteIfIssuanceFailure(name string, err error) {
	if name == "" {
		return
	}
	// 判据：错误链里带我们自己的哨兵就是闸门拒绝。
	//
	// 靠 %w 链成立 —— 核实过 certmagic v0.25.4：DecisionFunc 的错误经
	// checkIfCertShouldBeObtained（handshake.go:488 `fmt.Errorf("decision func: %w", err)`）
	// 与 getCertDuringHandshake（:361 同样用 %w）两层包装后到达这里，
	// errors.Is 一路可用。
	for _, sentinel := range []error{
		ErrUnqualified, ErrUnknownHost, ErrBudget, ErrRecentFailure,
	} {
		if errors.Is(err, sentinel) {
			return
		}
	}
	m.stats.IssueFailed.Add(1)
	// Warn 而不是 Info：这条意味着我们**已经**打过 CA 并被拒，
	// 配额已经扣掉了。它是运维要立刻看的东西。
	m.log.Warn("签发失败，开始静默期",
		"name", name, "静默期", m.cfg.FailureCooldown, "err", err)
	m.NoteFailure(name)
}

// nameFromHello 取 ClientHello 里的服务名。
//
// **不**在 SNI 为空时回落到本地连接 IP（certmagic 自己会那样做）：
// 那个名字必然被闸门①拒掉，永远不该进负缓存表 —— 否则场景二那些用裸 IP
// 直连的设备会往这张表里塞条目，而表的键是外部可指定的。
func nameFromHello(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	return normalizeName(hello.ServerName)
}

// HandleACMEConn 处理一条 ALPN 为 acme-tls/1 的连接，完成 TLS-ALPN-01 挑战。
//
// 装到 gateway.DiscriminatorConfig.ACME 上。
//
// # 为什么必须由我们喂给它
//
// certmagic 的 TLS-ALPN-01 solver 会自己去 bind :443，而那个端口已经被
// 判别器占了。它探测到「address already in use」后**返回 (nil, nil) 静默
// 假设「占用者会自己应答挑战」**，只打一条 WARNING 到标准 log。
// 也就是说：如果我们不把 acme-tls/1 连接交给 GetCertificate，
// 挑战会**静默失败**，而日志里只有一行容易被忽略的警告。
func (m *Manager) HandleACMEConn(c net.Conn) {
	defer c.Close()

	// 只用于挑战：ALPN 固定 acme-tls/1，MinVersion 保持我们自己的下限。
	// CurvePreferences 保持 nil —— 手动设置会静默关掉后量子曲线。
	tc := tls.Server(c, &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{ACMETLSALPNProto},
		MinVersion:     tls.VersionTLS12,
	})
	// 挑战只需要握手成功：CA 验证的是握手里那张特殊证书。
	// 握手完就可以关，不需要读写任何应用数据。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		m.log.Debug("ACME 挑战握手失败", "err", err)
	}
}

// ACMETLSALPNProto 是 TLS-ALPN-01 的 ALPN 标识（RFC 8737）。
const ACMETLSALPNProto = "acme-tls/1"

// HTTPChallengeHandler 把 HTTP-01 挑战挂到调用方自己的 :80 上。
//
// 作**备份**路径而不是主路径：家庭宽带封 80 很常见。
// 主路径是 TLS-ALPN-01（只需要 443，而 443 本来就要监听）。
func (m *Manager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.issuer.HandleHTTPChallenge(w, r) {
			return
		}
		if fallback != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// ── 决策 ────────────────────────────────────────────────────────────────────

// decide 是 certmagic 的 DecisionFunc：返回非 nil 即拒签。
//
// 四道闸门，顺序不能换：先便宜后贵，且先「一定不该签」后「暂时不该签」。
func (m *Manager) decide(ctx context.Context, name string) error {
	// 先归一化。
	//
	// certmagic 的 normalizedName 只做 ToLower + TrimSpace，**不去根点**
	//（handshake.go:954-956），所以 "web.example.com." 与 "web.example.com"
	// 在它眼里是两个名字。我们的 per-name 预算若跟着它分桶，攻击者靠加一个点
	// 就能多拿一份 5 次的配额 —— 加两个点、加大小写变体还能再多拿。
	// 记账用归一化后的键，闸门②那边网关的 normalizeHost 本来就去点，两侧一致。
	name = normalizeName(name)

	// 再清过期记录。
	//
	// 放在最前面而不是预算判定处：那里在闸门 ①② 之后，
	// 而一个只发未注册域名的扫描器永远走不到那里 —— 于是合法域名的
	// 过期记录会一直留着，直到下一次合法握手。清理必须与「这次决策的结果」
	// 无关，否则它的触发条件就取决于攻击者发什么。
	m.pruneNow()

	// ① 名字本身有没有资格。
	//
	// 两个检查都要：
	//   * SubjectIsIP 拒 IP 字面量。**必须显式调它** ——
	//     SubjectQualifiesForPublicCert 只调 SubjectIsInternal，
	//     而后者对 IP 只判私有/回环，公网 IP 字面量能一路通过
	//     （核实过 certificates.go:586，与研究档案的记载相反）。
	//     而空 SNI 时 certmagic 会拿本地连接 IP 当域名 —— 那个地址
	//     在有公网 IP 的中继上正是一个公网 IP。
	//   * SubjectQualifiesForPublicCert 拒 localhost、.local、.internal、
	//     .home.arpa 与非法通配符。
	if certmagic.SubjectIsIP(name) || !certmagic.SubjectQualifiesForPublicCert(name) {
		m.stats.DeniedUnqualified.Add(1)
		// Debug 而不是 Warn：裸 IP 部署下这条会持续出现且完全正常
		//（场景二的设备直接连 IP，没有 SNI）。
		m.log.Debug("拒绝签发：名字不适合公网证书", "name", name)
		return fmt.Errorf("%w：%s", ErrUnqualified, name)
	}

	// ② 这个域名是不是我们的业务。
	if !m.cfg.Hosts.KnowsHost(name) {
		m.stats.DeniedUnknownHost.Add(1)
		// Info：正常客户端不会对没配过的域名发起握手，
		// 所以持续上涨通常意味着有人在拿我们的 IP 试域名。
		m.log.Info("拒绝签发：域名不在路由表里", "name", name)
		return fmt.Errorf("%w：%s", ErrUnknownHost, name)
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// ③ 失败负缓存。
	//
	// certmagic 没有失败退避，一个被 CA 拒掉的域名下一次握手会原样重试。
	// 而 CA 的 failed-validation 限制比成功签发的更容易撞上 ——
	// 一个配错的域名能把整个中继的签发能力烧掉几个小时。
	if at, ok := m.failed[name]; ok && now.Sub(at) < m.cfg.FailureCooldown {
		m.stats.DeniedRecentFailure.Add(1)
		return fmt.Errorf("%w：%s（还剩 %s）",
			ErrRecentFailure, name, (m.cfg.FailureCooldown - now.Sub(at)).Round(time.Second))
	}

	// ④ 预算：per-name 与全局。
	if len(m.issued[name]) >= m.cfg.PerNameIssuances {
		m.stats.DeniedBudget.Add(1)
		m.log.Warn("拒绝签发：该域名撞上预算",
			"name", name, "上限", m.cfg.PerNameIssuances, "窗口", m.cfg.PerNameWindow)
		return fmt.Errorf("%w：%s 在 %s 内已签发 %d 次",
			ErrBudget, name, m.cfg.PerNameWindow, len(m.issued[name]))
	}
	if len(m.total) >= m.cfg.GlobalIssuances {
		m.stats.DeniedBudget.Add(1)
		m.log.Warn("拒绝签发：全局预算已满", "上限", m.cfg.GlobalIssuances)
		return fmt.Errorf("%w：全局 %s 内已签发 %d 次",
			ErrBudget, m.cfg.PerNameWindow, len(m.total))
	}

	// 记账**在这里**而不是签发成功之后。
	//
	// 因为失败也要扣配额：CA 的 failed-validation 限制就是按尝试次数算的。
	// 只在成功后记账等于让失败无限重试 —— 那正是最容易烧掉配额的路径。
	m.issued[name] = append(m.issued[name], now)
	m.total = append(m.total, now)
	m.stats.Allowed.Add(1)
	return nil
}

// NoteFailure 记录一次签发失败，开始负缓存。
//
// 由调用方在观察到签发失败时调用。certmagic 不提供失败回调，
// 所以这条路径要靠上层（比如 GetCertificate 返回错误时）触发。
func (m *Manager) NoteFailure(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed[name] = time.Now()
}

// pruneNow 取锁并丢弃窗口外的记录。
func (m *Manager) pruneNow() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now())
}

// pruneLocked 丢弃窗口外的记录。调用方须持锁。
//
// 顺手清理而不是靠定时器：预算只在有握手时才需要推进，
// 没有流量时也就不需要清理。
func (m *Manager) pruneLocked(now time.Time) {
	cutoff := now.Add(-m.cfg.PerNameWindow)

	for name, times := range m.issued {
		kept := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(m.issued, name)
			continue
		}
		m.issued[name] = kept
	}

	kept := m.total[:0]
	for _, t := range m.total {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	m.total = kept

	// 负缓存也要清，否则它随域名数无界增长 —— 中继是长期运行的进程，
	// 而域名可以由任何人在握手里指定。
	failCutoff := now.Add(-m.cfg.FailureCooldown)
	for name, at := range m.failed {
		if at.Before(failCutoff) {
			delete(m.failed, name)
		}
	}
}

// Budget 返回当前预算用量，供控制台与指标使用。
func (m *Manager) Budget() (perNameUsed map[string]int, globalUsed, globalLimit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now())

	perNameUsed = make(map[string]int, len(m.issued))
	for name, times := range m.issued {
		perNameUsed[name] = len(times)
	}
	return perNameUsed, len(m.total), m.cfg.GlobalIssuances
}

// IsStaging 报告当前用的是不是 staging CA（控制台要显著标注）。
func (m *Manager) IsStaging() bool {
	return strings.Contains(m.cfg.CA, "staging") ||
		m.cfg.CA == certmagic.LetsEncryptStagingCA
}
