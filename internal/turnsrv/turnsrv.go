// Package turnsrv 把 pion/turn 包成一个可嵌入的 TURN/STUN 服务，
// 并补上它不提供的三件东西：对端地址过滤、字节计量、全局配额。
//
// # 为什么必须包一层，不能照抄示例
//
// pion/turn 的 PermissionHandler 若留 nil，会用 DefaultPermissionHandler ——
// 它 `return true`，**放行一切对端**（server_config.go:48-51）。照抄示例得到的
// 就是一台通向本机私网的开放中继：任何拿到凭据的人 CreatePermission 到
// 127.0.0.1 或 10.0.0.0/8，就能把流量中继进中继主机的内网，
// 而 169.254.169.254 更是一次请求换一套云凭据。coturn 有 denied-peer-ip
// 正是为此。所以本包**默认拒绝**私有与特殊用途地址。
//
// 另外两件（研究文档 15 §A6 已核实）：pion/turn 既不暴露带宽计数器、
// 也没有枚举分配的 API。它的 client-facing 监听器**从不自己开 socket**
// （由我们传入 net.PacketConn / net.Listener），这正是计量的挂钩点；
// 中继端口是每分配一个，所以字节数能干净地归属到分配上。
package turnsrv

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"

	"github.com/nomifun/nomifun-net-infra/internal/policy"
)

// Stats 是 TURN 服务的计量。
//
// 每个字段都对应一个 nf_turn_* 指标。丢弃/拒绝要分原因：
// 配额满要加上限，对端被拒要看是不是有人在拿它当跳板 ——
// 后者是安全事件，混在一个「失败数」里就看不见了。
type Stats struct {
	// Relayed 是经中继端口搬运的字节数（上行 + 下行）。
	RelayedBytesUp   atomic.Int64
	RelayedBytesDown atomic.Int64
	RelayedPacketsUp atomic.Int64

	// AllocationsCreated 是累计分配数（当前数由 AllocationCount 给出）。
	AllocationsCreated atomic.Int64

	// PeerDenied 是被对端过滤挡掉的 CreatePermission / ChannelBind 次数。
	//
	// **这个数字非零就该看一眼**：正常的 WebRTC 客户端不会请求中继到
	// 私有地址，所以它上涨意味着有人在探路。
	PeerDenied atomic.Int64

	// QuotaRejected 是撞上全局分配上限的次数。
	QuotaRejected atomic.Int64

	// AuthFailed 是鉴权失败次数。临时凭据过期也会计入，
	// 所以它上涨不一定是攻击 —— 但持续上涨且没有成功分配就值得看。
	AuthFailed atomic.Int64

	// AllocationErrors 是分配读循环异常退出的次数。
	AllocationErrors atomic.Int64
}

// Config 是 TURN 服务参数。
type Config struct {
	// Realm 是 TURN realm，进 MESSAGE-INTEGRITY 的密钥推导。
	Realm string

	// PublicIP 是告知客户端的中继地址。
	//
	// 必须是**真实可达**的地址。RelayAddressGeneratorPortRange 把它原样
	// 写进 XOR-RELAYED-ADDRESS 而绑定的是 Address（0.0.0.0）——
	// 填错的话客户端会往一个不存在的地址发媒体，表现为「ICE 连不上」。
	// 1:1 NAT 后面填公网 IP。
	PublicIP netip.Addr

	// ListenAddr 是 STUN/TURN 的明文监听地址（UDP + TCP），默认 ":3478"。
	ListenAddr string

	// TLSAddr 是 turns: 的监听地址，为空则不起。默认端口 5349。
	TLSAddr string

	// TLSConfig 供 turns: 使用。TLSAddr 非空时必填。
	TLSConfig *tls.Config

	// MinPort/MaxPort 是中继端口范围。
	//
	// **必须有界**：一个分配占一个中继 UDP 端口，所以
	// MaxPort-MinPort+1 就是并发分配的硬上限，也是防火墙上要放行的范围。
	MinPort, MaxPort uint16

	// Secret 是临时凭据的 HMAC 密钥，与 coturn 的 use-auth-secret 逐字节兼容。
	Secret []byte

	// MaxAllocations 是全局分配上限，<=0 时按端口范围推导。
	MaxAllocations int

	// PeerAllow 是**额外**放行的对端网段。
	//
	// 默认只放行全球单播：私有段、回环、链路本地（含云元数据）一律拒绝。
	// 需要中继到私有地址的场景（例如全内网的会议）在这里显式开通 ——
	// 显式开通与默认放行的区别，就是「运维知道自己开了什么」。
	PeerAllow []netip.Prefix

	// allowLoopbackPeers 允许把媒体中继到回环。
	//
	// **故意不导出。** 只有本包的测试能设它 —— 端到端测试必须让 TURN 客户端
	// 与媒体对端都跑在 127.0.0.1 上，那是唯一在任何 CI 上都可达的地址。
	// 而在生产里中继到回环等于把中继主机上的任何本地服务（包括控制台本身）
	// 暴露给任何持有临时凭据的人，而凭据本来就是发给浏览器/App 的。
	//
	// 用「不导出的字段」而不是「导出的字段 + 文档说别用」：
	// 后者迟早会被某个部署脚本设成 true，而前者在编译期就不可能。
	allowLoopbackPeers bool

	Log *slog.Logger
}

// 默认值。
const (
	// DefaultListenAddr 是 RFC 7065 的 turn: 默认端口。
	DefaultListenAddr = ":3478"
	// DefaultTLSPort 是 RFC 7065 的 turns: 默认端口。
	DefaultTLSPort = 5349

	// DefaultMinPort/DefaultMaxPort 是默认中继端口范围（241 个端口）。
	//
	// 家用中继同时几十路通话已经很多；范围设在「远高于正常用量、
	// 又小到防火墙规则不至于形同虚设」的区间。
	DefaultMinPort uint16 = 49160
	DefaultMaxPort uint16 = 49400

	// DefaultCredentialTTL 是临时凭据的默认有效期。
	//
	// 10 分钟而不是几小时：凭据泄露的暴露窗口应当短，浏览器侧靠
	// setConfiguration 刷新即可（研究文档 15 §A5）。
	DefaultCredentialTTL = 10 * time.Minute
)

// Server 是一个运行中的 TURN 服务。
type Server struct {
	// srv 必须是原子指针。
	//
	// turn.NewServer **在返回之前就启动了读循环**（NewServer.gowrap1 →
	// readLoop），所以 QuotaHandler 可能在我们把返回值赋给字段**之前**
	// 就被调用。普通字段在这里是一次真实的数据竞争 —— 竞态检测器抓到了它，
	// 而危害不止于「测试偶发失败」：那个窗口里配额检查会被静默跳过，
	// 一批早到的 Allocate 请求就全部放行、无视上限。
	srv atomic.Pointer[turn.Server]

	cfg   Config
	log   *slog.Logger
	stats Stats

	// peers 是对端地址过滤器（含私有段等本地拒绝规则）。
	peers *policy.Policy

	// base 只带**永久**拒绝段（云元数据、链路本地、多播等），没有本地规则。
	//
	// 分成两个策略是为了让判定分层：永久拒绝段绝对优先，
	// 显式开通的网段次之，本地拒绝规则最后。
	// 只用一个策略做不到这件事 —— 见 permit 的说明。
	base *policy.Policy

	// peerAllow 是用户显式开通的对端网段。
	peerAllow []netip.Prefix

	// reg 是自己维护的分配表 —— pion 不提供枚举分配的 API。
	reg *registry

	// udpAddr 是实际绑定的 UDP 地址。
	//
	// 配置里写 :0 时它才有价值 —— 但那正是测试与容器环境的常见写法，
	// 而「日志里只说 :0」等于没说。
	udpAddr *net.UDPAddr

	closers []func() error

	closeOnce sync.Once
}

// New 起一个 TURN 服务。
func New(cfg Config) (*Server, error) {
	if cfg.Realm == "" {
		return nil, errors.New("turnsrv: 必须指定 realm")
	}
	if !cfg.PublicIP.IsValid() {
		// 不给默认值。猜一个地址的后果是客户端往错处发媒体，
		// 表现为「ICE 连不上」——那是最难查的一类故障。
		return nil, errors.New("turnsrv: 必须指定 public_ip（告知客户端的中继地址）")
	}
	if len(cfg.Secret) == 0 {
		return nil, errors.New("turnsrv: 必须指定临时凭据密钥")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.MinPort == 0 {
		cfg.MinPort = DefaultMinPort
	}
	if cfg.MaxPort == 0 {
		cfg.MaxPort = DefaultMaxPort
	}
	if cfg.MinPort > cfg.MaxPort {
		return nil, fmt.Errorf("turnsrv: 中继端口范围非法：%d > %d", cfg.MinPort, cfg.MaxPort)
	}
	if cfg.MaxAllocations <= 0 {
		// 一个分配占一个中继端口，所以端口数就是天然上限。
		cfg.MaxAllocations = int(cfg.MaxPort-cfg.MinPort) + 1
	}
	if cfg.TLSAddr != "" && cfg.TLSConfig == nil {
		return nil, errors.New("turnsrv: 配了 turns: 监听地址但没给 TLS 配置")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}

	peers, base, err := newPeerPolicies(cfg.PublicIP, cfg.allowLoopbackPeers)
	if err != nil {
		return nil, err
	}
	// 显式开通的网段若整段落在永久拒绝段里，那是配置错误 ——
	// 用户以为自己开通了，而它永远不会通。当场报错而不是让人线上排查。
	for _, p := range cfg.PeerAllow {
		if d := base.CheckAddr(netip.AddrPortFrom(p.Addr(), 1)); !d.Allowed {
			return nil, fmt.Errorf(
				"turnsrv: 开通的对端网段 %s 落在永久拒绝段里（%s），永远不会生效", p, d.Reason)
		}
	}

	s := &Server{
		cfg: cfg, log: log,
		peers: peers, base: base, peerAllow: cfg.PeerAllow,
		reg: newRegistry(),
	}

	// 客户端侧监听器由**我们**创建 —— pion/turn 从不自己开 socket。
	// 这既是计量的挂钩点，也让 turns: 将来能接进 443 的多路复用。
	//
	// 钉 udp4/tcp4 而不是双栈：v5.0.10 起，客户端省略
	// REQUESTED-ADDRESS-FAMILY 时会跟随监听器的地址族，双栈监听会让
	// 省略该属性的浏览器拿到一个 IPv6 中继地址。IPv6 中继留作
	// 「有真实浏览器可测时」的后续项（见 README 缺口清单）。
	udpConn, tcpLn, err := listenPair(cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, udpConn.Close)
	s.udpAddr, _ = udpConn.LocalAddr().(*net.UDPAddr)
	s.closers = append(s.closers, tcpLn.Close)

	listeners := []turn.ListenerConfig{{
		Listener:              tcpLn,
		RelayAddressGenerator: s.newRelayGenerator(),
		PermissionHandler:     s.permit,
	}}

	if cfg.TLSAddr != "" {
		tlsLn, err := tls.Listen("tcp4", cfg.TLSAddr, cfg.TLSConfig)
		if err != nil {
			s.closeAll()
			return nil, fmt.Errorf("turnsrv: 监听 TLS %s 失败：%w", cfg.TLSAddr, err)
		}
		s.closers = append(s.closers, tlsLn.Close)
		listeners = append(listeners, turn.ListenerConfig{
			Listener:              tlsLn,
			RelayAddressGenerator: s.newRelayGenerator(),
			PermissionHandler:     s.permit,
		})
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		// 临时凭据（TURN REST API）：用户名是 "<过期时间戳>:<用户标识>"，
		// 口令是 base64(HMAC-SHA1(secret, 用户名))。与 coturn 的
		// use-auth-secret 逐字节兼容，所以控制台签发的凭据也能喂给 coturn ——
		// turn.mode: external 这条逃生口因此是真的可用，不是纸面承诺。
		AuthHandler: s.wrapAuth(turn.LongTermTURNRESTAuthHandler(string(cfg.Secret), nil)),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            udpConn,
			RelayAddressGenerator: s.newRelayGenerator(),
			PermissionHandler:     s.permit,
		}},
		ListenerConfigs: listeners,
		QuotaHandler:    s.quota,
		// EventHandler 是 pion 给的唯一生命周期钩子，我们用它自己
		// 维护一张分配表（它没有枚举分配的 API）。
		EventHandler: s.eventHandler(),
	})
	if err != nil {
		s.closeAll()
		return nil, fmt.Errorf("turnsrv: 启动失败：%w", err)
	}
	s.srv.Store(srv)

	log.Info("TURN 已就绪",
		"realm", cfg.Realm, "监听", s.Addr(), "turns", cfg.TLSAddr,
		"公网地址", cfg.PublicIP.String(),
		"中继端口", fmt.Sprintf("%d-%d", cfg.MinPort, cfg.MaxPort),
		"分配上限", cfg.MaxAllocations)

	// 显式开通的网段必须**逐条打出来**。
	//
	// -turn-peer-allow 是这个组件里唯一能扩大暴露面的参数，而它接受的是
	// CIDR —— 一个手误（写 /8 而不是 /24）会开通 1600 万个地址而不是 254 个。
	// 启动时不打印的话，运维没有任何机会发现自己开通了什么：
	// 界面上没有这一项，日志里也没有，只有真的被利用之后才知道。
	if len(cfg.PeerAllow) > 0 {
		for _, p := range cfg.PeerAllow {
			log.Warn("TURN 已显式开通对端网段（默认拒绝之外）",
				"网段", p.String(), "地址数", prefixSize(p))
		}
	}
	return s, nil
}

// prefixSize 给出一个网段里的地址数，用于日志。
//
// 写成人能一眼看懂的形式：运维看到「地址数 16777216」会立刻发现自己把
// /24 写成了 /8，而看到「10.0.0.0/8」不一定会。
func prefixSize(p netip.Prefix) string {
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	host := bits - p.Bits()
	if host >= 63 {
		return "极大（IPv6 段）"
	}
	return fmt.Sprintf("%d", uint64(1)<<uint(host))
}

// listenPair 在同一个端口上同时拿到 UDP 与 TCP 监听。
//
// # 为什么两者必须同端口
//
// 客户端从 turn: URI 只得到**一个**端口号，UDP 与 TCP 都往那里连。
// 两者端口不同的 TURN 服务是坏的：UDP 试通了而 TCP 回退试到一个空端口，
// 表现为「有时能连有时不能」——最难查的那类故障。
//
// # 为什么 :0 需要重试
//
// UDP 与 TCP 的端口空间是**独立**的。让内核挑一个空闲 UDP 端口，
// 那个号在 TCP 上完全可能已被占用 —— 于是启动失败并给出一句
// 「address already in use」，而用户配的是 :0、压根没指定端口。
//
// 这不是测试才会遇到的事：容器编排与「让系统分配端口」的部署都用 :0。
// 所以重试几次，而不是把一个可恢复的竞争变成启动失败。
//
// 钉 udp4/tcp4 而不是双栈：pion v5.0.10 起，客户端省略
// REQUESTED-ADDRESS-FAMILY 时会跟随监听器的地址族，双栈监听会让
// 省略该属性的浏览器拿到一个 IPv6 中继地址。
func listenPair(addr string) (net.PacketConn, net.Listener, error) {
	const attempts = 8

	explicit := portOf(addr) != "0" && portOf(addr) != ""

	var lastErr error
	for i := 0; i < attempts; i++ {
		udpConn, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("turnsrv: 监听 UDP %s 失败：%w", addr, err)
		}

		tcpAddr := addr
		if ua, ok := udpConn.LocalAddr().(*net.UDPAddr); ok && !explicit {
			tcpAddr = net.JoinHostPort(ua.IP.String(), strconv.Itoa(ua.Port))
		}

		tcpLn, err := net.Listen("tcp4", tcpAddr)
		if err == nil {
			return udpConn, tcpLn, nil
		}
		_ = udpConn.Close()
		lastErr = err

		if explicit {
			// 端口是用户显式指定的：重试没有意义，它不会变。
			return nil, nil, fmt.Errorf("turnsrv: 监听 TCP %s 失败：%w", tcpAddr, err)
		}
	}
	return nil, nil, fmt.Errorf(
		"turnsrv: 试了 %d 次都没能在同一个端口上同时拿到 UDP 与 TCP 监听：%w",
		attempts, lastErr)
}

// newPeerPolicies 造两个策略：带本地拒绝规则的，与只带永久拒绝段的。
//
// 复用 internal/policy 而不是另写一套判定：那里已经有云元数据永久黑名单、
// IPv4-in-IPv6 规范化（::ffff:127.0.0.1 不做 unmap 就能绕过 IPv4 黑名单）、
// 以及「allow 真包含 deny 是安全的」这套语义，并且都测过了。
//
// 注意语义与 agent 侧**相反**：agent 的用途是暴露内网服务，所以默认放行
// 私有段；TURN 的用途是中继外部对端之间的媒体，私有段必须拒 ——
// 同一套机制，两套策略。
func newPeerPolicies(publicIP netip.Addr, allowLoopback bool) (peers, base *policy.Policy, err error) {
	// 放行全部，再逐段扣除。0.0.0.0/0 真包含所有永久拒绝段，
	// 按 policy.New 的语义这是「安全的包含」而非配置错误。
	allowAll := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	// permanent 是**显式开通也不能放行**的段（判定第一层）。
	//
	// 回环必须在这里而不是在 deny 里：deny 只进第三层，而第二层
	// （PeerAllow）在它之前就短路返回 true。于是一个含回环但不以 127 起头的
	// 网段（126.0.0.0/7、64.0.0.0/2，或者干脆 127.0.0.1/32）就能开通回环 ——
	// 而中继到 127.0.0.1 等于把中继主机上的任何本地服务（包括控制台本身）
	// 暴露给任何持有 TURN 凭据的人，而凭据本来就是发给浏览器/App 的。
	//
	// 私有段仍然留在 deny（第三层）：「开通一个私有子段」是文档承诺的用法，
	// 家庭部署里把媒体中继到 192.168.x.x 是合理的。回环不是。
	permanent := []netip.Prefix{}
	if !allowLoopback {
		permanent = append(permanent,
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"))
	}
	// 中继主机自己的地址也是永久拒绝段。
	//
	// 不加它的话，回环那条拒绝可以**用公网 IP 绕过**：任何持一对临时凭据的人
	// 都能让 TURN 中继到 <中继公网 IP>:<任意端口> —— 于是控制台（若绑在
	// 非 loopback）、agent 承载端口、以及所有裸端口隧道都对他敞开，
	// 而这些服务本来只在「用户自己能连到」的假设下暴露。
	//
	// 枚举本机所有地址而不是只加 PublicIP：多宿主主机上别的地址同样可达，
	// 而攻击者能从 STUN 响应或 DNS 里拿到它们。
	if !allowLoopback {
		permanent = append(permanent, selfPrefixes(publicIP)...)
	}

	deny := []netip.Prefix{
		// RFC 1918 私有段：中继主机所在的内网。
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
		// 运营商级 NAT 与基准测试保留段 —— 都不是合法的媒体对端。
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("198.18.0.0/15"),
		// 文档用段。
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),

		// ── 内嵌 IPv4 的 IPv6 形式 ────────────────────────────────
		//
		// 这几段都能把一个 IPv4 地址写成 IPv6 的样子。在开了相应转换的
		// 主机上，中继到 64:ff9b::a00:1 就等于中继到 10.0.0.1 ——
		// 而上面那些 IPv4 前缀检查一条都不会命中，因为地址族不同。
		//
		// netip 的 Is4In6 只认 ::ffff:a.b.c.d 这一种（policy.CheckAddr
		// 已经处理），其余几种必须显式列出。它们也从来不是合法的媒体对端。
		netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 众所周知前缀（RFC 6052）
		netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 本地前缀（RFC 8215）
		netip.MustParsePrefix("2002::/16"),      // 6to4（RFC 3056）
		netip.MustParsePrefix("2001::/32"),      // Teredo（RFC 4380）
		netip.MustParsePrefix("::/96"),          // 已废弃的 IPv4-compatible
	}

	peers, err = policy.New(policy.Config{Allow: allowAll, Deny: append(deny, permanent...)})
	if err != nil {
		return nil, nil, fmt.Errorf("turnsrv: 对端过滤策略非法：%w", err)
	}
	// base 只带 permanent，所以第一层会拒绝「显式开通也不能放行」的段：
	// policy 包自己的默认永久拒绝段（云元数据、链路本地、多播），
	// 加上回环与中继主机自己的地址。
	base, err = policy.New(policy.Config{Allow: allowAll, Deny: permanent})
	if err != nil {
		return nil, nil, fmt.Errorf("turnsrv: 永久拒绝段策略非法：%w", err)
	}
	return peers, base, nil
}

// selfPrefixes 列出中继主机自己的地址（各自 /32 或 /128）。
//
// 拿不到接口列表时退回只加 publicIP —— 那是攻击者最容易知道的一个
// （STUN 响应里就有），少几个总比一个都没有好。
func selfPrefixes(publicIP netip.Addr) []netip.Prefix {
	out := []netip.Prefix{}
	add := func(a netip.Addr) {
		if !a.IsValid() {
			return
		}
		a = a.Unmap()
		bits := 32
		if a.Is6() {
			bits = 128
		}
		p := netip.PrefixFrom(a, bits)
		if slices.Contains(out, p) {
			return
		}
		out = append(out, p)
	}
	add(publicIP)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
			add(ip)
		}
	}
	return out
}

// inAny 报告 addr 是否落在任一前缀内（地址族必须一致）。
func inAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return true
		}
	}
	return false
}

// permit 是 PermissionHandler：过滤 CreatePermission 与 ChannelBind 的对端地址。
// permit 是 PermissionHandler：过滤 CreatePermission 与 ChannelBind 的对端地址。
//
// # 判定分三层，顺序不能换
//
//  1. **永久拒绝段**（云元数据、链路本地、多播）—— 绝对优先，
//     显式开通也不能放它过去。
//  2. **显式开通的网段** —— 用户明确要求中继到这里。
//  3. **本地拒绝规则**（私有段、CGNAT 等）—— 默认拒绝。
//
// 为什么不能只用一个策略：policy.CheckAddr 的顺序是 deny 先于 allow，
// 这个通用规则是对的。但那意味着「开通一个私有子段」只能靠把对应的 deny
// 段删掉 —— 而删掉 10.0.0.0/8 来开通 10.0.0.0/24，等于用户要开 254 个地址
// 却开了 1600 万个。CIDR 相减（把 /8 减成一堆不含 /24 的子段）正是
// policy 包注释里警告过的做法：「错了反而扩大暴露面」。
// 所以显式开通在**这一层**判定，deny 列表保持完整。
func (s *Server) permit(clientAddr net.Addr, peerIP net.IP) bool {
	addr, ok := netip.AddrFromSlice(peerIP)
	if !ok {
		s.stats.PeerDenied.Add(1)
		return false
	}
	// 规范化，与 policy.CheckAddr 内部一致 —— 否则 ::ffff:10.0.0.1
	// 不会命中下面按 IPv4 写的开通网段。
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	// 端口在这一层拿不到（PermissionHandler 只给 IP），用 1 占位 ——
	// 我们的对端策略只按网段判定，不涉及端口。
	ap := netip.AddrPortFrom(addr, 1)

	// 第一层：永久拒绝段，绝对优先。
	if d := s.base.CheckAddr(ap); !d.Allowed {
		s.stats.PeerDenied.Add(1)
		s.log.Warn("TURN 拒绝了对端地址（永久拒绝段）",
			"客户端", clientAddr.String(), "对端", addr.String(),
			"规则", d.Rule, "原因", d.Reason)
		return false
	}

	// 第二层：显式开通的网段。
	if inAny(s.peerAllow, addr) {
		return true
	}

	// 第三层：本地拒绝规则。
	if d := s.peers.CheckAddr(ap); !d.Allowed {
		s.stats.PeerDenied.Add(1)
		// 记成 Warn 而不是 Debug：正常的 WebRTC 客户端不会请求中继到
		// 私有地址，所以这条日志出现意味着有人在拿 TURN 当跳板探内网。
		s.log.Warn("TURN 拒绝了对端地址",
			"客户端", clientAddr.String(), "对端", addr.String(),
			"规则", d.Rule, "原因", d.Reason)
		return false
	}
	return true
}

// wrapAuth 把 pion 的鉴权处理器包一层，只为了**把它漏掉的失败计上**。
//
// # pion 的 OnAuth 回调覆盖不全
//
// 核实过 v5.0.12 的 internal/server/util.go：AuthHandler 返回 !ok 时
// （凭据过期、用户名未知、时间戳不是数字）它**直接返回**，
// 根本不调 genAuthEvent。OnAuth(verdict=false) 只在用户名/realm 都对、
// 而 MESSAGE-INTEGRITY 校验失败时才触发 —— 也就是只覆盖「口令错」。
//
// 而 allocations.go 里那段注释写的恰恰是「临时凭据的过期也会走到这里」。
// 那句话是错的：AuthFailed 对过期凭据、未知用户名、任意垃圾 USERNAME 恒不增。
// 于是「有人在拿旧凭据反复重试」与「有人在喷用户名」这两件事在指标上完全看不见。
func (s *Server) wrapAuth(inner turn.AuthHandler) turn.AuthHandler {
	return func(attrs *turn.RequestAttributes) (string, []byte, bool) {
		userID, key, ok := inner(attrs)
		if !ok {
			s.stats.AuthFailed.Add(1)
			// Info 而不是 Warn：临时凭据过期是**正常**现象（客户端拿着一张
			// 到期的凭据重试一次就会命中），持续上涨才值得看。
			s.log.Info("TURN 鉴权失败：凭据不被接受",
				"来源", attrs.SrcAddr.String(), "用户", attrs.Username,
				"方法", attrs.Method.String())
		}
		return userID, key, ok
	}
}

// quota 是 QuotaHandler：撞上限时返回 false，客户端收到 486。
func (s *Server) quota(username, realm string, srcAddr net.Addr) bool {
	srv := s.srv.Load()
	if srv == nil {
		// 还在 turn.NewServer 里面（它先起读循环再返回）。此刻分配数
		// 必然是 0，所以放行是**正确**结果而不是权宜之计。
		return true
	}
	if srv.AllocationCount() >= s.cfg.MaxAllocations {
		s.stats.QuotaRejected.Add(1)
		s.log.Warn("TURN 分配已达上限，拒绝新分配",
			"上限", s.cfg.MaxAllocations, "用户", username, "来源", srcAddr.String())
		return false
	}
	return true
}

// Addr 返回实际绑定的监听地址（host:port）。
//
// 配置里写 :0 时这是唯一能知道真实端口的途径。
func (s *Server) Addr() string {
	if s.udpAddr == nil {
		return s.cfg.ListenAddr
	}
	return net.JoinHostPort(s.udpAddr.IP.String(), strconv.Itoa(s.udpAddr.Port))
}

// portOf 取 host:port 里的 port，取不出来时返回空串。
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// AllocationCount 返回当前分配数。
func (s *Server) AllocationCount() int {
	if srv := s.srv.Load(); srv != nil {
		return srv.AllocationCount()
	}
	return 0
}

// Stats 返回计量指针。
func (s *Server) Stats() *Stats { return &s.stats }

// Close 关闭服务。可重复调用。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if srv := s.srv.Load(); srv != nil {
			err = srv.Close()
		}
		s.closeAll()
	})
	return err
}

func (s *Server) closeAll() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		_ = s.closers[i]()
	}
	s.closers = nil
}

// ── 凭据 ────────────────────────────────────────────────────────────────────

// Credential 是一对临时 TURN 凭据。
type Credential struct {
	Username  string    `json:"username"`
	Password  string    `json:"credential"`
	ExpiresAt time.Time `json:"expires_at"`
	TTL       int       `json:"ttl_seconds"`
}

// MintCredential 签发一对临时凭据。
//
// 格式与 coturn 的 use-auth-secret 逐字节相同：
// 用户名 "<过期时间戳>:<用户标识>"，口令 base64(HMAC-SHA1(secret, 用户名))。
// 所以控制台签发的凭据也能喂给一台外置 coturn —— turn.mode: external
// 那条逃生口因此是真的可用，不是纸面承诺。
//
// # 为什么直接用 pion 的函数而不自己算 HMAC
//
// 校验方是 pion 的 LongTermTURNRESTAuthHandler，签发方若自己实现一遍，
// 两边就有两份对「用户名怎么拼」的理解 —— 比如时间戳是 Add(ttl) 之前还是
// 之后取的、user 为空时冒号留不留。差一个字符 HMAC 就不匹配，
// 表现是「凭据看起来对但 401」。所以让**签发与校验共用同一份代码**，
// 过期时刻从它产出的用户名里解回来，而不是另算一遍。
func MintCredential(secret []byte, userID string, ttl time.Duration) (Credential, error) {
	if len(secret) == 0 {
		return Credential{}, errors.New("turnsrv: 签发凭据需要密钥")
	}
	if ttl <= 0 {
		ttl = DefaultCredentialTTL
	}

	username, password, err := turn.GenerateLongTermTURNRESTCredentials(
		string(secret), userID, ttl)
	if err != nil {
		return Credential{}, fmt.Errorf("turnsrv: 签发凭据失败：%w", err)
	}

	// 过期时刻从用户名里解回来 —— 那是校验方实际会读的那个值。
	expiry := time.Now().Add(ttl)
	if ts, _, ok := splitRESTUsername(username); ok {
		expiry = time.Unix(ts, 0)
	}

	return Credential{
		Username:  username,
		Password:  password,
		ExpiresAt: expiry,
		TTL:       int(time.Until(expiry).Seconds()),
	}, nil
}

// splitRESTUsername 从 "<时间戳>:<用户标识>" 里取出两部分。
//
// 与 pion 的 LongTermTURNRESTAuthHandler 同一口径：按第一个冒号分割，
// 前半是时间戳。用户标识可以含冒号，所以只切一次。
func splitRESTUsername(username string) (unix int64, userID string, ok bool) {
	i := strings.IndexByte(username, ':')
	if i < 0 {
		ts, err := strconv.ParseInt(username, 10, 64)
		return ts, "", err == nil
	}
	ts, err := strconv.ParseInt(username[:i], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return ts, username[i+1:], true
}

// MintCredential 用本服务的密钥签发一对临时凭据。
//
// 方法形式而不是让调用方自己拿 cfg.Secret 去调包级函数：那样密钥就得
// 从服务对象里漏出来，而它没有任何理由离开这个包。
func (s *Server) MintCredential(userID string, ttl time.Duration) (Credential, error) {
	return MintCredential(s.cfg.Secret, userID, ttl)
}

// PublicHost 返回应当写进 turn: URL 的主机名。
//
// 用公布的公网地址而不是监听地址：后者常是 0.0.0.0，
// 写进 URL 给浏览器等于让它连自己。
func (s *Server) PublicHost() string { return s.cfg.PublicIP.String() }

// ICEConfigFor 按本服务的实际端口拼出 iceServers。
//
// 端口从**实际绑定**的地址取，而不是从配置里取：配置写 :0 时两者不同，
// 而发一个错端口的 turn: URL 会让浏览器白等一个 ICE 超时。
func (s *Server) ICEConfigFor(host string, cred Credential) ICEConfig {
	port := 0
	if s.udpAddr != nil {
		port = s.udpAddr.Port
	}
	tlsPort := 0
	if s.cfg.TLSAddr != "" {
		if p := portOf(s.cfg.TLSAddr); p != "" {
			tlsPort, _ = strconv.Atoi(p)
		}
	}
	return BuildICEConfig(host, port, tlsPort, cred)
}

// ── 给浏览器的 iceServers ───────────────────────────────────────────────────

// ICEServer 对应 W3C WebRTC 的 RTCIceServer。
//
// 只有三个成员：现行 REC（2025-03-13）已经**没有** credentialType 了，
// 多发一个字段会让严格的实现报错。
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// ICEConfig 是控制台交给浏览器的完整配置。
type ICEConfig struct {
	ICEServers []ICEServer `json:"iceServers"`
	TTLSeconds int         `json:"ttl_seconds"`
	ExpiresAt  time.Time   `json:"expires_at"`
}

// BuildICEConfig 拼出交给浏览器的 iceServers。
//
// 四条 URL 共用同一对凭据 —— HMAC 只覆盖用户名，与 URL 无关。
// turns: **必须**用于 TLS-over-TCP（RFC 7065）；host 直接拼接而不经
// URL 解析器：RFC 7065 §3.1 明确要求「不得用通用的分层 URI 解析器
// 解析 turn:/turns: URI」。
func BuildICEConfig(host string, port, tlsPort int, cred Credential) ICEConfig {
	if port == 0 {
		port = 3478
	}
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	urls := []string{
		"stun:" + hostPort,
		"turn:" + hostPort + "?transport=udp",
		"turn:" + hostPort + "?transport=tcp",
	}
	if tlsPort > 0 {
		urls = append(urls,
			"turns:"+net.JoinHostPort(host, strconv.Itoa(tlsPort))+"?transport=tcp")
	}
	return ICEConfig{
		ICEServers: []ICEServer{{
			URLs: urls, Username: cred.Username, Credential: cred.Password,
		}},
		TTLSeconds: cred.TTL,
		ExpiresAt:  cred.ExpiresAt,
	}
}
