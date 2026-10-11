// 命令 nfrelay 是 NomiRelay 的公网中继：接受 agent 承载、按隧道监听入口端口、
// 把用户连接转发给对应的 agent，并提供 Web 控制台。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/acmecert"
	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/turnsrv"
	"github.com/nomifun/nomifun-net-infra/web"
)

// 由 -ldflags 注入。
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nfrelay: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir       = flag.String("data-dir", "./data", "数据目录（SQLite、证书）")
		bindQUIC      = flag.String("bind", "0.0.0.0:8443", "QUIC 承载监听地址（agent 连这里）")
		advertiseAddr = flag.String("advertise", "", "给 agent 安装命令使用的公网承载地址（host:port）；留空自动推导")
		consoleAddr   = flag.String("console", "127.0.0.1:9443", "控制台监听地址")
		consoleHosts  = flag.String("console-hosts", "",
			"控制台允许的额外 Host，逗号分隔（防 DNS 重绑定）")
		consoleBehindTLS = flag.Bool("console-behind-tls-proxy", false,
			"声明控制台前面有做了 TLS 终止的反代；会给会话 Cookie 加 Secure 与 __Host- 前缀")
		desktopBusinessURL = flag.String("desktop-business-url", "",
			"Desktop 最终交给 Mobile 的稳定 HTTP(S) 业务入口（例如 https://desktop.example.com）；留空使用独立隧道端口")
		desktopBootstrapURL = flag.String("desktop-bootstrap-url", "", "显式公共 Desktop bootstrap URL（https://relay.example.com:9444/api/bootstrap/desktop/v2）")
		desktopDevInsecure  = flag.Bool("desktop-dev-insecure", false, "仅本机集成测试：允许 loopback HTTP Desktop 接入")
		desktopDevEnrolTTL  = flag.Duration("desktop-dev-enrol-ttl", console.DefaultEnrolTTL, "仅本机集成测试：短时 Desktop v2 入网 TTL（需 -desktop-dev-insecure）")
		drainWait           = flag.Duration("drain", 30*time.Second, "优雅关闭的排空上限")

		sharedAddr = flag.String("shared", "",
			"共享入口监听地址（gateway 模式与 SNI 路由，例如 0.0.0.0:443）；留空则不启用")

		acmeEnabled = flag.Bool("acme", false,
			"用 ACME 自动签发共享入口与 turns: 的证书（需要域名已解析到本机）")
		acmeEmail = flag.String("acme-email", "",
			"ACME 账户邮箱，CA 用它发到期提醒；启用 ACME 时必填")
		acmeCA = flag.String("acme-ca", "",
			"ACME 目录 URL；留空用 staging（签出的证书浏览器不信任，确认流程后再改生产）")
		sharedTrustProxy = flag.Bool("shared-trust-proxy-protocol", false,
			"信任共享入口上的 PROXY protocol 头。**只有当这个端口只能被前置负载"+
				"均衡连到时才可以开** —— 否则任何人都能伪造源 IP")

		acmeHTTP = flag.String("acme-http", "",
			"HTTP-01 挑战的监听地址（必须是 :80）；备份路径，家宽封 80 时用不上")

		turnPublicIP = flag.String("turn-public-ip", "",
			"内置 TURN 告知客户端的公网地址；留空则不启用 TURN")
		turnListen = flag.String("turn-listen", turnsrv.DefaultListenAddr,
			"内置 TURN 的 STUN/TURN 监听地址（UDP + TCP）")
		turnRealm     = flag.String("turn-realm", "nomirelay", "TURN realm")
		turnMinPort   = flag.Uint("turn-min-port", uint(turnsrv.DefaultMinPort), "TURN 中继端口下界")
		turnMaxPort   = flag.Uint("turn-max-port", uint(turnsrv.DefaultMaxPort), "TURN 中继端口上界")
		turnPeerAllow = flag.String("turn-peer-allow", "",
			"额外允许 TURN 中继到的对端网段，逗号分隔；默认只放行全球单播")
		turnTLSListen = flag.String("turn-tls-listen", "",
			"turns: 的监听地址（例如 0.0.0.0:5349）；留空则不起 turns:")
		turnDomain = flag.String("turn-domain", "",
			"turns: 对外的域名，用于 ACME 签发；起 turns: 且启用 ACME 时必填")

		logLevel = flag.String("log-level", "info", "日志级别 debug|info|warn|error")
		showVer  = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("nfrelay %s (%s)\n", version, commit)
		return nil
	}

	// 参数校验放在**做任何事之前**。
	//
	// 这几条拒绝的都是「静默变成别的东西」而不是「明显不合法」的输入 ——
	// 那类输入最贵：进程照常起来、日志一切正常，而行为与你以为的不同。
	// 详见 ValidateListenAddr / ValidatePortRange 的注释。
	for _, c := range []struct {
		what, addr string
	}{
		{"-console", *consoleAddr},
		{"-bind", *bindQUIC},
	} {
		if err := ValidateListenAddr(c.what, c.addr); err != nil {
			return err
		}
	}
	if err := validateAdvertisedAddr(*advertiseAddr); err != nil {
		return err
	}
	if err := validateDesktopBusinessURL(*desktopBusinessURL); err != nil {
		return err
	}
	if *turnPublicIP != "" {
		if err := ValidatePortRange("-turn-min-port/-turn-max-port", *turnMinPort, *turnMaxPort); err != nil {
			return err
		}
	}

	log := newLogger(*logLevel)

	db, err := store.Open(store.Options{
		Path: filepath.Join(*dataDir, "relay.db"), Log: log,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	// 证书持久化到数据目录。
	//
	// 不持久化的话每次重启指纹都变，所有 agent 都得重新配 —— 那是不可用的。
	cert, leaf, err := loadOrCreateCert(*dataDir)
	if err != nil {
		return err
	}
	pin := carrier.SPKIPinBase64(leaf)

	ln, err := carrier.ListenQUIC(*bindQUIC, carrier.QUICConfig{
		TLSConfig: carrier.ServerTLSConfig(cert),
		Rung:      carrier.RungQUIC,
	})
	if err != nil {
		return err
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 对外公布的承载地址：绑定在 0.0.0.0 时要给用户一个能真正连的地址。
	advertised := advertisedAddr(*bindQUIC, ln.Addr(), *advertiseAddr)

	rt := newRuntime(ctx, db, log, version, advertised, pin)
	rt.setDesktopBusinessURL(*desktopBusinessURL)
	if err := validateDesktopBootstrapURL(*desktopBootstrapURL, *desktopDevInsecure); err != nil {
		return err
	}
	rt.desktopBootstrapURL = strings.TrimRight(*desktopBootstrapURL, "/")
	rt.desktopDevInsecure = *desktopDevInsecure
	if *desktopDevEnrolTTL < time.Second || *desktopDevEnrolTTL > console.DefaultEnrolTTL || (!*desktopDevInsecure && *desktopDevEnrolTTL != console.DefaultEnrolTTL) {
		return errors.New("-desktop-dev-enrol-ttl 仅测试模式可缩短，范围为 1 秒到 15 分钟")
	}
	rt.desktopEnrolTTL = *desktopDevEnrolTTL

	// ACME。
	//
	// 装配顺序有讲究：ACME 的域名闸门要查共享入口的路由表，而共享入口
	// 又要用 ACME 的 GetCertificate —— 循环依赖。破法是 ACME 拿 rt 当
	// HostChecker（rt 在此之前已经存在，只是路由表还空着），
	// 而路由表在 ApplyTunnels 时才填上。第一次握手若早于 ApplyTunnels，
	// 域名会被判为「不在路由表」而拒签 —— 那是**正确**的保守行为，
	// 下一次握手就会通过。
	//
	// 装在 TURN **之前**：turns: 的证书也从这里来。turns: 的域名不是隧道，
	// 所以要用 StaticHosts 额外告知，否则闸门②会把它判成「不是我们的业务」。
	if *turnTLSListen != "" && *acmeEnabled && *turnDomain == "" {
		// 起 turns: 又开了 ACME 却不给域名，结果会是「turns: 用自签证书、
		// 客户端一律握手失败」—— 那是个在客户端侧才看得见的故障，
		// 所以在启动时就拒绝。
		return errors.New("起 turns: 且启用 ACME 时必须用 -turn-domain 给出域名")
	}
	var turnHosts acmecert.HostChecker
	if *turnDomain != "" {
		turnHosts = acmecert.StaticHosts{*turnDomain}
	}
	acme, err := acmecert.New(acmecert.Config{
		Enabled:    *acmeEnabled,
		Email:      *acmeEmail,
		CA:         *acmeCA,
		StorageDir: filepath.Join(*dataDir, "acme"),
		Hosts:      acmecert.AnyOf(rt, turnHosts),
		Log:        log,
	})
	if err != nil {
		return err
	}

	// 内置 TURN。
	//
	// 默认**不启用**：它需要一个真实可达的公网地址，而猜一个的后果是
	// 客户端往错处发媒体、表现为「ICE 连不上」—— 那是最难查的一类故障。
	// 所以宁可让用户显式提供，也不给默认值。
	var turnSrv *turnsrv.Server
	if *turnPublicIP != "" {
		ip, err := netip.ParseAddr(*turnPublicIP)
		if err != nil {
			return fmt.Errorf("-turn-public-ip 不是合法地址：%w", err)
		}
		peerAllow, err := parsePrefixes(splitCSV(*turnPeerAllow))
		if err != nil {
			return err
		}
		// 凭据密钥从库里取（首启时生成并持久化）——
		// 每次启动换一个的话，重启就会让所有在用的凭据失效。
		secret, err := db.TurnSecret(ctx)
		if err != nil {
			return err
		}
		turnSrv, err = turnsrv.New(turnsrv.Config{
			Realm:      *turnRealm,
			PublicIP:   ip,
			ListenAddr: *turnListen,
			MinPort:    uint16(*turnMinPort),
			MaxPort:    uint16(*turnMaxPort),
			Secret:     secret,
			PeerAllow:  peerAllow,
			TLSAddr:    *turnTLSListen,
			TLSConfig:  turnTLS(*turnTLSListen, cert, acme),
			Log:        log,
		})
		if err != nil {
			return err
		}
		defer turnSrv.Close()
	} else {
		log.Info("未配置 -turn-public-ip，内置 TURN 未启用")
	}

	rt.acme = acme

	// 挑战可达性：启动时就要判，不能等签发超时。
	//
	// TLS-ALPN-01 按 RFC 8737 只走 **443**、HTTP-01 只走 **80**，两者都不可
	// 重定向到别的端口。所以「开了 ACME 但既没有 443 也没有 80」是一个
	// **必然签不出证书**的配置 —— 而它的现象是签发静默超时，
	// 日志里只有 certmagic 的重试。宁可在启动时拒绝。
	if err := checkACMEReachable(acme, *sharedAddr, *acmeHTTP, log); err != nil {
		return err
	}
	if stop, err := startACMEHTTP(acme, *acmeHTTP, log); err != nil {
		return err
	} else if stop != nil {
		defer stop()
	}

	// 共享入口（gateway / SNI 路由）。
	//
	// 未启用 ACME 时用自签证书终止 TLS。这是**过渡态**且必须如实说明：
	// 浏览器会报证书错误。而 SNI 透传路由**不需要**证书 ——
	// SNI 是明文，读它不用解密，所以没有可信证书时共享端口仍然可用。
	if err := rt.startShared(*sharedAddr, gatewayTLS(cert, acme),
		carrierTLS(cert, acme), acmeHandler(acme),
		*sharedTrustProxy); err != nil {
		return err
	}
	defer rt.closeShared()

	cons, err := console.New(consoleOptions(consoleConfig{
		addr:      *consoleAddr,
		hosts:     *consoleHosts,
		behindTLS: *consoleBehindTLS,
	}, db, rt, turnAdapter(turnSrv), log))
	if err != nil {
		return err
	}
	rt.consoleHardened = *consoleBehindTLS
	rt.attachConsole(cons)
	// 启动时自检一次：有没有纯诊断项因为键名而会在支持包里被脱敏掉。
	// 等到某人真的导出支持包才发现，就已经是在排障的最坏时刻了。
	cons.WarnRedactedDiagnostics(rt.Settings())
	warnConsoleExposure(*consoleAddr, *consoleBehindTLS, log)

	if err := rt.ApplyTunnels(); err != nil {
		log.Warn("启动时应用隧道未完全成功", "err", err)
	}

	_ = db.AppendEvent(ctx, store.Event{
		Kind: store.KindRelayStarted, Level: store.LevelInfo,
		Message: "中继启动 " + version,
	})

	var wg sync.WaitGroup

	// 控制台。
	consoleSrv := &http.Server{
		Addr:              *consoleAddr,
		Handler:           consoleHandler(cons),
		ReadHeaderTimeout: 10 * time.Second,
		// 不设 WriteTimeout：SSE 是长连接，写超时会把事件流掐断。
		// 慢客户端的防护在应用层（订阅者队列满即丢弃）。
	}
	// HTTP/2 让 SSE 摆脱浏览器每源 6 连接的限制。
	consoleSrv.Protocols = new(http.Protocols)
	consoleSrv.Protocols.SetHTTP1(true)
	consoleSrv.Protocols.SetUnencryptedHTTP2(true)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := consoleSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("控制台服务退出", "err", err)
		}
	}()

	stopPump := cons.StartMetricsPump(time.Second)
	defer stopPump()
	stopMaint := rt.startMaintenance()
	defer stopMaint()

	// agent 承载。
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptLoop(ctx, ln, rt, log)
	}()

	log.Info("nfrelay 已启动",
		"版本", version, "承载", advertised, "控制台", *consoleAddr,
		"数据目录", *dataDir)
	printWelcome(ctx, db, *consoleAddr, advertised, pin)

	<-ctx.Done()
	log.Info("收到退出信号，开始排空", "上限", *drainWait)
	_ = db.AppendEvent(context.Background(), store.Event{
		Kind: store.KindRelayDraining, Level: store.LevelInfo, Message: "中继正在关闭",
	})

	// 优雅关闭：先停止接受新连接，再给在途连接一段排空时间。
	// frp 的服务端**从不排空**，重启即断掉所有隧道。
	rt.closeEntries()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), *drainWait)
	defer cancel()
	_ = consoleSrv.Shutdown(shutdownCtx)

	rt.sessions.CloseAll("中继正在关闭")
	ln.Close()

	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
		log.Info("已干净退出")
	case <-time.After(2 * time.Second):
		log.Warn("部分 goroutine 未在期限内退出，强制结束")
	}
	return nil
}

// consoleHandler 把 API 与内嵌的 SPA 拼在一起。
//
// **返回值必须是 cons.HostCheck(cons.SecurityHeaders(mux))，不能直接返回 mux。**
// cons.Handler() 里那层安全头只包住 /api/ 与 /healthz，够不到这里的 `/`；
// 于是 CSP 与 frame-ancestors 'none' 只装饰 JSON，而 index.html ——
// 唯一一个真的加载脚本、唯一一个能被 iframe 套的响应 —— 一个头都没有。
// 这个洞存在过一次，判据在 TestSecurityHeadersCoverTheSPAAndNotOnlyJSON。
//
// 包在 mux 外面（而不是让 web.AssetHandler 自己设）还额外覆盖两处
// 容易漏的响应：ServeMux 自己产生的 404/405，以及下面 noweb 分支那句
// 纯文本说明。
//
// HostCheck 同理，而且它必须在**最外层**（先确认这个请求是给我们的，
// 再做任何别的事）。不包住 `/` 的话失败形态是「半开」——页面 200 载入正常
// 而所有 /api/* 421，运维看到一个渲染完整却点不动的控制台、界面上零解释；
// 而且给别名 Host 返回完整 index.html 会泄露产品名与带哈希的资源名。
// 判据在 console_host_test.go。
func consoleHandler(cons *console.Server) http.Handler {
	api := cons.Handler()

	assets, err := web.FS()
	if err != nil {
		// 无前端资源（noweb 构建）时只提供 API，并在根路径说明清楚，
		// 而不是返回一个空白页让人以为控制台坏了。
		mux := http.NewServeMux()
		mux.Handle("/api/", api)
		mux.Handle("/healthz", api)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w,
				"本二进制未内嵌控制台前端（noweb 构建）。请跑 make ui 后重新构建，"+
					"或用 --assets-dir 指定资源目录。API 仍在 /api/ 下可用。",
				http.StatusNotFound)
		})
		return cons.HostCheck(cons.SecurityHeaders(mux))
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.Handle("/healthz", api)
	// web.AssetHandler 在 SPA 回退之外还做两件 http.FileServerFS 不做的事：
	// 哈希资源 immutable 缓存 + index.html no-cache（反过来会让用户升级后
	// 永远看到旧 SPA），以及按 Accept-Encoding 挑构建时预压缩好的 .br/.gz
	// —— 而不是每个请求现场再压一遍已经压过的资源。
	mux.Handle("/", web.AssetHandler(assets))
	return cons.HostCheck(cons.SecurityHeaders(mux))
}

// printWelcome 在首启时把关键信息打到 stdout。
//
// 「可复制的一行命令」是 onboarding 的核心：frp 完全没有引导，
// 新用户必须读 README 并手写 TOML。
func printWelcome(ctx context.Context, db *store.DB, consoleAddr, relayAddr, pin string) {
	fmt.Printf("\n  控制台：http://%s\n", consoleAddr)
	if !db.HasAdmin(ctx) {
		fmt.Printf("  首次使用请打开控制台完成初始化（创建管理员）。\n")
	}
	fmt.Printf("\n  承载地址：%s\n  证书指纹：%s\n\n", relayAddr, pin)
}

func acceptLoop(ctx context.Context, ln *carrier.QUICListener, rt *runtime, log *slog.Logger) {
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("接受承载失败", "err", err)
			continue
		}
		go handleCarrier(ctx, c, rt, log)
	}
}

func handleCarrier(ctx context.Context, c carrier.Carrier, rt *runtime, log *slog.Logger) {
	ctrl, err := c.AcceptStream(ctx)
	if err != nil {
		_ = c.CloseWithError(1, "未收到控制流")
		return
	}

	// 信道绑定：与 agent 侧对称，见 carrier.Carrier.ChannelBinding 的说明。
	// 两端必须给出相同的材料，否则 MAC 不匹配、握手失败。
	binding, err := c.ChannelBinding()
	if err != nil {
		log.Warn("取信道绑定材料失败，拒绝这次握手", "err", err)
		_ = c.CloseWithError(1, "信道绑定不可用")
		return
	}

	out, err := relay.Handshake(ctrl, binding, relay.HandshakeConfig{
		Auth:               rt,
		Guard:              rt.guard,
		RelayVersion:       version,
		MinProtocolVersion: 1,
		Log:                log,
	})
	if err != nil {
		// outcome 直接就是 nf_agent_handshakes_total{outcome} 的标签值 ——
		// 这个指标本身就是安全看板。
		log.Warn("agent 握手失败", "outcome", out.Outcome, "err", err)
		_ = rt.db.AppendEvent(rt.ctx, store.Event{
			Kind: store.KindHandshakeFailed, Level: store.LevelWarn,
			Subject: out.Outcome, Message: err.Error(),
		})
		_ = c.CloseWithError(1, "握手失败")
		return
	}

	// 每次（重）连都刷新画像：用户升级了 agent、改了主机名，
	// 控制台应当立刻反映，而不是一直显示首次入网时的值。
	rt.touchProfile(out.AgentID, out.Profile)

	sess := &relay.Session{
		AgentID:      out.AgentID,
		Carrier:      c,
		Capabilities: out.Capabilities,
		ConnectedAt:  time.Now(),
	}
	if old := rt.sessions.Add(sess); old != nil {
		old.Close("被新连接顶替")
	}

	log.Info("agent 已上线", "agent", out.AgentID, "世代", sess.Generation,
		"承载", c.Rung().String(), "数据报", sess.SupportsDatagrams())
	_ = rt.db.AppendEvent(rt.ctx, store.Event{
		Kind: store.KindAgentOnline, Level: store.LevelInfo,
		Subject: out.AgentID, Message: "代理端上线（" + c.Rung().String() + "）",
	})
	rt.publish(console.EventState, map[string]any{"agent": out.AgentID, "online": true})

	// 起数据报接收循环。
	//
	// 每会话一条，而不是每 UDP 隧道一条：QUIC 的 ReceiveDatagram 是
	// **连接级**的，多个消费者会互相抢包，各自只拿到属于别人的帧。
	// 收下之后按帧头里的隧道短标识分发 —— 那个字段正是为此存在。
	//
	// 承载不支持数据报时这个循环立刻返回，UDP 隧道的状态会由
	// refreshStates 如实标成降级，而不是悄悄把 UDP 塞进一条可靠流。
	go relay.RunDatagramLoop(c.Context(), sess, rt.DatagramRouter(), log)

	// agent 上线会让「等待代理端上线后自动绑定」的隧道变得可绑，
	// 所以先跑一次 ApplyTunnels 再下发。
	if err := rt.ApplyTunnels(); err != nil {
		log.Warn("agent 上线后应用隧道未完全成功", "err", err)
	}

	// 在控制流上收 agent 的周期性计数器上报。
	//
	// 握手之后控制流在两侧都还开着、谁都没在用它 —— 而中继只
	// AcceptStream 一次，所以 agent 主动开新流会挂住。控制流是这类
	// 「agent → 中继的周期性消息」唯一的去处。
	//
	// **不能**把这个循环当作「对端还活着」的判据（下面那个 select 仍然
	// 监听承载 Context）：agent 被强杀时这条流的读要等到 QUIC 空闲超时
	// 才返回，期间中继会把用户连接派给一个已经死掉的 agent。
	go rt.readAgentMetrics(out.Rest, sess)

	// 周期性 Ping，测承载 RTT。
	//
	// 规格 §8.4 要求每隧道 p50/p95/p99 承载 RTT，而 store.RecordRTT 与直方图表
	// 早就写好了却没有生产写入点 —— 控制台上那三个数字一直显示「—」。
	go rt.pingAgent(ctrl, sess)

	// 承载断开即下线。监听承载 Context 而不是「在控制流上读一下」：
	// agent 被强杀时控制流的读要等到空闲超时才返回。
	select {
	case <-c.Context().Done():
	case <-ctx.Done():
	}

	if rt.sessions.Remove(sess.AgentID, sess.Generation) {
		log.Info("agent 已下线", "agent", sess.AgentID, "世代", sess.Generation)
		// agent 掉线后隧道就不可用了，状态必须跟着变 ——
		// 否则控制台还显示「运行中」，而实际连接会被干净拒掉。
		rt.RefreshStates()
		_ = rt.db.AppendEvent(rt.ctx, store.Event{
			Kind: store.KindAgentOffline, Level: store.LevelWarn,
			Subject: sess.AgentID, Message: "代理端下线",
		})
		rt.publish(console.EventState, map[string]any{"agent": sess.AgentID, "online": false})
	}
}

// gatewayTLS 造共享入口终止 TLS 用的配置。
//
// 与 agent 承载的 TLS 配置**分开**：那一份要保持指纹稳定（agent 靠 SPKI
// 绑定，换证书等于全机队掉线），而这一份用 ACME 签发的、会随续期而变的证书。
// 混用会让 ACME 一上线就把所有 agent 踢下去。
//
// CurvePreferences 保持 nil —— 手动设置会静默关掉后量子曲线。
func gatewayTLS(cert tls.Certificate, acme *acmecert.Manager) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// **只宣告 http/1.1，绝不宣告 h2。**
		//
		// 网关刻意只开 HTTP/1.1（见 gateway.server() 的注释）：
		// WebSocket 升级需要 ResponseWriter 支持 Hijack，而 h2 的不支持，
		// 而场景一明确要求 WebSocket 穿透。
		//
		// 我第一版在这里宣告了 h2。后果是 curl 协商到 h2、然后等 SETTINGS 帧，
		// 等到的是一个 HTTP/1.1 响应 → nghttp2 报 PROTOCOL_ERROR 关连接。
		// 表现是「TLS 握手成功、请求发出去了、然后连接被断开」，
		// 而中继侧一条日志都没有 —— 因为它这边一切正常。
		//
		// 宣告一个自己不会说的协议，就是把一个握手成功的连接变成一个
		// 无法排查的失败。ALPN 列表必须与实际能力**逐项**对应。
		NextProtos: []string{"http/1.1"},
	}
	if acme != nil {
		// GetCertificate 优先于 Certificates：有 SNI 时走 ACME，
		// 没有 SNI 或签不出来时 Go 会回落到 Certificates 里的自签证书。
		// 这个回落是刻意保留的 —— 场景二的设备用 IP 直连，永远签不出证书，
		// 但它们本来就靠固件里的指纹校验，不需要可信证书。
		cfg.GetCertificate = acme.GetCertificate
	}
	return cfg
}

// carrierTLS 造 L2 承载（TLS/TCP:443 + smux）用的 TLS 配置。
//
// # 为什么必须与 gatewayTLS 分开
//
// 两者服务同一个端口，靠 ALPN 区分：业务流量协商 `http/1.1`，
// agent 协商 `nomifun-relay/1`。**绝不能把两个协议塞进同一个 NextProtos** ——
// 那等于告诉浏览器「我会说 nomifun-relay/1」，而 Go 的服务端会按客户端的
// 偏好顺序选，于是一个恰好把它排在前面的客户端会协商到一个自己不会说的协议。
//
// 这正是 gatewayTLS 那段注释里记的那个坑（我在 h2 上踩过一次）：
// 宣告一个自己不会说的协议，就是把一个握手成功的连接变成一个无法排查的失败。
// ALPN 列表必须与**这一条分支**的实际能力逐项对应。
//
// 证书来源与 gatewayTLS 一致（含 ACME 的 GetCertificate 与自签回落）：
// agent 靠 SPKI 指纹校验，证书可不可信对它无所谓，但它得先拿到一张。
func carrierTLS(cert tls.Certificate, acme *acmecert.Manager) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 是硬要求：信道绑定用 ExportKeyingMaterial，
		// 而它在 TLS 1.2 上要求 Extended Master Secret，不是所有实现都有。
		// QUIC 那边天然强制 1.3，这里显式对齐 —— 两个梯级的绑定必须同源。
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{proto.ALPN},
	}
	if acme != nil {
		cfg.GetCertificate = acme.GetCertificate
	}
	return cfg
}

// turnTLS 造 turns: 用的 TLS 配置。addr 为空时返回 nil（turnsrv 据此不起 turns:）。
//
// # 为什么不能复用 gatewayTLS
//
// gatewayTLS 的 NextProtos 是 ["http/1.1"]。TURN over TLS 不用 ALPN，
// 而 Go 的服务端在客户端**提供了** ALPN 却没有交集时会发
// no_application_protocol 告警并断开 —— 于是一个正常的 turns: 客户端
// （某些实现会带上 ALPN）会握手失败，现象是「ICE 连不上」。
// 宣告一个自己不说的协议就是制造无法排查的故障，所以这里干脆不宣告。
func turnTLS(addr string, cert tls.Certificate, acme *acmecert.Manager) *tls.Config {
	if addr == "" {
		return nil
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if acme != nil {
		cfg.GetCertificate = acme.GetCertificate
	}
	return cfg
}

// checkACMEReachable 判断至少有一条挑战路径真的可达。
func checkACMEReachable(acme *acmecert.Manager, sharedAddr, httpAddr string, log *slog.Logger) error {
	if acme == nil {
		return nil
	}
	alpnOK := portOfAddr(sharedAddr) == "443"
	httpOK := portOfAddr(httpAddr) == "80"

	switch {
	case alpnOK && httpOK:
		// 两条都在。certmagic 会先试 TLS-ALPN-01，失败再试 HTTP-01。
		return nil
	case alpnOK:
		log.Info("ACME 走 TLS-ALPN-01（443）；未开 -acme-http，没有备份挑战路径")
		return nil
	case httpOK:
		// 只有 80 也能签，但共享入口不在 443 意味着签出来的证书
		// 大概率没人用得上 —— 说清楚而不是默默放过。
		log.Warn("ACME 只有 HTTP-01（80）可用；共享入口不在 443，" +
			"签出的证书只有 turns: 或非标准端口的客户端用得到")
		return nil
	case sharedAddr == "" && httpAddr == "":
		return errors.New("启用了 -acme 但既没有 -shared 也没有 -acme-http：" +
			"TLS-ALPN-01 只走 443、HTTP-01 只走 80，两条路都没有时证书永远签不出来")
	default:
		return fmt.Errorf("启用了 -acme 但挑战端口不对：-shared 是 %q（需要 :443）、"+
			"-acme-http 是 %q（需要 :80）。这两个端口号由 RFC 8737 / RFC 8555 规定，"+
			"不能重定向到别处", sharedAddr, httpAddr)
	}
}

// startACMEHTTP 起 HTTP-01 挑战用的 :80 监听器。
//
// 作**备份**路径：家庭宽带封 80 很常见，所以主路径是 TLS-ALPN-01
// （只需要 443，而 443 本来就要监听）。
//
// 非挑战请求一律 301 到 https —— 一个开着 80 的中继如果对普通请求
// 回 404，用户会以为服务没起。
func startACMEHTTP(acme *acmecert.Manager, addr string, log *slog.Logger) (func(), error) {
	if acme == nil || addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ACME HTTP-01 监听 %s 失败：%w", addr, err)
	}
	srv := &http.Server{
		Handler: acme.HTTPChallengeHandler(redirectToHTTPS()),
		// 挑战请求很小很快。给一个短超时，别让这个口子变成一个
		// 可以攥着连接不放的位置。
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("ACME HTTP-01 监听退出", "err", err)
		}
	}()
	log.Info("ACME HTTP-01 已就绪", "监听", ln.Addr().String())
	return func() { _ = srv.Close() }, nil
}

// redirectToHTTPS 是 :80 上非挑战请求的兜底。
//
// 抽成函数是为了让测试用**同一段**代码 —— 内联一个闭包的话，
// 测试只能重写一遍，于是它验证的是自己那份拷贝。
func redirectToHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(),
			http.StatusMovedPermanently)
	})
}

// portOfAddr 取一个监听地址的端口字符串，取不到返回 ""。
func portOfAddr(addr string) string {
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// acmeHandler 返回判别器要装的 acme-tls/1 处理器（未启用 ACME 时为 nil）。
//
// 为 nil 时判别器会**拒绝** acme-tls/1 连接 —— 那个默认是安全的：
// 没接 ACME 却收到挑战请求，说明有人在试探。
func acmeHandler(acme *acmecert.Manager) func(net.Conn) {
	if acme == nil {
		return nil
	}
	return acme.HandleACMEConn
}

// ── TURN 适配 ───────────────────────────────────────────────────────────────

// turnAdapter 把 *turnsrv.Server 适配成 console.TurnSource。
//
// 需要这一层是因为控制台**故意不 import internal/turnsrv**：TURN 是可选
// 组件，让控制台依赖它会把 pion 的依赖树拖进每一处用到控制台的地方。
// 未启用时返回 nil 接口，端点会如实回「未启用」而不是空列表 ——
// 空列表会让用户以为「TURN 在跑但没人用」，从而去查客户端，方向全错。
func turnAdapter(s *turnsrv.Server) console.TurnSource {
	if s == nil {
		return nil
	}
	return &turnBridge{srv: s}
}

type turnBridge struct{ srv *turnsrv.Server }

func (b *turnBridge) Allocations() []console.TurnAllocation {
	src := b.srv.Allocations()
	out := make([]console.TurnAllocation, 0, len(src))
	for _, a := range src {
		out = append(out, console.TurnAllocation{
			ID: a.ID, Username: a.Username, RelayedAddr: a.RelayedAddr,
			PeerCount: a.PeerCount, BytesRelayed: a.BytesRelayed,
			CredentialTTLSeconds: a.CredentialTTLSeconds, CreatedAt: a.CreatedAt,
		})
	}
	return out
}

func (b *turnBridge) MintCredential(userID string, ttl time.Duration) (any, error) {
	cred, err := b.srv.MintCredential(userID, ttl)
	if err != nil {
		return nil, err
	}
	// 直接返回可喂给 RTCPeerConnection 的 iceServers，而不是一对裸凭据：
	// 让调用方自己拼 turn:/turns: URL 是在请他犯错 ——
	// RFC 7065 明确要求「不得用通用的分层 URI 解析器解析 turn: URI」。
	host := b.srv.PublicHost()
	return b.srv.ICEConfigFor(host, cred), nil
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

// parsePrefixes 把逗号分隔的 CIDR 列表解析成前缀。
func parsePrefixes(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, it := range items {
		p, err := netip.ParsePrefix(it)
		if err != nil {
			return nil, fmt.Errorf("网段 %q 非法：%w", it, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validateAdvertisedAddr checks the operator-provided address used in
// generated agent commands. It does not affect the bind address or any data
// plane listener.
func validateAdvertisedAddr(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return fmt.Errorf("-advertise 必须是可访问的 host:port（例如 relay.example.com:8443）：%q", raw)
	}
	if strings.ContainsAny(host, " \t\r\n/") {
		return fmt.Errorf("-advertise 的主机名包含非法字符：%q", host)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("-advertise 的端口必须是 1-65535：%q", port)
	}
	if ip, err := netip.ParseAddr(host); err == nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return fmt.Errorf("-advertise 不能使用未指定或组播地址：%q", host)
	}
	return nil
}

// validateDesktopBusinessURL 校验最终写入 Mobile 配对 URL 的稳定业务入口。
//
// 这里只允许 origin 形状，不允许路径、query、fragment 或凭据。否则最终
// 拼接 /qr-login 时会产生双路径或把敏感信息扩散到二维码/日志。
func validateDesktopBusinessURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-desktop-business-url 必须是完整 HTTP(S) origin（例如 https://desktop.example.com）：%q", raw)
	}
	if u.User != nil {
		return errors.New("-desktop-business-url 不得包含用户名或密码")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("-desktop-business-url 不得包含 query 或 fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("-desktop-business-url 不得包含路径")
	}
	return nil
}

// advertisedAddr 推导一个 agent 能真正连上的地址。
//
// 绑在 0.0.0.0 时不能把 "0.0.0.0:8443" 写进入网命令 —— 那在 agent 侧无意义。
// 运维可以用 -advertise 显式声明公网 IP、域名或端口映射后的地址；
// 未声明时才退化为本机第一个非回环 IPv4。这个值只影响展示和安装命令，
// 不改变实际监听。
func advertisedAddr(configured string, actual net.Addr, override string) string {
	if override = strings.TrimSpace(override); override != "" {
		return override
	}
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return actual.String()
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return configured
	}
	if ip := firstNonLoopbackIPv4(); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func firstNonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// loadOrCreateCert 从数据目录加载证书，不存在则生成并落盘。
//
// **必须持久化**：不然每次重启 SPKI 指纹都变，所有 agent 都要重新配指纹，
// 那等于每次重启都把整个机队踢下线。
func loadOrCreateCert(dataDir string) (tls.Certificate, *x509.Certificate, error) {
	certPath := filepath.Join(dataDir, "relay-cert.pem")
	keyPath := filepath.Join(dataDir, "relay-key.pem")

	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		leaf := c.Leaf
		if leaf == nil && len(c.Certificate) > 0 {
			leaf, err = x509.ParseCertificate(c.Certificate[0])
			if err != nil {
				return tls.Certificate{}, nil, fmt.Errorf("解析已存证书失败：%w", err)
			}
			c.Leaf = leaf
		}
		return c, leaf, nil
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("创建数据目录失败：%w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nomirelay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		DNSNames:     []string{"nomirelay"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	// 私钥 0600：这是中继身份的根，任何人可读就等于任何人可冒充。
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf,
	}, leaf, nil
}
