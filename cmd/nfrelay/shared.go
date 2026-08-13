package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/gateway"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 共享入口（gateway / SNI 路由）的装配与生命周期。
//
// # 为什么它与 exposure: port 的入口分开
//
// 独占端口的隧道各有一个监听器，删掉隧道就关掉监听器。共享入口反过来：
// **一个**监听器服务任意多条隧道，隧道增删只改路由表、不动监听器。
// 混在一起会让「删最后一条共享隧道要不要关端口」这种问题每次都要重新想。
//
// # 为什么之前这一整块都没被装配
//
// internal/gateway 有 14 个文件、全套测试，但**生产路径上一个调用点都没有**
// —— 与 internal/udpflow 之前的处境完全一样。README 却把网关模式列在
// 「已实现」里，只说「证书是自签」。实现了不等于接上了；
// 一个没有调用点的包，测试再全也只证明它自己自洽。

// shareState 是共享入口的运行时状态。
type shareState struct {
	ln    net.Listener
	disc  *gateway.Discriminator
	gw    *gateway.Gateway
	reg   *gateway.Registry
	port  uint16
	tlsOn bool

	// trustProxy 是这个端口的 PROXY protocol 信任标记。
	//
	// **必须记住它。** applyShared 每次都造一张新注册表再整体替换，而
	// 「这个端口信任 PROXY 头」不由任何一条隧道产生 —— 不重新设置的话，
	// 第一次隧道变更就会把它悄悄关掉。
	//
	// 关掉的方向是**安全**的（不再解析不可信的头），但它是一次静默的行为改变：
	// 前置 LB 后面的部署会突然把所有客户端的源地址看成 LB 的地址，
	// 于是白名单开始误拒，而配置一个字都没改。
	// 这与 EnsurePort 是同一个坑，只是方向相反。
	trustProxy bool

	// routed 是上一轮成功注册过路由的隧道 ID。
	//
	// 只为回收反向代理缓存而存在：被**删掉**的隧道不在下一轮的 desired 里，
	// 所以只失效 desired 的话，它那条缓存永远回收不掉（g.proxies 只增不减，
	// 而 closeShared 连 gw.Close 都不调）。失效「上一轮 ∪ 本轮」的并集。
	//
	// 由 applyShared 在持 rt.mu 时读写。
	routed map[string]struct{}
}

// startShared 在 addr 上起共享入口。addr 为空表示不启用。
func (rt *runtime) startShared(
	addr string, tlsCfg, carrierCfg *tls.Config, acme func(net.Conn), trustProxy bool,
) error {
	if addr == "" {
		rt.log.Info("未配置 -shared，共享入口（gateway / SNI 路由）未启用")
		return nil
	}

	reg := gateway.NewRegistry()

	// 拨号器把公网请求接到隧道另一端。生产实现走会话表，
	// 与 L4 入口共用同一套开流与确认语义（relay.DialTunnelStream）——
	// 同一个故障在两条路径上必须长得一样。
	dialer := &gateway.TunnelDialer{Lookup: rt}

	gw := gateway.NewGateway(gateway.GatewayConfig{
		Registry: reg,
		Dialer:   dialer,
		Log:      rt.log,
		// 学习模式观测点：共享入口每个**通过**来源校验的请求记一次。
		OnSource: rt.observed.note,
	})

	disc := gateway.NewDiscriminator(gateway.DiscriminatorConfig{
		Registry: reg,
		Gateway:  gw,
		Dialer:   dialer,
		// TLSConfig 为 nil 时 gateway 动作退化为拒绝（判别器自己会这样处理），
		// 而 SNI 透传路由不需要它 —— SNI 是明文，读它不用解密。
		// 所以没有证书时共享端口仍然可用，只是不能终止 TLS。
		TLSConfig: tlsCfg,
		// ACME 为 nil 时判别器会**拒绝** acme-tls/1 连接。那个默认是安全的：
		// 没接 ACME 却收到挑战请求，说明有人在试探。
		ACME: acme,
		// L2 承载入口：ALPN 为 nomifun-relay/1 的连接是一个 agent 在走降级路径
		//（它的网络封了 UDP）。没有证书时传 nil —— 判别器会明确拒绝，
		// 而 agent 侧看到的是一个可解释的 TLS 告警，不是「连上又被断开」。
		Carrier: rt.carrierAcceptor(carrierCfg),
		Log:     rt.log,
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("共享入口监听 %s 失败：%w", addr, err)
	}

	port := uint16(0)
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		port = uint16(ta.Port)
	}

	// PROXY protocol 信任开关。
	//
	// # 为什么它必须是一个显式的部署决定
	//
	// 对**不可信**来源解析 PROXY 头等于把源 IP 伪造能力直接送给公网：
	// 任何人都能在自己的连接前面加一行 `PROXY TCP4 1.2.3.4 ...`，
	// 于是 allow_cidrs 白名单、审计日志里的来源、每源 IP 配额全部失效。
	//
	// 所以默认 false，且只有当中继**确实**在一个前置负载均衡后面
	// （而那个 LB 是唯一能连到这个端口的东西）时才该打开。
	// 打开时启动日志里要显著警告 —— 一个开着这个开关又直接暴露在公网上的
	// 中继，它的所有来源判定都是可伪造的，而那从计数器上看不出来。
	if trustProxy {
		reg.SetTrustProxyProtocol(port, true)
		rt.log.Warn("共享入口已信任 PROXY protocol 头 —— "+
			"这个端口**必须**只能被前置负载均衡连到；"+
			"若它直接暴露在公网，任何人都能伪造源 IP，"+
			"于是来源白名单、审计来源、每源配额全部失效",
			"端口", port)
	}

	// 登记「这个端口我们在听」——与「这个端口上有路由」是两件事。
	// 不登记的话，判别器会在还没有任何隧道时把 ACME 挑战连接直接关掉
	//（理由见 Registry.EnsurePort）。
	reg.EnsurePort(port)

	rt.mu.Lock()
	rt.shared = &shareState{
		ln: ln, disc: disc, gw: gw, reg: reg, port: port, tlsOn: tlsCfg != nil,
		trustProxy: trustProxy,
		routed:     make(map[string]struct{}),
	}
	rt.mu.Unlock()

	go func() {
		if err := disc.Serve(rt.ctx, ln); err != nil {
			rt.log.Error("共享入口退出", "err", err)
		}
	}()

	rt.log.Info("共享入口已就绪",
		"监听", ln.Addr().String(), "TLS 终止", tlsCfg != nil)
	return nil
}

// applyShared 把当前隧道集合同步进共享入口的路由表。
//
// 全量重建而不是增量 diff：路由表就是一份期望状态的投影，
// 重建一次是纯内存操作（几十条路由），而增量 diff 要维护「哪条被改了」
// 的判断 —— 那正是最容易出「界面显示已生效、实际还是旧路由」的地方。
func (rt *runtime) applyShared(desired []*tunnel.Tunnel) {
	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh == nil {
		return
	}

	fresh := gateway.NewRegistry()
	// 端口本身必须留在表里，哪怕这一轮一条路由都没注册上 ——
	// 否则 ReplaceWith 之后 ACME 挑战会被判别器直接关掉
	//（理由见 Registry.EnsurePort）。全量重建最容易丢的就是这种
	// 「不由任何一条隧道产生」的状态。
	fresh.EnsurePort(sh.port)
	// PROXY 信任标记同理：它不由任何一条隧道产生，
	// 不重新设置就会在第一次隧道变更时被静默关掉。
	if sh.trustProxy {
		fresh.SetTrustProxyProtocol(sh.port, true)
	}
	routeErrs := make(map[string]string)
	var bound int
	for _, t := range desired {
		if !t.IsEnabled() || t.Exposure != tunnel.ExposureShared {
			continue
		}
		// UDP 走数据报路径，与共享 TCP 入口无关。
		if t.L4 == tunnel.L4UDP {
			continue
		}

		// 这里**刻意没有**「整端口独占」这一支。
		//
		// gateway.Registry.BindDedicated 存在且判别器第 0 步会用它，但它的正确
		// 配置表达是 exposure: port 的独立监听器 —— 在共享端口内部再造一个
		// 独占旁路会吞掉 ACME 的 TLS-ALPN-01 挑战（步骤 0 先于步骤 3），
		// 而且冲突赢家会由 slug 字典序决定。完整理由钉在 BindDedicated 上。
		//
		// catch_all 的隧道是这个端口的**默认落点**。
		//
		// 场景二在共享端口上的路径：设备只填「中继 IP + 端口」，不发 SNI，
		// Host 是 IP 字面量甚至缺失 —— 没有任何域名可匹配。
		// gateway.resolve 早就有 Fallback 分支，但在这次改动之前
		// **没有任何配置能设置它** —— BindDefault 从未被生产代码调用过，
		// 是「只被测试引用的导出标识符」扫描抓出来的。
		if t.Router.CatchAll {
			if err := fresh.BindDefault(sh.port, t); err != nil {
				rt.log.Warn("共享入口拒绝了默认落点", "隧道", t.Slug, "err", err)
				routeErrs[t.ID] = err.Error()
				continue
			}
			bound++
			continue
		}

		if err := fresh.AddShared(sh.port, t); err != nil {
			// 路由冲突（同一个域名被两条隧道声明）之类。把原因记下来，
			// 用户在控制台就能看到，而不是只看到「不通」。
			rt.log.Warn("共享入口拒绝了这条隧道", "隧道", t.Slug, "err", err)
			routeErrs[t.ID] = err.Error()
			continue
		}
		bound++
	}

	// 原地替换路由表内容。Registry 自己是并发安全的，但「换一整张表」
	// 需要判别器与网关都看到同一份 —— 所以两者共用同一个 *Registry 实例，
	// 这里替换的是它的内容而不是指针。
	sh.reg.ReplaceWith(fresh)

	// 换了路由表就要失效反向代理缓存。
	//
	// 不失效的后果不只是漏内存：ReverseProxy 的 Transport 把整个
	// *tunnel.Tunnel 闭包捕获进 DialContext，而 ListTunnels 每次都新分配
	// Tunnel 对象 —— 于是旧闭包里那份**旧定义**会一直被用下去。
	// 缓存键已经把 AgentID 与后端 authority 都带上了（那是承重的一层），
	// 这里是显式回收：让被删/被改的隧道不再占着一个 Transport 与它的空闲流。
	//
	// 失效「上一轮 ∪ 本轮」：被删掉的隧道不在 desired 里，只失效 desired
	// 的话它那条缓存永远回收不掉。
	for id := range sh.routed {
		sh.gw.Invalidate(id)
	}
	for _, t := range desired {
		sh.gw.Invalidate(t.ID)
	}
	// 丢掉已不存在隧道的限额状态。
	//
	// **不能挂在上面那个 Invalidate 循环里**：它对每条隧道都调一遍，而
	// applyShared 由 ApplyTunnels **与 refreshStates** 两处触发 ——
	// 后者在每次 agent 上下线时都跑。跟着它清零就等于每次抖动都把令牌桶
	// 清空（桶初始是满的 → 白送一份突发额度），并让在飞计数与还开着的连接脱节。
	// 见 internal/gateway/limits.go 顶部。
	live := make(map[string]bool, len(desired))
	for _, t := range desired {
		live[t.ID] = true
	}
	sh.reg.RetainLimits(live)

	nowRouted := make(map[string]struct{}, len(desired))
	for _, t := range desired {
		if _, bad := routeErrs[t.ID]; !bad {
			nowRouted[t.ID] = struct{}{}
		}
	}

	// 路由错误记在内存里而不是直接写库。
	//
	// 写库会被紧随其后的 refreshStates 覆盖 —— 它从零重算状态，
	// 不知道路由被拒过。把原因记在这里、让 refreshStates 跳过这些隧道，
	// 才能让「控制台显示 error 并说明原因」与「请求确实 404」一致。
	rt.mu.Lock()
	rt.routeErrors = routeErrs
	sh.routed = nowRouted
	rt.mu.Unlock()

	for id, reason := range routeErrs {
		_ = rt.db.SetTunnelState(rt.ctx, id, tunnel.StateError, reason)
	}

	rt.log.Debug("共享入口路由已更新",
		"端口", sh.port, "隧道数", bound, "被拒", len(routeErrs))
}

// closeShared 关闭共享入口。
func (rt *runtime) closeShared() {
	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh == nil {
		return
	}
	_ = sh.disc.Close()
	_ = sh.ln.Close()
}

// sharedStatus 返回共享入口的计量，未启用时返回 nil。
//
// # 为什么必须接上
//
// 共享入口是**一个**监听器服务任意多条隧道，所以按隧道的计数器回答不了
// 「443 上到底发生了什么」。判别是分级 peek 的，一次「域名打不开」可能停在
// 任何一级，而每一级对应完全不同的动作（SNI 未注册 = 域名没配上；
// 明文命中但 502 = agent 那头不通；AtCapacity = 并发上限太小；
// DeniedCIDR = 自己的白名单挡住了自己）。
//
// 这个函数原本存在但**没有任何调用点** —— 于是共享入口的所有数字在控制台上
// 恒为 0，而这正是本产品声称要解决的那类「只知道不通」的问题。
func (rt *runtime) sharedStatus() *console.SharedEntryStatus {
	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh == nil {
		return nil
	}
	d, g := sh.disc.Stats(), sh.gw.Stats()
	routes := 0
	if view, ok := sh.reg.View(sh.port); ok {
		routes = view.Hosts.Len()
	}
	return &console.SharedEntryStatus{
		Addr:           sh.ln.Addr().String(),
		TLSTermination: sh.tlsOn,
		Routes:         routes,

		Dedicated:     d.Dedicated.Load(),
		ProxyProtocol: d.ProxyProtocol.Load(),
		SNIPassthru:   d.SNIPassthru.Load(),
		SNIGateway:    d.SNIGateway.Load(),
		Cleartext:     d.Cleartext.Load(),
		ACME:          d.ACME.Load(),
		PortDefault:   d.PortDefault.Load(),
		Rejected:      d.Rejected.Load(),
		DeniedCIDR:    d.DeniedCIDR.Load(),
		AtCapacity:    d.AtCapacity.Load(),
		CarrierALPN:   d.CarrierALPN.Load(),

		Requests:   g.Requests.Load(),
		NoRoute:    g.NoRoute.Load(),
		BadGateway: g.BadGateway.Load(),
		Upgrades:   g.Upgrades.Load(),

		GatewayDeniedCIDR: g.DeniedCIDR.Load(),

		GatewayDeniedMaxConns: g.DeniedMaxConns.Load(),
		GatewayDeniedPerIP:    g.DeniedPerIP.Load(),
		SpliceDeniedMaxConns:  d.SpliceDeniedMaxConns.Load(),
		SpliceDeniedPerIP:     d.SpliceDeniedPerIP.Load(),
		DeniedPassthrough:     g.DeniedPassthrough.Load(),
	}
}

// KnowsHost 报告一个域名是否属于本中继的某条隧道（实现 acmecert.HostChecker）。
//
// # 为什么这是 ACME 的第二道闸门
//
// certmagic 会为**任何**握手里出现的名字去申请证书。任何人拿我们的 IP 发一个
// 带随机 SNI 的握手，就能让我们去找 CA 要一张证书 —— 几百次之后 CA 把我们
// 限速，真域名也签不出来。所以「这个域名是不是我们的业务」必须能回答。
//
// 只认**精确**注册过的域名（HasExactDomain 而不是 MatchHost）：通配回落会让
// 「*.example.com 下的任意子域」都变成可签发目标，而那正好是被滥用的形状。
// 代价是通配路由拿不到 ACME 证书 —— 那是刻意的，理由见 HasExactDomain。
func (rt *runtime) KnowsHost(name string) bool {
	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh == nil {
		return false
	}
	view, ok := sh.reg.View(sh.port)
	if !ok {
		return false
	}
	return view.Hosts.HasExactDomain(name)
}

// carrierAcceptor 造判别器的 Carrier 回调：在共享端口上收 L2 承载。
//
// cfg 为 nil（没有任何证书）时返回 nil —— 判别器据此**拒绝**这类连接。
// 那比「当成业务流量喂给网关」好得多：后者让 agent 看到「连上了又被断开」，
// 而中继侧的计数器一切正常。
//
// # 为什么在这里终止 TLS 而不是让判别器做
//
// 承载要那条 *tls.Conn 才能导出信道绑定材料（ExportKeyingMaterial 挂在
// tls.ConnectionState 上）。判别器把 net.Conn 交出来，这里自己 tls.Server ——
// PeekConn 已经把 ClientHello 重放回去了，所以这是一次完整正常的握手。
func (rt *runtime) carrierAcceptor(cfg *tls.Config) func(net.Conn) {
	if cfg == nil {
		return nil
	}
	return func(conn net.Conn) {
		// 握手要有期限：一个连上来就不说话的对端会占住一个连接槽
		// （判别器的 MaxConns 是有界的，占满就是拒绝服务）。
		tc := tls.Server(conn, cfg)
		hsCtx, cancel := context.WithTimeout(rt.ctx, 15*time.Second)
		err := tc.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			rt.log.Debug("L2 承载 TLS 握手失败", "来源", conn.RemoteAddr(), "err", err)
			_ = tc.Close()
			return
		}

		c, err := carrier.AdoptTLSMux(tc)
		if err != nil {
			rt.log.Warn("建立 L2 承载失败", "来源", conn.RemoteAddr(), "err", err)
			_ = tc.Close()
			return
		}
		rt.log.Info("收到 L2 承载连接（agent 走降级路径：它的网络大概封了 UDP）",
			"来源", conn.RemoteAddr(), "梯级", c.Rung().String())

		// 与 L0 走**同一个** handleCarrier：换承载不改变握手与数据面的任何一行。
		// 两条路径分头实现是漂移的开始，而这里的漂移意味着「换个梯级就有一半
		// 的安全检查不生效」。
		handleCarrier(rt.ctx, c, rt, rt.log)
	}
}

// 保证 runtime 满足 gateway 需要的会话查询接口 —— 少一个方法就会在
// 装配处才发现，而那时错误信息只会说「不满足接口」。
var _ gateway.SessionSource = (*runtime)(nil)

// 同样钉住 relay 侧：两条路径共用同一个查询实现。
var _ relay.TunnelLookup = (*runtime)(nil)
