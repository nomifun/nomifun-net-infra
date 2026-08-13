// 命令 nfagent 是 NomiRelay 的边缘代理：部署在被暴露服务旁，
// 主动外连中继，接受中继开来的流并拨本地目标。
//
// 本程序**不含 SQLite**（modernc.org/sqlite 无 MIPS 移植），
// 因此可以交叉编译到 MIPS 路由器。`make check` 会断言这条。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/agent"
	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/policy"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nfagent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		relayAddrs = flag.String("relay", "", "中继地址，多个用逗号分隔（按序故障切换）")
		pin        = flag.String("pin", "", "中继证书的 SPKI 指纹（base64），必填")
		token      = flag.String("token", "", "一次性入网令牌（首次入网必填）")
		serverName = flag.String("server-name", "nomirelay", "TLS SNI 名")
		allowSpec  = flag.String("allow", "", "额外允许的目标网段，逗号分隔；默认放行回环与私有段")
		stateDir   = flag.String("state-dir", "", "状态目录（存入网凭据与机器标识）；留空按平台默认，见 README")
		l2Port     = flag.Uint("l2-port", 443, "L2 承载回退端口（TLS/TCP + smux，与中继共享入口同端口）；"+
			"0 表示不回退，只用 L0/QUIC")
		logLevel = flag.String("log-level", "info", "日志级别 debug|info|warn|error")
		showVer  = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("nfagent %s (%s)\n", version, commit)
		return nil
	}
	if *relayAddrs == "" {
		return errors.New("必须用 -relay 指定中继地址")
	}
	if *pin == "" {
		// 不提供「跳过校验」的逃生口。frp 的默认 InsecureSkipVerify=true
		// 让它宣传的 TLS 只有加密没有认证；这里宁可让用户多贴一个指纹。
		return errors.New("必须用 -pin 指定中继证书指纹（本程序不提供跳过证书校验的选项）")
	}

	log := newLogger(*logLevel)

	pinRaw, err := carrier.ParseSPKIPin(*pin)
	if err != nil {
		return err
	}

	addrs := splitAddrs(*relayAddrs)
	if len(addrs) == 0 {
		return errors.New("-relay 未解析出任何地址")
	}

	pol, err := buildPolicy(*allowSpec)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	ident := agent.Identity{Version: version, Hostname: hostname}

	// 打开状态目录并读凭据 —— 必须在握手之前，因为它同时决定：
	//   * 已有凭据 → 直接用密钥握手，忽略命令行给的 -token；
	//   * 无凭据 → 走令牌首次入网，而 Load 顺手生成的 machine_id 会随
	//     那一次 Hello 上报（中继落库这个字段的唯一一次）。
	// OpenStore 已经确认过目录可写，所以「令牌被消费掉之后才发现写不进去」
	// 这个最贵的失败被提前到了启动时。
	store, err := agent.OpenStore(*stateDir, log)
	if err != nil {
		return err
	}
	cred, err := store.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("nfagent 启动", "版本", version, "中继候选", addrs, "主机名", hostname,
		"状态目录", store.Dir(), "已有凭据", cred.AgentID != "")
	if cred.AgentID != "" && *token != "" {
		// 有凭据时命令行令牌是多余的 —— 说清它被忽略，免得用户以为
		// 「我明明给了新令牌」却看到旧身份。
		log.Warn("已存在入网凭据，忽略命令行 -token（凭据优先；要重新入网请先删除状态目录里的 credential.json）")
	}

	a := &runner{
		addrs:      addrs,
		pin:        pinRaw,
		serverName: *serverName,
		token:      *token,
		policy:     pol,
		ident:      ident,
		tunnels:    agent.NewTunnelSet(),
		store:      store,
		cred:       cred,
		log:        log,
		l2Port:     uint16(*l2Port),
	}
	return a.loop(ctx)
}

// runner 持有 agent 的运行状态与重连循环。
type runner struct {
	addrs      []string
	pin        []byte
	serverName string
	token      string

	// l2Port 是 L2 梯级（TLS/TCP + smux）的端口。0 表示不启用回退。
	//
	// 与承载地址同主机、只换端口：多一个地址配置项就多一处能配错的地方，
	// 而这里配错的现象是「降级也连不上」—— 而那时用户已经在排查网络了。
	l2Port  uint16
	policy  *policy.Policy
	ident   agent.Identity
	tunnels *agent.TunnelSet
	store   *agent.Store
	log     *slog.Logger

	// udp 是当前会话的数据报处理器，供状态上报读取计数（无会话时为 nil）。
	udp atomic.Pointer[agent.UDPHandler]

	// cred 在首次入网后被填充。
	cred agent.Credential

	// credDirty 表示手里有一份**还没落盘**的凭据。
	//
	// # 为什么这个标记必须存在
	//
	// 落盘失败时不能退出：令牌已经被中继作废（一次性），退出之后重启会拿着
	// 一个空状态目录与一枚废令牌 → exit(1) → 配 Restart=always 就是崩溃循环。
	// 也就是说「退出」把一次**可恢复**的磁盘故障放大成了永久下线。
	//
	// 但也不能就这么算了：cred 在 Save **之前**就已经填好，所以下一次重连会走
	// HMAC 分支并成功，而那次的 IssuedKey 为空 —— 于是再也不会尝试落盘。
	// 净效果是一个「一次性 agent」在整个进程生命周期里**伪装成健康节点**，
	// 直到某次因升级/reboot/OOM 重启才暴露成崩溃循环。
	//
	// 所以：带着这个标记继续跑（流量不断），每次重连**重试落盘**（磁盘修好就自愈），
	// 并且周期性地把这件事重新喊出来（一条只出现一次的 ERROR 会被淹掉，
	// 而这个状态意味着「你离永久下线只差一次重启」）。
	credDirty     bool
	lastDirtyWarn time.Time

	// addrIdx 是当前使用的中继地址下标，故障切换时前进。
	addrIdx int
}

// 重连退避参数。
//
// frp 的 LoginFailExit 默认为 true（pkg/config/v1/client.go:88），
// 首次登录失败直接进程退出 —— 对开机时网络还没就绪的家用主机、
// 以及场景二的工厂机器人，这是**明确的错误默认值**（机器人会变砖）。
// 这里**永不退出**，只退避。
const (
	fastRetries  = 3
	fastInterval = 200 * time.Millisecond
	baseBackoff  = time.Second
	maxBackoff   = 60 * time.Second
	// 同一地址连续失败这么多次后，切到下一个中继候选。
	failuresBeforeFailover = 3
)

func (r *runner) loop(ctx context.Context) error {
	attempt := 0
	consecutiveFailures := 0

	for {
		if ctx.Err() != nil {
			return nil
		}

		addr := r.addrs[r.addrIdx]
		err := r.session(ctx, addr)
		if ctx.Err() != nil {
			return nil
		}

		if err == nil {
			// 连接正常结束（中继排空），立刻重连，不退避。
			attempt = 0
			consecutiveFailures = 0
			continue
		}

		// 不可重试的错误：凭据被撤销、版本过旧。
		//
		// 是否退出**按盘上有没有凭据分叉，不按错误码分叉**：
		//
		//   * 还没入网（cred.AgentID 为空）时收到不可重试拒绝 —— 令牌过期、
		//     打错、或已被用过（这三者在线上回同一个 auth_failed，不可区分）。
		//     此时有人正盯着终端做首次入网，快速失败退出是对的。
		//
		//   * 已入网（cred.AgentID 非空）时，「凭据被撤销」与「中继换了库、
		//     恢复了旧备份」同样回一个不可重试的 revoked（存储层把「查不到」
		//     与「revoked_at 非空」合并成同一个否定）。这两种在线上根本分不开，
		//     而后者是**瞬时**的 —— 中继修好库、agent 就该自动接回。所以
		//     已入网节点**绝不因此退出**，退避重试，等中继恢复。
		//
		// 这正是 frp 的 LoginFailExit 修不对的地方：它让一个有凭据的服务因
		// 一次瞬时状况而退出。把「有身份」与「没身份」两种处境合并成一条
		// 退出规则，就必然在其中一种上做错。
		var pe *proto.Error
		if errors.As(err, &pe) && !pe.Retryable {
			if r.cred.AgentID == "" {
				r.log.Error("入网被拒且不可重试，退出（令牌可能已过期、打错或被用过）",
					"code", pe.Code, "msg", pe.Message)
				return err
			}
			r.log.Warn("中继拒绝了本代理端（凭据被撤销，或中继正在恢复中）；"+
				"已入网节点不退出，将持续重试等待中继恢复",
				"code", pe.Code, "msg", pe.Message)
			// 落到下面的退避路径，不 return。
		}

		consecutiveFailures++
		if consecutiveFailures >= failuresBeforeFailover && len(r.addrs) > 1 {
			r.addrIdx = (r.addrIdx + 1) % len(r.addrs)
			consecutiveFailures = 0
			r.log.Warn("切换到下一个中继候选", "新地址", r.addrs[r.addrIdx])
		}

		d := backoff(attempt)
		attempt++
		r.log.Warn("连接中继失败，稍后重试", "地址", addr, "退避", d, "err", err)

		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil
		}
	}
}

// backoff 计算第 n 次重试的等待时间。
//
// 前 fastRetries 次快速重试（覆盖「网络刚抖了一下」这种常见情况），
// 之后指数退避到上限，并加 ±20% 抖动避免整个机队同时重连把中继打崩。
// **上限永不为「放弃」**。
func backoff(n int) time.Duration {
	if n < fastRetries {
		return fastInterval
	}
	d := baseBackoff << min(n-fastRetries, 6)
	if d > maxBackoff {
		d = maxBackoff
	}
	jitter := 1 + (rand.Float64()*0.4 - 0.2)
	return time.Duration(float64(d) * jitter)
}

// session 建立一次承载连接并服务到断开。
func (r *runner) session(ctx context.Context, addr string) error {
	tlsCfg, err := carrier.ClientTLSConfig(r.serverName, nil, r.pin)
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	c, err := r.dialCarrier(dialCtx, addr, tlsCfg)
	cancel()
	if err != nil {
		return err
	}
	defer c.CloseWithError(0, "会话结束")

	// 梯级要报出来。L2 上没有不可靠数据报，所以 UDP 隧道会被中继标成
	// degraded —— 运维必须能把那个现象与「这个 agent 走了降级路径」联系起来。
	if c.Rung() != carrier.RungQUIC {
		r.log.Warn("走的是降级承载梯级：UDP 隧道在这一级上不可用",
			"梯级", c.Rung().String(),
			"原因", "首选梯级（L0/QUIC）拨不通，通常是出口封了 UDP")
	}

	ctrl, err := c.OpenStream(ctx)
	if err != nil {
		return err
	}

	// 信道绑定：把握手证明绑到**这一条** TLS 连接上。
	//
	// 拿不到时按无绑定继续（返回空材料）——并非所有承载梯级都有 TLS，
	// 而两端在同一条连接上会得到同样的空值，MAC 仍然一致。
	// 拿到了却报错则是真异常（QUIC 强制 TLS 1.3，正常路径上不会），
	// 此时**不静默降级**：悄悄关掉一层防护比握手失败糟得多。
	binding, err := c.ChannelBinding()
	if err != nil {
		return fmt.Errorf("nfagent: 取信道绑定材料失败：%w", err)
	}

	res, err := agent.Handshake(ctrl, r.cred, r.token, binding, r.ident)
	if err != nil {
		return err
	}

	// 首次入网：持久化下发的凭据，并作废一次性令牌。
	if res.IssuedKey != "" {
		r.cred = agent.Credential{
			AgentID:   res.AgentID,
			Key:       res.IssuedKey,
			MachineID: r.cred.MachineID, // 保留 Load 时生成的机器标识
		}
		r.persistIssued(res.AgentID)
		r.token = "" // 一次性令牌用过即弃，后续重连走凭据。
	}

	// 上一次落盘失败过：每次重连都重试一遍。
	r.retryPersist()

	// 时钟偏移必须报出来 —— 它是握手失败最常见的现场原因，
	// 只说「鉴权失败」会让人查错方向。
	if skew := res.ClockSkew; skew > 5*time.Second || skew < -5*time.Second {
		r.log.Warn("本机时钟与中继偏差较大，可能导致握手失败", "偏差", skew)
	}

	r.log.Info("已连上中继",
		"agent", res.AgentID,
		"中继版本", res.RelayVersion,
		"承载", c.Rung().String(),
		"数据报", res.SupportsDatagrams(),
		"能力", res.Capabilities)

	handler := &agent.StreamHandler{Tunnels: r.tunnels, Policy: r.policy, Log: r.log}

	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()

	var wg sync.WaitGroup
	defer wg.Wait()

	// 在控制流上周期性上报计数器。
	//
	// # 为什么走控制流，而不是每次开一条新流
	//
	// 中继只 AcceptStream **一次**（拿控制流做握手），之后不再接受
	// agent 主动开的流 —— 开新流会挂住。而握手之后控制流在两侧都还开着、
	// 谁都没在用它，那正是这类「agent → 中继的周期性消息」该走的地方。
	//
	// # 为什么必须有这条上报
	//
	// 中继只看得见自己那一侧。agent 侧有一整类丢弃它完全不知道：
	// 拨本地目标失败、被本地策略否决、回向发送队列满、回向超限、
	// 回向重组失败。症状是「下行统计都对，就是收不到回包」，
	// 而在这之前**没有任何数字**能告诉运维为什么。
	// 控制流上的双向流量：agent 写计数器上报、中继写 Ping。
	//
	// **写者必须只有一个。** QUIC 流是全双工，读写可以并发，但两个协程
	// 同时往同一条流写会把帧交错撕开。所以读循环收到 Ping 之后不自己回，
	// 而是把序号交给写协程（pong 通道），由它统一写出去。
	pong := make(chan uint32, 4)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.serveControl(sessCtx, res.Rest, pong)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.reportMetrics(sessCtx, ctrl, pong)
	}()

	// 起 UDP 数据报处理。
	//
	// 与流处理并行、互不影响：数据报走的是另一条路（QUIC 的连接级
	// ReceiveDatagram），不经过 AcceptStream。承载不支持数据报时它立刻
	// 返回，不影响 TCP 隧道 —— 一条 UDP 隧道不通不该让整个 agent 停摆。
	udp := &agent.UDPHandler{Tunnels: r.tunnels, Policy: r.policy, Log: r.log}
	r.udp.Store(udp)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer r.udp.Store(nil)
		if err := udp.Serve(sessCtx, c); err != nil &&
			!errors.Is(err, carrier.ErrDatagramUnsupported) && sessCtx.Err() == nil {
			r.log.Warn("UDP 数据报处理退出", "err", err)
		}
	}()

	for {
		st, err := c.AcceptStream(sessCtx)
		if err != nil {
			if sessCtx.Err() != nil {
				return nil
			}
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			r.serveStream(sessCtx, st, handler)
		}()
	}
}

// 承载梯级探测的时限。
const (
	// dialTimeout 是整轮探测（含全部梯级）的总时限。
	dialTimeout = 20 * time.Second

	// rungHeadStart 是 L0 独占的时间。
	//
	// **不并发拨、而是给 L0 一段独占时间**，理由是「首选梯级要真的被优先」：
	// 并发竞速时 L2（TCP+TLS 1.3，两次往返）在近距离网络里经常比 QUIC 快，
	// 于是一台网络完全正常的中继上所有 agent 都跑在 L2 上 —— 而那一级
	// **没有数据报**，UDP 隧道会全线不可用。那是一次静默的能力降级。
	//
	// 1.5 秒：足够覆盖一次正常的 QUIC 握手（含丢一个包重传），
	// 又不至于让「UDP 真的被封」的部署等太久 —— 那种网络里 UDP 包是被
	// 静默丢弃的，所以 L0 不会快速失败，只能靠这个超时。
	rungHeadStart = 1500 * time.Millisecond
)

// dialCarrier 按梯级顺序建立承载：先 L0（QUIC），拨不通再退到 L2（TLS+smux）。
//
// # 为什么要有回退
//
// 工厂与企业网络常见只放行 TCP 80/443。场景二的 agent 就装在那种网络里，
// 没有回退的话它根本接不进来，而现象是「一直重连、日志里只有拨号超时」。
//
// # 为什么不并发竞速
//
// 见 rungHeadStart：L2 常常更快，而它**没有数据报**。让它赢等于在一台
// 网络正常的中继上静默关掉所有 UDP 隧道。规格 §5.1 说的「竞速取胜者」
// 必须理解成「按梯级优先、上一级失败才用下一级」，否则优先级就没有意义。
func (r *runner) dialCarrier(
	ctx context.Context, addr string, tlsCfg *tls.Config,
) (carrier.Carrier, error) {
	// ── L0：QUIC ──
	l0Ctx, cancel := context.WithTimeout(ctx, rungHeadStart)
	c, l0Err := carrier.DialQUIC(l0Ctx, addr, carrier.QUICConfig{
		TLSConfig: tlsCfg,
		Rung:      carrier.RungQUIC,
	})
	cancel()
	if l0Err == nil {
		return c, nil
	}
	if ctx.Err() != nil {
		return nil, l0Err
	}
	if r.l2Port == 0 {
		// 显式关掉了回退。如实说明，否则用户会以为「降级没生效」是缺陷。
		return nil, fmt.Errorf("L0/QUIC 拨不通且 -l2-port=0（已关闭回退）：%w", l0Err)
	}
	r.log.Info("L0/QUIC 拨不通，尝试降级梯级", "地址", addr, "err", l0Err)

	// ── L2：TLS/TCP + smux ──
	//
	// 地址用**同一个主机**、端口换成 L2 端口（默认 443）：承载与共享入口
	// 共用那个端口，靠 ALPN 区分。用同一个主机而不是让用户再配一个地址 ——
	// 多一个配置项就多一处可以配错的地方，而这里配错的现象是「降级也连不上」。
	l2Addr := r.l2AddrFor(addr)
	l2Cfg := tlsCfg.Clone()
	l2Ctx, cancel2 := context.WithTimeout(ctx, dialTimeout-rungHeadStart)
	c2, l2Err := carrier.DialTLSMux(l2Ctx, l2Addr, l2Cfg)
	cancel2()
	if l2Err == nil {
		return c2, nil
	}
	// 两级都失败时把**两个**原因都报出来。只报后一个会把人引向 443 的配置，
	// 而真正的问题可能是 L0 那边（比如指纹配错了，两级都会因此失败）。
	return nil, fmt.Errorf("所有承载梯级都拨不通：L0/QUIC %v；L2/TLS443（%s）%w",
		l0Err, l2Addr, l2Err)
}

// l2AddrFor 把承载地址换成 L2 的端口。
//
// -l2-port 为 0 表示不启用回退（那时 dialCarrier 不会走到这里）。
func (r *runner) l2AddrFor(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return net.JoinHostPort(host, strconv.Itoa(int(r.l2Port)))
}

// metricsInterval 是计数器上报间隔。
//
// 5 秒而不是 1 秒：这些是**累计值**，控制台的曲线由差分得出，
// 5 秒的分辨率对「哪一类丢弃在涨」这个问题完全够用，
// 而 1 秒会让一个装了几百个 agent 的中继光收上报就忙起来。
const metricsInterval = 5 * time.Second

// reportMetrics 周期性把本 agent 的计数器写到控制流上。
//
// 写失败**不重试也不报错退出**：控制流断了意味着会话已经结束，
// 外层的重连逻辑会处理它。在这里重试只会在一条已死的流上刷日志。
// serveControl 读控制流，回应中继的 Ping。
//
// **只读不写。** 收到 Ping 之后把序号交给写协程 —— 两个协程同时往同一条流
// 写会把帧交错撕开，而那种损坏在对端表现为「协议解析失败」，
// 与真正的协议不兼容长得一模一样。
//
// 未知帧类型只跳过（proto.Reader 的前向兼容语义），**绝不**因此断开会话：
// 一个更新的中继发来我们不认识的控制帧不该让整条隧道停掉。
func (r *runner) serveControl(ctx context.Context, rest io.Reader, pong chan<- uint32) {
	// **必须用握手交出来的 rest，不能新建 Reader 读裸流。**
	//
	// 握手那个 Reader 内部是 16 KiB bufio，可能已经把 HelloOK 之后的字节吞了
	//（中继紧接着发的 Ping 就会落在那里）；新建一个就会从帧中间开始解析
	// → 版本不匹配 → 整条控制流死掉，连计量上报一起。
	rd := proto.NewReader(rest)
	for {
		fr, err := rd.ReadFrame()
		if err != nil {
			// 会话结束时这里必然出错，不值得记日志。
			return
		}
		if fr.Header.Type != proto.TypePing {
			continue
		}
		select {
		case pong <- fr.Header.CorrID:
		case <-ctx.Done():
			return
		default:
			// 写协程忙不过来：丢掉这次回应。
			//
			// 丢掉比阻塞在这里好 —— 阻塞会让读循环停下，
			// 而这条流上还有别的（将来的）控制帧要读。
			// 中继侧会把它当成一次 ping 超时，那是正确的解读：
			// 我们确实没能及时回应。
			r.log.Debug("回应 Ping 时写队列已满，丢弃这次回应")
		}
	}
}

func (r *runner) reportMetrics(ctx context.Context, ctrl carrier.Stream, pong <-chan uint32) {
	w := proto.NewWriter(ctrl)
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()
	started := time.Now()

	// writeFrame 是这条流**唯一**的写入点。
	writeFrame := func(typ proto.Type, corrID uint32, flags uint8, payload any) error {
		// 写期限：控制流卡住时不该把这个协程和它持有的 ctrl 一起挂死。
		_ = ctrl.SetWriteDeadline(time.Now().Add(metricsInterval))
		defer func() { _ = ctrl.SetWriteDeadline(time.Time{}) }()
		return w.WriteMessage(typ, corrID, flags, payload)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case seq := <-pong:
			// 回应 Ping。**必须尽快** —— 这个延迟会被算进中继测到的 RTT。
			// 所以它与定时上报共用一个 select 而不是排在它后面。
			if err := writeFrame(proto.TypePong, seq, proto.FlagResponse, nil); err != nil {
				r.log.Debug("回应 Ping 失败（会话可能已结束）", "err", err)
				return
			}
			continue
		case <-ticker.C:
			// 还欠着落盘时周期性重新喊一次。
			//
			// 一条只在入网那一刻出现的 ERROR 会被后面几千行日志淹掉，
			// 而这个状态的含义是「你离永久下线只差一次重启」——
			// 它必须一直可见。间隔取 10 分钟：足够被看到，又不至于变成噪音。
			r.remindIfCredentialUnsaved()
		}

		m := proto.AgentMetrics{UptimeSeconds: int64(time.Since(started).Seconds())}
		if udp := r.udp.Load(); udp != nil {
			m.UDP = udp.Metrics()
		}
		if err := writeFrame(proto.TypeMetrics, 0, 0, m); err != nil {
			r.log.Debug("上报计数器失败（会话可能已结束）", "err", err)
			return
		}
	}
}

// serveStream 判断一条新流是控制帧还是数据流并分派。
//
// 控制流与数据流走同一个 AcceptStream，靠首帧类型区分：
// TunnelSet 是控制，StreamOpen 是数据。这样中继不需要预先约定流编号，
// 也就不需要 frp 那种「用 runID 认领连接」的机制（及其安全问题）。
func (r *runner) serveStream(ctx context.Context, st carrier.Stream, h *agent.StreamHandler) {
	// 变量名避开接收者 r（*runner）。
	pr := proto.NewReader(st)
	fr, err := pr.ReadFrame()
	if err != nil {
		st.Close()
		return
	}

	switch fr.Header.Type {
	case proto.TypeTunnelSet:
		defer st.Close()
		r.applyTunnelSet(st, fr)

	case proto.TypeStreamOpen:
		// 交给数据面。handler 需要这一帧，所以直接在这里内联它的逻辑入口。
		// 必须传 Remainder 而不是裸流：中继把 StreamOpen 头与用户首包
		// pipeline 在同一个包里发出，那些首包字节可能已被读帧时一并缓冲。
		if err := h.ServeWithOpen(ctx, st, fr, pr.Remainder(st)); err != nil && ctx.Err() == nil {
			r.log.Warn("处理隧道流失败", "err", err)
		}

	default:
		r.log.Warn("收到意外的流首帧", "帧", fr.Header.Type.String())
		st.Close()
	}
}

// applyTunnelSet 应用中继下发的隧道集合，并回报被本地策略否决的条目。
func (r *runner) applyTunnelSet(st carrier.Stream, fr proto.Frame) {
	var desired []*tunnel.Tunnel
	if err := proto.Decode(fr, &desired); err != nil {
		r.log.Warn("解析隧道集合失败", "err", err)
		return
	}

	rejected := r.tunnels.Reconcile(desired, r.policy)
	r.log.Info("已应用隧道集合",
		"下发", len(desired), "接受", r.tunnels.Len(), "否决", len(rejected))
	for id, reason := range rejected {
		r.log.Warn("本地策略否决隧道", "隧道", id, "原因", reason)
	}

	// 回报否决结果，让控制台能显示 rejected_by_agent 及原因。
	if err := proto.NewWriter(st).WriteMessage(
		proto.TypeTunnelRejected, fr.Header.CorrID, proto.FlagResponse, rejected,
	); err != nil {
		r.log.Warn("回报否决结果失败", "err", err)
	}
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

func splitAddrs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildPolicy 构造本地目标策略：默认值 + 用户追加的网段。
func buildPolicy(allowSpec string) (*policy.Policy, error) {
	cfg := policy.DefaultConfig()
	for _, p := range strings.Split(allowSpec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("-allow 中的 %q 不是合法 CIDR：%w", p, err)
		}
		cfg.Allow = append(cfg.Allow, prefix)
	}
	return policy.New(cfg)
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

// dirtyWarnInterval 是「凭据还没落盘」提醒的最小间隔。
const dirtyWarnInterval = 10 * time.Minute

// remindIfCredentialUnsaved 在凭据还欠着落盘时周期性重新告警。
//
// 不重试落盘（重试点在每次重连的握手之后）——这里只负责让这个状态**保持可见**。
// 两件事分开：重试要在有新连接时做（那时磁盘状况可能已经变了），
// 而提醒要按时间做（否则一个连接稳定几天的 agent 一条提醒都不会再打）。
func (r *runner) remindIfCredentialUnsaved() {
	if !r.credDirty {
		return
	}
	now := time.Now()
	if !r.lastDirtyWarn.IsZero() && now.Sub(r.lastDirtyWarn) < dirtyWarnInterval {
		return
	}
	r.lastDirtyWarn = now
	r.log.Error("入网凭据仍未落盘：本进程可用，但**任何一次重启都会导致永久失联**"+
		"（届时需要人工重签入网令牌，且既有隧道会因 agent ID 变化而悬空）",
		"状态目录", r.store.Dir(), "agent", r.cred.AgentID)
}

// persistIssued 把首次入网拿到的凭据落盘。**失败不返回错误、不退出。**
//
// 理由见 runner.credDirty：退出会把一次可恢复的磁盘故障放大成永久下线
// （令牌已作废 → 重启拿着空目录 + 废令牌 → exit(1) → 崩溃循环）。
func (r *runner) persistIssued(agentID string) {
	if err := r.store.Save(r.cred); err != nil {
		r.credDirty = true
		r.log.Error("入网成功但凭据落盘失败 —— 本进程仍可用，但**重启后会永久失联**；"+
			"请立刻修好状态目录（每次重连会自动重试落盘）",
			"agent", agentID, "状态目录", r.store.Dir(), "err", err)
		return
	}
	r.credDirty = false
	r.log.Info("入网成功，长期凭据已落盘", "agent", agentID, "状态目录", r.store.Dir())
}

// retryPersist 在还欠着落盘时重试一次。每次重连调用。
//
// 磁盘修好之后这一步自愈，不需要人工介入、也不需要重启 ——
// 而重启恰恰是这个状态下最危险的动作。
func (r *runner) retryPersist() {
	if !r.credDirty || r.cred.AgentID == "" {
		return
	}
	if err := r.store.Save(r.cred); err != nil {
		r.log.Error("凭据仍然无法落盘 —— 重启后会永久失联",
			"状态目录", r.store.Dir(), "err", err)
		return
	}
	r.credDirty = false
	r.lastDirtyWarn = time.Time{}
	r.log.Info("凭据已补写成功，重启后可自动重连", "状态目录", r.store.Dir())
}
