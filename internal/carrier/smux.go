package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xtaci/smux"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// L2 承载：TLS/TCP + smux。
//
// # 它为什么必须存在
//
// L0（QUIC/UDP）在**出口完全封锁 UDP** 的网络里连不上，而那不是罕见配置：
// 工厂与企业网络常见只放行 TCP 80/443。场景二的部署位置恰好在那种网络里 ——
// agent 装在被暴露服务旁边，也就是工厂内网。没有这一级，那些部署根本接不进来，
// 而现象是「agent 一直重连、日志里只有拨号超时」。
//
// # 为什么是 smux 而不是「一条 TCP 一条隧道连接」
//
// 隧道数据面要求**中继也能主动开流**（那是 0 额外 RTT 的全部来源，
// 见 Carrier.OpenStream 的说明）。裸 TCP 做不到这件事：一条 TCP 只有一条流，
// 中继想开新流就得让 agent 再拨一次，于是又回到 frp 那三次往返。
//
// smux 的流在**两侧都能开**（client 用奇数流 ID、server 用偶数，互不冲突），
// 所以换承载不改变数据面的任何一行。这正是规格挑它的理由。
//
// # 这一级**没有**不可靠数据报
//
// smux 只有可靠有序流。UDP 隧道在这一级上不可用，而这件事必须**如实上报**：
// SupportsDatagrams 返回 false，中继据此把 UDP 隧道标成 degraded 并写明
// 「代理端承载不支持不可靠数据报」。
//
// **绝不**把 UDP 悄悄塞进一条可靠流 —— frp 就是那样做的
// （把全部 UDP 塞进一条 TCP workConn），结果是语义错配导致的队头阻塞，
// 而用户以为自己拿到了一条低延迟通道。宁可让那条隧道明确不可用。
const (
	// smuxVersion 是 smux 协议版本。
	//
	// 2 而不是 1：v2 才有每流的接收窗口（v1 只有全局窗口），
	// 而一条承载上会同时跑几十条隧道流 —— 全局窗口意味着一条慢的流
	// 能把其他所有流一起憋住，那正是我们在 UDP 路径上花了大力气避免的形态。
	smuxVersion = 2

	// smuxKeepAliveInterval / smuxKeepAliveTimeout 是死连接检测。
	//
	// **必须设**：TCP 在对端掉电时不会通知任何人，一条已死的承载会挂在那里
	// 直到 OS 的 TCP keepalive 超时（Linux 默认 2 小时+）。那两个小时里
	// 中继以为 agent 在线、隧道显示绿点，而每一个连接都石沉大海。
	//
	// 取值与 QUIC 侧的空闲超时同量级，让两个梯级的失效时间尺度一致 ——
	// 否则运维会发现「同样的故障，换个梯级要等的时间完全不同」。
	smuxKeepAliveInterval = 10 * time.Second
	smuxKeepAliveTimeout  = 30 * time.Second

	// smuxMaxFrameSize 是单个 smux 帧的上限。
	//
	// 32 KiB：比默认的 4 KiB 大，减少大流量隧道上的帧头开销与系统调用次数；
	// 又远小于 MaxPayloadSize（1 MiB），所以一个控制帧永远不会因为
	// 「smux 帧装不下」而被切开成需要上层重组的形态。
	smuxMaxFrameSize = 32 * 1024

	// smuxMaxReceiveBuffer 是整条会话的接收缓冲上限。
	//
	// 这是一个**内存上界**，不是性能旋钮：它由对端的发送速率驱动，
	// 而对端在鉴权之前就能开始发。4 MiB 乘以并发 agent 数就是最坏情况，
	// 所以它不能取默认的 4 MiB × 无上限。
	smuxMaxReceiveBuffer = 4 * 1024 * 1024
	smuxMaxStreamBuffer  = 512 * 1024
)

// smuxConfig 造 smux 的配置。两端必须一致，否则版本协商直接失败。
func smuxConfig() *smux.Config {
	return &smux.Config{
		Version:           smuxVersion,
		KeepAliveInterval: smuxKeepAliveInterval,
		KeepAliveTimeout:  smuxKeepAliveTimeout,
		MaxFrameSize:      smuxMaxFrameSize,
		MaxReceiveBuffer:  smuxMaxReceiveBuffer,
		MaxStreamBuffer:   smuxMaxStreamBuffer,
	}
}

// deathWatchConn 在底层读出错时通知一次。
//
// # 为什么需要它（smux 的一个真实陷阱）
//
// 上层到处依赖 Carrier.Context()：会话结束时它必须被取消，否则那些 goroutine
// 永不退出 —— 一条已死的承载会留下一整套活着的协程，而 agent 每次重连再留一套。
//
// 而 smux 的 `Session.CloseChan()` **不是**这个信号：核实过 v1.5.57 的
// `recvLoop`，对端断开时它只调 `notifyReadError`（关一个内部 channel），
// **不**关 `die`。`die` 只在两种情况下关：本地显式 `Close()`，
// 或 keepalive 超时（session.go:535）。
//
// 所以只听 CloseChan 的话，一次干净的 FIN 要等满 keepalive 超时（30 秒）
// 才会被察觉 —— 那 30 秒里中继以为 agent 在线、隧道显示绿点，
// 而每一个连接都石沉大海。这条是测试抓出来的：对端关闭后 5 秒内 context 没动。
//
// smux 没有导出那个内部信号，所以在**它下面**拦：包一层 net.Conn，
// 任何读错误都立刻翻译成 context 取消。这也顺带覆盖了 RST 与本地 Close。
type deathWatchConn struct {
	net.Conn
	onDead func()
}

func (c *deathWatchConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.onDead()
	}
	return n, err
}

// muxCarrier 是 TLS/TCP + smux 上的 Carrier 实现。
type muxCarrier struct {
	conn    *tls.Conn
	sess    *smux.Session
	rung    Rung
	ctx     context.Context
	cancel  context.CancelFunc
	closing chan struct{}
}

// newMuxCarrier 在一条**已完成握手**的 TLS 连接上建立 smux 会话。
//
// server 决定 smux 的角色。它只影响流 ID 的奇偶（避免两端撞号），
// 不影响谁能开流 —— 两端都能。
func newMuxCarrier(conn *tls.Conn, rung Rung, server bool) (*muxCarrier, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// smux 读的是包了一层的连接，而 ChannelBinding 用的还是原来那个
	// *tls.Conn（它才有 ConnectionState）。两者是同一条连接的两个视图。
	watched := &deathWatchConn{Conn: conn, onDead: cancel}

	var (
		sess *smux.Session
		err  error
	)
	if server {
		sess, err = smux.Server(watched, smuxConfig())
	} else {
		sess, err = smux.Client(watched, smuxConfig())
	}
	if err != nil {
		cancel()
		_ = conn.Close()
		return nil, fmt.Errorf("carrier: 建立 smux 会话失败：%w", err)
	}

	c := &muxCarrier{
		conn: conn, sess: sess, rung: rung,
		ctx: ctx, cancel: cancel, closing: make(chan struct{}),
	}

	// CloseChan 仍然要听：keepalive 超时那条路会关 die 而**不一定**先产生
	// 读错误（超时是本地判定的）。两个信号都接上，谁先来都算。
	go func() {
		select {
		case <-sess.CloseChan():
		case <-c.closing:
		case <-ctx.Done():
		}
		cancel()
	}()
	return c, nil
}

func (c *muxCarrier) OpenStream(ctx context.Context) (Stream, error) {
	// smux 的 OpenStream 不带 context。用 deadline 近似：
	// 直接忽略 ctx 会让一次「拨号期限已到」的调用挂在这里。
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(dl)
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	}
	st, err := c.sess.OpenStream()
	if err != nil {
		return nil, translateMuxErr(err)
	}
	return st, nil
}

func (c *muxCarrier) AcceptStream(ctx context.Context) (Stream, error) {
	// smux.AcceptStream 也不带 context。它在会话关闭时返回错误，
	// 而 ctx 取消时我们主动关会话 —— 否则一个等在这里的协程永不退出。
	type result struct {
		st  *smux.Stream
		err error
	}
	ch := make(chan result, 1)
	go func() {
		st, err := c.sess.AcceptStream()
		ch <- result{st, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, translateMuxErr(r.err)
		}
		return r.st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SendDatagram 恒返回 ErrDatagramUnsupported。
//
// 见文件顶部：**绝不**把数据报塞进可靠流。
func (c *muxCarrier) SendDatagram([]byte) error { return ErrDatagramUnsupported }

// ReceiveDatagram 恒返回 ErrDatagramUnsupported。
//
// agent 的 UDP 处理器会用 errors.Is 认出它并安静退出（不影响 TCP 隧道）。
func (c *muxCarrier) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, ErrDatagramUnsupported
}

func (c *muxCarrier) SupportsDatagrams() bool { return false }

// MaxDatagramPayload 恒为 0：这一级没有数据报，谈不上上限。
func (c *muxCarrier) MaxDatagramPayload() int { return 0 }

func (c *muxCarrier) Rung() Rung               { return c.rung }
func (c *muxCarrier) Context() context.Context { return c.ctx }
func (c *muxCarrier) LocalAddr() net.Addr      { return c.conn.LocalAddr() }
func (c *muxCarrier) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

// RTT 恒为 0（「没测到」）。
//
// 与 QUIC 侧同一个取舍：承载 RTT 走上层的控制流 Ping/Pong，
// 那个数对两个梯级是同源可比的。smux 自己没有 RTT 估计可读。
func (c *muxCarrier) RTT() time.Duration { return 0 }

// ChannelBinding 从 TLS 状态导出信道绑定材料。
//
// 与 QUIC 侧**同一个 label、同一个长度**：绑定材料的定义属于协议，
// 不属于承载梯级。换梯级不该让握手证明的算法变一遍 ——
// 那会让第三方实现要按梯级分叉，而分叉就是漂移的开始。
func (c *muxCarrier) ChannelBinding() ([]byte, error) {
	// ConnectionState() 返回值，而 ExportKeyingMaterial 是指针方法 ——
	// 必须先落到一个变量上。
	st := c.conn.ConnectionState()
	return st.ExportKeyingMaterial(channelBindingLabel, nil, channelBindingLen)
}

func (c *muxCarrier) CloseWithError(_ uint64, _ string) error {
	// smux 没有应用层错误码（那是 QUIC 才有的）。原因只能落在日志里，
	// 对端看到的是一个普通的会话关闭 —— 如实接受这个差异，
	// 不假装两个梯级的关闭语义一样。
	close2 := func() {
		select {
		case <-c.closing:
		default:
			close(c.closing)
		}
	}
	close2()
	err := c.sess.Close()
	_ = c.conn.Close()
	c.cancel()
	return err
}

// translateMuxErr 把 smux 的错误翻成本包的哨兵错误。
//
// 不翻的话上层的 errors.Is(err, ErrClosed) 判断在这个梯级上一律为假，
// 于是「会话正常结束」会被当成异常打一行 WARN —— 每次 agent 重连一行。
func translateMuxErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, smux.ErrInvalidProtocol) {
		return fmt.Errorf("%w：smux 协议不匹配（两端版本或配置不一致）", ErrClosed)
	}
	switch {
	case errors.Is(err, net.ErrClosed), errors.Is(err, smux.ErrTimeout):
		return fmt.Errorf("%w：%v", ErrClosed, err)
	}
	// smux 在会话关闭后返回一个未导出的 errBrokenPipe，只能按文本认。
	if err.Error() == "broken pipe" {
		return ErrClosed
	}
	return err
}

// DialTLSMux 拨一条 L2 承载：TCP → TLS → smux。
//
// serverName 与 pinnedSPKI 的语义与 DialQUIC 完全一致 ——
// **同样不提供「跳过证书校验」的选项**。换梯级不该降低认证强度，
// 而一个「UDP 不通时自动放弃校验」的回退就是把降级变成攻击面：
// 攻击者只要封掉 UDP 就能把你推到那条路上。
func DialTLSMux(ctx context.Context, addr string, tlsCfg *tls.Config) (Carrier, error) {
	if tlsCfg == nil {
		return nil, errors.New("carrier: DialTLSMux 需要 TLS 配置")
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("carrier: 拨 TCP %s 失败：%w", addr, err)
	}

	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("carrier: TLS 握手失败：%w", err)
	}
	// ALPN 必须协商成我们的协议。没协商上意味着对面**不是**一台 NomiRelay
	// 的承载入口（可能是共享入口的网关分支，或者一个中间盒），
	// 那时继续跑 smux 只会得到一堆无从解释的解析错误。
	if got := conn.ConnectionState().NegotiatedProtocol; got != proto.ALPN {
		_ = conn.Close()
		return nil, fmt.Errorf("carrier: 对端没有协商 ALPN %q（实际 %q）—— "+
			"这个地址可能不是承载入口", proto.ALPN, got)
	}
	return newMuxCarrier(conn, RungTLS443, false)
}

// AdoptTLSMux 在一条**已经完成 TLS 握手**的连接上建立 L2 承载（中继侧）。
//
// 之所以是「收养」而不是「监听」：443/tcp 同时服务共享入口的业务流量，
// 那个端口的所有权属于判别器。判别器按 ALPN 认出 `nomifun-relay/1`
// 之后把连接交给这里 —— 承载与业务共用一个端口，正是规格 §5.1 要的形态。
func AdoptTLSMux(conn *tls.Conn) (Carrier, error) {
	if conn == nil {
		return nil, errors.New("carrier: AdoptTLSMux 需要一条已握手的 TLS 连接")
	}
	return newMuxCarrier(conn, RungTLS443, true)
}
