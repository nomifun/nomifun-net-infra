package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// quicCarrier 用一条 QUIC 连接实现 Carrier。
type quicCarrier struct {
	conn *quic.Conn
	rung Rung

	// maxDatagram 是**已学到的**数据报载荷上限。
	//
	// quic-go 不提供查询它的 getter，只能从 *quic.DatagramTooLargeError
	// 反应式获知（该类型 v0.41.0 引入）。0 表示尚未学到。
	// 用原子操作是因为多个 goroutine 会并发 SendDatagram。
	maxDatagram atomic.Int64

	supportsDatagrams bool
}

// QUICConfig 是建立 QUIC 承载的参数。
type QUICConfig struct {
	// TLSConfig 必须已设置 NextProtos 为 proto.ALPN。
	TLSConfig *tls.Config

	// Rung 标记本承载的梯级（RungQUIC 或 RungQUIC443）。
	Rung Rung

	// KeepAlivePeriod 是 QUIC 层保活间隔。
	//
	// 必须显式设置：frp 在默认配置下应用层心跳是**完全关闭**的
	// （tcpMux 开启时 HeartbeatInterval/Timeout 双双为 -1，
	// pkg/config/v1/client.go:156-163），存活性只靠 yamux keepalive，
	// 死对端检测约 40 秒。对 S1（家宽上行抖动）40 秒黑洞不可接受。
	KeepAlivePeriod time.Duration

	// MaxIdleTimeout 是无活动后断开的阈值。
	MaxIdleTimeout time.Duration
}

// DefaultKeepAlive 是默认 QUIC 保活间隔。
//
// 10 秒使死对端检测落在十几秒量级，而不是 frp 的 40 秒。
const DefaultKeepAlive = 10 * time.Second

// DefaultMaxIdleTimeout 是默认空闲断开阈值。
const DefaultMaxIdleTimeout = 30 * time.Second

func (c *QUICConfig) complete() {
	if c.KeepAlivePeriod <= 0 {
		c.KeepAlivePeriod = DefaultKeepAlive
	}
	if c.MaxIdleTimeout <= 0 {
		c.MaxIdleTimeout = DefaultMaxIdleTimeout
	}
}

// quicSettings 构造 quic.Config。
//
// EnableDatagrams 必须为 true，且**两端都要开**才能真正协商成功；
// 实际能力在握手后查 ConnectionState().SupportsDatagrams.Remote。
func quicSettings(cfg QUICConfig) *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: cfg.KeepAlivePeriod,
		MaxIdleTimeout:  cfg.MaxIdleTimeout,
		// 不设置 InitialPacketSize，让 DPLPMTUD（默认开启）去探路径 MTU
		// 并把可用数据报尺寸抬上去。
	}
}

// DialQUIC 主动建立一条 QUIC 承载（agent 侧使用）。
func DialQUIC(ctx context.Context, addr string, cfg QUICConfig) (Carrier, error) {
	cfg.complete()
	if cfg.TLSConfig == nil {
		return nil, errors.New("carrier: QUICConfig.TLSConfig 不能为空")
	}
	conn, err := quic.DialAddr(ctx, addr, cfg.TLSConfig, quicSettings(cfg))
	if err != nil {
		return nil, fmt.Errorf("carrier: 拨 QUIC %s 失败：%w", addr, err)
	}
	return newQUICCarrier(conn, cfg.Rung), nil
}

// QUICListener 接受 QUIC 承载（中继侧使用）。
type QUICListener struct {
	ln   *quic.Listener
	rung Rung
}

// ListenQUIC 在 addr 上监听 QUIC。
func ListenQUIC(addr string, cfg QUICConfig) (*QUICListener, error) {
	cfg.complete()
	if cfg.TLSConfig == nil {
		return nil, errors.New("carrier: QUICConfig.TLSConfig 不能为空")
	}
	ln, err := quic.ListenAddr(addr, cfg.TLSConfig, quicSettings(cfg))
	if err != nil {
		return nil, fmt.Errorf("carrier: 监听 QUIC %s 失败：%w", addr, err)
	}
	return &QUICListener{ln: ln, rung: cfg.Rung}, nil
}

// Accept 接受一条承载连接。
func (l *QUICListener) Accept(ctx context.Context) (Carrier, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQUICCarrier(conn, l.rung), nil
}

// Addr 返回实际监听地址（端口为 0 时用于取得系统分配的端口）。
func (l *QUICListener) Addr() net.Addr { return l.ln.Addr() }

// Close 关闭监听器。
func (l *QUICListener) Close() error { return l.ln.Close() }

func newQUICCarrier(conn *quic.Conn, rung Rung) *quicCarrier {
	st := conn.ConnectionState()
	// 两端都必须开启才算支持。只看本端会误报。
	supports := st.SupportsDatagrams.Local && st.SupportsDatagrams.Remote
	return &quicCarrier{conn: conn, rung: rung, supportsDatagrams: supports}
}

// quicStream 包装 *quic.Stream 以修正它的关闭语义。
type quicStream struct {
	*quic.Stream
}

// Close 同时关闭读写两个方向。
//
// **这个补丁不能省**：quic.Stream.Close() 只关闭写方向，读方向仍然挂着，
// 对端不写就永远不返回，于是流与其 goroutine 一起泄漏。
// 必须额外 CancelRead 才是真正的双向关闭。
func (s quicStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func (c *quicCarrier) OpenStream(ctx context.Context) (Stream, error) {
	// OpenStreamSync 会在流控允许时立即返回，不等对端 ACK ——
	// 所以开流本身不花往返，这正是「0 额外 RTT」成立的前提。
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{s}, nil
}

func (c *quicCarrier) AcceptStream(ctx context.Context) (Stream, error) {
	s, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{s}, nil
}

func (c *quicCarrier) SendDatagram(b []byte) error {
	if !c.supportsDatagrams {
		return ErrDatagramUnsupported
	}
	err := c.conn.SendDatagram(b)
	if err == nil {
		return nil
	}

	// 反应式学习：这是唯一能得知当前上限的途径。
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		c.maxDatagram.Store(tooLarge.MaxDatagramPayloadSize)
		return &DatagramTooLargeError{
			Attempted:  len(b),
			MaxPayload: int(tooLarge.MaxDatagramPayloadSize),
		}
	}
	return err
}

func (c *quicCarrier) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !c.supportsDatagrams {
		return nil, ErrDatagramUnsupported
	}
	return c.conn.ReceiveDatagram(ctx)
}

func (c *quicCarrier) SupportsDatagrams() bool { return c.supportsDatagrams }

func (c *quicCarrier) MaxDatagramPayload() int { return int(c.maxDatagram.Load()) }

// channelBindingLabel 是 exporter 的标签，两端必须一致。
//
// 带上协议名与版本：将来换绑定方式时旧新两端会得到不同的材料，
// 于是表现为「握手失败」而不是「绑定静默失效」—— 后者是更坏的失败。
const channelBindingLabel = "EXPORTER-nomirelay-carrier-v1"

// channelBindingLen 是取多少字节。32 字节 = 256 位，足够且与 HMAC-SHA256 同量级。
const channelBindingLen = 32

// ChannelBinding 从 QUIC 的 TLS 状态导出信道绑定材料。
func (c *quicCarrier) ChannelBinding() ([]byte, error) {
	st := c.conn.ConnectionState().TLS
	// ExportKeyingMaterial 在「允许重协商」或「既不支持 TLS 1.3 也不支持
	// Extended Master Secret」时返回错误。QUIC 强制 TLS 1.3，所以正常路径上
	// 这两条都不成立；真出错时原样上报，让调用方决定 —— 静默返回空材料等于
	// 悄悄关掉这层防护。
	return st.ExportKeyingMaterial(channelBindingLabel, nil, channelBindingLen)
}

func (c *quicCarrier) Rung() Rung { return c.rung }

// Context 返回一个在 QUIC 连接断开时被取消的 context。
func (c *quicCarrier) Context() context.Context { return c.conn.Context() }

func (c *quicCarrier) RTT() time.Duration {
	// **不是「quic-go 未导出 RTT」** —— 那句话是错的，核实过 v0.61.0：
	// Config.Tracer（interface.go:185）+ qlog.MetricsUpdated
	//（qlog/event.go:438-446 的 MinRTT / SmoothedRTT / LatestRTT / RTTVariance）
	// 能拿到拥塞控制器级别的路径 RTT。
	//
	// 这里返回 0 是一次**取舍**：开 Tracer 会给每个发出的包加一次切片分配
	// 与一次接口装箱，而且把 tracer 回调关联回 carrier 需要一张以对端 connID
	// 为键、鉴权前就插入的表。所以承载 RTT 走上层的控制流 Ping/Pong
	//（relay/rtt.go）—— 代价是测到的含重传、队头阻塞与对端调度延迟，
	// 偏大且在丢包时会跳。两者的区别如实写在 README 里。
	// 返回 0 表示未知，而不是编一个数字。
	return 0
}

func (c *quicCarrier) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *quicCarrier) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *quicCarrier) CloseWithError(code uint64, reason string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

// ServerTLSConfig 构造中继侧的 TLS 配置。
//
// CurvePreferences 故意保持 nil：Go 1.26 的 crypto/tls 默认曲线已包含
// 后量子的 X25519MLKEM768，**手动设置反而会静默把它关掉**。
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{proto.ALPN},
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig 构造 agent 侧的 TLS 配置。
//
// 与 frp 的关键区别：frp 在没有配 CA 时把 InsecureSkipVerify 设为 **true**
// （pkg/transport/tls.go:150-152），于是它宣传的「默认开启 TLS」只有加密
// 没有服务端认证，MITM 门槛为零。这里绝不提供那样的默认值 ——
// 要么给 rootCAs 走正常校验，要么给 pinnedSPKI 做指纹绑定，二者必须有其一。
func ClientTLSConfig(serverName string, rootCAs CertPool, pinnedSPKI []byte) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: serverName,
		NextProtos: []string{proto.ALPN},
		MinVersion: tls.VersionTLS13,
	}
	switch {
	case len(pinnedSPKI) > 0:
		// 指纹绑定模式：跳过链校验，改为逐字节比对服务端公钥指纹。
		// 这是自签证书场景的正确做法，比 InsecureSkipVerify 强得多。
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = pinVerifier(pinnedSPKI)
	case rootCAs != nil:
		cfg.RootCAs = rootCAs.Pool()
	default:
		return nil, errors.New("carrier: 必须提供 rootCAs 或 pinnedSPKI 之一；" +
			"本实现不提供「跳过证书校验」的默认值")
	}
	return cfg, nil
}
