// Package carrier 把不同的底层传输统一成一个 Carrier 接口。
//
// # 为什么需要这层抽象，以及它比 frp 强在哪
//
// frp 的 Connector 接口（client/connector.go:40-44）只有 Open/Connect/Close，
// **只有客户端能开流**。这一个限制直接导致它必须走
// ReqWorkConn → NewWorkConn → StartWorkConn 三次往返来建立一条被代理连接
// （server/control.go:595-637），即 1.5×RTT；连接池只能把它降到 0.5R，
// 而客户端 poolCount 默认只有 1（pkg/config/v1/client.go:153），
// 所以第二条并发连接就退化回 1.5R。手机开一个网页 6 条并发连接，5 条付满 1.5R
// —— 这是 frp 首屏慢的根因，不是带宽问题。
//
// QUIC 与 smux 的流都是**对称**的：服务端一样可以 OpenStream。
// 所以本接口是双向的（OpenStream + AcceptStream），中继可以主动开流并把
// StreamOpen 头与用户首包一起 pipeline 出去，三条控制消息全部消失，
// 新连接建立降到 **0 额外 RTT**，连接池、runID 认领及其安全问题一并删除。
//
// # 数据报
//
// QUIC 原生支持 RFC 9221 不可靠数据报，语义与 UDP 逐条对应（不可靠、无序、
// 不重传）。smux 承载没有这个能力，此时数据报降级为在一条专用可靠流上分帧，
// 由 SupportsDatagrams 报告真实能力，让上层能在控制台如实告知用户
// 「当前 UDP 走可靠流承载，延迟不保证」。
package carrier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Rung 标识承载梯级。梯级越低越优先。
type Rung uint8

const (
	// RungQUIC 是 L0：QUIC/UDP 走配置端口。正常网络的首选。
	RungQUIC Rung = 0
	// RungQUIC443 是 L1：QUIC/UDP 走 443，突破只放行 443 的出口过滤。
	RungQUIC443 Rung = 1
	// RungTLS443 是 L2：TLS/TCP:443 + smux，突破 UDP 被完全封锁。
	RungTLS443 Rung = 2
	// RungWSS443 是 L3：WSS:443 + smux，突破敌视 ALPN 的中间盒与 MITM 代理。
	RungWSS443 Rung = 3
)

// String 返回梯级的可读名，用于日志与控制台展示。
func (r Rung) String() string {
	switch r {
	case RungQUIC:
		return "L0/QUIC"
	case RungQUIC443:
		return "L1/QUIC:443"
	case RungTLS443:
		return "L2/TLS:443"
	case RungWSS443:
		return "L3/WSS:443"
	default:
		return "未知梯级"
	}
}

// Reliable 报告该梯级是否只能提供可靠有序传输。
//
// 可靠承载上的 UDP 会有队头阻塞，控制台必须据此提示用户。
func (r Rung) Reliable() bool {
	return r == RungTLS443 || r == RungWSS443
}

// Stream 是一条双向字节流。
type Stream interface {
	io.ReadWriteCloser

	// SetDeadline 等三个方法与 net.Conn 一致，便于直接复用现有的拷贝循环。
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Carrier 是一条已建立的承载连接。
//
// 实现必须是并发安全的：多个 goroutine 会同时 OpenStream 与 SendDatagram。
type Carrier interface {
	// OpenStream 主动开一条新流。
	//
	// 这是「0 额外 RTT」的关键：**两端都可以调用它**。
	// QUIC 与 smux 的 OpenStream 都不等对端 ACK，所以开流本身不花往返。
	OpenStream(ctx context.Context) (Stream, error)

	// AcceptStream 等待对端开来的流。
	AcceptStream(ctx context.Context) (Stream, error)

	// SendDatagram 发送一个不可靠数据报。
	//
	// 若载荷超过当前允许的尺寸，返回一个可用 errors.As 取出
	// *DatagramTooLargeError 的错误，调用方据此重新分片或丢弃。
	// 若本承载不支持数据报，返回 ErrDatagramUnsupported。
	SendDatagram(b []byte) error

	// ReceiveDatagram 接收一个数据报。
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	// SupportsDatagrams 报告本承载**当前**能否发不可靠数据报。
	//
	// 对 QUIC 而言这需要两端都开启 EnableDatagrams，故必须在握手后查询，
	// 不能靠梯级推断。
	SupportsDatagrams() bool

	// MaxDatagramPayload 返回当前已知的数据报载荷上限，未知时返回 0。
	//
	// quic-go **不提供**查询这个值的 getter —— 只能从
	// *quic.DatagramTooLargeError.MaxDatagramPayloadSize 反应式获知，
	// 且 PMTUD 完成前该值偏小。所以这里返回的是「已学到的」值，
	// 会随运行推进而变化，控制台应当把它显示出来：
	// 否则没人能解释「为什么大包失败小包正常」。
	MaxDatagramPayload() int

	// Rung 返回本承载所处的梯级。
	Rung() Rung

	// Context 在承载断开时被取消。
	//
	// 这是判断对端是否还在的**唯一可靠途径**：不能靠「在控制流上读一下」——
	// 对端进程被强杀时，那个读要等到 QUIC 的空闲超时才返回，
	// 期间中继会把用户连接派发给一个已经死掉的 agent（表现为请求挂死或
	// 返回陈旧数据），而不是干净地报「代理端不在线」。
	Context() context.Context

	// RTT 返回最近一次测得的往返时延，未知时返回 0。
	RTT() time.Duration

	// ChannelBinding 返回本承载的 TLS exporter 材料（RFC 5705），
	// 用于把握手证明绑定到**这一条具体的 TLS 连接**上。
	//
	// # 为什么必须由承载层提供
	//
	// 握手证明的 MAC 覆盖时间戳 + nonce + 协议版本 + ALPN。这些都不与具体连接
	// 绑定 —— 一个能在中间人位置观察到证明的攻击者，可以把它原样搬到**另一条**
	// 自己建立的 TLS 连接上重放（时钟窗内、nonce 尚未过期时）。
	// 把 exporter 材料纳入 MAC 之后那条路就断了：两条 TLS 连接的 exporter 不同。
	//
	// 拿不到时返回 (nil, nil) 而**不是错误**：并非所有承载梯级都有 TLS
	// （将来的 L2/L3 梯级各有自己的形态），而调用方对空材料的处理是
	// 「按无绑定签名」——那与本方法存在之前的行为一致，不会把握手弄坏。
	//
	// **两端必须给出相同的材料，否则 MAC 不匹配、握手全线失败。**
	// 所以 label 与长度是协议的一部分，写在实现里而不是让调用方传。
	ChannelBinding() ([]byte, error)

	// LocalAddr / RemoteAddr 用于日志与真实源地址填充。
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// CloseWithError 关闭承载并向对端告知原因。
	CloseWithError(code uint64, reason string) error
}

// DatagramTooLargeError 表示载荷超过当前允许的数据报尺寸。
//
// MaxPayload 是对端当前能接受的最大载荷；调用方应缓存它并据此分片或丢弃，
// 收到新的该错误时更新缓存。
type DatagramTooLargeError struct {
	// Attempted 是本次尝试发送的字节数。
	Attempted int
	// MaxPayload 是当前允许的最大载荷。
	MaxPayload int
}

func (e *DatagramTooLargeError) Error() string {
	return fmt.Sprintf("carrier: 数据报载荷过大：尝试 %d 字节，当前上限 %d 字节",
		e.Attempted, e.MaxPayload)
}

// DatagramMaxPayload 返回当前上限。
//
// 存在这个方法是为了让上层（internal/udpflow）能用一个**结构化接口**识别
// 「超限」这类错误，而不必 import internal/carrier —— udpflow 是中继与
// agent 共用的底层，保持它零依赖才能被两侧自由组合。
func (e *DatagramTooLargeError) DatagramMaxPayload() int { return e.MaxPayload }

// 承载层错误。
var (
	// ErrDatagramUnsupported 表示本承载不支持不可靠数据报。
	//
	// 上层收到它时应当降级到可靠流承载，并在控制台标注
	// 「当前 UDP 走可靠流承载，延迟不保证」——而不是静默地把 UDP
	// 塞进可靠流却让用户以为自己拿到了低延迟通道（frp 就是这样）。
	ErrDatagramUnsupported = errors.New("carrier: 本承载不支持不可靠数据报")

	// ErrClosed 表示承载已关闭。
	ErrClosed = errors.New("carrier: 承载已关闭")
)
