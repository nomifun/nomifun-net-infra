package gateway

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DefaultPeekSize 是 peek 缓冲的上限。
//
// 取值理由：TLS 记录载荷上限是 16384 字节，加 5 字节记录头，再留 507 字节余量
// 给「握手被切成多个记录」的情况。明文 HTTP 的头块也共用这个上限，
// 超出即拒绝 —— 判别阶段的缓冲必须有界，否则一条连接就能让中继替它攒内存。
const DefaultPeekSize = 16*1024 + 512

// peek 阶段的错误。
var (
	// ErrPeekTooLarge 表示判别需要的字节数超过了缓冲上限。
	//
	// 这不是内部错误而是一个判别结论：对方要么在做很不寻常的 TLS 分片，
	// 要么在故意灌一个巨大的头块。两种都该拒。
	ErrPeekTooLarge = errors.New("gateway: 判别所需字节超过 peek 缓冲上限")

	// ErrPeekBudget 表示整条连接的判别总预算已耗尽。
	//
	// 单步期限挡不住「每步都在期限内到一个字节」的慢速消耗，所以必须再有总预算。
	ErrPeekBudget = errors.New("gateway: 判别总预算耗尽")
)

// PeekConn 是一条可以先「看」后「取」的连接：被 peek 过的字节仍会原样
// 重放给最终消费者（透传时是隧道对端，网关时是 http.Server）。
//
// # 为什么必须是惰性分级 peek，而不是 frp 的做法
//
// frp 的端口复用嗅探对**每一条**连接都按「所有嗅探器需要的最大字节数」
// 做一次 io.ReadFull，并压一个硬编码的 10 秒超时
// （fatedier/golib@v0.8.1/net/mux/mux.go:189-198，DefaultTimeout 在同文件顶部）：
//
//	sharedConn, rd := gnet.NewSharedConnSize(conn, int(maxNeedBytesNum))
//	data := make([]byte, maxNeedBytesNum)
//	_ = conn.SetReadDeadline(time.Now().Add(DefaultTimeout))
//	_, err := io.ReadFull(rd, data)
//
// 后果是：首包比 maxNeedBytesNum 短的连接会**挂满 10 秒**才被判别 ——
// 而首包短是完全正常的（一个 40 字节的 ClientHello 分片、一个只发了请求行
// 就等服务端的客户端、任何 Nagle 与 MTU 组合）。这不是理论缺陷，
// 它把「新增一种嗅探器」的代价摊到了**所有**连接的建连延迟上。
//
// 所以这里的 Peek 语义是：**拿到当前这一步判别所需的字节就立刻返回**，
// 每一步有自己的期限，整条连接另有一个总预算。
type PeekConn struct {
	net.Conn

	br *bufio.Reader

	// budget 是整条连接的判别截止时刻，零值表示不限。
	//
	// 它是**软**期限：每步 peek 把 socket 读期限取 min(单步期限, budget)，
	// 而不是一次性把 socket 期限压到 budget —— 后者会让「已经判别完成、
	// 正在长连接搬数据」的连接继承一个早就该清掉的期限。
	budget time.Time
}

// NewPeekConn 用默认缓冲上限包装一条连接。
func NewPeekConn(c net.Conn) *PeekConn { return NewPeekConnSize(c, DefaultPeekSize) }

// NewPeekConnSize 用指定缓冲上限包装一条连接。
func NewPeekConnSize(c net.Conn, size int) *PeekConn {
	if size < 64 {
		size = 64
	}
	return &PeekConn{Conn: c, br: bufio.NewReaderSize(c, size)}
}

// SetPeekBudget 给整个判别过程设一个总期限，从现在开始计时。
func (c *PeekConn) SetPeekBudget(d time.Duration) {
	if d <= 0 {
		c.budget = time.Time{}
		return
	}
	c.budget = time.Now().Add(d)
}

// Peek 看前 n 个字节但**不消费**它们，本步最多等 step。
//
// 返回的切片指向内部缓冲，只在下一次 Peek / Read 之前有效；
// 需要留存就自己复制。
func (c *PeekConn) Peek(n int, step time.Duration) ([]byte, error) {
	b, err := c.peekAtLeast(n, step)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// peekAtLeast 保证至少 n 字节可见，并把**当前已缓冲的全部**字节一起返回。
//
// 多返回的字节是免费的（已经在缓冲里了），让上层的顺序读取器一次就能吃到
// 一整个首包，而不是每次 Read 都回到 socket 上摸一下。
func (c *PeekConn) peekAtLeast(n int, step time.Duration) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	if n > c.br.Size() {
		return nil, fmt.Errorf("%w：需要 %d 字节，缓冲上限 %d", ErrPeekTooLarge, n, c.br.Size())
	}
	if c.br.Buffered() >= n {
		// 已经够了就绝不回到 socket 上等 —— 这是「惰性」的全部含义。
		b, err := c.br.Peek(c.br.Buffered())
		return b, err
	}

	deadline := time.Now().Add(step)
	if !c.budget.IsZero() && c.budget.Before(deadline) {
		deadline = c.budget
	}
	if !time.Now().Before(deadline) {
		return nil, fmt.Errorf("%w：已缓冲 %d 字节，还需要 %d", ErrPeekBudget, c.br.Buffered(), n)
	}
	if err := c.Conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	// 每一步结束立刻清掉 socket 期限：判别完成后这条连接会被交给
	// ReverseProxy 或直接拼接到隧道，那两条路径都不该继承判别阶段的读期限
	// （frp 在 vhost.go:211 也是路由成功后才清，但它只清一次总期限）。
	defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()

	if _, err := c.br.Peek(n); err != nil {
		// 超时是**可恢复**的：已到的字节仍留在 bufio 缓冲里（读超时不消费数据），
		// 下一步 peek 会接着往里填。这正是分级 peek 能省掉 frp 那 10 秒的原因。
		return nil, fmt.Errorf("gateway: peek %d 字节失败（已到 %d）：%w", n, c.br.Buffered(), err)
	}
	b, err := c.br.Peek(c.br.Buffered())
	return b, err
}

// Buffered 返回当前已 peek 但尚未被消费的字节数。
func (c *PeekConn) Buffered() int { return c.br.Buffered() }

// Discard 真正消费掉前 n 个字节。
//
// 只用于**不属于业务数据**的前缀（当前只有 PROXY protocol 头）：
// 它不能重放给后端，否则后端会把它当成业务首包。
func (c *PeekConn) Discard(n int) error {
	m, err := c.br.Discard(n)
	if err != nil {
		return fmt.Errorf("gateway: 丢弃 %d 字节前缀失败（实际 %d）：%w", n, m, err)
	}
	return nil
}

// Read 先吐已缓冲的 peek 字节，再回到 socket —— 重放是自动的。
func (c *PeekConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// CloseWrite 透传到底层，让半关语义不被包装层吃掉。
//
// 拷贝循环靠类型断言判断能否半关；若这里不透传，透传模式下
// 「上行结束」这个信号就传不到后端，后端会一直等一个永远不来的请求尾。
func (c *PeekConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PeekReader 返回一个「只看不取」的顺序读取器。
//
// 它把 Peek 的偏移量往前推，但从不消费连接上的字节，所以喂给
// tls.Server 解析 ClientHello 之后，同样的字节仍会重放给真正的消费者。
// 每次 Read 至多等 step，且从不为「凑满调用方给的缓冲」而等待 ——
// crypto/tls 内部用 bytes.Buffer.ReadFrom 拉数据（会拿一个远大于所需的缓冲
// 反复 Read），若这里为了填满它而阻塞，就又回到 frp 那个「短首包挂满超时」的坑里。
func (c *PeekConn) PeekReader(step time.Duration) io.Reader {
	return &peekReader{c: c, step: step}
}

type peekReader struct {
	c    *PeekConn
	off  int
	step time.Duration
}

func (r *peekReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// 只要求「比已读偏移多一个字节」，能多拿是白拿。
	b, err := r.c.peekAtLeast(r.off+1, r.step)
	if err != nil {
		return 0, err
	}
	n := copy(p, b[r.off:])
	r.off += n
	return n, nil
}
