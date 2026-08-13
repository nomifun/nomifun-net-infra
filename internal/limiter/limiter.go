// Package limiter 给一条隧道的流量做**每隧道共享**的限速。
//
// # 为什么不用 io.Copy 之外再造一层复杂东西
//
// 限速只需要两件事：字节速率与包速率。两者都用 golang.org/x/time/rate 的
// 令牌桶，而不是自己写 —— 那个包已经处理了单调时钟、突发额度、
// 以及「一次要 N 个令牌但 N 大于桶容量」这个最容易写错的边界。
//
// # 为什么字节与包必须分开限
//
// 10 万 pps 的 64 字节小包是现实攻击形态（每秒 6.4 MB，任何按字节的限速器
// 都会放行它），而它足以打满一台家用路由器的 pps 能力。规格 §策略里
// BytesPerSecond 与 PacketsPerSecond 是**同时**存在的，正是这个理由。
//
// # 为什么 TCP 要等、UDP 要丢
//
// TCP 是字节流：丢掉中间一段就是把连接搞坏。所以 TCP 路径必须**等**
// （反压会自然传播到发送方的窗口）。
//
// UDP 是数据报：等一秒的音频包到达时已经没有价值，而等的代价是占住
// 共享的读循环。所以 UDP 路径**丢**，并计数。
//
// 这与本仓库其他地方同一条原则：实时路径宁可丢，批量路径宁可慢。
package limiter

import (
	"context"
	"io"
	"time"

	"golang.org/x/time/rate"
)

// Limits 是一条隧道的限速参数。0 表示该维度不限。
type Limits struct {
	BytesPerSecond   int64
	PacketsPerSecond int64
}

// Zero 报告这组参数是否完全不限速。
//
// 调用方据此完全跳过限速器，连一次原子读都不做 —— 绝大多数隧道不限速，
// 不该为它们付任何代价。
func (l Limits) Zero() bool {
	return l.BytesPerSecond <= 0 && l.PacketsPerSecond <= 0
}

// Limiter 是一条隧道的限速器。nil 值表示不限速，所有方法都能安全调用。
//
// **每隧道一个，被这条隧道的所有连接/流共享** —— 用户设的是「这条隧道最多
// 多少带宽」，而不是「每条连接最多多少」。每连接一个桶的话，
// 一百条连接就是一百倍带宽，那个配置项等于没有意义。
type Limiter struct {
	// 令牌桶自己是并发安全的，所以取用路径上不需要任何锁。
	bytes   *rate.Limiter
	packets *rate.Limiter
}

// New 造一个限速器。完全不限速时返回 nil。
func New(l Limits) *Limiter {
	if l.Zero() {
		return nil
	}
	return &Limiter{
		bytes:   newByteBucket(l.BytesPerSecond),
		packets: newPacketBucket(l.PacketsPerSecond),
	}
}

// newByteBucket 造字节桶。rate <= 0 时返回 nil（该维度不限）。
//
// 突发额度取一秒的量，但**下限是一个满尺寸数据报**：
// x/time/rate 对「一次要的令牌数大于桶容量」直接返回错误而不是等
// （AllowN 返回 false、WaitN 返回 err），于是桶容量低于 64 KiB 时
// 一个满尺寸 UDP 数据报会**永久**通不过 —— 而现象是「大包不通小包正常」，
// 那看起来像 MTU 问题，不像限速。
//
// 代价要说清楚：limit 低于 64 KiB/s 时，最初有一个 64 KiB 的额度
// （比如 1 KiB/s 的隧道头 64 KiB 是瞬间过的）。之后就是配置的速率。
// 那是令牌桶的常规行为，且比「大包永久失败」好得多。
func newByteBucket(perSecond int64) *rate.Limiter {
	if perSecond <= 0 {
		return nil
	}
	burst := max(perSecond, minByteBurst)
	return rate.NewLimiter(rate.Limit(perSecond), int(burst))
}

// newPacketBucket 造包桶。
//
// **不能套用字节桶的下限。** 包桶的单位是「个」，而每次申请恒为 1 ——
// 所以 minByteBurst 那条理由在这里完全不成立，套上去等于给出一个
// 65536 **个包**的突发额度：一次十万包的小包洪水会被整个放过去，
// 而那正是这个维度存在的唯一理由。
//
// 这是本包的测试抓出来的：只限包速率时一百个小包全部放行。
func newPacketBucket(perSecond int64) *rate.Limiter {
	if perSecond <= 0 {
		return nil
	}
	// 突发额度就是一秒的量。至少 1，否则 rate.NewLimiter 会拒绝一切。
	return rate.NewLimiter(rate.Limit(perSecond), int(max(perSecond, 1)))
}

// minByteBurst 是**字节**桶的突发额度下限。
//
// 64 KiB = UDP 载荷理论上限。低于它的话一个满尺寸数据报会因为
// 「一次要的令牌超过桶容量」而永远失败。
const minByteBurst = 64 << 10

// AllowN 非阻塞地取 n 字节 + 1 个包的额度。取不到返回 false。
//
// UDP 路径用它：等一个数据报的额度不如丢掉它。
func (l *Limiter) AllowN(n int) bool {
	if l == nil {
		return true
	}
	// 顺序有讲究：先判包再判字节。
	//
	// 反了的话，一个被包速率拒掉的包已经先扣掉了字节额度 ——
	// 于是字节限速会在攻击流量下比配置值更严，把正常流量一起饿死。
	if l.packets != nil && !l.packets.Allow() {
		return false
	}
	if l.bytes != nil && !l.bytes.AllowN(time.Now(), n) {
		return false
	}
	return true
}

// WaitReader 把一个 reader 包成受限速的。limiter 为 nil 时原样返回。
//
// TCP 路径用它：字节流丢中间一段就是把连接搞坏，所以只能等。
func (l *Limiter) WaitReader(ctx context.Context, r io.Reader) io.Reader {
	if l == nil {
		return r
	}
	return &limitedReader{ctx: ctx, r: r, l: l}
}

type limitedReader struct {
	ctx context.Context
	r   io.Reader
	l   *Limiter
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	// 先读再等，而不是先等再读。
	//
	// 先等的话我们只能按 len(p) 申请额度，而实际读到的往往少得多 ——
	// 于是限速会比配置值严好几倍（缓冲区多大就差多少倍）。
	// 按**实际读到的字节数**结账才是准的。
	n, err := lr.r.Read(p)
	if n > 0 {
		if werr := lr.l.Wait(lr.ctx, n); werr != nil {
			// ctx 结束了。把已经读到的字节交出去，错误留给下一次 Read ——
			// 丢掉它们等于在一条 TCP 流中间挖一个洞。
			return n, err
		}
	}
	return n, err
}

// Wait 阻塞直到拿到 n 字节 + 1 个包的额度。limiter 为 nil 时立刻返回。
//
// # 为什么这个原语要导出
//
// WaitReader 把桶**捕获在包装对象里**，于是一条长命连接（WebSocket、
// splice 出去的裸 TCP）会一直用建立那一刻的桶。而把 10 Mbps 调成 1 Mbps 的
// 典型动机恰恰是压住**正在进行**的滥用 —— 那条连接却不受影响，
// 而详情页显示的是新值「已设置」。
//
// 共享入口的包装因此不能捕获桶，而要在每次读/写时现取。它需要的正是这个
// 「等 n 字节额度」的原语，所以把它导出。
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l == nil {
		return nil
	}
	if l.packets != nil {
		if err := l.packets.Wait(ctx); err != nil {
			return err
		}
	}
	if l.bytes == nil {
		return nil
	}
	// n 可能大于桶容量（一次读到 1 MiB 而限速只有 64 KiB/s）。
	// x/time/rate 对 n > burst 直接返回错误而不是等 —— 那会让这条流
	// **永久失败**。所以分批要。
	burst := l.bytes.Burst()
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		if err := l.bytes.WaitN(ctx, take); err != nil {
			return err
		}
		n -= take
	}
	return nil
}
