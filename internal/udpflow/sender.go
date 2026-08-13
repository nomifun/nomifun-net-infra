package udpflow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Datagrammer 是 Sender 需要的最小承载能力。
//
// 用接口而不是直接依赖 internal/carrier：本包是中继与 agent 共用的底层，
// 保持零依赖让它能被两侧以及测试自由组合。
type Datagrammer interface {
	// SendDatagram 发一条不可靠数据报。
	SendDatagram([]byte) error

	// MaxDatagramPayload 返回当前已知的载荷上限，0 表示尚未获知。
	//
	// QUIC 不提供查询上限的接口，只能从 DatagramTooLargeError 反应式学习，
	// 且 PMTUD 完成前该值偏小 —— 所以「0 表示未知」是常态而不是异常。
	MaxDatagramPayload() int
}

// SenderStats 是发送侧计数器。每个字段对应一个
// nf_datagram_dropped_total{reason=...} 的标签值。
//
// 「我们丢了多少包」没有用，「我们在哪一道闸丢的」才告诉你该调什么：
// 队列满要加带宽或降码率，超限要等 PMTUD 或降包长，失败要查承载。
type SenderStats struct {
	Sent      atomic.Int64
	Bytes     atomic.Int64
	QueueFull atomic.Int64
	TooLarge  atomic.Int64
	Failed    atomic.Int64

	// MTUProbes 是「明知超限也发一次，看看路径是不是变宽了」的次数。
	//
	// 承载学到的上限只可能变小（唯一来源是 SendDatagram 的
	// DatagramTooLargeError），所以必须周期性地放一个超限包过去，
	// 否则一次瞬时的小 MTU 会让某一段包长永久丢失。
	MTUProbes atomic.Int64

	// Fragmented 是被切片发出的数据报数（不是分片数）。
	//
	// 规格 §遥测要求展示分片率。分片率高说明当前路径的 MTU 偏小，
	// 而分片放大丢包影响 —— 这是一个该让用户看见的性能信号。
	Fragmented atomic.Int64
}

// Sender 把组帧后的数据报经承载发出，且**绝不阻塞调用方**。
//
// # 为什么必须有这一层，不能直接调 SendDatagram
//
// quic-go 的 SendDatagram 在连接内已排队 32 条未发出的数据报时会**阻塞**
// 直到队列腾出位置（datagram_queue.go:44-46 明确写了这一点）。
// 若在 UDP 读循环里直接调它，一个拥塞或卡住的对端就会冻结整个读循环：
// 这条隧道上**所有**流的包一起停，而且没有计数、界面上看不到任何异常。
//
// 那正是本包包注释里点名批评 frp 的错误（server/proxy/udp.go:140 队列满即
// 阻塞），只是上移了一层。所以这里用一条有界队列 + 专用发送 goroutine：
// 阻塞被隔离在那一个 goroutine 里，队列满时**我们**决定丢谁并计数，
// 而不是把背压反向传导到读循环。
//
// # 为什么队列不深
//
// 实时媒体里「迟到的包」等于「丢了的包」，还额外占着带宽。队列越深，
// 拥塞时的排队延迟越大，而排到队尾的音频帧到达时早已过了播放时刻。
// 所以宁浅不深：早丢比晚丢好，且丢弃是可见的（QueueFull 计数）。
type Sender struct {
	car Datagrammer

	// out 传的是 *[]byte 而不是 []byte：缓冲要从池里取、经队列、
	// 发出后再还回池里，全程用同一个指针才不会每包多分配一个指针头。
	out  chan *[]byte
	pool sync.Pool

	// nextDgramID 给分片组编号。
	//
	// 必须有：同一条流上并发在途的两个数据报只靠 (fragOff, totalLen)
	// 分不开，两个长度相同的交错到达就会被重组器拼在一起 —— 静默数据损坏。
	nextDgramID atomic.Uint32

	stats *SenderStats

	// lastMTUProbe 是上一次「明知超限也发一次」的时刻（UnixNano）。
	//
	// 需要它是因为承载学到的上限**只会变小**：唯一的来源是 SendDatagram
	// 返回 DatagramTooLargeError，而 Send 的前置检查会让更大的包永远到不了
	// SendDatagram。于是一次瞬时的小 MTU 会让某一段包长永久丢失，
	// 而 QUIC 自己的 DPLPMTUD 明明会把真实上限探上去。
	lastMTUProbe atomic.Int64

	// now 供测试注入时钟。
	now func() time.Time

	closeOnce sync.Once
	done      chan struct{}
}

// MTUProbeInterval 是重探路径上限的间隔。
//
// 30 秒的依据：这条重探只发生在**本来就要被丢掉**的包上，所以代价是零；
// 而 QUIC 的 DPLPMTUD 在路径变化后通常几秒内就能探到新值，
// 30 秒足够快到让用户察觉不到「某一段包长丢了一会儿」。
const MTUProbeInterval = 30 * time.Second

func (s *Sender) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// dueForMTUProbe 报告是否该放一个超限包过去试试。
//
// CompareAndSwap 保证并发的多个超限包只有一个去探 —— 否则一场突发里
// 每个超限包都会去撞承载，那就等于没有前置检查了。
func (s *Sender) dueForMTUProbe() bool {
	now := s.clock().UnixNano()
	last := s.lastMTUProbe.Load()
	if last != 0 && now-last < int64(MTUProbeInterval) {
		return false
	}
	return s.lastMTUProbe.CompareAndSwap(last, now)
}

// DefaultSendQueueDepth 是默认发送队列深度。
//
// 128 条 ≈ 50pps 的单条音频流积压 2.5 秒，或 10 条并发流各 0.25 秒。
// 再深就只是在积累「注定过期的包」；再浅则会在正常的突发（比如一个视频
// 关键帧被拆成多个包）时误丢。
const DefaultSendQueueDepth = 128

// maxFrameBuffer 是池化缓冲的容量上限。
//
// 超过这个尺寸的缓冲不放回池里 —— 否则一次异常的大报文会让池永久
// 持有几十 KB，而绝大多数数据报只有一两 KB。
const maxFrameBuffer = 4 << 10

// NewSender 创建一个发送器。depth <= 0 时用 DefaultSendQueueDepth。
//
// stats 可由调用方提供，让统计对象在发送器创建之前就有一个稳定地址 ——
// 发送器往往是每会话延迟创建的，而指标采集不该因此拿不到数字。为 nil 时自建。
func NewSender(car Datagrammer, depth int, stats *SenderStats) *Sender {
	if depth <= 0 {
		depth = DefaultSendQueueDepth
	}
	if stats == nil {
		stats = &SenderStats{}
	}
	s := &Sender{
		car:   car,
		stats: stats,
		out:   make(chan *[]byte, depth),
		done:  make(chan struct{}),
		pool: sync.Pool{New: func() any {
			b := make([]byte, 0, 1500+HeaderSize)
			return &b
		}},
	}
	// 从**现在**开始计时，而不是从零。
	//
	// 零值会让第一个超限包立刻去探一次，而那时承载刚学到的上限是准确的
	//（它唯一的来源就是一次真实的 DatagramTooLargeError）—— 白丢一个包。
	s.lastMTUProbe.Store(s.clock().UnixNano())
	return s
}

// Stats 返回计数器指针，供指标采集读取。
func (s *Sender) Stats() *SenderStats { return s.stats }

// Send 组帧并入队。返回 false 表示这一包被丢弃（原因已计入 Stats）。
//
// **绝不阻塞。** payload 在返回后即可被调用方复用 —— 内容已拷进池化缓冲。
//
// # 超限时分片还是丢弃，由帧头的 FlagNoReassemble 决定
//
// 那个标志字面意思就是「别为我排队等重组」，所以拿它当信号最自然 ——
// 不需要再给 Send 加一个布尔参数，也不需要按隧道开两个发送器
// （发送器是**每会话**一个，因为 quic-go 的数据报队列是连接级的）。
//
// 置了它 = 实时路径 = 丢弃：分片放大丢包影响（任一片丢失整个数据报作废），
// 而一帧迟到的音频等于丢了还白占带宽，正确做法是让编码器降码率。
// 没置 = 批量路径 = 分片：IoT 的大报文丢了就是功能不可用。
//
// **默认（零值）是分片**，因为默认错向安全的一侧：一条本该丢弃的媒体流
// 被分片只是多点延迟，而一条本该分片的批量流被丢弃是静默数据丢失。
func (s *Sender) Send(h Header, payload []byte) bool {
	// 超过当前已知上限：按帧头的 FlagNoReassemble 决定分片还是丢弃。
	//
	// 上限未知（返回 0，PMTUD 完成前的常态）时一律直接发 ——
	// 把「未知」当成「上限为 0」会让连接刚建立、最需要通的那一批包全军覆没。
	if maxPayload := s.car.MaxDatagramPayload(); maxPayload > 0 &&
		len(payload)+HeaderSize > maxPayload {
		if h.NoReassemble() {
			// 实时路径：丢弃并计数，让编码器降码率，
			// 而不是等一个注定迟到的重组。
			//
			// 但**先看要不要重探一次**。承载学到的上限只可能变小
			// （它唯一的来源是 SendDatagram 返回 DatagramTooLargeError），
			// 而这道前置检查会让更大的包永远到不了 SendDatagram ——
			// 于是上限一旦被一次瞬时的小 MTU 拉低，就再也升不回来。
			// 症状是实时隧道对**某一段包长**永久 100% 丢包
			//（例如 1228~1399 字节的音视频包），直到承载重建。
			// 而 QUIC 自己的 DPLPMTUD 明明会把真实上限探上去。
			//
			// 重探在这条路径上是**免费**的：这个包本来就要被丢掉，
			// 让它去撞一次承载，最坏结果还是被丢掉（并顺手更新上限）。
			if !s.dueForMTUProbe() {
				s.stats.TooLarge.Add(1)
				return false
			}
			s.stats.MTUProbes.Add(1)
			// 落到下面的正常入队路径去试。
		} else {
			// 批量路径照常分片。这里**不**重探：上限偏小只会让分片多一些
			// （效率问题），而拿一个必然失败的整包去试会让这个数据报
			// 从「分片后能到」变成「丢了」—— 那是功能问题。
			return s.sendFragmented(h, payload, maxPayload)
		}
	}

	// 已关闭时先返回，不要走进 select —— 带 default 的 select 在两个 case
	// 都就绪时是**随机**选的，那会让关闭后的包偶尔进队列再没人消费。
	select {
	case <-s.done:
		s.stats.Failed.Add(1)
		return false
	default:
	}

	bp := s.pool.Get().(*[]byte)
	frame, err := h.AppendTo((*bp)[:0], payload)
	if err != nil {
		s.recycle(bp)
		s.stats.Failed.Add(1)
		return false
	}
	*bp = frame

	select {
	case s.out <- bp:
		return true
	default:
		// 队列满就丢，并让它可见。这是刻意的选择而不是疏漏：
		// 阻塞会把背压传导回读循环，冻结同一入口上的所有流。
		s.recycle(bp)
		s.stats.QueueFull.Add(1)
		return false
	}
}

// sendFragmented 把超限的数据报切片后逐片入队。
//
// 全部入队成功才算成功：只发出去一半的数据报在接收侧只会占着重组缓冲
// 直到超时 —— 既浪费带宽又浪费对端内存。所以这里先算清能不能装下，
// 中途入队失败就整组放弃（已入队的那几片会让对端超时丢弃，
// 这是 UDP 上无法避免的，但至少我们不主动制造半个数据报）。
func (s *Sender) sendFragmented(h Header, payload []byte, maxPayload int) bool {
	total := len(payload)
	if total > MaxPayload {
		// TotalLen 是 uint16，装不下更大的数据报。
		s.stats.TooLarge.Add(1)
		return false
	}

	// 分片帧的头比未分片的长 4 字节（多一个 dgramID）。
	chunk := maxPayload - FragHeaderSize
	if chunk <= 0 {
		// 上限连一个帧头都装不下 —— 这条链路上根本发不出数据报。
		s.stats.TooLarge.Add(1)
		return false
	}

	dgramID := s.nextDgramID.Add(1)
	h.Flags |= FlagFragmented
	// 分片路径与 FlagNoReassemble 互斥：那个标志的意思正是
	// 「别为我排队等重组」。同时置上会让对端无从判断该不该重组。
	h.Flags &^= FlagNoReassemble
	h.DgramID = dgramID
	h.TotalLen = uint16(total)

	for off := 0; off < total; off += chunk {
		end := min(off+chunk, total)
		fh := h
		fh.FragOff = uint16(off)
		fh.FragLen = uint16(end - off)
		if end == total {
			fh.Flags |= FlagLastFrag
		}
		if !s.enqueue(fh, payload[off:end]) {
			return false
		}
	}
	s.stats.Fragmented.Add(1)
	return true
}

// enqueue 组帧并入队，不做任何尺寸判断（调用方已经判过）。
func (s *Sender) enqueue(h Header, payload []byte) bool {
	bp := s.pool.Get().(*[]byte)
	frame, err := h.AppendTo((*bp)[:0], payload)
	if err != nil {
		s.recycle(bp)
		s.stats.Failed.Add(1)
		return false
	}
	*bp = frame

	select {
	case s.out <- bp:
		return true
	default:
		s.recycle(bp)
		s.stats.QueueFull.Add(1)
		return false
	}
}

// recycle 把缓冲还回池里（过大的不还，见 maxFrameBuffer）。
func (s *Sender) recycle(bp *[]byte) {
	if cap(*bp) <= maxFrameBuffer {
		*bp = (*bp)[:0]
		s.pool.Put(bp)
	}
}

// Run 消费队列并逐条发出。阻塞直到 ctx 取消或 Close。
//
// 只有这一个 goroutine 会调 SendDatagram，所以 quic-go 的队列阻塞
// 被完全隔离在这里。
func (s *Sender) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case bp := <-s.out:
			s.deliver(bp)
		}
	}
}

func (s *Sender) deliver(bp *[]byte) {
	n := len(*bp)
	err := s.car.SendDatagram(*bp)
	// 缓冲可以立刻回收：quic-go 的 SendDatagram 内部会 copy
	//（connection.go:3042-3043），不持有传入的切片。
	// 这一点是从源码确认的，不是推测 —— 若它改成持有，
	// 这里的复用就会静默损坏报文。
	s.recycle(bp)

	if err == nil {
		s.stats.Sent.Add(1)
		s.stats.Bytes.Add(int64(n))
		return
	}

	// 超限错误里带着新的上限，承载已经把它记下了（反应式 MTU 学习），
	// 所以下一包会被 Send 里的检查提前挡住，不必在这里做别的事。
	//
	// 用结构化接口而不是字符串匹配，也不 import internal/carrier ——
	// 本包要保持零依赖以便两侧共用。
	var tooLarge interface{ DatagramMaxPayload() int }
	if errors.As(err, &tooLarge) {
		s.stats.TooLarge.Add(1)
		return
	}
	s.stats.Failed.Add(1)
}

// Close 停止发送器。可重复调用。
func (s *Sender) Close() {
	s.closeOnce.Do(func() { close(s.done) })
}
