package udpflow

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ReassemblerStats 是重组侧计数器。
//
// 分开计数的理由与别处一样：「重组失败了多少」没用，
// 「因为超时/因为表满/因为分片重叠」才告诉你该调什么或该报警。
// 尤其 Overlapping 非零是**安全信号**：正常实现不会发重叠分片。
type ReassemblerStats struct {
	// Completed 是成功重组出的完整数据报数。
	Completed atomic.Int64
	// Fragments 是收到的分片总数。与 Completed 之比就是分片率
	//（规格 §遥测要求展示它）。
	Fragments atomic.Int64

	// TimedOut 是因等不到剩余分片而丢弃的数据报数。
	TimedOut atomic.Int64
	// TableFull 是因并发重组数达上限而被拒的分片数。
	TableFull atomic.Int64
	// BytesFull 是因缓冲字节总量达上限而被拒的分片数。
	BytesFull atomic.Int64
	// Overlapping 是与已收分片范围重叠而被拒的分片数。
	//
	// **非零就该看一眼**：正常的发送方按固定步长切片，不会重叠。
	// 重叠分片是 IP 分片时代的经典攻击手法（teardrop / rose），
	// 用来把内容藏过检查设备。
	Overlapping atomic.Int64
	// Malformed 是自相矛盾的分片（偏移越界等）。
	Malformed atomic.Int64
	// Duplicated 是内容相同的重复分片，只计数不算错（网络会重复）。
	Duplicated atomic.Int64

	// TooManyFrags 是「单个数据报的分片数超过上限」。
	//
	// **非零就是攻击信号**，与 TimedOut 那种链路质量信号不是一类：
	// 合法发送方按固定步长切片，片数是 ceil(TotalLen/(MTU-帧头))；
	// 要触发这条，对端得刻意发很多很小的分片 ——
	// 而那正好是把重叠检测拖成 O(n²) 的形状。
	TooManyFrags atomic.Int64
}

// Reassembler 把分片拼回完整数据报。
//
// # 为什么它有界，而且界得这么细
//
// 重组器是数据面上唯一**有状态**的部件：它必须为「还没到齐的数据报」
// 留着已收到的部分。这天生就是一个可被滥用的缓冲池 —— 攻击者只要
// 不停发「某个大数据报的第一片」就能让接收方无限攒内存，
// 而每一片都是合法帧、每一条流都在配额内。
//
// 所以四重约束：并发重组数上限、缓冲字节总量上限、单个数据报的超时、
// 以及**分片范围重叠即拒**。前三条防资源耗尽，第四条防内容夹带。
//
// # 为什么实时路径不该走这里
//
// 分片放大丢包影响：任一片丢失整个数据报作废。实时媒体应当直接丢弃超限包
// （发送方置 FlagNoReassemble），让编码器降码率，而不是等一个注定迟到的重组。
type Reassembler struct {
	cfg ReassemblerConfig

	mu      sync.Mutex
	pending map[reasmKey]*partial
	bytes   int

	stats *ReassemblerStats

	now func() time.Time
}

// reasmKey 唯一标识一个正在重组的数据报。
//
// 必须含 DgramID：同一条流上并发在途的两个数据报只靠 (Tunnel, FlowID)
// 分不开，两个长度相同的交错到达就会被拼成一个 —— 静默数据损坏。
// TotalLen 也进键，这样「同 ID 但长度不同」会被当成两个不同的数据报
// 而不是一个自相矛盾的，多一层保险。
type reasmKey struct {
	Tunnel   uint16
	FlowID   uint32
	DgramID  uint32
	TotalLen uint16
}

// partial 是一个正在重组的数据报。
type partial struct {
	buf      []byte
	received []span // 已收到的字节区间，按 off 升序
	got      int    // 已收到的字节数
	firstAt  time.Time
}

// span 是一个已收到的字节区间 [off, off+len)。
type span struct{ off, length int }

// ReassemblerConfig 是重组器参数。
type ReassemblerConfig struct {
	// MaxPending 是并发重组中的数据报数上限。
	MaxPending int

	// MaxBytes 是所有重组缓冲加起来的字节上限。
	//
	// 单独限字节数是必要的：只限个数的话，攻击者用
	// MaxPending 个「宣称 65535 字节的数据报」就能占 4 GiB。
	MaxBytes int

	// Timeout 是单个数据报等齐所有分片的期限。
	Timeout time.Duration

	// MaxFragments 是**单个**数据报允许的分片条数上限。
	//
	// # 为什么这条界不能省
	//
	// 前三条界（并发数、字节数、超时）都拦不住一个只发**稀疏 1 字节分片**
	// 的对端：它们既不占多少字节，也不超并发数，还在超时窗口之内。
	// 可 received 这个区间集合会长到 TotalLen 那么多条（最多 65535），
	// 而 overlapKind 是线性扫描、insertSpan 是 O(n) 重建 ——
	// 于是单个数据报的总代价是 O(n²) ≈ 2×10⁹ 次比较，
	// **持着 r.mu 跑在数据报解复用循环上**。
	//
	// 实测量级：约 279 KB/s（2.2 Mbps）的完全合法分片流量就能把一条承载的
	// 解复用循环钉在 100% CPU 上，而那条循环是这个 agent 上所有 UDP 隧道
	// 共用的。合法发送方按固定步长切片，分片数是
	// ceil(TotalLen / (MTU - 帧头))，即便 MTU 小到 576 也只有 ~120 片。
	MaxFragments int

	// Stats 可由调用方提供，让它在 Reassembler 创建之前就有一个稳定地址。
	//
	// 需要这个口子是因为重组器往往是**延迟创建**的（配置来自构造后才填的
	// 字段），而指标采集可能更早发生。返回 nil 让调用方自己判空是个陷阱 ——
	// 我第一版就是那样，测试立刻 nil 解引用崩了。为 nil 时自己分配一个。
	Stats *ReassemblerStats
}

// 默认值。
//
// 这些数字的量级依据：需要分片的数据报在正常流量里是少数
// （典型 UDP 载荷都在 1500 字节以内），所以并发重组数不该很大；
// 而超时要短 —— 等一个迟到的分片不如让上层重试。
const (
	DefaultMaxPending        = 256
	DefaultMaxReassemblyByte = 8 << 20 // 8 MiB
	DefaultReassemblyTimeout = 2 * time.Second

	// DefaultMaxFragments 允许的最小分片长度约 512 字节
	//（65535 / 128 ≈ 512），比任何真实路径的 MTU 都宽松。
	DefaultMaxFragments = 128
)

// 重组错误。调用方通常只需要计数，Reassembler 自己已经记好了。
var (
	ErrReasmTableFull    = errors.New("udpflow: 并发重组数已达上限")
	ErrReasmBytesFull    = errors.New("udpflow: 重组缓冲字节数已达上限")
	ErrReasmOverlap      = errors.New("udpflow: 分片范围与已收分片重叠")
	ErrReasmInconsistent = errors.New("udpflow: 分片自相矛盾")
	ErrReasmTooManyFrags = errors.New("udpflow: 单个数据报的分片数超过上限")
)

func (c *ReassemblerConfig) complete() {
	if c.MaxPending <= 0 {
		c.MaxPending = DefaultMaxPending
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxReassemblyByte
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultReassemblyTimeout
	}
	if c.MaxFragments <= 0 {
		c.MaxFragments = DefaultMaxFragments
	}
}

// NewReassembler 创建一个重组器。
func NewReassembler(cfg ReassemblerConfig) *Reassembler {
	cfg.complete()
	stats := cfg.Stats
	if stats == nil {
		stats = &ReassemblerStats{}
	}
	return &Reassembler{cfg: cfg, pending: make(map[reasmKey]*partial), stats: stats}
}

// Stats 返回计数器指针。**永不为 nil。**
func (r *Reassembler) Stats() *ReassemblerStats { return r.stats }

func (r *Reassembler) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Push 交进一个分片。
//
// 返回 (完整数据报, true) 表示这一片让某个数据报凑齐了；返回的切片是
// 重组器内部缓冲，**调用方必须在返回后立刻用掉或自己拷走** ——
// 下一次 Push 可能复用它。
//
// 非分片帧不该进这里：调用方应当直接用它的载荷。传进来会返回错误，
// 因为那意味着调用方的分派逻辑写错了，而静默接受会掩盖它。
func (r *Reassembler) Push(h Header, payload []byte) ([]byte, bool, error) {
	if !h.Fragmented() {
		return nil, false, ErrReasmInconsistent
	}
	r.stats.Fragments.Add(1)

	// ParseFrame 已经校验过 FragLen == len(payload) 与
	// FragOff+FragLen <= TotalLen，但 Push 也可能被直接调用（测试、
	// 将来的其他承载），所以这里再校验一遍。信任上游是可选的，
	// 而这段代码会拿这些数字去做切片下标。
	if int(h.FragLen) != len(payload) ||
		int(h.FragOff)+int(h.FragLen) > int(h.TotalLen) ||
		h.TotalLen == 0 {
		r.stats.Malformed.Add(1)
		return nil, false, ErrReasmInconsistent
	}

	key := reasmKey{
		Tunnel: h.Tunnel, FlowID: h.FlowID,
		DgramID: h.DgramID, TotalLen: h.TotalLen,
	}
	now := r.clock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 顺手清超时。放在这里而不是靠一个定时器：重组只在有分片进来时
	// 才需要推进，没有流量时也就不需要清理。
	r.expireLocked(now)

	p, ok := r.pending[key]
	if !ok {
		if len(r.pending) >= r.cfg.MaxPending {
			r.stats.TableFull.Add(1)
			return nil, false, ErrReasmTableFull
		}
		if r.bytes+int(h.TotalLen) > r.cfg.MaxBytes {
			r.stats.BytesFull.Add(1)
			return nil, false, ErrReasmBytesFull
		}
		p = &partial{buf: make([]byte, h.TotalLen), firstAt: now}
		r.pending[key] = p
		r.bytes += int(h.TotalLen)
	}

	off, ln := int(h.FragOff), int(h.FragLen)

	// 重叠即拒 —— 但**内容相同**的重复片只计数不报错（网络会重复）。
	switch overlapKind(p.received, off, ln) {
	case overlapContained:
		// 这一片的范围已经被收过了。
		//
		// 判据必须是**内容**而不是范围。第一版拿 (off, length) 与区间集合
		// 逐项比相等，可 insertSpan 会**合并**相邻区间 —— 于是一个
		// 完全正常的重复片（它的范围已经被并进一个更大的区间里）会落进
		// overlapPartial，整个数据报被作废、还误报一次 teardrop 安全信号。
		// 一个网络重复包就能触发。
		if bytes.Equal(p.buf[off:off+ln], payload) {
			r.stats.Duplicated.Add(1)
			return nil, false, nil
		}
		// 范围重复但内容不同 = 真的在试图改写已收到的字节。
		// 这比范围部分重叠更明确 —— 合并区间反而让这一判定变强了。
		r.stats.Overlapping.Add(1)
		delete(r.pending, key)
		r.bytes -= len(p.buf)
		return nil, false, ErrReasmOverlap
	case overlapPartial:
		// 这是**安全信号**。重叠分片是 IP 分片时代的经典手法，
		// 用来让检查设备与终端看到不同的内容。正常发送方不会这样做。
		r.stats.Overlapping.Add(1)
		// 整个数据报作废：留着一个已被污染的缓冲比丢掉危险。
		delete(r.pending, key)
		r.bytes -= len(p.buf)
		return nil, false, ErrReasmOverlap
	}

	// 分片条数上界。放在重叠判定**之后**：一个重复片不该消耗片数配额，
	// 否则一段丢包重传就能把一个正常数据报顶掉。
	if len(p.received) >= r.cfg.MaxFragments {
		r.stats.TooManyFrags.Add(1)
		delete(r.pending, key)
		r.bytes -= len(p.buf)
		return nil, false, ErrReasmTooManyFrags
	}

	copy(p.buf[off:off+ln], payload)
	p.received = insertSpan(p.received, span{off: off, length: ln})
	p.got += ln

	if p.got < int(h.TotalLen) {
		return nil, false, nil
	}

	// 凑齐了。received 现在必然是一个覆盖 [0, TotalLen) 的连续区间 ——
	// 因为重叠已被拒，所以 got == TotalLen 只可能是无缝铺满。
	delete(r.pending, key)
	r.bytes -= len(p.buf)
	r.stats.Completed.Add(1)
	return p.buf, true, nil
}

// expireLocked 丢弃超时未凑齐的数据报。调用方须持锁。
func (r *Reassembler) expireLocked(now time.Time) {
	for k, p := range r.pending {
		if now.Sub(p.firstAt) > r.cfg.Timeout {
			delete(r.pending, k)
			r.bytes -= len(p.buf)
			r.stats.TimedOut.Add(1)
		}
	}
}

// Pending 返回当前正在重组的数据报数与占用字节数，供指标使用。
func (r *Reassembler) Pending() (count, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending), r.bytes
}

// ── 区间集合 ────────────────────────────────────────────────────────────────

type overlapResult int

const (
	overlapNone overlapResult = iota
	// overlapContained 表示这一片的范围**完整落在**某个已收区间里。
	//
	// 不叫 overlapExact 了：insertSpan 会合并相邻区间，所以一个正常的
	// 重复片在集合里通常不再有一条与它逐字相等的记录 ——
	// 按「相等」判会把它当成 teardrop，那是一个由网络重复包触发的误报。
	overlapContained
	overlapPartial
)

// overlapKind 判断 [off, off+ln) 与已收区间的关系。
//
// 线性扫描而不是二分：分片数由 MaxFragments 封住（默认 128），
// 线性扫描比维护一棵树简单得多且更不容易写错。
// **那条上界不是可选的** —— 没有它，稀疏 1 字节分片会让这里变成 O(n²)。
func overlapKind(spans []span, off, ln int) overlapResult {
	for _, s := range spans {
		// 完整包含：范围上没有任何新字节。
		if off >= s.off && off+ln <= s.off+s.length {
			return overlapContained
		}
		// 两区间相交但不被包含：有新字节也有旧字节。
		if off < s.off+s.length && s.off < off+ln {
			return overlapPartial
		}
	}
	return overlapNone
}

// insertSpan 把一个区间插入有序集合，并合并相邻区间。
//
// 合并让「凑齐」的判据可以只看 got 累加值 —— 因为重叠已被拒，
// 不合并也不影响正确性，但合并让区间数保持很小，扫描更快。
func insertSpan(spans []span, ns span) []span {
	out := make([]span, 0, len(spans)+1)
	inserted := false
	for _, s := range spans {
		if !inserted && ns.off < s.off {
			out = append(out, ns)
			inserted = true
		}
		out = append(out, s)
	}
	if !inserted {
		out = append(out, ns)
	}

	// 合并相邻（首尾相接）的区间。
	merged := out[:1]
	for _, s := range out[1:] {
		last := &merged[len(merged)-1]
		if last.off+last.length == s.off {
			last.length += s.length
			continue
		}
		merged = append(merged, s)
	}
	return merged
}
