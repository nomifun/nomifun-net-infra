package relay

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// 承载 RTT 观测。
//
// # 为什么中继发起、中继两次取时间戳
//
// agent 的时钟完全不参与 —— 时钟偏移那一整套问题在这里不存在，
// 而且 agent 无法把自己的延迟报小：它最早只能在真实单程时延之后回包。
//
// 反过来若让 agent 自己测 RTT 再随 TypeMetrics 报上来，那个数就是
// **代理端自报**的，可信度与 AgentReportedMetrics 同级 ——
// 而要写进时序库的必须是中继观测值。
//
// # 为什么只允许一个在飞的 ping
//
// 「seq → 发出时刻」如果做成一张表，那张表的清理就成了一个必须想清楚的问题
// （没回的 ping 会积累）。而我们不需要高采样率：直方图是慢慢积累的，
// 每个间隔一个样本足够算分位数。一个 slot 换掉一整类无界增长，划算。
//
// # 为什么 seq 用随机数而不是自增
//
// 自增可猜。一个恶意 agent 可以预先把 Pong(1..N) 灌进控制流 ——
// 那些帧在对应 ping 发出前会被读到并丢弃（seq 不匹配），正常情况下没事；
// 但只要读循环有一瞬间落后（GC、调度），一个已经排在缓冲里的 Pong 就可能
// 被当成刚发出那个 ping 的回应，于是 RTT 被报成接近 0。
// 随机 seq 让这件事在 2^32 里撞一次。
const (
	// rttRingSize 是保留的最近观测数。
	//
	// 64 个样本 @ 5 秒间隔 ≈ 5 分钟窗口。分位数要的是分布而不是历史，
	// 更长的窗口只会让它对刚发生的变化反应更慢。
	rttRingSize = 64

	// pingTimeout 之后认为这个 ping 丢了，允许发下一个。
	//
	// 不把超时算成一次「很大的 RTT」观测：那会让一次丢包污染分位数，
	// 而丢包本身有自己的指标。超时只是让 slot 空出来。
	pingTimeout = 30 * time.Second
)

// rttState 是一个会话的 RTT 观测状态。
type rttState struct {
	// inFlight 是当前在飞的 ping 序号，0 表示没有。
	inFlight atomic.Uint32
	// sentAt 是它的发出时刻（UnixNano）。
	sentAt atomic.Int64

	// last 是最近一次观测（纳秒）。0 表示**还没测到** ——
	// 不是「0 毫秒」。控制台必须把这两者区分开。
	last atomic.Int64

	mu   sync.Mutex
	ring [rttRingSize]time.Duration
	n    int // 已写入的样本数（上界 rttRingSize）
	head int

	// pending 是**还没被写进时序库**的观测。
	//
	// 与 ring 是两回事：ring 是「最近 N 个」用来算分位数（每次快照都要读，
	// 所以不能被消费掉），pending 是「攒着等采样循环来取」。
	//
	// 只取 ring 里最近一个写库的话，ping 每 5 秒一次而采样每分钟一次 ——
	// 12 个观测里只有 1 个进直方图，剩下 11 个白测了。而直方图的价值
	// 恰恰在于样本数：一分钟一个点算不出有意义的 p95。
	//
	// 有界：超过 rttRingSize 就丢最旧的。采样循环停了（不该发生）也不会
	// 让它无界增长。
	pending []time.Duration
}

// beginPing 领取一个 ping 序号。返回 0 表示现在不该发。
func (r *rttState) beginPing(now time.Time) uint32 {
	// 已有在飞的且还没超时 → 不发。
	if cur := r.inFlight.Load(); cur != 0 {
		if now.UnixNano()-r.sentAt.Load() < int64(pingTimeout) {
			return 0
		}
		// 超时了：让 slot 空出来。**不**把它算成一次观测 ——
		// 那会让一次丢包污染分位数，而丢包有自己的指标。
		r.inFlight.CompareAndSwap(cur, 0)
	}
	seq := randomSeq()
	if !r.inFlight.CompareAndSwap(0, seq) {
		// 与另一个 ping 协程抢输了。正常路径上只有一个协程，
		// 但让这里安全比依赖「只有一个调用者」更不容易在将来被改错。
		return 0
	}
	r.sentAt.Store(now.UnixNano())
	return seq
}

// notePong 记录一次回应。seq 不匹配时**静默忽略**。
//
// 忽略而不是报错：一个陈旧的或伪造的 Pong 不该产生日志噪声，
// 更不该被算成一次观测（那正是把 RTT 报成接近 0 的路径）。
func (r *rttState) notePong(seq uint32, now time.Time) (time.Duration, bool) {
	if seq == 0 || !r.inFlight.CompareAndSwap(seq, 0) {
		return 0, false
	}
	rtt := time.Duration(now.UnixNano() - r.sentAt.Load())
	if rtt < 0 {
		// 单调时钟下不该发生；发生了就丢掉而不是记一个负数。
		return 0, false
	}
	r.last.Store(int64(rtt))

	r.mu.Lock()
	r.ring[r.head] = rtt
	r.head = (r.head + 1) % rttRingSize
	if r.n < rttRingSize {
		r.n++
	}
	// 攒进待写队列。超界丢最旧 —— 采样循环停了也不会无界增长。
	if len(r.pending) >= rttRingSize {
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, rtt)
	r.mu.Unlock()
	return rtt, true
}

// RTTSamples 返回最近的观测快照（升序）。没有观测时返回 nil。
func (r *rttState) samples() []time.Duration {
	r.mu.Lock()
	out := make([]time.Duration, r.n)
	copy(out, r.ring[:r.n])
	r.mu.Unlock()
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func randomSeq() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 拿不到随机数时退回时间戳低位。比固定值好：至少两次之间不同。
		return uint32(time.Now().UnixNano()) | 1
	}
	seq := binary.BigEndian.Uint32(b[:])
	if seq == 0 {
		// 0 是「没有在飞的 ping」的保留值。
		seq = 1
	}
	return seq
}

// ── Session 上的公开出口 ────────────────────────────────────────────────────

// DrainRTT 取走还没写进时序库的观测。
//
// 排空而不是「读最近一个」：ping 每 5 秒一次而采样循环每分钟一次，
// 只取最近一个等于把 12 个观测里的 11 个丢掉 ——
// 而直方图的价值恰恰在样本数，一分钟一个点算不出有意义的 p95。
func (s *Session) DrainRTT() []time.Duration {
	s.rtt.mu.Lock()
	defer s.rtt.mu.Unlock()
	if len(s.rtt.pending) == 0 {
		return nil
	}
	out := s.rtt.pending
	s.rtt.pending = nil
	return out
}

// LastRTT 返回最近一次观测到的承载 RTT。**0 表示还没测到，不是 0 毫秒。**
func (s *Session) LastRTT() time.Duration { return time.Duration(s.rtt.last.Load()) }

// RTTPercentiles 从最近的观测里算 p50/p95/p99。
//
// 没有观测时三个都返回 0，调用方必须把它显示成「—」而不是 0 ——
// 0 会被读成「测过，是零」。
func (s *Session) RTTPercentiles() (p50, p95, p99 time.Duration) {
	xs := s.rtt.samples()
	if len(xs) == 0 {
		return 0, 0, 0
	}
	at := func(q float64) time.Duration {
		// 最近秩法：样本数很少时（刚上线只有一两个）任何插值都在编数字。
		i := int(q*float64(len(xs)-1) + 0.5)
		return xs[i]
	}
	return at(0.50), at(0.95), at(0.99)
}

// SendPing 在控制流上发一帧 Ping。返回 false 表示这次不该发（已有在飞的）。
//
// **调用方必须是控制流唯一的写者。** 中继侧握手之后不再往控制流写别的东西，
// 所以这里不需要写锁 —— 那个前提写在这里，因为它不显然。
func (s *Session) SendPing(w *proto.Writer, now time.Time) (bool, error) {
	seq := s.rtt.beginPing(now)
	if seq == 0 {
		return false, nil
	}
	if err := w.WriteMessage(proto.TypePing, seq, 0, nil); err != nil {
		// 发失败就把 slot 还回去，否则这条会话再也不会测 RTT。
		s.rtt.inFlight.CompareAndSwap(seq, 0)
		return false, err
	}
	return true, nil
}

// NotePong 记录一次 Pong。seq 不匹配时静默忽略并返回 false。
func (s *Session) NotePong(seq uint32, now time.Time) bool {
	_, ok := s.rtt.notePong(seq, now)
	return ok
}
