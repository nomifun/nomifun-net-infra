package udpflow

import (
	"errors"
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Table 是有界的 UDP 流会话表。
//
// 它替代 frp 的 udpConnMap（pkg/proto/udp/udp.go:75），后者是一个**无上限**的
// map[string]*net.UDPConn，每个新源地址就 DialUDP 一个新 socket。
// 因为中继是公网暴露的，从随机源端口喷包即可在 30 秒回收窗口内耗尽 fd。
//
// 四重约束，任一被触发都返回明确的拒绝原因以便分类打点：
//
//   - Capacity: 全表条目硬上限，满则 LRU 淘汰最旧。
//   - PerSourceIP: 单个源 **IP**（不是 IP:端口）的并发流上限。这是关键 ——
//     按 IP 而非按 IP:端口计额，否则换个源端口就绕过了。
//   - NewFlowsPerSecond: 建表速率上限，压制突发喷射。
//   - IdleTimeout: 空闲回收。
//
// # 分片降锁竞争
//
// frp 把一把全局锁跨 net.DialUDP 这个阻塞 syscall 持有（:116-126），
// 把所有新会话的建立串行化了。本表按源地址哈希分成 shardCount 片，
// 且**锁内绝不做 syscall** —— 真正的 socket 创建由调用方在拿到许可后自己做。
type Table[V any] struct {
	cfg    Config
	shards []*shard[V]
	seed   maphash.Seed

	// perIP 跨分片统计，因此单独一把锁。
	// 它只在建表/删表时被触碰，不在每包路径上，所以竞争可接受。
	ipMu    sync.Mutex
	perIP   map[netip.Addr]int
	limiter *rateLimiter

	// capacityEvictions 是因超出容量被淘汰的条目数。
	//
	// 表满不返回错误（刻意选择淘汰最旧而不是拒绝新流），所以这是
	// 「表满」唯一的观测口 —— 没有它，控制台上那一格恒为 0。
	capacityEvictions atomic.Int64

	now func() time.Time
}

// shardCount 是固定分片数。
//
// 32 片在常见核数下足以把锁竞争降到可忽略，同时保持 perIP 统计的简单性。
// 取 2 的幂以便用位与取模。
const shardCount = 32

type shard[V any] struct {
	mu      sync.Mutex
	entries map[Key]*entry[V]

	// lru 是侵入式双向链表，头最旧尾最新。避免 container/list 的每条一次分配。
	head, tail *entry[V]
}

type entry[V any] struct {
	key      Key
	val      V
	lastSeen time.Time

	prev, next *entry[V]
}

// Config 是会话表参数。
type Config struct {
	// Capacity 是全表条目上限。<=0 时用 DefaultCapacity。
	Capacity int

	// PerSourceIP 是单个源 IP 的并发流上限。<=0 时用 DefaultPerSourceIP。
	PerSourceIP int

	// NewFlowsPerSecond 是建表速率上限。<=0 时用 DefaultNewFlowsPerSecond。
	NewFlowsPerSecond int

	// IdleTimeout 是空闲回收阈值。<=0 时用 DefaultIdleTimeout。
	IdleTimeout time.Duration
}

// 默认值。
//
// 这些数字的量级依据：一台家用中继同时服务几十个设备、每设备几条流是常态；
// 上限设在「远高于正常用量、远低于耗尽资源」的区间。
const (
	DefaultCapacity          = 8192
	DefaultPerSourceIP       = 256
	DefaultNewFlowsPerSecond = 512
	DefaultIdleTimeout       = 60 * time.Second
)

func (c *Config) complete() {
	if c.Capacity <= 0 {
		c.Capacity = DefaultCapacity
	}
	if c.PerSourceIP <= 0 {
		c.PerSourceIP = DefaultPerSourceIP
	}
	if c.NewFlowsPerSecond <= 0 {
		c.NewFlowsPerSecond = DefaultNewFlowsPerSecond
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
}

// 拒绝原因。调用方应把它们直接映射到
// nf_datagram_dropped_total{reason=...} 的标签值 ——
// 「我们丢了包」没用，「我们在每源 IP 配额处丢的」才告诉你该调哪个参数。
var (
	// ErrTableFull 保留但**永不返回**。
	//
	// 本表刻意选择「先登记再按 LRU 淘汰最旧的」而不是「拒绝新流」——
	// 对实时流量那是正确取舍（新来的通话不该因为一堆早已结束的流而进不来）。
	// 所以「表满」不是一次拒绝，而是一次**淘汰**，观测它要看
	// CapacityEvictions 而不是这个错误。
	//
	// 留着它是因为将来若加一种「拒绝新流」的模式（比如给批量隧道用），
	// 语义现成；删掉再加回来只会让调用方的 errors.Is 分支来回改。
	// 调用方的 ErrTableFull 分支现在是死代码，那是**如实**的：
	// 它对应的事件在另一个计数器上。
	ErrTableFull   = errors.New("udpflow: 会话表已满")
	ErrPerIPQuota  = errors.New("udpflow: 超过每源 IP 配额")
	ErrRateLimited = errors.New("udpflow: 建表速率超限")
)

// New 创建一个会话表。
func New[V any](cfg Config) *Table[V] {
	cfg.complete()
	t := &Table[V]{
		cfg:     cfg,
		shards:  make([]*shard[V], shardCount),
		seed:    maphash.MakeSeed(),
		perIP:   make(map[netip.Addr]int),
		limiter: newRateLimiter(cfg.NewFlowsPerSecond),
	}
	for i := range t.shards {
		t.shards[i] = &shard[V]{entries: make(map[Key]*entry[V])}
	}
	return t
}

func (t *Table[V]) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *Table[V]) shardFor(k Key) *shard[V] {
	// 按源地址 + FlowID 哈希。
	//
	// 中继侧只有源地址（FlowID 为 0），同一来源的流落在同一分片，
	// 保持缓存局部性。agent 侧反过来：所有流都来自同一个中继，
	// 若只哈希源地址就会全挤进一个分片，分片降锁竞争的效果归零 ——
	// 所以 FlowID 必须参与。
	var h maphash.Hash
	h.SetSeed(t.seed)
	addr := k.Src.Addr().As16()
	_, _ = h.Write(addr[:])
	var fid [4]byte
	fid[0] = byte(k.FlowID >> 24)
	fid[1] = byte(k.FlowID >> 16)
	fid[2] = byte(k.FlowID >> 8)
	fid[3] = byte(k.FlowID)
	_, _ = h.Write(fid[:])
	return t.shards[h.Sum64()&(shardCount-1)]
}

// Lookup 查找一条既有流并刷新其活跃时间。
//
// 这是**每包热路径**，所以它只做 map 查找 + LRU 移动，不涉及配额与限速。
func (t *Table[V]) Lookup(k Key) (V, bool) {
	s := t.shardFor(k)
	now := t.clock()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[k]
	if !ok {
		var zero V
		return zero, false
	}
	e.lastSeen = now
	s.moveToBackLocked(e)
	return e.val, true
}

// Admit 为一条新流申请许可并登记。
//
// create 在**持有分片锁之外**被调用，专门为了不重复 frp 的错误 ——
// 它把 net.DialUDP 放在全局锁内（pkg/proto/udp/udp.go:116-126），
// 使所有新会话建立被串行化。
//
// 若期间有并发的 Admit 抢先登记了同一个 key，本次创建的值会通过 discard 交还
// 调用方释放，返回既有值，且 created 为 false。
//
// # 为什么必须返回 created
//
// 调用方常常要为「新流」做一次性的副作用：起一个读回包的 goroutine、
// 把活跃流数 +1。抢输的那一次拿到的是**别人的**值，对它再做一遍副作用
// 就是两个 goroutine 读同一个 socket —— 其中一个退出时 close 掉，
// 另一个跟着死，而那条流在表里还活着（agent 侧真实发生过这个形状）。
//
// 不能让调用方靠「返回值等不等于我建的那个」去猜：抢输时我建的那个已经被
// 交给 discard 了，比较指针要求调用方在 discard 之后还持有它，
// 而那正是最容易写错的地方。
func (t *Table[V]) Admit(k Key, create func() (V, error), discard func(V)) (val V, created bool, err error) {
	var zero V

	// 先做便宜的检查：限速与配额，避免为注定被拒的流做 syscall。
	if !t.limiter.allow(t.clock()) {
		return zero, false, ErrRateLimited
	}

	ip := k.Src.Addr()
	if err := t.reserveIP(ip); err != nil {
		return zero, false, err
	}

	// 锁外创建。
	val, err = create()
	if err != nil {
		t.releaseIP(ip)
		return zero, false, err
	}

	s := t.shardFor(k)
	now := t.clock()

	s.mu.Lock()
	// 并发竞争：别人已经建好了。
	if existing, ok := s.entries[k]; ok {
		existing.lastSeen = now
		s.moveToBackLocked(existing)
		s.mu.Unlock()
		t.releaseIP(ip)
		if discard != nil {
			discard(val)
		}
		return existing.val, false, nil
	}

	e := &entry[V]{key: k, val: val, lastSeen: now}
	s.entries[k] = e
	s.pushBackLocked(e)
	s.mu.Unlock()

	// 全表容量：LRU 淘汰在登记之后做，保证新流一定能进来，
	// 被挤掉的是最旧的那条 —— 这对实时流量是正确取舍。
	t.enforceCapacity(discard)
	return val, true, nil
}

func (t *Table[V]) reserveIP(ip netip.Addr) error {
	t.ipMu.Lock()
	defer t.ipMu.Unlock()
	if t.perIP[ip] >= t.cfg.PerSourceIP {
		return ErrPerIPQuota
	}
	t.perIP[ip]++
	return nil
}

func (t *Table[V]) releaseIP(ip netip.Addr) {
	t.ipMu.Lock()
	defer t.ipMu.Unlock()
	if n := t.perIP[ip]; n <= 1 {
		delete(t.perIP, ip) // 不留零值条目，否则 map 本身就是泄漏
	} else {
		t.perIP[ip] = n - 1
	}
}

// Len 返回当前条目总数。
func (t *Table[V]) Len() int {
	n := 0
	for _, s := range t.shards {
		s.mu.Lock()
		n += len(s.entries)
		s.mu.Unlock()
	}
	return n
}

// CapacityEvictions 返回因**超出容量**而被淘汰的条目数。
//
// # 为什么必须有这个数字
//
// 本表满了不会拒绝新流，而是淘汰最旧的那条（对实时流量是正确取舍）。
// 后果是「表满」这件事**一个错误都不返回** —— 于是控制台上
// dropped_table_full 恒为 0，而真实情况是有人的流正在被静默挤掉。
//
// 那个 0 比没有数字更糟：README 自己写着「0 会被读成『测过，是零』」。
func (t *Table[V]) CapacityEvictions() int64 { return t.capacityEvictions.Load() }

// enforceCapacity 在超出容量时淘汰最旧条目。
func (t *Table[V]) enforceCapacity(discard func(V)) {
	for t.Len() > t.cfg.Capacity {
		// 从最旧条目所在的分片淘汰。为避免扫描全部分片的全部条目，
		// 只比较各分片的 LRU 队首（它们各自的最旧条目）。
		var victimShard *shard[V]
		var oldest time.Time

		for _, s := range t.shards {
			s.mu.Lock()
			if s.head != nil && (victimShard == nil || s.head.lastSeen.Before(oldest)) {
				oldest = s.head.lastSeen
				victimShard = s
			}
			s.mu.Unlock()
		}
		if victimShard == nil {
			return
		}

		victimShard.mu.Lock()
		e := victimShard.head
		if e == nil {
			victimShard.mu.Unlock()
			return
		}
		victimShard.removeLocked(e)
		victimShard.mu.Unlock()

		t.capacityEvictions.Add(1)
		t.releaseIP(e.key.Src.Addr())
		if discard != nil {
			discard(e.val)
		}
	}
}

// EvictIdle 回收空闲超时的条目，返回被回收的数量。
//
// 应由一个周期性 goroutine 调用（建议 IdleTimeout/4）。
// 之所以不在每包路径上顺带做，是因为那会让热路径的成本依赖于表的历史状态。
func (t *Table[V]) EvictIdle(discard func(V)) int {
	cutoff := t.clock().Add(-t.cfg.IdleTimeout)
	evicted := 0

	for _, s := range t.shards {
		for {
			s.mu.Lock()
			e := s.head
			// LRU 有序，队首不过期则整片都不过期。
			if e == nil || e.lastSeen.After(cutoff) {
				s.mu.Unlock()
				break
			}
			s.removeLocked(e)
			s.mu.Unlock()

			t.releaseIP(e.key.Src.Addr())
			if discard != nil {
				discard(e.val)
			}
			evicted++
		}
	}
	return evicted
}

// Delete 显式移除一条流。
func (t *Table[V]) Delete(k Key, discard func(V)) bool {
	s := t.shardFor(k)

	s.mu.Lock()
	e, ok := s.entries[k]
	if ok {
		s.removeLocked(e)
	}
	s.mu.Unlock()

	if !ok {
		return false
	}
	t.releaseIP(k.Src.Addr())
	if discard != nil {
		discard(e.val)
	}
	return true
}

// Close 清空表并对每个值调用 discard。
func (t *Table[V]) Close(discard func(V)) {
	for _, s := range t.shards {
		s.mu.Lock()
		vals := make([]V, 0, len(s.entries))
		for _, e := range s.entries {
			vals = append(vals, e.val)
		}
		s.entries = make(map[Key]*entry[V])
		s.head, s.tail = nil, nil
		s.mu.Unlock()

		if discard != nil {
			for _, v := range vals {
				discard(v)
			}
		}
	}
	t.ipMu.Lock()
	t.perIP = make(map[netip.Addr]int)
	t.ipMu.Unlock()
}

// ── 侵入式 LRU 链表（调用方须持分片锁）─────────────────────────────────────

func (s *shard[V]) pushBackLocked(e *entry[V]) {
	e.prev, e.next = s.tail, nil
	if s.tail != nil {
		s.tail.next = e
	} else {
		s.head = e
	}
	s.tail = e
}

func (s *shard[V]) unlinkLocked(e *entry[V]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		s.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		s.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (s *shard[V]) moveToBackLocked(e *entry[V]) {
	if s.tail == e {
		return
	}
	s.unlinkLocked(e)
	s.pushBackLocked(e)
}

func (s *shard[V]) removeLocked(e *entry[V]) {
	delete(s.entries, e.key)
	s.unlinkLocked(e)
}

// ── 建表速率限制 ────────────────────────────────────────────────────────────

// rateLimiter 是一个简单的令牌桶。
//
// 不用 golang.org/x/time/rate 是因为这里只需要「允许/拒绝」而不需要等待语义，
// 且要能注入时钟以便测试；自己实现约 30 行，省一个依赖。
type rateLimiter struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	perSec   float64
	last     time.Time
}

func newRateLimiter(perSec int) *rateLimiter {
	c := float64(perSec)
	return &rateLimiter{capacity: c, tokens: c, perSec: c}
}

func (l *rateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.last.IsZero() {
		l.last = now
	}
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens = min(l.capacity, l.tokens+elapsed*l.perSec)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
