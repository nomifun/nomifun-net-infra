package proto

import (
	"container/list"
	"sync"
	"time"
)

// ReplayGuard 是握手 nonce 的有界重放账本。
//
// frp 完全没有这一层：它的 token 校验只比较 hex(MD5(token‖timestamp)) 是否相等
// （pkg/auth/token.go:64-69），既不校验时间戳新鲜度也不记录已用 nonce，
// 所以**一次抓包得到的 (timestamp, signKey) 对可以永久重放**。
//
// 本类型与 Proof.Verify 配合：Verify 负责无状态部分（时钟偏移 + MAC），
// ReplayGuard 负责有状态部分（这个 nonce 用过没有）。两者都通过才算握手成功。
//
// # 为什么必须有界
//
// 账本本身不能成为攻击面。攻击者可以用无限多的伪造 nonce 灌满一个无界 map，
// 把内存打爆 —— 这与 frp 的 UDP 会话表无上限（pkg/proto/udp/udp.go:75）
// 是同一类错误。所以这里用「容量上限 + LRU 淘汰 + TTL 过期」三重约束。
//
// # 淘汰与安全的取舍
//
// LRU 满时淘汰最旧的条目，理论上让一个非常旧的 nonce 变得可重放。
// 但这不构成漏洞：能被淘汰的条目必然比 TTL 更早，而 TTL = 2 × MaxClockSkew，
// 那样的时间戳已经会被 Proof.Verify 以 ErrProofStale 拒掉。
// 换言之，**时钟偏移检查是第一道闸，LRU 只需覆盖闸门宽度内的窗口**。
type ReplayGuard struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration

	// order 是 LRU 链表，队首最旧。元素值为 *replayEntry。
	order *list.List
	// index 把 key 映射到链表元素，使命中判断是 O(1)。
	index map[replayKey]*list.Element

	// now 可注入以便测试；nil 表示 time.Now。
	now func() time.Time
}

type replayKey struct {
	agentID string
	nonce   string
}

type replayEntry struct {
	key      replayKey
	expireAt time.Time
}

// DefaultReplayCapacity 是账本默认容量。
//
// 按每 agent 每次重连一个 nonce 估算，2 万条足够覆盖一个大机队在
// TTL 窗口（2 分钟）内的全部握手，而内存占用约在百 KB 量级。
const DefaultReplayCapacity = 20000

// NewReplayGuard 创建一个重放账本。
//
// capacity <= 0 时用 DefaultReplayCapacity；ttl <= 0 时用 2 × MaxClockSkew。
func NewReplayGuard(capacity int, ttl time.Duration) *ReplayGuard {
	if capacity <= 0 {
		capacity = DefaultReplayCapacity
	}
	if ttl <= 0 {
		ttl = 2 * MaxClockSkew
	}
	return &ReplayGuard{
		capacity: capacity,
		ttl:      ttl,
		order:    list.New(),
		index:    make(map[replayKey]*list.Element, capacity),
	}
}

func (g *ReplayGuard) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// Check 尝试登记一个 (agentID, nonce) 组合。
//
// 首次见到返回 true；重复（且未过期）返回 false —— 调用方必须据此拒绝握手，
// 并以 outcome="replay" 打点。
//
// 按 agentID 分键而非全局分键，是为了避免一个 agent 的 nonce 空间影响别的 agent：
// 否则攻击者可以预先灌入大量 nonce，去碰撞受害者将来可能生成的值。
func (g *ReplayGuard) Check(agentID, nonce string) bool {
	k := replayKey{agentID: agentID, nonce: nonce}
	now := g.clock()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.evictExpiredLocked(now)

	if el, seen := g.index[k]; seen {
		ent := el.Value.(*replayEntry)
		if ent.expireAt.After(now) {
			// 真正的重放。不刷新 TTL —— 否则攻击者可以靠反复重放
			// 把一个条目永久钉在账本里，挤占容量。
			return false
		}
		// 已过期的残留条目：直接复用这个槽位。
		ent.expireAt = now.Add(g.ttl)
		g.order.MoveToBack(el)
		return true
	}

	// 容量满则淘汰最旧的。
	for g.order.Len() >= g.capacity {
		oldest := g.order.Front()
		if oldest == nil {
			break
		}
		g.removeLocked(oldest)
	}

	ent := &replayEntry{key: k, expireAt: now.Add(g.ttl)}
	g.index[k] = g.order.PushBack(ent)
	return true
}

// evictExpiredLocked 从队首开始清理已过期条目。
//
// 因为所有条目的 TTL 相同且按插入顺序入队，队首必然是最早过期的，
// 所以遇到第一个未过期的即可停止 —— 摊还成本是 O(1)。
func (g *ReplayGuard) evictExpiredLocked(now time.Time) {
	for {
		front := g.order.Front()
		if front == nil {
			return
		}
		if front.Value.(*replayEntry).expireAt.After(now) {
			return
		}
		g.removeLocked(front)
	}
}

func (g *ReplayGuard) removeLocked(el *list.Element) {
	ent := el.Value.(*replayEntry)
	delete(g.index, ent.key)
	g.order.Remove(el)
}

// Len 返回当前账本条目数，供指标与测试使用。
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.order.Len()
}
