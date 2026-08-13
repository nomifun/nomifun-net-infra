package turnsrv

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

// Allocation 是控制台「媒体中继」一屏里的一行。
//
// 字段与 web/src/api/types.ts 的 TurnAllocation 一一对应。
type Allocation struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	RelayedAddr  string `json:"relayed_addr"`
	PeerCount    int    `json:"peer_count"`
	BytesRelayed int64  `json:"bytes_relayed"`
	// CredentialTTLSeconds 是凭据还剩多久过期，从用户名里的时间戳算出。
	CredentialTTLSeconds int       `json:"credential_ttl_s"`
	CreatedAt            time.Time `json:"created_at"`
}

// registry 自己维护一张分配表。
//
// # 为什么必须自己维护
//
// pion/turn **没有枚举分配的 API** —— 只有 AllocationCount() 返回一个数字
// （研究文档 15 §A6 已核实，源码里也确实只有这一个）。而运营这类服务时，
// 「现在有几路、分别是谁、各用了多少流量」才是要看的东西；
// 一个总数回答不了「是不是某一个客户端在刷」。
//
// 它给的钩子是 EventHandler：OnAllocationCreated / OnAllocationDeleted /
// OnPermissionCreated / OnPermissionDeleted。字节数从计量生成器来 ——
// 中继 socket 是每分配一个，两者用中继地址对上。
type registry struct {
	mu    sync.RWMutex
	items map[string]*allocEntry

	// byRelay 让计量生成器创建的 socket 能找到自己的分配。
	//
	// 需要它是因为两条信息来自不同回调：分配的身份（谁、什么时候）
	// 来自 OnAllocationCreated，字节数来自我们包装的 socket。
	// 唯一的公共键是中继地址。
	byRelay map[string]*allocEntry

	// authUsers 暂存鉴权通过时看到的**完整** TURN 用户名。
	//
	// 必须有这一张表：OnAllocationCreated 给的是 userID —— 也就是
	// "<时间戳>:<用户标识>" 里冒号**后面**那半，时间戳被 pion 吃掉了。
	// 而凭据剩余有效期只能从时间戳算，所以要在 OnAuth 里把完整用户名截住。
	// 少了这一步，控制台的「凭据剩余」列会恒为 0 —— 看起来像「已过期」，
	// 而实际凭据还有几分钟。这是补测试时抓出来的。
	authUsers map[string]string
}

// maxPendingAuth 是 authUsers 的容量上限。
//
// 鉴权通过但最终没建成分配的情形会在这张表里留下条目（例如客户端在
// Allocate 之前断开），不设上限就是一个慢速内存泄漏。
const maxPendingAuth = 1024

type allocEntry struct {
	id        string
	username  string
	relayAddr string
	createdAt time.Time

	// peers 是已授权的对端 IP 集合。用集合而不是计数器：
	// 权限会被刷新（客户端每 2 分钟重发 CreatePermission），
	// 用计数器会一路涨上去，显示成「几十个对端」而实际只有一个。
	peers map[string]struct{}

	bytesUp   atomic.Int64
	bytesDown atomic.Int64
}

func newRegistry() *registry {
	return &registry{
		items:     make(map[string]*allocEntry),
		byRelay:   make(map[string]*allocEntry),
		authUsers: make(map[string]string),
	}
}

// allocKey 把五元组里能唯一定位一个分配的部分拼成键。
//
// pion 的分配是按 (srcAddr, dstAddr, protocol) 五元组索引的，
// 而 OnAllocationDeleted 只给这三样 —— 所以键必须只用它们，
// 不能掺入中继地址（删除回调里没有）。
func allocKey(srcAddr, dstAddr net.Addr, protocol string) string {
	return protocol + "|" + srcAddr.String() + "|" + dstAddr.String()
}

func (r *registry) onCreated(srcAddr, dstAddr net.Addr, protocol, userID, realm string,
	relayAddr net.Addr, _ int) {
	key := allocKey(srcAddr, dstAddr, protocol)

	r.mu.Lock()
	// 优先用 OnAuth 截下的完整用户名（含时间戳），否则退回 userID ——
	// 后者算不出凭据剩余有效期，但总比什么都不显示好。
	name := userID
	if full, ok := r.authUsers[key]; ok {
		name = full
	}
	e := &allocEntry{
		id:        key,
		username:  name,
		relayAddr: relayAddr.String(),
		createdAt: time.Now(),
		peers:     make(map[string]struct{}),
	}
	r.items[key] = e
	r.byRelay[relayAddr.String()] = e
	r.mu.Unlock()
}

// onAuth 在鉴权通过时截住完整的 TURN 用户名。
func (r *registry) onAuth(srcAddr, dstAddr net.Addr, protocol, username string) {
	key := allocKey(srcAddr, dstAddr, protocol)

	r.mu.Lock()
	defer r.mu.Unlock()

	// 分配已存在时直接更新它（Refresh / CreatePermission 也会走鉴权，
	// 那时用户名可能已经换成新签发的一对）。
	if e, ok := r.items[key]; ok {
		e.username = username
		return
	}

	if len(r.authUsers) >= maxPendingAuth {
		// 清掉没有对应分配的陈旧条目。只在撑满时做一次，
		// 所以这个 O(n) 不在热路径上。
		for k := range r.authUsers {
			if _, live := r.items[k]; !live {
				delete(r.authUsers, k)
			}
		}
	}
	r.authUsers[key] = username
}

func (r *registry) onDeleted(srcAddr, dstAddr net.Addr, protocol, _, _ string) {
	key := allocKey(srcAddr, dstAddr, protocol)
	r.mu.Lock()
	if e, ok := r.items[key]; ok {
		delete(r.byRelay, e.relayAddr)
		delete(r.items, key)
	}
	delete(r.authUsers, key)
	r.mu.Unlock()
}

func (r *registry) onPermission(srcAddr, dstAddr net.Addr, protocol string,
	peer net.IP, added bool) {
	key := allocKey(srcAddr, dstAddr, protocol)
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[key]
	if !ok {
		return
	}
	ip := unmapIP(peer)
	if added {
		e.peers[ip] = struct{}{}
	} else {
		delete(e.peers, ip)
	}
}

// lookupByRelay 找中继地址对应的分配，供计量记账。
func (r *registry) lookupByRelay(addr string) *allocEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byRelay[addr]
}

// list 返回分配快照，按创建时间排序。
//
// 排序不是装饰：不确定的顺序会让控制台列表每次刷新都跳动。
func (r *registry) list() []Allocation {
	r.mu.RLock()
	out := make([]Allocation, 0, len(r.items))
	for _, e := range r.items {
		ttl := 0
		if ts, _, ok := splitRESTUsername(e.username); ok {
			if d := time.Until(time.Unix(ts, 0)); d > 0 {
				ttl = int(d.Seconds())
			}
		}
		out = append(out, Allocation{
			ID:                   e.id,
			Username:             e.username,
			RelayedAddr:          e.relayAddr,
			PeerCount:            len(e.peers),
			BytesRelayed:         e.bytesUp.Load() + e.bytesDown.Load(),
			CredentialTTLSeconds: ttl,
			CreatedAt:            e.createdAt,
		})
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Allocations 返回当前分配明细，供控制台的「媒体中继」一屏使用。
func (s *Server) Allocations() []Allocation { return s.reg.list() }

// eventHandler 把 pion 的生命周期回调接到我们的分配表上。
func (s *Server) eventHandler() turn.EventHandler {
	return turn.EventHandler{
		OnAllocationCreated: s.reg.onCreated,
		OnAllocationDeleted: s.reg.onDeleted,
		OnPermissionCreated: func(srcAddr, dstAddr net.Addr, protocol, _, _ string,
			_ net.Addr, peer net.IP) {
			s.reg.onPermission(srcAddr, dstAddr, protocol, peer, true)
		},
		OnPermissionDeleted: func(srcAddr, dstAddr net.Addr, protocol, _, _ string,
			_ net.Addr, peer net.IP) {
			s.reg.onPermission(srcAddr, dstAddr, protocol, peer, false)
		},
		OnAuth: func(srcAddr, dstAddr net.Addr, protocol, username, _, method string,
			verdict bool) {
			if verdict {
				// 截住完整用户名 —— OnAllocationCreated 只给冒号后面那半，
				// 而凭据剩余有效期只能从前面的时间戳算。
				s.reg.onAuth(srcAddr, dstAddr, protocol, username)
				return
			}
			// 鉴权失败要记下来。反复失败意味着有人在猜凭据 ——
			// 而临时凭据的过期也会走到这里，所以只记日志不报警。
			s.stats.AuthFailed.Add(1)
			s.log.Info("TURN 鉴权失败",
				"来源", srcAddr.String(), "用户", username, "方法", method)
		},
		OnAllocationError: func(srcAddr, _ net.Addr, protocol, message string) {
			s.stats.AllocationErrors.Add(1)
			s.log.Warn("TURN 分配出错",
				"来源", srcAddr.String(), "协议", protocol, "详情", message)
		},
	}
}

// unmapIP 把 IPv4-in-IPv6 规范化，避免同一个对端被记成两个。
func unmapIP(ip net.IP) string {
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap().String()
	}
	return ip.String()
}
