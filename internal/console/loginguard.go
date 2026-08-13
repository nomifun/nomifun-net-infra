package console

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 未鉴权端点的登录限速。
//
// # 它关的是哪一半
//
// argon2 并发闸（internal/store）关的是**内存放大**：修它之前 120 个匿名请求
// 能把 RSS 推到 5.6 GiB。但闸只是把 argon2 串行化，攻击者仍然能以
// 「每次约 40ms、闸宽 2」的速度**无限次**地猜那把唯一的管理员口令 ——
// 全系统只有一个管理员、没有多因素、没有分权令牌，那把口令就是全部。
//
// 这道限速关的是次数。两者正交，缺一个都不够。
//
// # 为什么不读 X-Forwarded-For
//
// 数据面把 XFF/XFP 当作**不可配置的安全不变量**在剥（internal/gateway/headers.go
// 论证过：没有可信代理白名单时用请求头做安全决策是错的）。控制台再立一个
// 「信任这个请求头」的开关，仓库里就有了两个互相矛盾的信任锚 ——
// 而下一个人会拿松的那个去松动紧的那个。
//
// 代价是**反代形态下所有请求共用一个桶**（源 IP 都是反代）。这不是缺陷而是
// 正确的降级：那个形态下中继看到的确实只有一个客户端，而共用桶恰好把
// 「经反代来的总攻击速率」限住了。这一点如实记在 README。
//
// # 为什么没有独立的全局桶
//
// 全局桶能挡住「一千个 IP 各试一次」的分布式爆破，但它同时是一个**锁死管理员**
// 的开关：攻击者打满全局桶，管理员就连一次尝试都发不出去。而 per-IP 桶在两种
// 真实部署里都已经够：反代形态下它本来就是全局桶（见上）；直接暴露形态下
// 攻击者要换 IP 才能绕，而换 IP 的成本远高于换密码。
// 与其为一个更弱的威胁引入一个更强的自伤面，不如不做，并如实写进诚实清单。

const (
	// loginBurst 是一个源 IP 能连续尝试几次。
	//
	// 10 次：一个手打错口令的人极少连错 10 次，而**成功登录会把这个源 IP 的
	// 失败预算清零**（见 attempt.succeeded），所以正常使用永远碰不到这个上限。
	loginBurst = 10

	// loginRefill 是补一个令牌要多久。
	//
	// 30 秒 = 稳定 2 次/分钟。选它是在两件事之间折中：
	//   * 太松（比如 1 秒）挡不住字典攻击 —— 8 万次/天足够跑完常见口令表；
	//   * 太紧（比如 5 分钟）让管理员打错一次就等到怀疑服务坏了。
	// 最坏情况下管理员等 30 秒，而攻击者拿到 2880 次/天。
	// 配合 argon2id（m=64MiB）的单次成本，那个速率对任何有熵的口令都无意义。
	loginRefill = 30 * time.Second

	// loginMaxTracked 是最多跟踪几个源 IP。
	//
	// 键是**攻击者指定的**，所以这张表必须有硬上限 —— 中继是长期运行的进程，
	// 一个换着 IP 打的人否则能把它撑爆。满了之后新来的 IP 落进一个共享的
	// 溢出桶（见 limiterFor），那是刻意的：一个正在换 IP 打的攻击者被归成
	// 一伙处理，正好是我们想要的行为。
	loginMaxTracked = 4096

	// loginIdleEvict 是一个空闲条目多久后可被清掉。
	//
	// 只清「桶已经满」的条目：桶没满意味着这个 IP 还欠着惩罚，
	// 清掉它等于把惩罚一笔勾销 —— 那样攻击者只要等到清理就能重置配额。
	loginIdleEvict = 10 * time.Minute

	// loginThrottleDedup 是同一个 IP 的限速事件最小间隔。
	//
	// 与 runtime.go 的 deniedSeen 同一条理由：一次爆破会让**每一个**请求
	// 都被拒一次，不去重就是几秒钟上千条一模一样的事件，
	// 把真正有用的事件挤出可视范围。
	loginThrottleDedup = time.Minute
)

// loginGuard 是未鉴权端点的按源 IP 限速器。
type loginGuard struct {
	mu sync.Mutex
	// ips 按源 IP（IPv6 归并到 /64）索引。
	ips map[netip.Addr]*loginBucket
	// overflow 是表满之后所有新 IP 共用的桶。
	overflow *rate.Limiter
	// eventSeen 给限速事件去重，键同 ips。
	eventSeen map[netip.Addr]time.Time
}

type loginBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newLoginGuard() *loginGuard {
	return &loginGuard{
		ips:       make(map[netip.Addr]*loginBucket),
		overflow:  rate.NewLimiter(rate.Every(loginRefill), loginBurst),
		eventSeen: make(map[netip.Addr]time.Time),
	}
}

// clientKey 从请求里取限速键。
//
// 只用 RemoteAddr，不看任何请求头（理由见文件头）。IPv6 归并到 /64：
// 一个住宅 IPv6 用户手上通常有 2^64 个地址，按单地址限速等于没限。
func clientKey(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// 解析不出来（不该发生）时归进一个固定的零值键，
		// 也就是所有这类请求共用一个桶 —— 宁可过严，不要放行。
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return addr
}

// attempt 是一次已经扣掉令牌的尝试。
//
// 拿到它就意味着**令牌已经扣了**（进门即扣，不是「先查再扣」）。
// 先查再扣在并发下等于没限：N 个请求同时看到「还有额度」，然后 N 个一起扣。
type attempt struct {
	guard *loginGuard
	key   netip.Addr
	// shared 为 true 时这次尝试用的是溢出桶（跟踪表已满）。
	// 那个桶是许多陌生 IP 共用的，**绝不能**因为其中一个成功就整体清零。
	shared bool
}

// allow 为一次未鉴权尝试扣一个令牌。
//
// 第二个返回值是建议的 Retry-After 秒数，被拒时才有意义。
func (g *loginGuard) allow(r *http.Request) (*attempt, int) {
	key := clientKey(r)
	now := time.Now()

	g.mu.Lock()
	lim, shared := g.limiterFor(key, now)
	g.mu.Unlock()

	// 用 Allow 而不是 Reserve/Cancel。
	//
	// **x/time/rate 的 Reservation.Cancel 不能用来「事后退还」**：它的实现里
	// 有一句 `if r.timeToAct.Before(t) { return }` —— 也就是说预约一旦到期
	// 就不再退还任何令牌。而我们要退还的时机是 argon2 跑完之后（约 40ms），
	// 那时 timeToAct 早已过去，Cancel 是一次静默的空操作。
	//
	// 这不是推测：本文件的 TestSuccessfulLoginDoesNotSpendQuota 用
	// Reserve/Cancel 写过第一版，第 11 次成功登录就被 429 —— 也就是说
	// 一个每天登录十几次的运维会被自己的**正常使用**关在门外。
	if !lim.Allow() {
		// 没有可用令牌。把等待时间如实告诉客户端。
		//
		// 从桶的当前水位算，而不是回一个固定值：固定值要么偏大（让用户白等）、
		// 要么偏小（让他撞第二次 429 并以为服务坏了）。
		secs := int(loginRefill.Seconds() * (1 - lim.Tokens()))
		if secs < 1 {
			secs = 1
		}
		return nil, secs
	}
	return &attempt{guard: g, key: key, shared: shared}, 0
}

// succeeded 清掉这个源 IP 的失败预算。**只在尝试成功时调用。**
//
// # 为什么是「清零」而不是「退还一个」
//
// x/time/rate 没有加回令牌的接口，而事后 Cancel 是空操作（见 allow）。
// 剩下两条路：自己手写一个令牌桶，或者把「成功」当成清掉惩罚。选后者 ——
// 手写限速器的时钟与溢出处理是经典 bug 温床，而清零的语义本身也说得通：
// 一次成功的认证证明了这个源不是在盲猜。
//
// 攻击者利用不了它：能触发清零就意味着他已经有口令了，那时限速已无意义。
//
// # 已知的弱化，以及为什么可以接受
//
// 反代形态下所有请求共用一个键，于是管理员每成功登录一次，
// 与他同源的攻击者也拿到一份新的突发额度。代价量级：管理员一天登录 5 次
// = 攻击者多 50 次尝试，而基线本来就有 2880 次/天。可以忽略。
func (a *attempt) succeeded() {
	if a == nil || a.guard == nil || a.shared {
		return
	}
	a.guard.mu.Lock()
	defer a.guard.mu.Unlock()
	// 直接删掉条目：下一次来会建一个满桶的新条目。
	// 比「换一个新 limiter」少一次分配，效果相同。
	delete(a.guard.ips, a.key)
}

// limiterFor 取（或建）一个源 IP 的桶。调用方须持锁。
func (g *loginGuard) limiterFor(key netip.Addr, now time.Time) (lim *rate.Limiter, shared bool) {
	if b, ok := g.ips[key]; ok {
		b.seen = now
		return b.lim, false
	}
	if len(g.ips) >= loginMaxTracked {
		g.evictIdle(now)
	}
	if len(g.ips) >= loginMaxTracked {
		// 还是满的：所有新 IP 共用溢出桶。表的大小因此有硬上限，
		// 而一个换着 IP 打的攻击者被归成一伙 —— 正是想要的行为。
		return g.overflow, true
	}
	b := &loginBucket{lim: rate.NewLimiter(rate.Every(loginRefill), loginBurst), seen: now}
	g.ips[key] = b
	return b.lim, false
}

// evictIdle 清掉空闲且**没有欠惩罚**的条目。调用方须持锁。
func (g *loginGuard) evictIdle(now time.Time) {
	for k, b := range g.ips {
		if now.Sub(b.seen) < loginIdleEvict {
			continue
		}
		// 桶没满 = 这个 IP 还欠着惩罚。清掉它等于一笔勾销，
		// 那样攻击者只要等到清理就能重置自己的配额。
		if b.lim.Tokens() < float64(loginBurst) {
			continue
		}
		delete(g.ips, k)
	}
	for k, ts := range g.eventSeen {
		if now.Sub(ts) > 10*loginThrottleDedup {
			delete(g.eventSeen, k)
		}
	}
}

// shouldLogThrottle 报告这次限速要不要落一条事件（同 IP 一分钟一条）。
func (g *loginGuard) shouldLogThrottle(r *http.Request) bool {
	key := clientKey(r)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.eventSeen[key]; ok && now.Sub(last) < loginThrottleDedup {
		return false
	}
	g.eventSeen[key] = now
	return true
}

// writeThrottled 回 429 并给出 Retry-After。
//
// 429 而不是 401：这不是凭据错误。回 401 会让一个刚打错一次口令的运维
// 以为自己又错了，而真正的原因是「太频繁」——两者的下一步动作完全不同。
func writeThrottled(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, http.StatusTooManyRequests, "throttled",
		"尝试过于频繁，请等待 "+strconv.Itoa(retryAfter)+" 秒后重试。这不是密码错误。")
}
