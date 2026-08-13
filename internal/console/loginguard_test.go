package console

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// loginAs 发一次登录请求，可指定源 IP 与请求体。
func loginAs(t *testing.T, s *Server, remote, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Host = "127.0.0.1:9443"
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

const wrongCreds = `{"username":"ops","password":"definitely-wrong-x"}`

// TestBruteForceIsThrottledAfterTheBurst 是这道限速存在的全部理由。
//
// argon2 并发闸关的是内存放大（120 个匿名请求从 5.6 GiB 压到 350 MiB），
// 但闸只是把计算串行化 —— 攻击者仍然能以「每次约 40ms」的速度**无限次**
// 猜那把唯一的管理员口令。全系统只有一个管理员、没有多因素、没有分权令牌，
// 那把口令就是全部。
//
// 实测过修复前的行为：连打 8 次错口令，全部 401、耗时恒 ~42ms、零退避。
func TestBruteForceIsThrottledAfterTheBurst(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s) // 建管理员（它自己会占掉一个令牌又退还）

	const ip = "203.0.113.9:5555"
	var got401, got429 int
	for range loginBurst + 5 {
		w := loginAs(t, s, ip, wrongCreds)
		switch w.Code {
		case http.StatusUnauthorized:
			got401++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("意外状态码 %d：%s", w.Code, w.Body.String())
		}
	}
	if got429 == 0 {
		t.Fatalf("连打 %d 次错口令一次都没被限速（%d 个 401）—— "+
			"那把唯一的管理员口令面对无限次在线爆破", loginBurst+5, got401)
	}
	if got401 == 0 {
		t.Fatal("一次都没放行 —— 突发额度应当让手打错口令的人有几次机会")
	}
	if got401 > loginBurst+1 {
		t.Errorf("放行了 %d 次，超过突发额度 %d", got401, loginBurst)
	}
}

// TestThrottledResponseIsNotMistakenForABadPassword 钉住状态码与文案。
//
// 回 401 会让一个刚打错一次口令的运维以为自己又错了，而真正的原因是「太频繁」
// —— 两者的下一步动作完全不同（换密码 vs 等一会儿）。
func TestThrottledResponseIsNotMistakenForABadPassword(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	const ip = "203.0.113.10:5555"
	var throttled *httptest.ResponseRecorder
	for range loginBurst + 3 {
		if w := loginAs(t, s, ip, wrongCreds); w.Code == http.StatusTooManyRequests {
			throttled = w
			break
		}
	}
	if throttled == nil {
		t.Fatal("没能触发限速，本测试没测到目标")
	}

	ra := throttled.Header().Get("Retry-After")
	secs, err := strconv.Atoi(ra)
	if err != nil || secs < 1 {
		t.Errorf("Retry-After = %q，必须是一个 >=1 的秒数 —— 客户端要靠它决定等多久", ra)
	}
	if secs > int(loginRefill.Seconds())+1 {
		t.Errorf("Retry-After = %d 秒，超过补一个令牌所需的 %v", secs, loginRefill)
	}
	body := throttled.Body.String()
	if !strings.Contains(body, "throttled") {
		t.Errorf("响应里要有稳定的 code 供客户端分支：%s", body)
	}
	if !strings.Contains(body, "不是密码错误") {
		t.Errorf("必须说清这不是密码错误，否则用户会去改密码（查错方向）：%s", body)
	}
}

// TestSuccessfulLoginDoesNotSpendQuota 钉住「进门即扣、成功清零」。
//
// 不清的话，一个每天登录几十次的运维会被自己的**正常使用**逐步耗尽配额，
// 然后在某个再普通不过的早上被自己的防护关在门外。限速的目标是失败的尝试。
//
// 这条测试的第一版就抓出了一个真 bug：实现用 x/time/rate 的
// Reserve/Cancel 做「事后退还」，而 Cancel 在预约到期后是**静默空操作**
// （`if r.timeToAct.Before(t) { return }`）—— 第 11 次成功登录就被 429。
func TestSuccessfulLoginDoesNotSpendQuota(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)
	good := `{"username":"admin","password":"a-very-long-password"}`

	const ip = "203.0.113.11:5555"
	// 成功登录的次数远超突发额度。一次都不该被限。
	for i := range loginBurst * 3 {
		w := loginAs(t, s, ip, good)
		if w.Code != http.StatusOK {
			t.Fatalf("第 %d 次成功登录被拒（%d）：%s —— 成功的尝试不该占配额",
				i+1, w.Code, w.Body.String())
		}
	}
}

// TestThrottlingHappensBeforeParsingTheBody 钉住闸的位置。
//
// 一个正在爆破的人不该让我们先做任何工作。若限速排在解析之后，
// 攻击者可以用畸形请求体让我们一直做 JSON 解析 + 分配，
// 而那些请求连令牌都不扣（走的是 400 分支）。
func TestThrottlingHappensBeforeParsingTheBody(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	const ip = "203.0.113.12:5555"
	// 先用畸形请求体把额度打光 —— 它们必须**也**扣令牌。
	var got400 int
	for range loginBurst + 5 {
		w := loginAs(t, s, ip, "这不是 JSON")
		switch w.Code {
		case http.StatusBadRequest:
			got400++
		case http.StatusTooManyRequests:
			// 到达限速：说明畸形请求体也扣了令牌，正是要验的。
			return
		default:
			t.Fatalf("意外状态码 %d", w.Code)
		}
	}
	t.Fatalf("畸形请求体发了 %d 次全是 400，一次都没被限速 —— "+
		"限速排在了解析之后，攻击者可以用坏请求体免费驱动工作", got400)
}

// TestDifferentSourceIPsHaveIndependentBudgets 钉住 per-IP 语义。
//
// 一个被打满的 IP 不该把别人一起锁死 —— 否则攻击者只要打满一次，
// 就能让所有管理员都登不进来（那是用防护制造的拒绝服务）。
func TestDifferentSourceIPsHaveIndependentBudgets(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	// 打满第一个 IP。
	for range loginBurst + 3 {
		loginAs(t, s, "203.0.113.20:1", wrongCreds)
	}
	if w := loginAs(t, s, "203.0.113.20:1", wrongCreds); w.Code != http.StatusTooManyRequests {
		t.Fatalf("前置不成立：第一个 IP 应当已被限速，实际 %d", w.Code)
	}
	// 另一个 IP 必须还能试。
	if w := loginAs(t, s, "198.51.100.7:1", wrongCreds); w.Code != http.StatusUnauthorized {
		t.Errorf("另一个源 IP 被牵连了（%d）—— per-IP 桶失效，"+
			"攻击者打满一次就能把所有人锁在门外", w.Code)
	}
}

// TestIPv6IsGroupedByPrefix 钉住 /64 归并。
//
// 一个住宅 IPv6 用户手上通常有 2^64 个地址。按单地址限速等于没限 ——
// 攻击者每次换一个末位就能拿到一份新配额。
func TestIPv6IsGroupedByPrefix(t *testing.T) {
	s, _ := newTestServer(t)
	setupAndLogin(t, s)

	// 同一个 /64 里换着地址打。
	for i := range loginBurst + 5 {
		addr := "[2001:db8:1:2::" + strconv.Itoa(i+1) + "]:5555"
		if w := loginAs(t, s, addr, wrongCreds); w.Code == http.StatusTooManyRequests {
			// 被限住了 —— 说明 /64 内共用一个桶，正是要验的。
			// 顺带确认**另一个** /64 不受影响。
			other := loginAs(t, s, "[2001:db8:9:9::1]:5555", wrongCreds)
			if other.Code == http.StatusTooManyRequests {
				t.Error("另一个 /64 也被限了 —— 归并得太宽")
			}
			return
		}
	}
	t.Fatalf("在同一个 /64 里换了 %d 个地址都没被限速 —— "+
		"按单地址限速等于没限（一个住宅用户手上有 2^64 个地址）", loginBurst+5)
}

// TestClientKeyGroupsAndNormalises 直接测键的推导。
//
// 走 HTTP 测不到边界形态（畸形 RemoteAddr、IPv4-in-IPv6）。
func TestClientKeyGroupsAndNormalises(t *testing.T) {
	key := func(remote string) netip.Addr {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		r.RemoteAddr = remote
		return clientKey(r)
	}

	// 同一个 /64 → 同一个键。
	a := key("[2001:db8:1:2::1]:1")
	b := key("[2001:db8:1:2:ffff:ffff:ffff:ffff]:2")
	if a != b {
		t.Errorf("同一个 /64 应当归成一个键：%v vs %v", a, b)
	}
	// 不同 /64 → 不同键。
	if c := key("[2001:db8:1:3::1]:1"); c == a {
		t.Errorf("不同 /64 不该归成一个键：%v", c)
	}
	// IPv4-in-IPv6 必须与裸 IPv4 归成同一个键，否则攻击者靠改写形式
	// 就能拿到第二份配额。
	if x, y := key("203.0.113.5:1"), key("[::ffff:203.0.113.5]:1"); x != y {
		t.Errorf("IPv4-in-IPv6 应当与裸 IPv4 同键：%v vs %v", x, y)
	}
	// 畸形地址不能 panic，且必须归到同一个（过严的）键。
	if p, q := key("garbage"), key(""); p != q {
		t.Errorf("解析不出来的地址应当共用一个键（宁可过严）：%v vs %v", p, q)
	}
}

// TestTrackedIPTableIsBounded 钉住这张表的硬上限。
//
// 键是**攻击者指定的**，而中继是长期运行的进程。没有上限的话一个换着 IP 打的人
// 能把它撑爆 —— 那是用限速器本身做的内存耗尽攻击。
func TestTrackedIPTableIsBounded(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()

	g.mu.Lock()
	for i := range loginMaxTracked + 500 {
		// 造出一堆互不相同的 /64。
		addr := netip.MustParseAddr("2001:db8::").As16()
		addr[4] = byte(i >> 16)
		addr[5] = byte(i >> 8)
		addr[6] = byte(i)
		g.limiterFor(netip.AddrFrom16(addr), now)
	}
	n := len(g.ips)
	g.mu.Unlock()

	if n > loginMaxTracked {
		t.Fatalf("跟踪表有 %d 条，超过上限 %d —— 键由攻击者指定，"+
			"没有上限就是一个可被外部驱动的内存耗尽面", n, loginMaxTracked)
	}
	if n < loginMaxTracked/2 {
		t.Errorf("只跟踪了 %d 条，远低于上限 —— 太早退化成共享桶会让"+
			"正常用户被陌生人牵连", n)
	}
}

// TestIdleEvictionDoesNotForgiveAnOutstandingPenalty 钉住清理的判据。
//
// 只清「桶已经满」的条目。清掉一个还欠着惩罚的条目等于把惩罚一笔勾销 ——
// 那样攻击者只要等到下一次清理就能重置自己的配额，限速形同虚设。
func TestIdleEvictionDoesNotForgiveAnOutstandingPenalty(t *testing.T) {
	g := newLoginGuard()
	guilty := netip.MustParseAddr("203.0.113.66")
	innocent := netip.MustParseAddr("198.51.100.66")
	now := time.Now()

	g.mu.Lock()
	// 有罪的那个把令牌花光。
	lim, _ := g.limiterFor(guilty, now)
	for range loginBurst {
		lim.Allow()
	}
	// 清白的那个只是来过一次，桶还是满的。
	g.limiterFor(innocent, now)
	// 两个都标成很久没活动。
	for _, b := range g.ips {
		b.seen = now.Add(-2 * loginIdleEvict)
	}
	g.evictIdle(now)
	_, guiltyKept := g.ips[guilty]
	_, innocentKept := g.ips[innocent]
	g.mu.Unlock()

	if !guiltyKept {
		t.Error("欠着惩罚的条目被清掉了 —— 攻击者等到清理就能重置配额")
	}
	if innocentKept {
		t.Error("桶已满且空闲的条目应当被清掉，否则表只增不减")
	}
}

// TestThrottleEventsAreDeduplicated 钉住事件去重。
//
// 一次爆破会让**每一个**请求都被拒一次。不去重的话几秒钟就能写上千条
// 一模一样的事件，把真正有用的事件挤出可视范围 —— 事件流的价值在于信噪比。
func TestThrottleEventsAreDeduplicated(t *testing.T) {
	g := newLoginGuard()
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "203.0.113.77:1"

	if !g.shouldLogThrottle(r) {
		t.Fatal("第一次应当记事件")
	}
	for i := range 50 {
		if g.shouldLogThrottle(r) {
			t.Fatalf("窗口内第 %d 次又记了一条 —— 一次爆破会把事件表刷成噪音", i+2)
		}
	}
	// 另一个 IP 是另一条线索，必须各自记一条。
	r2 := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r2.RemoteAddr = "198.51.100.77:1"
	if !g.shouldLogThrottle(r2) {
		t.Error("不同源 IP 应当各自记一条 —— 它们是不同的线索")
	}
}
