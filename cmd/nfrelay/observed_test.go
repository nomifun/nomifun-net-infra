package main

import (
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// TestLearnedPrefixesAreGroupedTheWayWhitelistsCanUse 钉住归一规则。
//
// 学习模式的产物会被直接写进 allow_cidrs，所以「记成什么粒度」决定了
// 收窄之后谁还连得上。两个方向都会出错：
//
//   - 太细（IPv6 用 /128）：住宅客户端按 SLAAC 隐私扩展每天换地址
//     （Windows 与 Android 默认），白名单在几小时内就把同一个用户锁在门外，
//     而现象是「昨天还能用」—— 一种没人会怀疑到白名单的失效。
//   - 太粗（IPv4 用 /24）：把邻居整段一起放行，收窄变成了摆设。
func TestLearnedPrefixesAreGroupedTheWayWhitelistsCanUse(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.7", "203.0.113.7/32", true},
		{"2001:db8:1:2:dead:beef:1:2", "2001:db8:1:2::/64", true},
		// IPv4-in-IPv6 必须与裸 IPv4 归成同一条，否则同一个客户端换个
		// 表示形式就会在列表里出现两行，运维会以为是两个人。
		{"::ffff:203.0.113.7", "203.0.113.7/32", true},
		// 回环**要记**。第一版滤掉了它，理由是「那不是外部客户端」——
		// 而 allow_cidrs 里有 127.0.0.1/32 之后所有非回环来源都会被拒，
		// 那是可能的最强约束，不是「没有约束」。滤掉它还会让本机部署与
		// 开发环境下这个功能永远是空的，而看到空列表的人会以为它坏了。
		{"127.0.0.1", "127.0.0.1/32", true},
		{"::1", "::/64", true},
		// 链路本地同样要记：fe80::/10 是局域网客户端的真实来源。
		{"fe80::1", "fe80::/64", true},
		// 未指定地址不是任何真实对端的地址；出现它只说明上游解析出了问题。
		{"0.0.0.0", "", false},
		{"::", "", false},
	}
	for _, c := range cases {
		got, ok := learnPrefix(netip.MustParseAddr(c.in))
		if ok != c.ok {
			t.Errorf("learnPrefix(%s) 的 ok = %v，期望 %v", c.in, ok, c.ok)
			continue
		}
		if ok && got.String() != c.want {
			t.Errorf("learnPrefix(%s) = %s，期望 %s", c.in, got, c.want)
		}
	}
}

// TestHitsDistinguishARealClientFromAScanner 钉住命中计数与时间戳。
//
// 学习窗口里（allow_cidrs 为空、放行一切）扫描器与真客户端的地址是混在
// 一起的，机器分不开。运维分得开 —— 靠的正是「这个地址来过 1 次还是 900 次」
// 与「首见/末见相隔多久」。这两项若不对，那个面板就只是一张无从判断的地址表。
func TestHitsDistinguishARealClientFromAScanner(t *testing.T) {
	o := newObservedSources()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	o.nowForTest = func() time.Time { return now }

	client := netip.MustParseAddr("203.0.113.10")
	scanner := netip.MustParseAddr("198.51.100.66")

	o.note("t1", scanner) // 扫描器只来过一次
	for range 5 {
		now = now.Add(time.Minute)
		o.note("t1", client)
	}

	got, ok := o.ObservedSources("t1")
	if !ok {
		t.Fatal("没有记录 —— 观测点没生效")
	}
	if len(got.Sources) != 2 {
		t.Fatalf("记了 %d 条，期望 2 条：%+v", len(got.Sources), got.Sources)
	}
	// 排序必须把常来的放前面：面板默认勾选靠前的几条。
	if got.Sources[0].CIDR != "203.0.113.10/32" {
		t.Errorf("命中最多的应当排第一，实际第一是 %s", got.Sources[0].CIDR)
	}
	if got.Sources[0].Hits != 5 {
		t.Errorf("命中次数 = %d，期望 5", got.Sources[0].Hits)
	}
	if got.Sources[1].Hits != 1 {
		t.Errorf("扫描器的命中次数 = %d，期望 1", got.Sources[1].Hits)
	}
	// 首见与末见必须真的不同，否则「来过多久」这个判断没有依据。
	first, last := got.Sources[0].FirstSeen, got.Sources[0].LastSeen
	if !last.After(first) {
		t.Errorf("末见 %v 没有晚于首见 %v —— 时间戳没在更新", last, first)
	}
	if got.ObservedFrom.IsZero() {
		t.Error("observed_from 是零值 —— 界面无法说明「这份列表攒了多久」，" +
			"而一份只攒了五分钟的列表会被当成完整的")
	}
}

// TestTruncationIsVisibleBecauseAnIncompleteListLocksPeopleOut 是这个功能
// 最要紧的一条测试。
//
// 键是来源 IP，由任何能连上来的人指定 —— 所以必须有上限。但这里比
// loginguard 与 udpflow 多一个要求：**截断必须能被看见**。
//
// 一份被截断过的列表拿去「一键收窄」，写出的是一个不完整的白名单，
// 把没上榜的真实客户端全部锁死。现象是「我点了一下推荐按钮，
// 然后一半客户端连不上了」—— 而如果 truncated 不上报，界面会把那份
// 残缺列表渲染成一条自信的推荐。
func TestTruncationIsVisibleBecauseAnIncompleteListLocksPeopleOut(t *testing.T) {
	o := newObservedSources()

	// 灌满，再多灌 100 个。
	for i := range learnMaxPerTunnel + 100 {
		a := netip.MustParseAddr("2001:db8::").As16()
		a[4] = byte(i >> 16)
		a[5] = byte(i >> 8)
		a[6] = byte(i)
		o.note("t1", netip.AddrFrom16(a))
	}

	got, _ := o.ObservedSources("t1")
	if len(got.Sources) > learnMaxPerTunnel {
		t.Fatalf("记了 %d 条，超过上限 %d —— 键由外部指定，"+
			"没有上限就是一个可被驱动的内存耗尽面", len(got.Sources), learnMaxPerTunnel)
	}
	if !got.Truncated {
		t.Fatal("列表被上限截断了却没有上报 truncated —— " +
			"界面会把一份残缺的列表渲染成一条自信的推荐，" +
			"运维一键应用之后没上榜的客户端全部失联")
	}

	// truncated 一旦为真就不该翻回假：被挤掉的那个客户端已经不在列表里了，
	// 后来腾出空位并不能让这件事变得无害。
	o.note("t1", netip.MustParseAddr("203.0.113.1"))
	if again, _ := o.ObservedSources("t1"); !again.Truncated {
		t.Error("truncated 翻回了假 —— 那会让一份仍然残缺的列表重新变成推荐")
	}
}

// TestEarlyObservationsSurviveAScanFlood 钉住「到顶时拒新，而不是挤掉最旧」。
//
// 反过来做的话，一次端口扫描会把运维真正在找的那几个早期客户端全部冲走，
// 而列表看起来还是满的 —— 那比截断更坏：它是一份**看不出问题**的错列表。
func TestEarlyObservationsSurviveAScanFlood(t *testing.T) {
	o := newObservedSources()

	real1 := netip.MustParseAddr("203.0.113.10")
	o.note("t1", real1)

	// 一次扫描：灌满剩下的位置再溢出。
	for i := range learnMaxPerTunnel + 50 {
		a := netip.MustParseAddr("2001:db8::").As16()
		a[4], a[5], a[6] = byte(i>>16), byte(i>>8), byte(i)
		o.note("t1", netip.AddrFrom16(a))
	}

	got, _ := o.ObservedSources("t1")
	for _, s := range got.Sources {
		if s.CIDR == "203.0.113.10/32" {
			return // 早期观测还在，正是要验的
		}
	}
	t.Fatal("一次扫描把最早观测到的真实客户端冲掉了 —— " +
		"列表看起来还是满的，但里面全是扫描器，而运维无从察觉")
}

// TestTrackedTunnelsAreBounded 钉住隧道维度的上限。
func TestTrackedTunnelsAreBounded(t *testing.T) {
	o := newObservedSources()
	for i := range learnMaxTunnels + 200 {
		o.note("tunnel-"+strconv.Itoa(i), netip.MustParseAddr("203.0.113.9"))
	}
	o.mu.Lock()
	n := len(o.tunnels)
	o.mu.Unlock()
	if n > learnMaxTunnels {
		t.Fatalf("跟踪了 %d 条隧道，超过上限 %d", n, learnMaxTunnels)
	}
}

// TestRetainDropsObservationsForDeletedTunnels 钉住清理。
//
// 不清的话，被删掉隧道的第三方地址会一直驻留在内存里，
// 而且**没有任何界面能看到它们**（隧道已经不在了）——
// 一份看不见、删不掉、还在增长的第三方地址集合。
func TestRetainDropsObservationsForDeletedTunnels(t *testing.T) {
	o := newObservedSources()
	o.note("keep", netip.MustParseAddr("203.0.113.1"))
	o.note("gone", netip.MustParseAddr("203.0.113.2"))

	o.retain(map[string]bool{"keep": true})

	if _, ok := o.ObservedSources("keep"); !ok {
		t.Error("仍然存在的隧道的观测被清掉了")
	}
	if _, ok := o.ObservedSources("gone"); ok {
		t.Error("已删隧道的观测没被清掉 —— 第三方地址会无限期驻留且不可见")
	}
}

// TestDeclineIsRememberedWithoutInventingObservations 钉住「拒绝」的语义。
//
// 拒绝一条还没有任何观测的隧道不该凭空造出一份记录，
// 但那个标记必须记住 —— 否则界面每次刷新都会重新弹同一条提示。
func TestDeclineIsRememberedWithoutInventingObservations(t *testing.T) {
	o := newObservedSources()
	o.DeclineLearnedSources("t1")

	got, ok := o.ObservedSources("t1")
	if !ok {
		t.Fatal("拒绝之后应当有一条记录来承载 declined 标记")
	}
	if !got.Declined {
		t.Error("declined 没记住 —— 界面会一直重复弹同一条提示")
	}
	if len(got.Sources) != 0 {
		t.Errorf("凭空造出了 %d 条观测：%+v", len(got.Sources), got.Sources)
	}
}
