package relay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func TestTCPPerSourceIPQuotaIsEnforced(t *testing.T) {
	// TCP 侧原本**压根没有**每源 IP 限制，只有一个全局信号量。
	// 于是一个源 IP 就能把它占满并把别人挤出去 —— 而「最多 N 路」这个配置
	// 在用户看来是保护，实际保护的是中继不被压垮，不是保护其他用户。
	//
	// UDP 侧本来就有每源配额（udpflow 的 PerSourceIP），TCP 侧没有。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.Policy = &tunnel.Policy{MaxConns: 16, MaxConnsPerIP: 2}

	// 必须绑一个**活着但不应答**的会话，让 handle 卡在等 StreamOK 上。
	//
	// 不绑会话的话 handle 会立刻以 NoSession 返回、顺手归还配额 ——
	// 于是第三条连接能进，而测试看起来像「配额没生效」。
	// 我第一版就是那样，测的其实是「handle 有多快返回」。
	car := newPipeCarrier()
	t.Cleanup(func() { _ = car.CloseWithError(0, "测试结束") })
	lookup := newStubLookup()
	lookup.bind("agent-1", &Session{
		AgentID: "agent-1", Carrier: car, ConnectedAt: time.Now(),
	})
	lookup.put(tun)

	el, err := NewEntryListener("127.0.0.1:0", tun, lookup, EntryOptions{
		Log: quietLogger(t),
		// 够长到让配额在「第三条被拒」这个断言期间稳定被占住，
		// 又够短到让「handle 结束后归还」能在测试预算内被观察到。
		SetupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = el.Serve(ctx) }()

	addr := el.Addr().String()
	// 开三条：前两条应当被接住（配额 2），第三条必须被拒。
	var live []net.Conn
	defer func() {
		for _, c := range live {
			c.Close()
		}
	}()
	for range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		live = append(live, c)
	}
	// 等两条都真的进了 handle（占住配额）。
	waitFor(t, func() bool { return el.Stats().Accepted.Load() == 0 && inUse(el) == 2 },
		"头两条应当各占一个配额位")

	// 第三条：TCP 的 accept 会成功（内核已完成握手），但中继必须立刻关掉它。
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	waitFor(t, func() bool { return el.Stats().PerIPQuota.Load() >= 1 },
		"超过每源 IP 配额的连接必须被拒并计数")

	// 必须记在 PerIPQuota 而不是 RateLimited：前者是「某个 IP 自己的份额满了」
	// （要么它在滥用，要么配额配小了），后者是「入口的全局并发满了」
	// （要加 max_conns）。两者的处置方向相反。
	if got := el.Stats().RateLimited.Load(); got != 0 {
		t.Errorf("不该记成全局限速，实际 %d —— 合成一个数字会让「有人在刷」"+
			"看起来像「容量不够」", got)
	}

	// handle 结束（这里是等 StreamOK 超时）之后配额位必须归还。
	//
	// 不归还的话这条隧道会缓慢饿死：每条结束的连接永久吃掉一个位，
	// 直到这个 IP 再也连不进来 —— 而计数器上只会看到 PerIPQuota 在涨，
	// 看起来像「有人在刷」。
	waitFor(t, func() bool { return inUse(el) == 0 }, "handle 结束后配额位必须全部归还")
}

// inUse 是当前占用的配额位总数。
func inUse(el *EntryListener) int {
	el.perIPMu.Lock()
	defer el.perIPMu.Unlock()
	n := 0
	for _, v := range el.perIP {
		n += v
	}
	return n
}

func TestPerSourceIPQuotaIsClampedToTheGlobalCap(t *testing.T) {
	// 每源配额大于全局上限时它永远不会触发 —— 而一个永远不触发的闸门
	// 比没有闸门更糟：用户以为自己配了保护。
	// （udpflow 那边犯过同一个错：max_conns=32 让 256 的每源配额失效。）
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.Policy = &tunnel.Policy{MaxConns: 4, MaxConnsPerIP: 100}

	el, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(),
		EntryOptions{Log: quietLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()

	if el.maxPerIP != 4 {
		t.Fatalf("每源配额应当被收敛到全局上限 4，实际 %d", el.maxPerIP)
	}
}

func TestPerIPTableDoesNotGrowWithoutBound(t *testing.T) {
	// 表的键是**源 IP**，由任何能连上来的人指定。计数归零时必须 delete
	// 而不是留一个 0 —— 不删就是一个可被外部驱动的无界增长，
	// 而中继是长期运行的进程。这个错本仓库在别处犯过（ACME 的预算表）。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.Policy = &tunnel.Policy{MaxConns: 64, MaxConnsPerIP: 8}

	el, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(),
		EntryOptions{Log: quietLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()

	for i := range 200 {
		ip := netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i%256))
		if !el.acquirePerIP(ip) {
			t.Fatalf("第 %d 个不该被拒", i)
		}
		el.releasePerIP(ip)
	}

	el.perIPMu.Lock()
	n := len(el.perIP)
	el.perIPMu.Unlock()
	if n != 0 {
		t.Fatalf("归零的条目必须被删掉，还剩 %d 条 —— 键由外部指定，"+
			"留着 0 就是可被外部驱动的无界增长", n)
	}
}

func TestPerIPQuotaNormalizesIPv4InIPv6(t *testing.T) {
	// ::ffff:203.0.113.9 与 203.0.113.9 是同一个来源。
	// 不归一化的话同一个客户端能拿到两份配额。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.Policy = &tunnel.Policy{MaxConns: 64, MaxConnsPerIP: 1}

	el, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(),
		EntryOptions{Log: quietLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()

	// **必须经过 sourceIP()**，那才是归一化发生的地方。
	//
	// 我第一版在测试里自己先 Unmap 再调 acquirePerIP —— 那绕开了被测的那个点，
	// 于是「去掉 Unmap」这个变异是绿的。测试要走真实的入口。
	plain, ok := sourceIP(fakeConn{remote: "203.0.113.9:1000"})
	if !ok {
		t.Fatal("解析 IPv4 源地址失败")
	}
	mapped, ok := sourceIP(fakeConn{remote: "[::ffff:203.0.113.9]:1001"})
	if !ok {
		t.Fatal("解析 IPv4-in-IPv6 源地址失败")
	}
	if plain != mapped {
		t.Fatalf("::ffff:203.0.113.9 与 203.0.113.9 是同一个来源，"+
			"归一化后必须相等：%v vs %v", plain, mapped)
	}

	if !el.acquirePerIP(plain) {
		t.Fatal("第一条不该被拒")
	}
	if el.acquirePerIP(mapped) {
		t.Fatal("同一个来源的第二条应当被配额拒掉（每源上限 1）")
	}
}

// fakeConn 只为让 sourceIP 有一个 RemoteAddr 可读。
type fakeConn struct {
	net.Conn
	remote string
}

func (c fakeConn) RemoteAddr() net.Addr { return fakeAddr(c.remote) }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func TestSessionEventsAreEmittedForOpenAndClose(t *testing.T) {
	// 会话网格在这之前是**空壳**：console.EventSession 常量在、前端有网格与
	// LiveSession 类型、SessionFrame 契约也在，而中继**一帧都不发**。
	// 界面因此为空并如实标注「只显示本页打开后观测到的会话」。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")

	// **必须用会应答 StreamOK 的假 agent**：开启帧发在 Accepted 之后，
	// 而 Accepted 在开流成功之后。用一个不应答的 agent 的话 handle 在那之前
	// 就 return 了，测试看起来像「一帧都没发」。
	//
	// 会话的语义本来就是「开流成功」—— 一次开流失败不是一个会话，
	// 那时该出现的是 open_failed 计数而不是网格里的一行。
	backend := echoBackend(t)
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", backend)
	})
	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))
	lookup.put(tun)

	var mu sync.Mutex
	var got []SessionEvent
	el, err := NewEntryListener("127.0.0.1:0", tun, lookup, EntryOptions{
		Log:          quietLogger(t),
		SetupTimeout: 2 * time.Second,
		OnSession: func(ev SessionEvent) bool {
			mu.Lock()
			got = append(got, ev)
			mu.Unlock()
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = el.Serve(ctx) }()

	c, err := net.Dial("tcp", el.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	snapshot := func() []SessionEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]SessionEvent(nil), got...)
	}

	// 开一帧。
	waitFor(t, func() bool { return len(snapshot()) >= 1 }, "应当推一帧会话开启")
	open := snapshot()[0]
	if open.Delta != 1 {
		t.Errorf("开启帧的 delta 应为 +1，实际 %d", open.Delta)
	}
	if open.Active != 1 {
		t.Errorf("开启时活跃数应为 1，实际 %d", open.Active)
	}
	if open.Total != 1 {
		t.Errorf("累计数应为 1，实际 %d —— 两个数字都要带上，"+
			"前端自己累加会在丢帧后永久偏移", open.Total)
	}
	if open.Peer == "" {
		t.Error("必须带真实客户端地址 —— 会话网格的全部价值就在这一列")
	}
	if open.Path != "relayed" {
		t.Errorf("v1 恒为 relayed（P2P 是非目标），实际 %q", open.Path)
	}

	// 关掉客户端连接 → 拷贝循环结束 → handle 返回 → 关闭帧。
	c.Close()

	// handle 结束之后必须有关闭帧。
	waitFor(t, func() bool {
		for _, e := range snapshot() {
			if e.Delta == -1 {
				return true
			}
		}
		return false
	}, "会话结束时必须推一帧关闭 —— 只发 open 不发 close 会留下一条永不消失的行")

	for _, e := range snapshot() {
		if e.Delta == -1 && e.Active != 0 {
			t.Errorf("关闭后活跃数应为 0，实际 %d", e.Active)
		}
	}
}

func TestSessionOpenEventsAreThrottledButClosesAreNot(t *testing.T) {
	// 这个事件的速率由**外部输入**（用户连接）决定。一次端口扫描会产生几千次
	// 开/关，而控制台的事件队列是共享且有界的 —— 冲垮它意味着把 1Hz 的权威
	// 快照挤掉，那时界面停在旧数据上，而用户看到的是
	// 「一个正在被扫的中继看起来风平浪静」。
	//
	// 而关闭帧**不能**限流：它的总量已经被已发出的开启帧封顶，
	// 而丢一个关闭帧的代价是界面上一条永不消失的幽灵行。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	el, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(), EntryOptions{
		Log:       quietLogger(t),
		OnSession: func(SessionEvent) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()

	// 直接打 announceSession，避免依赖真实连接的时序。
	var opened int
	for range sessionEventBurst * 3 {
		if el.announceSession(1, "203.0.113.9:1", 1, true) {
			opened++
		}
	}
	if opened > sessionEventBurst {
		t.Fatalf("开启帧应当被限流到 %d 帧/秒，实际发出 %d 帧 —— "+
			"一次端口扫描会把控制台的共享队列冲垮，把权威快照挤掉",
			sessionEventBurst, opened)
	}
	if opened == 0 {
		t.Fatal("限流不该把正常流量也挡掉")
	}

	// 关闭帧不过桶：桶已经空了，它仍然必须发出去。
	for range 5 {
		if !el.announceSession(-1, "203.0.113.9:1", 0, false) {
			t.Fatal("关闭帧不该被限流 —— 丢一个就是界面上一条永不消失的行")
		}
	}
}

func TestSessionSinkNilIsSafe(t *testing.T) {
	// OnSession 可以为 nil（e2e 与单元测试里大多不装）。
	// 那时 announceSession 必须返回 false 而不是 panic —— 而返回 false
	// 也让 handle 的 defer 不去发一个没有配对 open 的 close。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	el, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(),
		EntryOptions{Log: quietLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()
	if el.announceSession(1, "203.0.113.9:1", 1, true) {
		t.Fatal("没有装 sink 时不该报告「发出去了」")
	}
}

func TestEveryAnnouncedOpenGetsAMatchingClose(t *testing.T) {
	// 这是会话网格唯一真正重要的不变量：**每个发出的 open 都必须有配对的
	// close**。缺一个就是界面上一条永不消失的幽灵行，而它不会自愈 ——
	// 用户只能刷新页面，而刷新会清掉全部网格。
	//
	// 关闭帧因此**不能**过限流桶：桶已经被开启帧消耗掉了，
	// 而关闭帧的总量本来就被已发出的开启帧封顶。
	//
	// 单独测 announceSession 抓不住这一点（那绕开了 handle 的配对逻辑），
	// 所以这条走完整路径，并**先把桶耗干**。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	backend := echoBackend(t)
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", backend)
	})
	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))
	lookup.put(tun)

	var mu sync.Mutex
	opens, closes := 0, 0
	el, err := NewEntryListener("127.0.0.1:0", tun, lookup, EntryOptions{
		Log:          quietLogger(t),
		SetupTimeout: 2 * time.Second,
		OnSession: func(ev SessionEvent) bool {
			mu.Lock()
			if ev.Delta > 0 {
				opens++
			} else {
				closes++
			}
			mu.Unlock()
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = el.Serve(ctx) }()

	// 开**超过桶深**的连接：一部分开启帧会被限流丢掉，那是设计如此。
	addr := el.Addr().String()
	conns := make([]net.Conn, 0, sessionEventBurst*2)
	for range sessionEventBurst * 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return opens > 0
	}, "至少要发出一些开启帧")

	// 全部关掉。
	for _, c := range conns {
		c.Close()
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return closes >= opens
	}, "每个发出的开启帧都必须有配对的关闭帧 —— "+
		"缺一个就是界面上一条永不消失的幽灵行，而它不会自愈")

	mu.Lock()
	o, c := opens, closes
	mu.Unlock()
	if c != o {
		t.Fatalf("开启 %d 帧、关闭 %d 帧 —— 必须严格配对（多发关闭帧会去删"+
			"一条从没加过的行，虽然无害，但说明配对逻辑写错了）", o, c)
	}
	if o >= sessionEventBurst*2 {
		t.Errorf("开启帧应当被限流（发了 %d 帧 / %d 条连接）",
			o, sessionEventBurst*2)
	}
}
