package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// dgramCarrier 是支持数据报的内存承载。
//
// SendDatagram 把帧塞进一条队列，测试从那里取出来，模拟「agent 收到了」。
type dgramCarrier struct {
	*pipeCarrier
	sent chan []byte
}

func newDgramCarrier() *dgramCarrier {
	return &dgramCarrier{pipeCarrier: newPipeCarrier(), sent: make(chan []byte, 256)}
}

func (c *dgramCarrier) SendDatagram(b []byte) error {
	// 必须拷贝：Sender 会把缓冲还回池里复用。
	select {
	case c.sent <- append([]byte(nil), b...):
		return nil
	default:
		return nil // 测试里满了就丢，不阻塞
	}
}

func (c *dgramCarrier) SupportsDatagrams() bool { return true }
func (c *dgramCarrier) MaxDatagramPayload() int { return 1200 }

// dgramSession 造一个支持数据报的会话。
func dgramSession(t *testing.T, agentID string) (*Session, *dgramCarrier) {
	t.Helper()
	car := newDgramCarrier()
	t.Cleanup(func() { _ = car.CloseWithError(0, "测试结束") })
	return &Session{
		AgentID:      agentID,
		Carrier:      car,
		Capabilities: []proto.Capability{proto.CapDatagram},
		ConnectedAt:  time.Now(),
	}, car
}

// flowIDOf 从 agent 侧收到的上行帧里读出中继分配的 FlowID。
//
// **不能在测试里写死 1。** FlowID 现在从一个随机值起（理由见
// NewDatagramEntry：短标识 + 端口 + FlowID 三者都会被复用，
// 从 1 开始会让删了重建的隧道与旧隧道在途的回包串台）。
// 写死会让这些测试在换了起点之后集体变红 —— 而它们本来是要测别的东西。
//
// 顺带这也是**更真实**的路径：真正的 agent 就是从上行帧里读走 FlowID
// 再原样带回来的。
func flowIDOf(t *testing.T, car *dgramCarrier, shortID uint16) uint32 {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case raw := <-car.sent:
			h, _, err := udpflow.ParseFrame(raw)
			if err != nil {
				t.Fatalf("上行帧解析失败：%v", err)
			}
			if h.Tunnel == shortID {
				return h.FlowID
			}
		case <-deadline:
			t.Fatalf("没有收到隧道 %d 的上行帧", shortID)
			return 0
		}
	}
}

// udpTunnel 造一条 UDP 隧道。
func udpTunnel(id, agentID string, shortID uint16) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID:       id,
		Slug:     id,
		AgentID:  agentID,
		ShortID:  shortID,
		Kind:     tunnel.KindService,
		TLS:      tunnel.TLSPassthrough,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4UDP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	t.Complete()
	return t
}

// startDgramEntry 起一个 UDP 入口，返回它与绑定端口。
func startDgramEntry(t *testing.T, tun *tunnel.Tunnel, lookup TunnelLookup,
	cfg udpflow.Config) (*DatagramEntry, netip.AddrPort) {
	t.Helper()

	e, err := NewDatagramEntry("127.0.0.1:0", tun, lookup, DatagramOptions{
		Log: quietLogger(t), Table: cfg,
	})
	if err != nil {
		t.Fatalf("起 UDP 入口失败：%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		e.Close()
		<-done
	})
	ap := netip.MustParseAddrPort(e.Addr().String())
	return e, ap
}

func TestDatagramEntryRefusesATunnelWithoutAShortID(t *testing.T) {
	// 0 是「未分配」的保留值。让它上线会让所有帧都带 Tunnel=0，
	// 解复用直接错位 —— 静默把流量送到别处，比起不了服务糟糕得多。
	tun := udpTunnel("t1", "agent-1", 0)
	if _, err := NewDatagramEntry("127.0.0.1:0", tun, newStubLookup(), DatagramOptions{}); err == nil {
		t.Fatal("短标识为 0 的隧道不该被接受")
	}
}

func TestDatagramEntryRefusesATCPTunnel(t *testing.T) {
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:80")
	if _, err := NewDatagramEntry("127.0.0.1:0", tun, newStubLookup(), DatagramOptions{}); err == nil {
		t.Fatal("TCP 隧道不该被 NewDatagramEntry 接受")
	}
}

func TestDatagramEntryFramesUpstreamPacketsWithTheTunnelShortID(t *testing.T) {
	const shortID = 7
	sess, car := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatalf("客户端拨号失败：%v", err)
	}
	defer client.Close()

	want := "一帧音频"
	if _, err := client.Write([]byte(want)); err != nil {
		t.Fatalf("客户端发包失败：%v", err)
	}

	select {
	case raw := <-car.sent:
		h, payload, err := udpflow.ParseFrame(raw)
		if err != nil {
			t.Fatalf("发给 agent 的帧解析失败：%v", err)
		}
		if h.Tunnel != shortID {
			t.Fatalf("帧头的隧道标识应为 %d，实际 %d", shortID, h.Tunnel)
		}
		if h.DstPort != entryAP.Port() {
			t.Fatalf("帧头的目的端口应为 %d，实际 %d —— frp 正是把这个信息丢了",
				entryAP.Port(), h.DstPort)
		}
		if h.FlowID == 0 {
			t.Fatal("FlowID 不该为 0：回向路径要靠它找回客户端")
		}
		if string(payload) != want {
			t.Fatalf("载荷被改动：%q", payload)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent 侧没有收到数据报")
	}

	if got := e.Stats().PacketsIn.Load(); got != 1 {
		t.Errorf("PacketsIn 应为 1，实际 %d", got)
	}
}

func TestDatagramEntryReturnsRepliesToTheOriginalClient(t *testing.T) {
	// 回向路径是整条链最容易出错的一段：帧里没有源地址（帧头装不下，
	// 也不该装 —— 那会让 agent 知道用户的真实地址），
	// 所以中继必须自己记住 FlowID → 客户端。
	const shortID = 3
	sess, car := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("上行")); err != nil {
		t.Fatal(err)
	}

	var flowID uint32
	select {
	case raw := <-car.sent:
		h, _, err := udpflow.ParseFrame(raw)
		if err != nil {
			t.Fatal(err)
		}
		flowID = h.FlowID
	case <-time.After(20 * time.Second):
		t.Fatal("agent 侧没有收到上行数据报")
	}

	// agent 用同一个 FlowID 回一包。
	reply := "下行回包"
	e.Deliver("agent-1", udpflow.Header{
		Tunnel: shortID, FlowID: flowID, DstPort: entryAP.Port(),
	}, []byte(reply))

	_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("客户端没收到回包：%v", err)
	}
	if string(buf[:n]) != reply {
		t.Fatalf("回包内容不对：%q", buf[:n])
	}
	if got := e.Stats().PacketsOut.Load(); got != 1 {
		t.Errorf("PacketsOut 应为 1，实际 %d", got)
	}
}

func TestDatagramEntryDropsRepliesForUnknownFlowsAndMismatchedPorts(t *testing.T) {
	// 不校验就等于给了一条旁路：构造一个帧就能让 A 隧道的回包
	// 出现在 B 隧道的客户端那里。
	const shortID = 5
	sess, car := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	// 不存在的 FlowID。
	e.Deliver("agent-1", udpflow.Header{Tunnel: shortID, FlowID: 999, DstPort: entryAP.Port()},
		[]byte("野包"))
	if got := e.Stats().UnknownFlow.Load(); got != 1 {
		t.Fatalf("未知流应当被计数，实际 %d", got)
	}

	// 建一条真流，然后用**错的目的端口**投递。
	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("上行")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.Stats().PacketsIn.Load() == 1 }, "上行包应当被转发")

	e.Deliver("agent-1", udpflow.Header{
		Tunnel: shortID, FlowID: flowIDOf(t, car, shortID), DstPort: entryAP.Port() + 1,
	}, []byte("串台包"))
	if got := e.Stats().UnknownFlow.Load(); got != 2 {
		t.Fatalf("目的端口不符也应当被拒，实际计数 %d", got)
	}
	if got := e.Stats().PacketsOut.Load(); got != 0 {
		t.Fatalf("这两包都不该被送出，实际 %d", got)
	}
}

func TestDatagramEntryDeniesDisallowedSources(t *testing.T) {
	const shortID = 9
	sess, car := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	tun.Policy = &tunnel.Policy{AllowCIDRs: []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	}}
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("该被拒")); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool { return e.Stats().DeniedCIDR.Load() == 1 },
		"白名单外的来源应当被拒并计数")
	select {
	case <-car.sent:
		t.Fatal("被白名单拒掉的包不该发给 agent")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestDatagramEntryAttributesAdmissionRejectionsToTheRightGate(t *testing.T) {
	// 「丢了多少」没用，「在哪一道闸丢的」才告诉你该调哪个参数：
	// 表满要加容量，配额要提每源上限，限速要放宽建表速率 ——
	// 三者对应的运维动作完全不同。frp 这三道闸一个都没有。
	const shortID = 11
	sess, _ := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	// 容量 1：第二条流必然撞上限。
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{
		Capacity: 1, PerSourceIP: 1, NewFlowsPerSecond: 1000,
	})

	// 两个不同源端口 = 两条流。
	for i := range 2 {
		c, err := net.Dial("udp", entryAP.String())
		if err != nil {
			t.Fatalf("第 %d 个客户端拨号失败：%v", i, err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("包")); err != nil {
			t.Fatal(err)
		}
		// 逐个发，确保第二条是在第一条已建之后才来的。
		time.Sleep(50 * time.Millisecond)
	}

	waitFor(t, func() bool {
		return e.Stats().PerIPQuota.Load() > 0 || e.Stats().TableFull.Load() > 0
	}, "第二条流应当在某一道准入闸上被拒并计数")

	// 且拒绝原因必须是**具体**那一道闸，不能落到未分类。
	if e.Stats().PerIPQuota.Load()+e.Stats().TableFull.Load() == 0 {
		t.Fatal("拒绝原因没有归到任何一道闸 —— 那就没法指导运维动作")
	}
}

func TestDatagramEntryDropsWhenTheAgentIsOffline(t *testing.T) {
	const shortID = 13
	lookup := newStubLookup() // 不注册会话
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("没人接")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.Stats().NoSession.Load() == 1 },
		"agent 不在线时应当计入 NoSession")
}

func TestDatagramEntryRefusesCarriersWithoutDatagramSupport(t *testing.T) {
	// 不能悄悄把 UDP 塞进一条可靠流让用户以为自己拿到了低延迟通道 ——
	// frp 就是那样做的（把全部 UDP 挤一条 TCP workConn）。
	// 如实拒绝并计数，等承载降级路径做好了再谈。
	const shortID = 15
	car := newPipeCarrier() // 不支持数据报
	t.Cleanup(func() { _ = car.CloseWithError(0, "测试结束") })
	sess := &Session{AgentID: "agent-1", Carrier: car, ConnectedAt: time.Now()}

	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("包")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.Stats().NoDatagram.Load() == 1 },
		"承载不支持数据报时应当计入 NoDatagram")
}

func TestDatagramEntryEvictionClearsTheReverseLookupTable(t *testing.T) {
	// byFlow 若不随会话表一起清，就是一个慢速内存泄漏 ——
	// 中继是长期运行的进程。
	const shortID = 17
	sess, _ := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{
		Capacity: 2, PerSourceIP: 8, NewFlowsPerSecond: 1000,
	})

	// 建 4 条流，容量只有 2，LRU 会淘汰掉前面的。
	for range 4 {
		c, err := net.Dial("udp", entryAP.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("包")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
	}

	waitFor(t, func() bool { return e.Stats().PacketsIn.Load() >= 2 }, "至少两条流应当建成")

	// 反查表的大小必须与活跃流数一致。
	waitFor(t, func() bool {
		e.mu.RLock()
		n := len(e.byFlow)
		e.mu.RUnlock()
		return n <= 2
	}, "被淘汰的流应当同时从反查表里删掉")

	e.mu.RLock()
	n := len(e.byFlow)
	e.mu.RUnlock()
	if int64(n) != e.Stats().Flows.Load() {
		t.Fatalf("反查表 %d 条与活跃流计数 %d 不一致", n, e.Stats().Flows.Load())
	}
}

// ── 解复用 ──────────────────────────────────────────────────────────────────

func TestDatagramRouterDispatchesByTunnelShortID(t *testing.T) {
	// 数据报是**每承载**一条流（QUIC 的 ReceiveDatagram 是连接级的），
	// 所以不能让每个入口各自去收 —— 那样多个入口会互相抢包。
	// 必须一条循环收下、按帧头里的 Tunnel 分发。
	sess, car := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)

	tunA := udpTunnel("t-a", "agent-1", 21)
	tunB := udpTunnel("t-b", "agent-1", 22)
	lookup.put(tunA)
	lookup.put(tunB)
	eA, apA := startDgramEntry(t, tunA, lookup, udpflow.Config{})
	eB, apB := startDgramEntry(t, tunB, lookup, udpflow.Config{})

	r := NewDatagramRouter(quietLogger(t))
	r.Register(eA)
	r.Register(eB)

	// 两条隧道各建一条流。
	clientA, err := net.Dial("udp", apA.String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.Dial("udp", apB.String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()
	if _, err := clientA.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		return eA.Stats().PacketsIn.Load() == 1 && eB.Stats().PacketsIn.Load() == 1
	}, "两条隧道的上行包都应当被转发")

	// 给 B 的回包必须只到 B。FlowID 从上行帧里读，不写死。
	flowB := flowIDOf(t, car, 22)
	frame, err := udpflow.Header{Tunnel: 22, FlowID: flowB, DstPort: apB.Port()}.
		AppendTo(nil, []byte("只给 B"))
	if err != nil {
		t.Fatal(err)
	}
	r.Dispatch("agent-1", frame)

	_ = clientB.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 64)
	n, err := clientB.Read(buf)
	if err != nil {
		t.Fatalf("B 没收到回包：%v", err)
	}
	if string(buf[:n]) != "只给 B" {
		t.Fatalf("B 收到的内容不对：%q", buf[:n])
	}
	if got := eA.Stats().PacketsOut.Load(); got != 0 {
		t.Fatalf("A 不该收到任何回包，实际 %d 包", got)
	}
}

func TestDatagramRouterCountsMalformedAndUnroutedSeparately(t *testing.T) {
	// 畸形帧绝不能让承载被关掉：一个坏包不该让整条隧道断掉。
	// 这与 proto.Reader 遇到未知帧类型的处置一致（跳过、继续，从不关闭）。
	r := NewDatagramRouter(quietLogger(t))

	r.Dispatch("agent-1", []byte("太短")) // 短于帧头
	malformed, unrouted := r.Stats()
	if malformed != 1 || unrouted != 0 {
		t.Fatalf("畸形帧应当只计入 malformed，实际 malformed=%d unrouted=%d", malformed, unrouted)
	}

	// 结构合法但没有对应入口。
	frame, err := udpflow.Header{Tunnel: 999, FlowID: 1, DstPort: 1}.AppendTo(nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	r.Dispatch("agent-1", frame)
	malformed, unrouted = r.Stats()
	if malformed != 1 || unrouted != 1 {
		t.Fatalf("无路可投应当计入 unrouted，实际 malformed=%d unrouted=%d", malformed, unrouted)
	}
}

func TestDatagramRouterUnregisterStopsDelivery(t *testing.T) {
	sess, _ := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	tun := udpTunnel("t1", "agent-1", 31)
	lookup.put(tun)
	e, _ := startDgramEntry(t, tun, lookup, udpflow.Config{})

	r := NewDatagramRouter(quietLogger(t))
	r.Register(e)
	r.Unregister(e.ShortID())

	frame, err := udpflow.Header{Tunnel: 31, FlowID: 1, DstPort: 1}.AppendTo(nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	r.Dispatch("agent-1", frame)
	if _, unrouted := r.Stats(); unrouted != 1 {
		t.Fatalf("注销后的入口不该再收到投递，unrouted=%d", unrouted)
	}
}

func TestDatagramEntryRefusesRepliesFromAnAgentThatDoesNotOwnTheTunnel(t *testing.T) {
	// 所有 agent 会话共用**一个**全局 DatagramRouter，而帧头里的隧道短标识
	// 是明文、16 位、可枚举的。不校验发送方的话，任何一个已入网的 agent
	// 都能构造一帧、填上别人隧道的短标识与一个猜中的 FlowID，
	// 让载荷从中继的公网端口发到**别人隧道的真实客户端**上。
	//
	// 源地址与正常回包完全一致（都是中继）、所有计数器正常递增、
	// 控制台看不出异常 —— 运维只会怀疑「对面那个 agent 有问题」。
	// 它同时也是一个 UDP 反射器：被打的人看到的源 IP 是中继。
	const shortID = 7
	victimSess, car := dgramSession(t, "victim-agent")
	lookup := newStubLookup()
	lookup.bind("victim-agent", victimSess)
	tun := udpTunnel("t1", "victim-agent", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	// 受害者的真实客户端建一条流。
	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("上行")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.Stats().PacketsIn.Load() == 1 }, "上行包应当被转发")

	// 攻击者是**另一个**已入网的 agent。这里直接把真实 FlowID 给它 ——
	// 测的是「知道了 FlowID 也不该被放行」，而不是「猜不中」。
	// 真实攻击者靠枚举或靠看自己隧道上的号段推测，都不该是防线。
	flowID := flowIDOf(t, car, shortID)
	e.Deliver("attacker-agent", udpflow.Header{
		Tunnel: shortID, FlowID: flowID, DstPort: entryAP.Port(),
	}, []byte("注入的载荷"))

	if got := e.Stats().WrongAgent.Load(); got != 1 {
		t.Fatalf("非本隧道 agent 的包应当被记成 WrongAgent，实际 %d", got)
	}
	if got := e.Stats().PacketsOut.Load(); got != 0 {
		t.Fatalf("注入的包绝不该被送给客户端，实际送出 %d 包", got)
	}
	// 不能被记成「未知流」：那个分项的处置是「查会话为什么过期」，
	// 而这一项的处置是**吊销凭据**。混在一起等于把安全事件藏进容量指标里。
	if got := e.Stats().UnknownFlow.Load(); got != 0 {
		t.Errorf("注入不该被记成未知流，实际 %d", got)
	}

	// 客户端一个字节都不该收到。
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := client.Read(make([]byte, 64)); err == nil {
		t.Fatalf("客户端收到了注入的 %d 字节 —— 这条隧道被别的 agent 污染了", n)
	}

	// 真正的 agent 照常能投递：这道闸不能把正常路径一起关掉。
	e.Deliver("victim-agent", udpflow.Header{
		Tunnel: shortID, FlowID: flowID, DstPort: entryAP.Port(),
	}, []byte("正常回包"))
	waitFor(t, func() bool { return e.Stats().PacketsOut.Load() == 1 }, "真 agent 的回包应当送出")
}

func TestDatagramEntryFollowsARebindInsteadOfASnapshot(t *testing.T) {
	// 校验必须**每包现取**隧道的 AgentID，不能在建入口时快照。
	//
	// 隧道可以被改绑到另一个 agent（控制台上的常规操作）。快照的话，
	// 旧 agent 在改绑之后仍然能往这条隧道投递 —— 而「改绑」在用户看来
	// 就是「已经换人了」。
	const shortID = 9
	oldSess, carOld := dgramSession(t, "old-agent")
	newSess, _ := dgramSession(t, "new-agent")
	lookup := newStubLookup()
	lookup.bind("old-agent", oldSess)
	lookup.bind("new-agent", newSess)
	tun := udpTunnel("t1", "old-agent", shortID)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("上行")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.Stats().PacketsIn.Load() == 1 }, "上行包应当被转发")

	// 改绑到 new-agent。
	rebound := udpTunnel("t1", "new-agent", shortID)
	lookup.put(rebound)

	flowID := flowIDOf(t, carOld, shortID)
	e.Deliver("old-agent", udpflow.Header{
		Tunnel: shortID, FlowID: flowID, DstPort: entryAP.Port(),
	}, []byte("旧 agent 的包"))
	if got := e.Stats().WrongAgent.Load(); got != 1 {
		t.Fatalf("改绑后旧 agent 应当被拒，实际 WrongAgent=%d —— "+
			"说明 AgentID 是建入口时快照的", got)
	}

	e.Deliver("new-agent", udpflow.Header{
		Tunnel: shortID, FlowID: flowID, DstPort: entryAP.Port(),
	}, []byte("新 agent 的包"))
	waitFor(t, func() bool { return e.Stats().PacketsOut.Load() == 1 }, "新 agent 的包应当送出")
}

func TestDatagramEntryFlowIDsDoNotRestartFromOneAfterARebuild(t *testing.T) {
	// 短标识、入口端口、FlowID 三者都会被复用：删掉一条 UDP 隧道、立刻用
	// 同一个端口新建一条（后端不同，这正是重建的动机），短标识会被
	// allocShortID 重新分给它，端口是用户填的同一个，而 FlowID 从 1 重新开始。
	//
	// 于是旧隧道在途的回包（Tunnel / DstPort / FlowID 三项全对）会被送给
	// **新**隧道的用户，新用户的包也会被送到旧后端 —— 双向串台，
	// 而所有计数器一切正常。
	//
	// 随机起点让「旧帧撞上新流」的概率降到 流数/2^32。
	const shortID = 11
	seen := map[uint32]bool{}
	for range 8 {
		sess, car := dgramSession(t, "agent-1")
		lookup := newStubLookup()
		lookup.bind("agent-1", sess)
		tun := udpTunnel("t1", "agent-1", shortID)
		lookup.put(tun)
		e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{})

		client, err := net.Dial("udp", entryAP.String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("上行")); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return e.Stats().PacketsIn.Load() == 1 }, "上行包应当被转发")
		id := flowIDOf(t, car, shortID)
		client.Close()

		if seen[id] {
			t.Fatalf("重建之后第一条流又拿到了 FlowID %d —— "+
				"旧隧道在途的回包会串到新隧道的用户身上", id)
		}
		seen[id] = true
		if id <= 8 {
			t.Fatalf("FlowID 起点看起来还是从 0/1 递增（拿到 %d）—— "+
				"删了重建的隧道会与旧隧道在途的帧撞号", id)
		}
	}
}

func TestPerSourceIPQuotaIsClampedToCapacitySoItActuallyFires(t *testing.T) {
	// 默认容量 8192、每源 256，比例是对的。但用户一填 max_conns=4，
	// 容量就变成 4 而每源仍是 256 —— 每源那道闸永远轮不到触发，
	// 一个 IP 就能占满整张表并把别人的流按 LRU 挤掉，
	// 而 PerIPQuota / TableFull / RateLimited 三个计数器全是 0。
	// 用户以为自己填的是保护，实际是把保护关掉了。
	tun := udpTunnel("t1", "agent-1", 13)
	tun.Policy = &tunnel.Policy{MaxConns: 4}
	sess, _ := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	lookup.put(tun)

	// 显式给一个大于容量的每源配额 —— 这正是 max_conns 造成的形状。
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{
		PerSourceIP: 256, NewFlowsPerSecond: 10000,
	})

	// 同一个源 IP、不同源端口，灌远超容量的流。
	for range 20 {
		c, err := net.Dial("udp", entryAP.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("包")); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, func() bool { return e.Stats().PerIPQuota.Load() > 0 },
		"每源 IP 配额必须真的触发 —— 大于容量时它是个摆设，"+
			"而用户填 max_conns 的本意是保护自己")
}

func TestUDPTunnelRateLimitIsActuallyEnforced(t *testing.T) {
	// policy.bytes_per_second / packets_per_second 全链路可配（向导有输入框、
	// 详情页显示「已设置」、库里存着），而在这次改动之前**生产代码零读取点** ——
	// 用户填了限速、界面确认「已设置」，实际上一个字节都没被限。
	//
	// 那比没有这个功能糟糕得多：用户以为自己保护了一条裸端口暴露的隧道。
	const shortID = 17
	tun := udpTunnel("t1", "agent-1", shortID)
	tun.Policy = &tunnel.Policy{PacketsPerSecond: 5}
	sess, _ := dgramSession(t, "agent-1")
	lookup := newStubLookup()
	lookup.bind("agent-1", sess)
	lookup.put(tun)
	e, entryAP := startDgramEntry(t, tun, lookup, udpflow.Config{
		NewFlowsPerSecond: 10000, PerSourceIP: 500, Capacity: 500,
	})

	client, err := net.Dial("udp", entryAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// 灌远超包速率的量。
	for range 60 {
		if _, err := client.Write([]byte("包")); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, func() bool { return e.Stats().RateLimitedBytes.Load() > 0 },
		"超过 packets_per_second 的数据报必须被丢弃并计数 —— "+
			"用户填了限速、界面说「已设置」，那就必须真的限")

	// 而且不能把所有包都丢掉：桶初始是满的，头几个要能过。
	if got := e.Stats().PacketsIn.Load(); got == 0 {
		t.Fatal("桶初始应当是满的，头几个包必须能过")
	}
}
