package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/policy"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// dgramCarrier 是一个只做数据报的内存承载。
type dgramCarrier struct {
	in   chan []byte
	out  chan []byte
	ctx  context.Context
	stop context.CancelFunc
}

func newDgramCarrier() *dgramCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	return &dgramCarrier{
		in:   make(chan []byte, 64),
		out:  make(chan []byte, 64),
		ctx:  ctx,
		stop: cancel,
	}
}

func (c *dgramCarrier) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, carrier.ErrClosed
}
func (c *dgramCarrier) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *dgramCarrier) SendDatagram(b []byte) error {
	select {
	case c.out <- append([]byte(nil), b...):
	default:
	}
	return nil
}
func (c *dgramCarrier) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, carrier.ErrClosed
	}
}
func (c *dgramCarrier) SupportsDatagrams() bool { return true }
func (c *dgramCarrier) MaxDatagramPayload() int { return 1200 }
func (c *dgramCarrier) Rung() carrier.Rung      { return carrier.RungQUIC }

// ChannelBinding 返回空材料：这个假承载没有 TLS。
// 两端在同一条连接上都拿到空值，所以 MAC 仍然一致。
func (c *dgramCarrier) ChannelBinding() ([]byte, error) { return nil, nil }
func (c *dgramCarrier) Context() context.Context        { return c.ctx }
func (c *dgramCarrier) RTT() time.Duration              { return 0 }
func (c *dgramCarrier) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *dgramCarrier) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}
func (c *dgramCarrier) CloseWithError(uint64, string) error {
	c.stop()
	return nil
}

// noDgramCarrier 明确不支持数据报。
type noDgramCarrier struct{ *dgramCarrier }

func (c *noDgramCarrier) SupportsDatagrams() bool { return false }

// udpEcho 起一个把收到的包原样回写的 UDP 服务，充当 agent 的本地目标。
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("起 UDP 回显失败：%v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 65535) // 不能按 MTU 猜：截断会让「重组对了但内容少了」看起来像重组缺陷
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDPAddrPort(buf[:n], src)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// udpTunnel 造一条下发给 agent 的 UDP 隧道。
func udpTunnel(id string, shortID uint16, backend string) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID:       id,
		Slug:     id,
		ShortID:  shortID,
		Kind:     tunnel.KindService,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4UDP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend},
	}
	t.Complete()
	return t
}

// startHandler 起一个 agent 侧 UDP 处理器。
func startHandler(t *testing.T, set *TunnelSet, pol *policy.Policy,
	cfg udpflow.Config) (*UDPHandler, *dgramCarrier) {
	t.Helper()

	car := newDgramCarrier()
	h := &UDPHandler{Tunnels: set, Policy: pol, Log: quiet(), Table: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(ctx, car)
	}()
	t.Cleanup(func() {
		cancel()
		_ = car.CloseWithError(0, "测试结束")
		<-done
	})
	return h, car
}

// frame 组一条发给 agent 的数据报。
func frame(t *testing.T, shortID uint16, flowID uint32, dstPort uint16, payload string) []byte {
	t.Helper()
	b, err := udpflow.Header{Tunnel: shortID, FlowID: flowID, DstPort: dstPort}.
		AppendTo(nil, []byte(payload))
	if err != nil {
		t.Fatalf("组帧失败：%v", err)
	}
	return b
}

func loopbackPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.New(policy.Config{
		Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUDPHandlerForwardsToTheLocalTargetAndReturnsReplies(t *testing.T) {
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	if rejected := set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t)); len(rejected) > 0 {
		t.Fatalf("隧道不该被否决：%v", rejected)
	}
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	const want = "一帧音频"
	car.in <- frame(t, 7, 42, 5000, want)

	select {
	case raw := <-car.out:
		hdr, payload, err := udpflow.ParseFrame(raw)
		if err != nil {
			t.Fatalf("回包帧解析失败：%v", err)
		}
		// 三个标识必须原样带回，中继才能找回用户 ——
		// 帧里没有源地址，中继全靠这些字段做反查。
		if hdr.Tunnel != 7 || hdr.FlowID != 42 || hdr.DstPort != 5000 {
			t.Fatalf("回包的标识被改动：%+v", hdr)
		}
		if string(payload) != want {
			t.Fatalf("回包内容不对：%q", payload)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("没收到回包（下行 %d 包，丢弃：策略 %d 拨号 %d 未知隧道 %d）",
			h.Stats().PacketsOut.Load(), h.Stats().Denied.Load(),
			h.Stats().DialFailed.Load(), h.Stats().UnknownTunnel.Load())
	}
}

func TestUDPHandlerEnforcesTargetPolicyJustLikeTheTCPPath(t *testing.T) {
	// 这是本文件里最重要的一条。UDP 路径若绕开 policy，攻击者只要把隧道的
	// l4 从 tcp 改成 udp 就能穿过 SSRF 防线 —— 一道防线有两份实现，
	// 等于迟早只剩一份是对的。
	//
	// 这里刻意**绕过** Reconcile 的配置期预检（直接塞进可服务集合），
	// 以确保测的是拨号期那道闸。真实场景里也确实可能走到这一步：
	// 预检只判 IP 字面量，主机名一律放过、留给拨号时判定。
	set := NewTunnelSet()
	metadata := udpTunnel("t-ssrf", 9, "169.254.169.254:80")
	set.mu.Lock()
	set.byID[metadata.ID] = metadata
	set.mu.Unlock()

	pol, err := policy.New(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	h, car := startHandler(t, set, pol, udpflow.Config{})

	car.in <- frame(t, 9, 1, 5000, "试探云元数据")

	waitFor(t, func() bool { return h.Stats().Denied.Load() == 1 },
		"指向云元数据的 UDP 目标必须被本地策略否决")

	// 且**绝不**能有任何包被送出去。
	if got := h.Stats().PacketsOut.Load(); got != 0 {
		t.Fatalf("被否决的目标不该收到任何字节，实际送出 %d 包", got)
	}
	select {
	case <-car.out:
		t.Fatal("被否决的流不该产生回包")
	case <-time.After(200 * time.Millisecond):
	}

	// 策略否决与拨号失败必须分开计数：前者重试永远不会成功。
	if got := h.Stats().DialFailed.Load(); got != 0 {
		t.Fatalf("策略否决不该被记成拨号失败，实际 %d", got)
	}
}

func TestUDPHandlerRefusesFramesForTunnelsItDoesNotServe(t *testing.T) {
	// 短标识不在可服务集合里，说明这条隧道没下发给我、或被本地策略否决过。
	// 无论哪种都不该为它开 socket —— 否则一个构造过的帧就能让 agent
	// 去连任意本地端口。
	set := NewTunnelSet()
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- frame(t, 123, 1, 5000, "不属于我的隧道")
	waitFor(t, func() bool { return h.Stats().UnknownTunnel.Load() == 1 },
		"未知隧道短标识应当被拒并计数")

	// 短标识 0 是保留值，同样要拒。
	car.in <- frame(t, 0, 2, 5000, "保留值")
	waitFor(t, func() bool { return h.Stats().UnknownTunnel.Load() == 2 },
		"短标识 0 应当被拒")
}

func TestUDPHandlerCountsMalformedFramesWithoutTearingDownTheCarrier(t *testing.T) {
	// 一个坏包不该让整条隧道停掉。这与 proto.Reader 遇到未知帧类型的处置
	// 一致：跳过、继续，从不关闭。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- []byte("太短")
	waitFor(t, func() bool { return h.Stats().Malformed.Load() == 1 }, "畸形帧应当被计数")

	// 坏包之后，好包必须照常工作 —— 证明承载没被拆掉。
	car.in <- frame(t, 7, 1, 5000, "好包")
	select {
	case <-car.out:
	case <-time.After(20 * time.Second):
		t.Fatal("坏包之后好包也不通了 —— 承载被误关了")
	}
}

func TestUDPHandlerReusesOneSocketPerFlow(t *testing.T) {
	// 同一条流的多个包必须走同一个 socket：每包新建 socket 会让本地服务
	// 看到不断变化的源端口，任何有会话概念的 UDP 协议都会失效。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	for i := range 5 {
		car.in <- frame(t, 7, 42, 5000, "包")
		_ = i
	}
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() == 5 }, "5 个包都该被转发")

	// 只应当有一条流。
	if got := h.Stats().Flows.Load(); got != 1 {
		t.Fatalf("同一 FlowID 的包应当共用一条流，实际建了 %d 条", got)
	}
}

func TestUDPHandlerSeparatesDistinctFlowIDs(t *testing.T) {
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- frame(t, 7, 100, 5000, "甲")
	car.in <- frame(t, 7, 200, 5000, "乙")
	waitFor(t, func() bool { return h.Stats().Flows.Load() == 2 }, "不同 FlowID 应当各建一条流")

	// 两条流的回包都要带回自己的 FlowID。
	seen := map[uint32]bool{}
	deadline := time.After(3 * time.Second)
	for len(seen) < 2 {
		select {
		case raw := <-car.out:
			hdr, _, err := udpflow.ParseFrame(raw)
			if err != nil {
				t.Fatal(err)
			}
			seen[hdr.FlowID] = true
		case <-deadline:
			t.Fatalf("只收到 %d 条流的回包：%v", len(seen), seen)
		}
	}
	if !seen[100] || !seen[200] {
		t.Fatalf("回包的 FlowID 不对：%v", seen)
	}
}

func TestUDPHandlerBoundsTheFlowTableAndClosesEvictedSockets(t *testing.T) {
	// frp 每个新源地址就 DialUDP 一个，回收只靠 30s 读超时
	//（pkg/proto/udp/udp.go:75,117-124）—— 向公网 UDP 端口喷包即可耗尽 fd。
	// 这里必须有界，且被淘汰的 socket 必须真的关掉，否则 fd 还是会漏。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{
		Capacity: 2, PerSourceIP: 2, NewFlowsPerSecond: 1000,
	})

	for i := range 8 {
		car.in <- frame(t, 7, uint32(1000+i), 5000, "包")
		time.Sleep(20 * time.Millisecond)
	}

	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() >= 2 }, "应当有包被转发")
	waitFor(t, func() bool { return h.Stats().Flows.Load() <= 2 },
		"活跃流数不得超过容量上限")
}

func TestUDPHandlerRejectsCarriersWithoutDatagramSupport(t *testing.T) {
	// 不能悄悄把 UDP 塞进一条可靠流让用户以为自己拿到了低延迟通道。
	h := &UDPHandler{Tunnels: NewTunnelSet(), Policy: loopbackPolicy(t), Log: quiet()}
	car := &noDgramCarrier{dgramCarrier: newDgramCarrier()}
	defer car.CloseWithError(0, "结束")

	err := h.Serve(context.Background(), car)
	if err == nil {
		t.Fatal("承载不支持数据报时 Serve 应当报错返回")
	}
}

func TestUDPHandlerStopsSendingAfterTheCarrierGoesAway(t *testing.T) {
	// 承载断了之后回包 goroutine 必须能退出，否则每次重连都漏一批 goroutine。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))

	car := newDgramCarrier()
	h := &UDPHandler{Tunnels: set, Policy: loopbackPolicy(t), Log: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(ctx, car)
	}()

	car.in <- frame(t, 7, 1, 5000, "包")
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() == 1 }, "包应当被转发")

	_ = car.CloseWithError(0, "断开")
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("承载断开后 Serve 没有退出")
	}
	// 发送器已被摘掉，之后的回包不会再尝试发送。
	if h.sender.Load() != nil {
		t.Error("Serve 退出时应当把发送器摘掉")
	}
}

// waitFor 轮询等一个条件成立。
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

func TestUDPHandlerReassemblesFragmentedDatagrams(t *testing.T) {
	// 大报文（超过承载的数据报上限）会被中继侧切片。agent 必须把它拼回来
	// 再交给本地服务 —— 交半个出去比丢掉危险得多，本地服务会把它当成一个
	// 合法但内容被截断的报文。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	// 3 KiB 的报文，按 1000 字节切 —— 4 片。
	want := bytes.Repeat([]byte("IoT 大报文"), 300)
	frames := fragmentFrames(t, 7, 42, 5000, want, 1000)
	if len(frames) < 3 {
		t.Fatalf("测试前置条件不成立：只切了 %d 片", len(frames))
	}
	for _, f := range frames {
		car.in <- f
	}

	// 本地服务会把完整报文回显，所以回包也会被 agent 切片发回来。
	// 收齐所有回向分片再拼起来验证。
	got := collectReassembled(t, car.out, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("往返后内容不符：长度 %d vs %d", len(got), len(want))
	}
	if n := h.ReassemblyStats().Completed.Load(); n != 1 {
		t.Errorf("下行应当重组出 1 个完整数据报，实际 %d", n)
	}
	// 交给本地服务的必须是**一个**完整报文，不是 4 个碎片。
	if n := h.Stats().PacketsOut.Load(); n != 1 {
		t.Errorf("本地服务应当只收到 1 个报文，实际 %d —— 碎片被单独交付了", n)
	}
}

func TestUDPHandlerDropsFragmentsItCannotReassemble(t *testing.T) {
	// 少一片就永远拼不齐。必须计数并最终释放缓冲，而不是无限攒着。
	backend := udpEcho(t)
	set := NewTunnelSet()
	tun := udpTunnel("t1", 7, backend.String())
	set.Reconcile([]*tunnel.Tunnel{tun}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	payload := bytes.Repeat([]byte("x"), 3000)
	frames := fragmentFrames(t, 7, 1, 5000, payload, 1000)
	// 故意漏掉中间一片。
	for i, f := range frames {
		if i == 1 {
			continue
		}
		car.in <- f
	}

	waitFor(t, func() bool { return h.ReassemblyStats().Fragments.Load() >= int64(len(frames)-1) },
		"分片应当被收下")

	// 拼不齐 → 本地服务什么都不该收到。
	if n := h.Stats().PacketsOut.Load(); n != 0 {
		t.Fatalf("拼不齐的数据报不该被交付，实际交了 %d 个", n)
	}
	if n := h.ReassemblyStats().Completed.Load(); n != 0 {
		t.Fatalf("不该有重组完成，实际 %d", n)
	}
}

// fragmentFrames 把一个报文切成分片帧序列（测试自己的切片器）。
func fragmentFrames(t *testing.T, shortID uint16, flowID uint32, dstPort uint16,
	payload []byte, chunk int) [][]byte {
	t.Helper()

	var out [][]byte
	total := len(payload)
	for off := 0; off < total; off += chunk {
		end := min(off+chunk, total)
		h := udpflow.Header{
			Tunnel: shortID, FlowID: flowID, DstPort: dstPort,
			Flags:   udpflow.FlagFragmented,
			DgramID: 1,
			FragOff: uint16(off), FragLen: uint16(end - off), TotalLen: uint16(total),
		}
		if end == total {
			h.Flags |= udpflow.FlagLastFrag
		}
		f, err := h.AppendTo(nil, payload[off:end])
		if err != nil {
			t.Fatalf("组分片帧失败（off=%d）：%v", off, err)
		}
		out = append(out, f)
	}
	return out
}

// collectReassembled 从回向队列收齐分片并拼成完整报文。
func collectReassembled(t *testing.T, out chan []byte, wantLen int) []byte {
	t.Helper()

	buf := make([]byte, wantLen)
	got := 0
	deadline := time.After(5 * time.Second)
	for got < wantLen {
		select {
		case raw := <-out:
			h, payload, err := udpflow.ParseFrame(raw)
			if err != nil {
				t.Fatalf("回向帧解析失败：%v", err)
			}
			if !h.Fragmented() {
				// 没被切片，直接就是完整报文。
				return payload
			}
			if int(h.TotalLen) != wantLen {
				t.Fatalf("回向 TotalLen 应为 %d，实际 %d", wantLen, h.TotalLen)
			}
			copy(buf[h.FragOff:int(h.FragOff)+len(payload)], payload)
			got += len(payload)
		case <-deadline:
			t.Fatalf("回向分片只收到 %d/%d 字节", got, wantLen)
		}
	}
	return buf
}

func TestUDPFlowSelfHealsAfterTheReplyPumpDies(t *testing.T) {
	// 这是本文件里最贵的一条缺陷：一条通了很久的 UDP 隧道在一次安静之后
	// **100% 丢包且永不恢复**。
	//
	// 原因：pumpReplies 的读超时到了就 return，defer 只关 socket；
	// 而原注释说「流表的空闲回收会把表项一并清掉」—— 那句话是错的。
	// EvictIdle 的判据是 lastSeen，而 lastSeen 由**下行每包**的 Lookup
	// 刷新。于是一条 socket 已死的表项被正在被它丢掉的那些包不断续命，
	// 永远逐不掉。此后每个包都 Write 一个已关闭的 socket 失败。
	//
	// 用 ICMP 端口不可达在毫秒级触发同一个退出点，所以测试不用等 60 秒：
	// 已连接的 UDP socket 会把端口不可达变成 Read 的 ECONNREFUSED。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dead := netip.MustParseAddrPort(pc.LocalAddr().String())
	pc.Close() // 这个端口现在没人收

	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{udpTunnel("t1", 7, dead.String())}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	// 第一个包：拨号成功（UDP 的「拨号」只是绑定），随后 ICMP 把 pump 打死。
	car.in <- frame(t, 7, 42, 5000, "第一个包")
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() >= 1 }, "第一个包应当发出")
	waitFor(t, func() bool { return h.flows.Len() == 0 },
		"pumpReplies 退出时必须把表项一起删掉 —— 只关 socket 会让这条流永久黑洞化")

	// 本地服务现在起来了（重启完成 / 一开始就还没起）。
	backend, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(dead))
	if err != nil {
		t.Skipf("端口 %s 被别人占了，换一次运行：%v", dead, err)
	}
	defer backend.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := backend.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDPAddrPort(buf[:n], src)
		}
	}()

	// 同一条流的后续包必须重新拨号并通。
	car.in <- frame(t, 7, 42, 5000, "恢复之后的包")
	select {
	case <-car.out:
	case <-time.After(20 * time.Second):
		t.Fatal("后端起来之后这条流仍然不通 —— 表项还挂着一个已关闭的 socket")
	}
	if got := h.Stats().Flows.Load(); got != 1 {
		t.Errorf("活跃流数应为 1，实际 %d（pumpReplies 退出没有 -1 会长期虚高）", got)
	}
}

func TestUDPReplyFlagsFollowTheTunnelPolicy(t *testing.T) {
	// replyFlags 从来没被赋值 —— 那让 README 的「实时隧道超限即丢」
	// 在**回向**方向根本不存在：回包永远走分片路径。
	//
	// 不对称的策略比策略错更难查：上行看起来对，下行悄悄换了行为。
	backend := udpEcho(t)

	realtime := udpTunnel("rt", 7, backend.String())
	realtime.Policy = &tunnel.Policy{RealtimeDatagram: true}
	bulk := udpTunnel("bulk", 8, backend.String())

	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{realtime, bulk}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- frame(t, 7, 1, 5000, "实时")
	car.in <- frame(t, 8, 2, 5001, "批量")
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() == 2 }, "两条流都该通")

	got := map[uint16]uint8{}
	for range 2 {
		select {
		case raw := <-car.out:
			hdr, _, err := udpflow.ParseFrame(raw)
			if err != nil {
				t.Fatal(err)
			}
			got[hdr.Tunnel] = hdr.Flags
		case <-time.After(20 * time.Second):
			t.Fatal("回包没到")
		}
	}
	if got[7]&udpflow.FlagNoReassemble == 0 {
		t.Error("实时隧道的回包必须带 FlagNoReassemble（超限即丢），" +
			"否则回向会去分片 —— README 那句承诺只兑现了上行一半")
	}
	if got[8]&udpflow.FlagNoReassemble != 0 {
		t.Error("批量隧道的回包不该带 FlagNoReassemble：" +
			"请求被分片而回包被丢掉是不对称的静默失败，表现为「发得出去收不回来」")
	}
}

func TestUDPFlowIsTornDownWhenTheBackendChanges(t *testing.T) {
	// 用户在控制台把 backend.addr 改掉（常见动机：原来那台不该被暴露）。
	// 在途、流量不断的流原本会**无限期**继续打旧后端 ——
	// 而用户以为改完就生效了。
	oldBackend := udpEcho(t)
	newBackend := udpEcho(t)

	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{udpTunnel("t1", 7, oldBackend.String())}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- frame(t, 7, 42, 5000, "改之前")
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() == 1 }, "第一个包应当发出")
	<-car.out

	// 控制台改后端并重新下发。
	set.Reconcile([]*tunnel.Tunnel{udpTunnel("t1", 7, newBackend.String())}, loopbackPolicy(t))

	// 同一条流（同 FlowID）的下一个包：必须拆掉旧流。
	car.in <- frame(t, 7, 42, 5000, "改之后")
	waitFor(t, func() bool { return h.Stats().BackendChanged.Load() == 1 },
		"后端变了应当拆掉在途流并计数 —— 继续打旧后端等于改了配置不生效")

	// 再下一个包重新拨号，落到**新**后端。
	car.in <- frame(t, 7, 42, 5000, "重新拨号")
	select {
	case <-car.out:
	case <-time.After(20 * time.Second):
		t.Fatal("拆掉之后没有重新拨号")
	}
}

// slowResolver 让一个主机名的解析挂住，直到测试放它走。
//
// 必须能真的挂住：用一个「解析不出来」的名字是不够的 —— NXDOMAIN 在多数
// 机器上是毫秒级返回的，于是同步拨号那个 bug 撞不出来（我第一版就是这样，
// 把变异测试跑成了绿色）。
type slowResolver struct {
	slowHost string
	release  chan struct{}
}

func (r *slowResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	if host == r.slowHost {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestUDPHandlerDoesNotStallAllFlowsWhileDialing(t *testing.T) {
	// 建流原本是**同步**做的：Policy.ResolveAllowed 里等 DNS，最长 5 秒
	//（DialTimeout）。那期间这个 agent 上所有 UDP 隧道的下行全停 ——
	// 一条 backend.addr 写成主机名的隧道遇上局域网 DNS 抖动，
	// 就能把通话和游戏一起卡死，而计数器上什么都看不到。
	fast := udpEcho(t)
	res := &slowResolver{slowHost: "slow.invalid", release: make(chan struct{})}
	t.Cleanup(func() { close(res.release) })

	pol, err := policy.New(policy.Config{
		Allow:    []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Resolver: res,
	})
	if err != nil {
		t.Fatal(err)
	}

	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{
		udpTunnel("slow", 7, "slow.invalid:5004"),
		udpTunnel("fast", 8, fast.String()),
	}, pol)
	h, car := startHandler(t, set, pol, udpflow.Config{})

	// 先戳慢的那条，让它挂在 DNS 上。
	car.in <- frame(t, 7, 1, 5000, "慢")
	// 立刻戳快的那条：它必须在慢的那条解析完成**之前**就通。
	car.in <- frame(t, 8, 2, 5001, "快")

	select {
	case <-car.out:
	case <-time.After(3 * time.Second):
		t.Fatal("一条流的 DNS 解析把整条读循环卡住了 —— " +
			"这个 agent 上所有 UDP 隧道的下行会一起停")
	}
	_ = h
}

func TestUDPPendingDialQueueIsBounded(t *testing.T) {
	// 拨号期间要排队（否则每条新流的开头都丢包，通话起始的关键帧丢大半），
	// 但队列必须有界：一个拨不通的目标加上一次源端口喷射就是内存放大器。
	res := &slowResolver{slowHost: "slow.invalid", release: make(chan struct{})}
	t.Cleanup(func() { close(res.release) })
	pol, err := policy.New(policy.Config{
		Allow:    []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Resolver: res,
	})
	if err != nil {
		t.Fatal(err)
	}
	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{udpTunnel("slow", 7, "slow.invalid:5004")}, pol)
	h, car := startHandler(t, set, pol, udpflow.Config{})

	// 同一条流灌远超上界的包。
	for range maxPendingPackets * 4 {
		car.in <- frame(t, 7, 1, 5000, "排队")
	}
	waitFor(t, func() bool { return h.Stats().PendingDial.Load() > 0 },
		"超出排队上界的包必须被丢弃并计数，而不是无声地占内存")
}

func TestMetricsSnapshotCoversAllThreeCounterSources(t *testing.T) {
	// SendStats() 与 ReassemblyStats() 原本**一个读取点都没有**（连测试都没有）。
	// 它们各自的文档写着「没有这个出口的话，agent 侧的发送丢弃完全不可观测 ——
	// 表现为『下行统计都对，就是收不到回包』」，而那句话在这条上报接上之前
	// 一直是当前状态。
	//
	// 这条测的是打包**不漏源**：三处计数器（UDPStats / SenderStats /
	// ReassemblerStats）都要出现在上报里。漏掉一处的后果是那一整类丢弃
	// 在控制台上永远是 0。
	backend := udpEcho(t)
	set := NewTunnelSet()
	set.Reconcile([]*tunnel.Tunnel{udpTunnel("t1", 7, backend.String())}, loopbackPolicy(t))
	h, car := startHandler(t, set, loopbackPolicy(t), udpflow.Config{})

	car.in <- frame(t, 7, 42, 5000, "一包")
	waitFor(t, func() bool { return h.Stats().PacketsOut.Load() == 1 }, "包应当被转发")
	<-car.out

	// 人为往三处各打一个数，确认它们都被搬进上报里。
	h.Stats().DialFailed.Add(3)
	h.SendStats().QueueFull.Add(5)
	h.ReassemblyStats().TimedOut.Add(7)
	h.Stats().PendingDial.Add(11)

	m := h.Metrics()
	if m.DialFailed != 3 {
		t.Errorf("UDPStats 没被搬进来：DialFailed=%d", m.DialFailed)
	}
	if m.SendQueueFull != 5 {
		t.Errorf("SenderStats 没被搬进来：SendQueueFull=%d —— "+
			"回向发送队列满是「发得出去收不回来」最常见的原因之一", m.SendQueueFull)
	}
	if m.ReasmTimedOut != 7 {
		t.Errorf("ReassemblerStats 没被搬进来：ReasmTimedOut=%d —— "+
			"丢一个分片是最常见的重组失败", m.ReasmTimedOut)
	}
	if m.PendingDial != 11 {
		t.Errorf("PendingDial 没被搬进来：%d", m.PendingDial)
	}
	// 转发量也要有，否则控制台画不出「这个 agent 到底在传东西吗」。
	if m.PacketsToLocal != 1 || m.BytesToLocal == 0 {
		t.Errorf("转发量没被搬进来：%d 包 / %d 字节", m.PacketsToLocal, m.BytesToLocal)
	}
}
