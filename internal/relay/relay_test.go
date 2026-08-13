package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 本文件覆盖的每一条，都对应一次**手工验证抓出来的真实缺陷**。
//
// 这个包原先一个测试都没有，而它恰恰是三个已修缺陷的现场：
// 入口监听器持过期快照、死会话上的用户连接挂死、世代号误删新会话。
// 手工验证能发现它们，但发现不等于钉住 —— 下一次重构没有任何东西会拦住回归。

// testSetupTimeout 是测试里用的建连期限。
//
// 取值远小于生产的 StreamSetupTimeout：这些测试要证的是「有期限、会快失败」，
// 而不是「期限恰好是 5 秒」。后者由
// TestStreamSetupTimeoutStaysWellBelowTheCarrierIdleTimeout 钉住。
const testSetupTimeout = 300 * time.Millisecond

// ── 测试替身 ────────────────────────────────────────────────────────────────

// pipeCarrier 是 carrier.Carrier 的内存实现：OpenStream 造一对 net.Pipe，
// 近端给中继，远端进 accept 队列给「假 agent」。
//
// 用它而不是真 QUIC，是为了让本包的测试只测会话与入口逻辑；
// 真承载上的端到端在 test/e2e 里跑。
type pipeCarrier struct {
	accept chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc

	// opened 记录开流次数，用来断言「该拒的连接根本没去开流」——
	// 只断言结果为拒，分不清是在闸门拒的还是绕了一圈才失败。
	opened atomic.Int64
}

func newPipeCarrier() *pipeCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	return &pipeCarrier{accept: make(chan net.Conn, 16), ctx: ctx, cancel: cancel}
}

func (c *pipeCarrier) OpenStream(ctx context.Context) (carrier.Stream, error) {
	near, far := net.Pipe()
	select {
	case c.accept <- far:
		c.opened.Add(1)
		return near, nil
	case <-ctx.Done():
		near.Close()
		far.Close()
		return nil, ctx.Err()
	case <-c.ctx.Done():
		near.Close()
		far.Close()
		return nil, carrier.ErrClosed
	}
}

func (c *pipeCarrier) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case s := <-c.accept:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, carrier.ErrClosed
	}
}

func (c *pipeCarrier) SendDatagram([]byte) error { return carrier.ErrDatagramUnsupported }
func (c *pipeCarrier) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, carrier.ErrDatagramUnsupported
}
func (c *pipeCarrier) SupportsDatagrams() bool { return false }
func (c *pipeCarrier) MaxDatagramPayload() int { return 0 }
func (c *pipeCarrier) Rung() carrier.Rung      { return carrier.RungQUIC }

// ChannelBinding 返回空材料：这个假承载没有 TLS。
// 两端在同一条连接上都拿到空值，所以 MAC 仍然一致。
func (c *pipeCarrier) ChannelBinding() ([]byte, error) { return nil, nil }
func (c *pipeCarrier) Context() context.Context        { return c.ctx }
func (c *pipeCarrier) RTT() time.Duration              { return 0 }
func (c *pipeCarrier) LocalAddr() net.Addr             { return pipeAddr{} }
func (c *pipeCarrier) RemoteAddr() net.Addr            { return pipeAddr{} }
func (c *pipeCarrier) CloseWithError(uint64, string) error {
	c.cancel()
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// fakeAgent 扮演隧道另一端：读 StreamOpen → 拨后端 → 回 StreamOK → 双向搬字节。
//
// 与 internal/agent 的真实实现同形，这样测试覆盖的是真实的开流握手，
// 而不是一个「假设已经通了」的桩。
type fakeAgent struct {
	car   *pipeCarrier
	opens chan proto.StreamOpen
}

// agentBehaviour 决定假 agent 收到 StreamOpen 后怎么做。
type agentBehaviour func(proto.StreamOpen) (net.Conn, error)

// startFakeAgent 起一个假 agent。behave 返回 nil error 才回 StreamOK。
func startFakeAgent(t *testing.T, behave agentBehaviour) *fakeAgent {
	t.Helper()

	a := &fakeAgent{car: newPipeCarrier(), opens: make(chan proto.StreamOpen, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = a.car.CloseWithError(0, "测试结束")
	})

	go func() {
		for {
			st, err := a.car.AcceptStream(ctx)
			if err != nil {
				return
			}
			go a.serve(st, behave)
		}
	}()
	return a
}

// startRawAgent 起一个**没有** accept 循环的 agent 替身，由调用方自己接流。
//
// 需要它是因为 startFakeAgent 自带的循环会和调用方的接流竞争同一个队列，
// 谁抢到都不确定 —— 测试必须是确定的。
func startRawAgent(t *testing.T) *fakeAgent {
	t.Helper()

	a := &fakeAgent{car: newPipeCarrier(), opens: make(chan proto.StreamOpen, 16)}
	t.Cleanup(func() { _ = a.car.CloseWithError(0, "测试结束") })
	return a
}

// startMuteAgent 起一个「读了 StreamOpen 但永不回话」的 agent。
//
// 这是 agent 被 kill -9 后的准确模型：进程没了，但中继那次头写入已经落进
// 本地 QUIC 发送窗口（所以写是成功的），承载则要等到空闲超时（30s）
// 才发现对端已死。考的是 AwaitStreamOK 的读期限。
func startMuteAgent(t *testing.T) *fakeAgent {
	t.Helper()
	return startHoldingAgent(t, true)
}

// startDeafAgent 起一个「接了流但**根本不读**」的 agent。
//
// 这是另一种故障：对端还活着，但已经停止消费（读循环卡死、内存换页），
// 流的流控窗口填满后中继那次写就地阻塞。考的是 OpenTunnelStream 的写期限 ——
// 那一侧原先完全没有期限，卡住的 handle 会一直占着入口信号量槽位。
func startDeafAgent(t *testing.T) *fakeAgent {
	t.Helper()
	return startHoldingAgent(t, false)
}

// startHoldingAgent 接流后握着不放。drain 决定它是否把 StreamOpen 读掉。
func startHoldingAgent(t *testing.T, drain bool) *fakeAgent {
	t.Helper()

	a := &fakeAgent{car: newPipeCarrier(), opens: make(chan proto.StreamOpen, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = a.car.CloseWithError(0, "测试结束")
	})

	go func() {
		var held []carrier.Stream
		defer func() {
			for _, st := range held {
				st.Close()
			}
		}()
		for {
			st, err := a.car.AcceptStream(ctx)
			if err != nil {
				return
			}
			// 握着不放、不回话 —— 死进程不会礼貌地关闭连接。
			held = append(held, st)
			if drain {
				go func(st carrier.Stream) {
					// 只把字节读掉，永不回帧。
					_, _ = io.Copy(io.Discard, st)
				}(st)
			}
		}
	}()
	return a
}

func (a *fakeAgent) serve(st carrier.Stream, behave agentBehaviour) {
	defer st.Close()

	fr, err := proto.NewReader(st).ReadFrame()
	if err != nil {
		return
	}
	var open proto.StreamOpen
	if err := proto.Decode(fr, &open); err != nil {
		return
	}
	select {
	case a.opens <- open:
	default:
	}

	w := proto.NewWriter(st)
	local, err := behave(open)
	if err != nil {
		_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
			Code: proto.ErrCodeTargetDenied, Message: err.Error(),
		})
		return
	}
	defer local.Close()

	if err := w.WriteMessage(proto.TypeStreamOK, fr.Header.CorrID, proto.FlagResponse,
		proto.StreamOK{LocalAddr: local.LocalAddr().String()}); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, st)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(st, local)
		st.Close()
	}()
	wg.Wait()
}

func (a *fakeAgent) session(agentID string) *Session {
	return &Session{AgentID: agentID, Carrier: a.car, ConnectedAt: time.Now()}
}

// stubLookup 是 TunnelLookup 的测试实现。
//
// tunnels 存的是**指针**，测试可以在监听器创建之后改动它，
// 以此验证监听器是现取还是持了快照。
type stubLookup struct {
	mu       sync.Mutex
	tunnels  map[string]*tunnel.Tunnel
	sessions map[string]*Session
}

func newStubLookup() *stubLookup {
	return &stubLookup{
		tunnels:  make(map[string]*tunnel.Tunnel),
		sessions: make(map[string]*Session),
	}
}

func (s *stubLookup) put(t *tunnel.Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnels[t.ID] = t
}

func (s *stubLookup) bind(agentID string, sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[agentID] = sess
}

func (s *stubLookup) TunnelByID(id string) (*tunnel.Tunnel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tunnels[id]
	return t, ok
}

func (s *stubLookup) TunnelByListenPort(port uint16) (*tunnel.Tunnel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tunnels {
		if t.ListenPort == port {
			return t, true
		}
	}
	return nil, false
}

func (s *stubLookup) SessionFor(agentID string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 空 agentID 不再意味着「随便哪个在线 agent」—— 那个二义性是一个已修缺陷。
	if agentID == "" {
		return nil, false
	}
	sess, ok := s.sessions[agentID]
	return sess, ok
}

func quietLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(logWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Logf("日志：%s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}

// echoBackend 起一个把收到的字节原样回写的 TCP 服务，充当 agent 侧的本地服务。
func echoBackend(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起回显后端失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// serviceTunnel 造一条最简单的服务隧道（场景一的形状）。
func serviceTunnel(id, agentID, backend string) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID:       id,
		Slug:     id,
		AgentID:  agentID,
		Kind:     tunnel.KindService,
		TLS:      tunnel.TLSPassthrough,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4TCP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend},
	}
	t.Complete()
	return t
}

// startEntry 在随机端口上起一个入口监听器，返回它的地址。
//
// setup 为正数时覆盖建连期限：验证「快失败」这个机制不需要真等 5 秒。
func startEntry(t *testing.T, tun *tunnel.Tunnel, lookup TunnelLookup,
	setup time.Duration, sink RejectSink) (*EntryListener, string) {
	t.Helper()

	l, err := NewEntryListener("127.0.0.1:0", tun, lookup, EntryOptions{
		Log: quietLogger(t), OnReject: sink, SetupTimeout: setup,
	})
	if err != nil {
		t.Fatalf("起入口监听器失败：%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		<-done
	})
	return l, l.Addr().String()
}

// ── 会话世代 ────────────────────────────────────────────────────────────────

func TestRemoveWithStaleGenerationDoesNotEvictNewSession(t *testing.T) {
	// 这是世代号存在的**唯一**理由：agent 重连后，旧连接的清理 goroutine
	// 可能才刚跑到 Remove。若按 AgentID 直接删，就把刚建立的新会话误删了，
	// 表现是「agent 明明在线，隧道却说代理端不在线」，且下一次重连才恢复。
	m := NewSessionManager(quietLogger(t))

	old := &Session{AgentID: "a1", Carrier: newPipeCarrier()}
	m.Add(old)
	oldGen := old.Generation

	fresh := &Session{AgentID: "a1", Carrier: newPipeCarrier()}
	replaced := m.Add(fresh)

	if replaced != old {
		t.Fatalf("Add 应当返回被顶替的旧会话，得到 %v", replaced)
	}
	if fresh.Generation == oldGen {
		t.Fatalf("新会话的世代号必须不同于旧世代，都是 %d", oldGen)
	}

	// 迟到的旧世代清理。
	if m.Remove("a1", oldGen) {
		t.Fatal("按旧世代 Remove 必须返回 false —— 否则它删掉的是新会话")
	}
	got, ok := m.Get("a1")
	if !ok || got != fresh {
		t.Fatalf("新会话必须还在，得到 ok=%v sess=%v", ok, got)
	}

	// 按正确世代清理才生效。
	if !m.Remove("a1", fresh.Generation) {
		t.Fatal("按当前世代 Remove 应当成功")
	}
	if m.Len() != 0 {
		t.Fatalf("清理后应当没有会话，还剩 %d 个", m.Len())
	}
}

func TestAliveReportsFalseOnceCarrierClosed(t *testing.T) {
	// 入口监听器靠这个判断把连接派出去之前对端还在不在。
	car := newPipeCarrier()
	s := &Session{AgentID: "a1", Carrier: car}

	if !s.Alive() {
		t.Fatal("刚建立的会话应当是活的")
	}
	s.Close("测试")
	if s.Alive() {
		t.Fatal("承载已关闭后 Alive 必须为 false")
	}
	// Close 可重复调用。
	s.Close("再来一次")
}

// ── 入口监听器 ──────────────────────────────────────────────────────────────

func TestEntryListenerReadsCurrentTunnelNotACreationSnapshot(t *testing.T) {
	// 这是浏览器验证抓出的回归：入口监听器原先持有 t.Clone() 快照，
	// 而隧道的 AgentID 会在运行中被改写（未指定 agent 的隧道在某个 agent
	// 上线后被解析并回写绑定）。持快照的表现是
	// 「控制台显示已绑定、流量却一直不通」—— 两个真相互相打脸。
	backend := echoBackend(t)
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", backend)
	})

	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))

	// 建监听器时隧道还**没有**绑定 agent。
	unbound := serviceTunnel("t1", "", backend)
	lookup.put(unbound)
	_, addr := startEntry(t, unbound, lookup, 0, nil)

	// 此刻应当拨不通：空 agent_id 不代表「随便哪个在线 agent」。
	if err := probeEcho(addr, "早"); err == nil {
		t.Fatal("未绑定 agent 的隧道不该通 —— 空 agent_id 必须只有一种含义")
	}

	// 现在把绑定写回去（runtime.bindUnassigned 做的正是这件事）。
	bound := serviceTunnel("t1", "agent-1", backend)
	lookup.put(bound)

	// 监听器没有重建，但必须立刻用上新的 AgentID。
	if err := probeEcho(addr, "你好中继"); err != nil {
		t.Fatalf("回写绑定后应当立刻可用，却失败了：%v", err)
	}
}

func TestEntryListenerDeniesDisallowedSourceBeforeOpeningAStream(t *testing.T) {
	// 便宜的闸门要放在贵的操作前面：源 IP 白名单判定不该付出一次跨网络开流。
	// frp 把这个检查放进一个进程外的 HTTP 插件，等于给每条连接加一次 RPC。
	backend := echoBackend(t)
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", backend)
	})

	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))

	tun := serviceTunnel("t1", "agent-1", backend)
	// 只放行一个不可能是本机回环的网段。
	tun.Policy = &tunnel.Policy{AllowCIDRs: []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	}}
	lookup.put(tun)
	l, addr := startEntry(t, tun, lookup, 0, nil)

	if err := probeEcho(addr, "该被拒"); err == nil {
		t.Fatal("来源不在白名单内的连接必须被拒")
	}

	waitFor(t, func() bool { return l.Stats().DeniedCIDR.Load() == 1 },
		"DeniedCIDR 应当计到 1")
	if n := agent.car.opened.Load(); n != 0 {
		t.Fatalf("被白名单拒掉的连接不该开流，却开了 %d 条", n)
	}
}

func TestEntryListenerFailsFastWhenTheAgentNeverReplies(t *testing.T) {
	// agent 被 kill -9 时不发 QUIC 关闭帧，承载在空闲超时（30s）前
	// 看起来还活着，Session.Alive() 挡不住这个检测窗口。
	// 没有独立期限的话，用户连接会一直挂到客户端自己超时 ——
	// 这是手工验证里 curl 挂死的那一次。
	assertEntryFailsFast(t, startMuteAgent(t), "读期限")
}

func TestEntryListenerFailsFastWhenTheAgentStopsReading(t *testing.T) {
	// 另一侧：对端还活着但已经停止消费，流控窗口填满，中继写头就地阻塞。
	// 这一侧原先**完全没有期限** —— 补本包测试时才发现。
	// 后果比一条连接挂死严重：卡住的 handle 一直占着入口信号量槽位，
	// 攒够 MaxConns 条就把整个入口锁死，之后新连接全被记成 RateLimited，
	// 看起来像过载，实际是死锁。
	assertEntryFailsFast(t, startDeafAgent(t), "写期限")
}

// assertEntryFailsFast 断言用户连接在 StreamSetupTimeout 附近干净失败。
func assertEntryFailsFast(t *testing.T, agent *fakeAgent, which string) {
	t.Helper()

	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	lookup.put(tun)
	l, addr := startEntry(t, tun, lookup, testSetupTimeout, nil)

	start := time.Now()
	err := probeEcho(addr, "会不会挂死")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("%s：不回话的 agent 上不该拿到成功响应", which)
	}
	// 必须在建连期限附近失败，而不是一路等到承载空闲超时。
	if elapsed > 4*testSetupTimeout {
		t.Fatalf("%s：失败耗时 %v，远超建连期限(%v) —— 说明这一侧没有期限",
			which, elapsed, testSetupTimeout)
	}
	waitFor(t, func() bool { return l.Stats().OpenFailed.Load() >= 1 },
		which+"：OpenFailed 应当被计数")

	// handle 必须真的返回，槽位必须真的还回来 —— 否则入口会被慢慢锁死。
	// 用「再来一条连接还能被受理」来验证，而不是去读内部状态。
	waitFor(t, func() bool {
		_ = probeEcho(addr, "槽位还回来了吗")
		return l.Stats().OpenFailed.Load() >= 2
	}, which+"：槽位应当已归还，后续连接仍能进入开流阶段")
}

func TestEntryListenerCountsMissingSessionSeparatelyFromOpenFailure(t *testing.T) {
	// 「agent 根本不在线」与「开流失败」要分开计数：前者指向部署，
	// 后者指向链路。混在一起，看板就没法告诉你该去调什么。
	lookup := newStubLookup() // 故意不注册任何会话
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	lookup.put(tun)
	l, addr := startEntry(t, tun, lookup, 0, nil)

	if err := probeEcho(addr, "没人接"); err == nil {
		t.Fatal("没有会话时不该成功")
	}
	waitFor(t, func() bool { return l.Stats().NoSession.Load() == 1 },
		"NoSession 应当计到 1")
	if n := l.Stats().OpenFailed.Load(); n != 0 {
		t.Fatalf("会话缺失不该同时计入 OpenFailed，却计了 %d", n)
	}
}

func TestEntryListenerRejectsBeyondMaxConnsInsteadOfPilingUpGoroutines(t *testing.T) {
	// frp 对每条接受的连接直接起一个 goroutine，既没有信号量也没有
	// accept 速率限制，唯一的刹车是 10s 读超时。这里必须有界，
	// 且超限时**立刻拒**而不是排队 —— 排队只是把过载往后推。
	agent := startMuteAgent(t) // 让第一条连接卡在等确认，占住信号量不放

	lookup := newStubLookup()
	lookup.bind("agent-1", agent.session("agent-1"))
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.Policy = &tunnel.Policy{MaxConns: 1}
	lookup.put(tun)
	l, addr := startEntry(t, tun, lookup, testSetupTimeout, nil)

	// 第一条连接会卡在等 StreamOK（沉默 agent），占住唯一的槽位。
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("第一条连接拨号失败：%v", err)
	}
	defer first.Close()
	waitFor(t, func() bool { return agent.car.opened.Load() == 1 },
		"第一条连接应当已经开流并占住槽位")

	// 第二条必须被立刻拒掉。
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("第二条连接拨号失败：%v", err)
	}
	defer second.Close()

	_ = second.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("超出并发上限的连接应当被关闭，而不是读到数据")
	}
	waitFor(t, func() bool { return l.Stats().RateLimited.Load() == 1 },
		"RateLimited 应当计到 1")
}

func TestEntryListenerRefusesUDPTunnel(t *testing.T) {
	// UDP 走数据报路径，不是 net.Listener。让类型错误在构造期就炸，
	// 而不是在第一个包到达时。
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	tun.L4 = tunnel.L4UDP

	if _, err := NewEntryListener("127.0.0.1:0", tun, newStubLookup(), EntryOptions{Log: quietLogger(t)}); err == nil {
		t.Fatal("UDP 隧道不该被 NewEntryListener 接受")
	}
}

func TestStreamSetupTimeoutStaysWellBelowTheCarrierIdleTimeout(t *testing.T) {
	// 上面两个测试把期限调小以免空转，所以 5 秒这个**取值**要在这里钉住。
	//
	// 不变式：建连期限必须远小于承载空闲超时。agent 被强杀时不发关闭帧，
	// 承载要等到空闲超时才发现对端已死；若建连期限不比它小得多，
	// 用户连接就会一直挂着 —— 那正是手工验证里 curl 挂死 30 秒的那次。
	if StreamSetupTimeout >= carrier.DefaultMaxIdleTimeout/2 {
		t.Fatalf("建连期限 %v 相对承载空闲超时 %v 太长，故障不会快速可见",
			StreamSetupTimeout, carrier.DefaultMaxIdleTimeout)
	}
	if StreamSetupTimeout < time.Second {
		t.Fatalf("建连期限 %v 太短，正常的跨网络开流 + 本地拨号会被误杀",
			StreamSetupTimeout)
	}
}

func TestEntryListenerReportsExplicitRejectionsButNotNetworkFailures(t *testing.T) {
	// 事件流的价值在信噪比。「agent 说不」要进事件流：那是用户可行动的
	// 已知原因（他自己的策略挡住了自己的隧道）。而网络类失败不能进 ——
	// 那种故障看 OpenFailed 指标比看事件流有用，且它可能每秒发生几百次。
	var mu sync.Mutex
	var got []string
	sink := func(tunnelID, code, message string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, code+"|"+message)
	}
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}

	// ① agent 明确拒绝 → 必须上报。
	rejecting := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return nil, errors.New("目标被本地策略否决：不在允许网段内")
	})
	lookup := newStubLookup()
	lookup.bind("agent-1", rejecting.session("agent-1"))
	tun := serviceTunnel("t1", "agent-1", "127.0.0.1:1")
	lookup.put(tun)
	_, addr := startEntry(t, tun, lookup, testSetupTimeout, sink)

	_ = probeEcho(addr, "会被拒")
	waitFor(t, func() bool { return len(snapshot()) == 1 }, "明确拒绝应当上报一次")
	if ev := snapshot()[0]; !strings.HasPrefix(ev, proto.ErrCodeTargetDenied+"|") {
		t.Fatalf("上报的错误码应为 %s，实际 %q", proto.ErrCodeTargetDenied, ev)
	}

	// ② 对端不回话（网络类失败）→ 不该上报。
	mute := startMuteAgent(t)
	lookup2 := newStubLookup()
	lookup2.bind("agent-2", mute.session("agent-2"))
	tun2 := serviceTunnel("t2", "agent-2", "127.0.0.1:1")
	lookup2.put(tun2)
	l2, addr2 := startEntry(t, tun2, lookup2, testSetupTimeout, sink)

	_ = probeEcho(addr2, "会超时")
	waitFor(t, func() bool { return l2.Stats().OpenFailed.Load() >= 1 }, "超时应当计入 OpenFailed")
	if n := len(snapshot()); n != 1 {
		t.Fatalf("网络类失败不该进事件流，上报数从 1 变成了 %d", n)
	}
}

// ── 开流握手 ────────────────────────────────────────────────────────────────

func TestAwaitStreamOKSurfacesAgentRejectionWithItsCode(t *testing.T) {
	// agent 说「不」与网络出问题必须能分开：前者要把原因原样呈现给用户
	//（他自己的策略挡住了自己的隧道），后者要指向承载链路。
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return nil, errors.New("目标被本地策略否决")
	})
	sess := agent.session("agent-1")

	st, err := OpenTunnelStream(context.Background(), sess, proto.StreamOpen{TunnelID: "t1"})
	if err != nil {
		t.Fatalf("开流失败：%v", err)
	}
	defer st.Close()

	_, _, err = AwaitStreamOK(st, 3*time.Second)
	var rej *StreamRejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("应当拿到 StreamRejectedError，得到 %#v", err)
	}
	if rej.Code != proto.ErrCodeTargetDenied {
		t.Fatalf("错误码应当原样透传，得到 %q", rej.Code)
	}
	if rej.Message == "" {
		t.Fatal("拒绝原因不能为空 —— 用户要看的就是这句话")
	}
}

func TestAwaitStreamOKTimesOutRatherThanBlockingForever(t *testing.T) {
	agent := startMuteAgent(t)
	sess := agent.session("agent-1")

	st, err := OpenTunnelStream(context.Background(), sess, proto.StreamOpen{TunnelID: "t1"})
	if err != nil {
		t.Fatalf("开流失败：%v", err)
	}
	defer st.Close()

	start := time.Now()
	if _, _, err := AwaitStreamOK(st, 300*time.Millisecond); err == nil {
		t.Fatal("沉默的 agent 上必须超时失败")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("超时没有生效，等了 %v", elapsed)
	}
}

func TestDialTunnelStreamReaderYieldsBytesCoalescedIntoTheFrameRead(t *testing.T) {
	// proto.NewReader 把流包进一个 16 KiB 的 bufio.Reader，
	// 所以紧跟在 StreamOK 之后发出的业务字节很可能被一并读进缓冲。
	// 若拷贝循环直接读 carrier.Stream，那些字节就被静默丢掉 ——
	// 表现是「响应头没了」或「首包丢了」，极难排查。
	const payload = "紧跟着确认帧发出的首批业务字节"

	agent := startRawAgent(t) // 自己接流，不要 startFakeAgent 的循环来抢
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		st, err := agent.car.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer st.Close()
		if _, err := proto.NewReader(st).ReadFrame(); err != nil {
			return
		}
		w := proto.NewWriter(st)
		// 确认帧与业务字节**连着**写，尽量让它们落进同一次读。
		if err := w.WriteMessage(proto.TypeStreamOK, 0, proto.FlagResponse,
			proto.StreamOK{LocalAddr: "127.0.0.1:1"}); err != nil {
			return
		}
		_, _ = io.WriteString(st, payload)
		// 别关流，让读端能把数据读完。
		<-ctx.Done()
	}()

	ts, err := DialTunnelStream(context.Background(), agent.session("agent-1"),
		proto.StreamOpen{TunnelID: "t1"}, 3*time.Second)
	if err != nil {
		t.Fatalf("拨隧道流失败：%v", err)
	}
	defer ts.Close()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(ts.Reader, buf); err != nil {
		t.Fatalf("从 TunnelStream.Reader 读首批字节失败：%v", err)
	}
	if string(buf) != payload {
		t.Fatalf("首批字节被改动或丢失：得到 %q，应为 %q", buf, payload)
	}
}

// ── 小工具 ──────────────────────────────────────────────────────────────────

// probeEcho 向入口写一句话并读回同样长度，验证整条链路真的通了。
//
// 不只看「连得上」：TCP 连上入口端口只证明中继在监听，
// 证明不了字节真的走到了 agent 侧的后端。
func probeEcho(addr, msg string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return errors.New("回显内容不一致：" + string(buf))
	}
	return nil
}

// waitFor 轮询等一个条件成立，避免用 sleep 猜时间。
//
// 期限取 20 秒而不是 3 秒：它是「只有真挂死才该触发」的上界，不是被测量的
// 东西 —— 条件一满足就立刻返回，放宽不会让套件慢一毫秒。而 3 秒在
// `go test ./...`（跨包并行）加 -race 的负载下会偶发超时，
// 于是断言本身变成了一个偶发失败的门禁 —— 那比没有断言更糟，
// 因为它会让人开始习惯性重跑，直到有一天把真缺陷也重跑掉。
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
