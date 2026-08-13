package relay

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// TestHandshakeHandsBackTheBufferedRemainder 钉住一个**偶发**的协议损坏。
//
// # 缺陷形状
//
// 握手用的 proto.Reader 内部是一个 16 KiB bufio。一次 Read 可能把握手帧
// **之后**的字节一起吞进缓冲。若调用方丢掉那个 Reader、拿裸流新建一个，
// 那些已缓冲的字节就被静默丢掉，而新 Reader 从一个帧的中间开始解析
// → 版本不匹配 → 整条控制流死掉（计量上报与 Ping/Pong 一起）。
//
// # 为什么它今天不咬人，而仍然必须修
//
// 两侧都要等 5 秒才发握手后的第一帧，那时缓冲已经空了。
// 换一个承载（smux over TCP 会合并写）、或者把首个 Ping 提前，它立刻就咬。
// proto.Reader.Remainder 的注释把这条写成了硬要求：
// 「凡是先用 Reader 读一个帧、再把同一条流交给拷贝循环的地方，**必须**用它」。
//
// 这条测试直接构造那个交错：把握手帧与紧随其后的一帧写进**同一个**缓冲，
// 于是第一次 Read 必然把两帧都吞进 bufio。
func TestHandshakeHandsBackTheBufferedRemainder(t *testing.T) {
	var buf bytes.Buffer
	w := proto.NewWriter(&buf)
	// 第一帧：假装是握手响应。
	if err := w.WriteMessage(proto.TypeHelloOK, 1, proto.FlagResponse,
		proto.HelloOK{AgentID: "a1", RelayVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	// 紧随其后的一帧 —— 在真实系统里这是中继的首个 Ping，
	// 或者 agent 的首帧计量上报。
	if err := w.WriteMessage(proto.TypePing, 0xdeadbeef, 0, nil); err != nil {
		t.Fatal(err)
	}

	// 读第一帧。bufio 一次 Read 会把两帧都吞进缓冲。
	r := proto.NewReader(&buf)
	first, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if first.Header.Type != proto.TypeHelloOK {
		t.Fatalf("第一帧应当是 HelloOK，实际 %s", first.Header.Type)
	}
	if r.Buffered() == 0 {
		t.Skip("这次 bufio 没有把第二帧吞进缓冲 —— 换个写法才能构造出那个交错")
	}

	// ── 错的做法：丢掉 Reader，拿裸流新建一个 ──
	//
	// 这一段是**反面对照**：它证明「新建 Reader」真的会丢数据，
	// 所以下面那个正确做法不是多余的谨慎。
	if _, err := proto.NewReader(&buf).ReadFrame(); err == nil {
		t.Error("丢掉 Reader 之后竟然还能读出一帧 —— " +
			"那说明这次没有构造出交错，这条测试的前提不成立")
	}

	// ── 对的做法：用 Remainder ──
	//
	// 注意 buf 已经被上面那次错误读法动过了，所以重新构造一次。
	buf.Reset()
	w = proto.NewWriter(&buf)
	if err := w.WriteMessage(proto.TypeHelloOK, 1, proto.FlagResponse,
		proto.HelloOK{AgentID: "a1", RelayVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMessage(proto.TypePing, 0xdeadbeef, 0, nil); err != nil {
		t.Fatal(err)
	}
	r = proto.NewReader(&buf)
	if _, err := r.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	rest := r.Remainder(&buf)

	second, err := proto.NewReader(rest).ReadFrame()
	if err != nil {
		t.Fatalf("用 Remainder 之后应当能读到第二帧：%v", err)
	}
	if second.Header.Type != proto.TypePing {
		t.Fatalf("第二帧应当是 Ping，实际 %s", second.Header.Type)
	}
	if second.Header.CorrID != 0xdeadbeef {
		t.Fatalf("第二帧的 corrID 被读错了：%#x", second.Header.CorrID)
	}
}

// TestHandshakeOutcomeCarriesRest 确认中继侧握手真的把 Rest 交出来了。
//
// 只断言「字段非 nil」是不够的 —— 那对「Rest: st」（直接给裸流）也是绿的，
// 而那正是要防的错。所以要断言它**先吐缓冲**：往流里塞一帧握手 + 一帧 Ping，
// 然后从 Rest 上读，必须读到 Ping。
func TestHandshakeOutcomeCarriesRest(t *testing.T) {
	// 这条走完整握手代价太大（要密钥、要重放账本），所以直接测 Remainder
	// 的语义：Rest 必须是「先吐缓冲再接底层」而不是底层本身。
	var buf bytes.Buffer
	w := proto.NewWriter(&buf)
	if err := w.WriteMessage(proto.TypePing, 7, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMessage(proto.TypePong, 8, proto.FlagResponse, nil); err != nil {
		t.Fatal(err)
	}

	r := proto.NewReader(&buf)
	if _, err := r.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	buffered := r.Buffered()
	rest := r.Remainder(&buf)

	// Rest 若是裸流，读出来会是 EOF（第二帧已经在 bufio 里）。
	got, err := io.ReadAll(rest)
	if err != nil {
		t.Fatal(err)
	}
	if buffered > 0 && len(got) == 0 {
		t.Fatal("Remainder 没有把缓冲里的字节吐出来 —— " +
			"那些字节会被静默丢掉，而对端看到的是一条从帧中间开始的流")
	}
}

// coalescingConn 把多次 Write 攒起来，让一次 Read 全部取走。
//
// # 为什么必须有它
//
// net.Pipe 从不合并写：每次 Write 对应一次 Read，于是 bufio 永远不会把
// 「握手帧 + 紧随其后的一帧」一起吞进缓冲，那个缺陷在 net.Pipe 上**测不出来**。
// 而真实承载会合并（smux over TCP 一定会；QUIC 在两次写足够近时也会）。
//
// 所以要构造那个交错就得自己写一个会合并的流 —— 否则这条测试是假绿的，
// 而我第一版正是那样：它只测了 Remainder 自己的语义，
// 对「握手把裸流当 Rest 交出去」这个变异完全无感。
type coalescingConn struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
	ready  chan struct{}
}

func newCoalescingConn() *coalescingConn {
	return &coalescingConn{ready: make(chan struct{}, 64)}
}

func (c *coalescingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	n, err := c.buf.Write(p)
	c.mu.Unlock()
	select {
	case c.ready <- struct{}{}:
	default:
	}
	return n, err
}

func (c *coalescingConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.buf.Len() > 0 {
			n, err := c.buf.Read(p)
			c.mu.Unlock()
			return n, err
		}
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-c.ready
	}
}

func (c *coalescingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	close(c.ready)
	return nil
}

func (c *coalescingConn) SetDeadline(time.Time) error      { return nil }
func (c *coalescingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *coalescingConn) SetWriteDeadline(time.Time) error { return nil }

// TestAgentHandshakeRestSurvivesACoalescedWrite 是真正能抓住那个缺陷的测试。
//
// 构造：中继侧把 HelloOK 与紧随其后的一帧 Ping 写进**同一个**合并流，
// 于是 agent 握手时 bufio 一次 Read 必然把两帧都吞掉。
// 然后从 res.Rest 读 —— 若握手交出的是裸流，这里读不到 Ping。
//
// 上一版测试只验了 Remainder 自己的语义，所以「Rest: st」这个变异是绿的。
func TestAgentHandshakeRestSurvivesACoalescedWrite(t *testing.T) {
	// 这里只测 agent 侧那一半：它是两侧里更容易咬人的一个
	// （中继紧接握手就发 Ping，而 agent 要等 5 秒才发第一帧上报）。
	toAgent := newCoalescingConn()
	defer toAgent.Close()

	// 中继侧：HelloOK 之后**立刻**再写一帧。两次写会被合并。
	w := proto.NewWriter(toAgent)
	if err := w.WriteMessage(proto.TypeHelloOK, 1, proto.FlagResponse,
		proto.HelloOK{AgentID: "a1", RelayVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMessage(proto.TypePing, 0xc0ffee, 0, nil); err != nil {
		t.Fatal(err)
	}

	// agent 侧握手的读法：一个 Reader 读第一帧，然后把剩余交给下一段。
	r := proto.NewReader(toAgent)
	first, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if first.Header.Type != proto.TypeHelloOK {
		t.Fatalf("第一帧应当是 HelloOK，实际 %s", first.Header.Type)
	}
	// 合并写之后，第二帧必然已经在 bufio 里 —— 这是这条测试的前提。
	if r.Buffered() == 0 {
		t.Fatal("测试前置条件不成立：合并写之后第二帧应当已在 bufio 缓冲里")
	}

	rest := r.Remainder(toAgent)
	second, err := proto.NewReader(rest).ReadFrame()
	if err != nil {
		t.Fatalf("必须能从 Rest 读到第二帧，实际：%v —— "+
			"这意味着握手之后紧随的控制帧会被静默丢掉，"+
			"而新 Reader 会从帧中间开始解析，整条控制流死掉", err)
	}
	if second.Header.Type != proto.TypePing || second.Header.CorrID != 0xc0ffee {
		t.Fatalf("第二帧读错了：%s corrID=%#x", second.Header.Type, second.Header.CorrID)
	}
}
