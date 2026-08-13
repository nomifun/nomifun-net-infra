package agent

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// coalescingPair 是一对会**合并写**的内存流。
//
// net.Pipe 从不合并写：每次 Write 对应一次 Read，于是 bufio 永远不会把
// 「HelloOK + 紧随其后的一帧」一起吞进缓冲 —— 那个缺陷在 net.Pipe 上测不出来。
// 而真实承载会合并（smux over TCP 一定会，QUIC 在两次写足够近时也会）。
type coalescingPair struct {
	mu     sync.Mutex
	toA    bytes.Buffer // 写给 A 读
	toB    bytes.Buffer // 写给 B 读
	closed bool
	sig    chan struct{}
}

func newCoalescingPair() *coalescingPair {
	return &coalescingPair{sig: make(chan struct{}, 256)}
}

func (p *coalescingPair) wake() {
	select {
	case p.sig <- struct{}{}:
	default:
	}
}

func (p *coalescingPair) read(from *bytes.Buffer, b []byte) (int, error) {
	for {
		p.mu.Lock()
		if from.Len() > 0 {
			n, err := from.Read(b)
			p.mu.Unlock()
			return n, err
		}
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		select {
		case <-p.sig:
		case <-time.After(5 * time.Second):
			return 0, io.EOF
		}
	}
}

func (p *coalescingPair) write(to *bytes.Buffer, b []byte) (int, error) {
	p.mu.Lock()
	n, err := to.Write(b)
	p.mu.Unlock()
	p.wake()
	return n, err
}

func (p *coalescingPair) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	close(p.sig)
	return nil
}

// sideA 是 agent 那一端。
type sideA struct{ p *coalescingPair }

func (s sideA) Read(b []byte) (int, error)       { return s.p.read(&s.p.toA, b) }
func (s sideA) Write(b []byte) (int, error)      { return s.p.write(&s.p.toB, b) }
func (s sideA) Close() error                     { return nil }
func (s sideA) SetDeadline(time.Time) error      { return nil }
func (s sideA) SetReadDeadline(time.Time) error  { return nil }
func (s sideA) SetWriteDeadline(time.Time) error { return nil }

// TestHandshakeResultRestCarriesFramesCoalescedWithHelloOK 是**真的**在测
// agent.Handshake 有没有把 bufio 余量交出来。
//
// # 为什么这条测试必须调 Handshake 本身
//
// 我第一版只测了 proto.Reader.Remainder 自己的语义 —— 那对
// 「Handshake 里写 Rest: st（直接给裸流）」这个变异完全无感：类型对、编译过、
// 测试绿，而运行时会静默丢掉握手之后紧随的每一帧。
//
// 现在的构造：中继侧把 HelloOK 与紧随其后的一帧 Ping 写进同一个合并流，
// 于是 Handshake 内部那次 Read 必然把两帧都吞进 bufio。
// 然后从 res.Rest 读 —— 若它是裸流，这里读不到 Ping。
func TestHandshakeResultRestCarriesFramesCoalescedWithHelloOK(t *testing.T) {
	pair := newCoalescingPair()
	defer pair.Close()
	agentSide := sideA{p: pair}

	// 扮演中继：读 Hello，然后把 HelloOK 与 Ping **连着**写出去。
	relayDone := make(chan error, 1)
	go func() {
		r := proto.NewReader(readerB{pair})
		if _, err := r.ReadFrame(); err != nil {
			relayDone <- err
			return
		}
		w := proto.NewWriter(writerB{pair})
		if err := w.WriteMessage(proto.TypeHelloOK, 1, proto.FlagResponse, proto.HelloOK{
			AgentID: "a1", RelayVersion: "test", ServerUnixMilli: time.Now().UnixMilli(),
		}); err != nil {
			relayDone <- err
			return
		}
		// 紧随其后 —— 真实系统里这就是中继的首个 Ping。
		relayDone <- w.WriteMessage(proto.TypePing, 0xc0ffee, 0, nil)
	}()

	res, err := Handshake(agentSide, Credential{}, "nf_enrol_test", nil, Identity{Hostname: "h"})
	if err != nil {
		t.Fatalf("握手失败：%v", err)
	}
	if err := <-relayDone; err != nil {
		t.Fatalf("扮演中继的那一侧出错：%v", err)
	}

	if res.Rest == nil {
		t.Fatal("HandshakeResult.Rest 不能为 nil —— " +
			"握手之后必须有一条能继续读控制帧的路径")
	}

	fr, err := proto.NewReader(res.Rest).ReadFrame()
	if err != nil {
		t.Fatalf("必须能从 Rest 读到紧随 HelloOK 的那一帧，实际：%v\n"+
			"这意味着握手之后紧随的控制帧被静默丢掉了，"+
			"而新 Reader 会从帧中间开始解析 → 版本不匹配 → 整条控制流死掉"+
			"（计量上报与 Ping/Pong 一起）", err)
	}
	if fr.Header.Type != proto.TypePing || fr.Header.CorrID != 0xc0ffee {
		t.Fatalf("读到的帧不对：%s corrID=%#x", fr.Header.Type, fr.Header.CorrID)
	}
}

type readerB struct{ p *coalescingPair }

func (s readerB) Read(b []byte) (int, error) { return s.p.read(&s.p.toB, b) }

type writerB struct{ p *coalescingPair }

func (s writerB) Write(b []byte) (int, error) { return s.p.write(&s.p.toA, b) }
