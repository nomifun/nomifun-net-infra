package gateway

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestPeekReplaysExactBytes 证明被 peek 过的字节会**原样**重放给消费者。
//
// 这是透传模式能成立的前提：后端要用逐字节完整的 ClientHello 做真实握手，
// 少一个字节它就握不上手。
func TestPeekReplaysExactBytes(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		peek    int
	}{
		{"只 peek 首字节", []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), 1},
		{"peek 一半", bytes.Repeat([]byte{0xAB}, 200), 100},
		{"peek 全部", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			near, far := net.Pipe()
			defer near.Close()
			defer far.Close()

			go func() {
				_, _ = far.Write(tc.payload)
				far.Close()
			}()

			pc := NewPeekConn(near)
			got, err := pc.Peek(tc.peek, time.Second)
			if err != nil {
				t.Fatalf("peek 失败：%v", err)
			}
			if !bytes.Equal(got, tc.payload[:tc.peek]) {
				t.Fatalf("peek 到 %x，期望 %x", got, tc.payload[:tc.peek])
			}

			all, err := io.ReadAll(pc)
			if err != nil {
				t.Fatalf("读全部失败：%v", err)
			}
			if !bytes.Equal(all, tc.payload) {
				t.Fatalf("重放 %d 字节与原始 %d 字节不一致\n收到 %x\n期望 %x",
					len(all), len(tc.payload), all, tc.payload)
			}
		})
	}
}

// TestPeekShortFirstPacketDoesNotWaitForMore 是本文件最重要的测试：
// **它钉住我们相对 frp 修掉的那个缺陷。**
//
// frp 的端口复用嗅探对每条连接按「全局最大需求字节数」做 io.ReadFull，
// 并压一个硬编码 10 秒超时（golib/net/mux/mux.go:189-198），
// 所以首包只有几个字节的连接要挂满 10 秒才被判别。
//
// 这里首包只有 1 个字节，而单步期限是 5 秒 —— 若实现是「按最大值 ReadFull」，
// 这个测试会跑满 5 秒；惰性实现必须立刻返回。
func TestPeekShortFirstPacketDoesNotWaitForMore(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	// 只发一个字节，之后**什么都不发**、也不关连接（模拟等服务端先说话的客户端）。
	go func() { _, _ = far.Write([]byte{0x16}) }()

	pc := NewPeekConn(near)
	start := time.Now()
	b, err := pc.Peek(1, 5*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("peek 首字节失败：%v", err)
	}
	if b[0] != 0x16 {
		t.Fatalf("首字节 = %#x，期望 0x16", b[0])
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("短首包耗时 %v —— 惰性 peek 必须立刻返回，这正是 frp 那 10 秒的病根", elapsed)
	}
	t.Logf("短首包判别耗时 %v", elapsed)
}

// TestPeekTimeoutIsRecoverable 证明单步超时不丢数据：
// 已到的字节仍在缓冲里，补齐后下一步 peek 能接着用。
//
// 这条性质是分级 peek 的地基：若一次超时就把已读字节丢掉，
// 就只能回到「一次性读满最大值」的老路。
func TestPeekTimeoutIsRecoverable(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() { _, _ = far.Write([]byte("PRO")) }()

	pc := NewPeekConn(near)
	if _, err := pc.Peek(3, time.Second); err != nil {
		t.Fatalf("peek 前 3 字节失败：%v", err)
	}

	// 要 6 字节但只有 3 字节 → 本步超时。
	if _, err := pc.Peek(6, 50*time.Millisecond); err == nil {
		t.Fatal("字节不够时 peek 必须超时报错")
	}

	go func() { _, _ = far.Write([]byte("XY ")) }()
	got, err := pc.Peek(6, time.Second)
	if err != nil {
		t.Fatalf("补齐后 peek 失败：%v", err)
	}
	if string(got) != "PROXY " {
		t.Fatalf("peek = %q，期望 %q —— 超时不该丢掉已到的字节", got, "PROXY ")
	}
}

// TestPeekBudgetBoundsSlowSender 证明总预算能挡住「每步都刚好在期限内到一个字节」
// 的慢速消耗 —— 单步期限单独是挡不住它的。
func TestPeekBudgetBoundsSlowSender(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() {
		for i := range 100 {
			if _, err := far.Write([]byte{byte('a' + i%26)}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	pc := NewPeekConn(near)
	pc.SetPeekBudget(100 * time.Millisecond)

	start := time.Now()
	var err error
	for range 100 {
		if _, err = pc.Peek(64, time.Second); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("总预算耗尽后 peek 必须报错")
	}
	// 第一次是 socket 期限被压到预算上（超时错误），之后才是 ErrPeekBudget；
	// 两者都算正确，关键是**不许**超过预算继续等。
	t.Logf("预算耗尽后的错误：%v（是否 ErrPeekBudget：%v）", err, errors.Is(err, ErrPeekBudget))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("总预算 100ms 却花了 %v", elapsed)
	}
}

// TestPeekTooLargeIsRejected 证明缓冲上限是硬界：判别阶段不能替对端攒内存。
func TestPeekTooLargeIsRejected(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	pc := NewPeekConnSize(near, 128)
	if _, err := pc.Peek(129, time.Millisecond); !errors.Is(err, ErrPeekTooLarge) {
		t.Fatalf("err = %v，期望 ErrPeekTooLarge", err)
	}
}

// TestPeekDiscardConsumesPrefix 证明 Discard 真的消费掉前缀 ——
// PROXY 头必须被吃掉，绝不能重放给后端（那会被当成业务首包）。
func TestPeekDiscardConsumesPrefix(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() {
		_, _ = far.Write([]byte("PREFIX业务数据"))
		far.Close()
	}()

	pc := NewPeekConn(near)
	if _, err := pc.Peek(6, time.Second); err != nil {
		t.Fatalf("peek 失败：%v", err)
	}
	if err := pc.Discard(6); err != nil {
		t.Fatalf("discard 失败：%v", err)
	}
	rest, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("读剩余失败：%v", err)
	}
	if string(rest) != "业务数据" {
		t.Fatalf("剩余 = %q，期望 %q", rest, "业务数据")
	}
}

// TestPeekReaderDoesNotConsume 证明 PeekReader 只推进「看」的偏移，不消费连接。
//
// crypto/tls 会用一个远大于所需的缓冲反复 Read，所以这个读取器
// **绝不能**为了填满调用方缓冲而阻塞 —— 否则又变成 frp 那个形状。
func TestPeekReaderDoesNotConsume(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	payload := []byte("0123456789")
	go func() { _, _ = far.Write(payload) }()

	pc := NewPeekConn(near)
	r := pc.PeekReader(time.Second)

	// 要 4096 字节但只有 10 字节可用：必须立刻返回 10 字节而不是等。
	big := make([]byte, 4096)
	start := time.Now()
	n, err := r.Read(big)
	if err != nil {
		t.Fatalf("PeekReader.Read 失败：%v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Read 等了 %v —— 不该为凑满缓冲而阻塞", elapsed)
	}
	if n != len(payload) {
		t.Fatalf("读到 %d 字节，期望 %d", n, len(payload))
	}

	// 连接本身一个字节都没被消费。
	got, err := pc.Peek(len(payload), time.Second)
	if err != nil {
		t.Fatalf("peek 失败：%v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("peek = %q，期望 %q", got, payload)
	}
}
