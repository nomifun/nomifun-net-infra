package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// TestUnknownTypeIsSkippedAndStreamStaysAligned 是本包最重要的测试。
//
// 它守护前向兼容契约：一个未知类型的帧必须被跳过，且流必须保持对齐，
// 使其后的已知帧仍能被正确解析。frp 在这里的做法是直接断连
// （golib/msg/json/process.go:249-252），导致旧服务端遇到新客户端就杀连接。
func TestUnknownTypeIsSkippedAndStreamStaysAligned(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	// 一个已知帧、一个未知帧（带非空 payload）、再一个已知帧。
	// 若跳过逻辑算错了 payload 长度，第三个帧就会解析失败。
	if err := w.WriteMessage(TypePing, 1, 0, nil); err != nil {
		t.Fatalf("写 Ping: %v", err)
	}
	const unknownType Type = 0x7FFF
	if err := w.WriteMessage(unknownType, 2, 0, map[string]string{
		"未来字段": strings.Repeat("x", 500),
	}); err != nil {
		t.Fatalf("写未知帧: %v", err)
	}
	if err := w.WriteMessage(TypePong, 3, FlagResponse, nil); err != nil {
		t.Fatalf("写 Pong: %v", err)
	}

	var gotPing, gotPong bool
	var unknownSeen []Header

	d := NewDispatcher(nil)
	d.OnUnknown = func(h Header) { unknownSeen = append(unknownSeen, h) }
	d.Handle(TypePing, func(Frame) error { gotPing = true; return nil })
	d.Handle(TypePong, func(fr Frame) error {
		gotPong = true
		if fr.Header.CorrID != 3 {
			t.Errorf("Pong 的 CorrID = %d，期望 3 —— 流很可能错位了", fr.Header.CorrID)
		}
		return nil
	})

	if err := d.Serve(NewReader(&buf)); err != nil {
		t.Fatalf("Serve 应当在跳过未知帧后正常读到 EOF，却得到：%v", err)
	}

	if !gotPing {
		t.Error("未收到未知帧之前的 Ping")
	}
	if !gotPong {
		t.Error("未收到未知帧之后的 Pong —— 跳过逻辑没有正确消费 payload")
	}
	if len(unknownSeen) != 1 {
		t.Fatalf("OnUnknown 调用了 %d 次，期望 1 次", len(unknownSeen))
	}
	if unknownSeen[0].Type != unknownType {
		t.Errorf("未知帧类型 = %v，期望 %v", unknownSeen[0].Type, unknownType)
	}
}

// TestCriticalUnknownGetsUnsupportedReplyButStillContinues 验证带 FlagCritical
// 的未知帧会收到 TypeUnsupported 回告，但连接**不**因此终止。
func TestCriticalUnknownGetsUnsupportedReplyButStillContinues(t *testing.T) {
	var in bytes.Buffer
	inW := NewWriter(&in)

	const unknownType Type = 0x7FFE
	if err := inW.WriteMessage(unknownType, 42, FlagCritical, map[string]int{"a": 1}); err != nil {
		t.Fatalf("写 critical 未知帧: %v", err)
	}
	if err := inW.WriteMessage(TypePing, 43, 0, nil); err != nil {
		t.Fatalf("写 Ping: %v", err)
	}

	var out bytes.Buffer
	outW := NewWriter(&out)

	var gotPing bool
	d := NewDispatcher(outW)
	d.Handle(TypePing, func(Frame) error { gotPing = true; return nil })

	if err := d.Serve(NewReader(&in)); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !gotPing {
		t.Error("critical 未知帧之后的 Ping 丢了 —— 连接不该被终止")
	}

	// 检查回告。
	fr, err := NewReader(&out).ReadFrame()
	if err != nil {
		t.Fatalf("读回告: %v", err)
	}
	if fr.Header.Type != TypeUnsupported {
		t.Fatalf("回告类型 = %v，期望 %v", fr.Header.Type, TypeUnsupported)
	}
	if fr.Header.CorrID != 42 {
		t.Errorf("回告 CorrID = %d，期望 42（要能关联回原帧）", fr.Header.CorrID)
	}
	if !fr.Header.IsResponse() {
		t.Error("回告应当置 FlagResponse")
	}
	var p UnsupportedPayload
	if err := Decode(fr, &p); err != nil {
		t.Fatalf("解码回告: %v", err)
	}
	if p.Type != uint16(unknownType) {
		t.Errorf("回告里的 Type = %d，期望 %d", p.Type, uint16(unknownType))
	}
}

// TestNonCriticalUnknownGetsNoReply 确认非 critical 的未知帧是静默跳过的，
// 否则一个只发单向事件的新版本对端会收到一堆无用回告。
func TestNonCriticalUnknownGetsNoReply(t *testing.T) {
	var in bytes.Buffer
	if err := NewWriter(&in).WriteMessage(Type(0x7FFD), 7, 0, nil); err != nil {
		t.Fatalf("写: %v", err)
	}

	var out bytes.Buffer
	d := NewDispatcher(NewWriter(&out))
	if err := d.Serve(NewReader(&in)); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("非 critical 未知帧不该产生回告，却写出了 %d 字节", out.Len())
	}
}

// TestPayloadTooLargeRejectedBeforeAllocation 验证超长声明会在分配之前被拒。
//
// 这是内存耗尽的防线：如果先 make([]byte, length) 再校验，一个声称 4 GiB
// 的恶意帧就能把进程打爆。
func TestPayloadTooLargeRejectedBeforeAllocation(t *testing.T) {
	// 手工构造帧头，声明一个远超上限的长度，但不提供 payload。
	// 若实现先分配再校验，这里会尝试分配 4 GiB。
	var hdr [HeaderSize]byte
	hdr[0] = Version
	binary.BigEndian.PutUint16(hdr[2:4], uint16(TypePing))
	binary.BigEndian.PutUint32(hdr[8:12], ^uint32(0)) // 0xFFFFFFFF

	_, err := NewReader(bytes.NewReader(hdr[:])).ReadFrame()
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v，期望 ErrPayloadTooLarge", err)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	var hdr [HeaderSize]byte
	hdr[0] = Version + 1
	binary.BigEndian.PutUint16(hdr[2:4], uint16(TypePing))

	_, err := NewReader(bytes.NewReader(hdr[:])).ReadFrame()
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("err = %v，期望 ErrVersionMismatch", err)
	}
}

// TestTruncatedPayloadIsUnexpectedEOF 确认 payload 被截断时报的是
// ErrUnexpectedEOF 而不是干净的 EOF —— 两者语义不同，后者会被 Serve 当成正常关闭。
func TestTruncatedPayloadIsUnexpectedEOF(t *testing.T) {
	var buf bytes.Buffer
	if err := NewWriter(&buf).WriteMessage(TypePing, 1, 0, map[string]string{"k": "vvvvvvvv"}); err != nil {
		t.Fatalf("写: %v", err)
	}
	full := buf.Bytes()

	// 砍掉最后 3 字节。
	_, err := NewReader(bytes.NewReader(full[:len(full)-3])).ReadFrame()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v，期望 io.ErrUnexpectedEOF", err)
	}
}

// TestHeaderRoundTrip 验证帧头的每个字段都能无损往返，
// 包括 flags 里的各个位。
func TestHeaderRoundTrip(t *testing.T) {
	cases := []Header{
		{Version: Version, Type: TypeHello, CorrID: 0, Length: 0},
		{Version: Version, Type: TypeHelloOK, CorrID: 1, Flags: FlagResponse, Length: 7},
		{Version: Version, Type: Type(0xFFFF), CorrID: ^uint32(0), Flags: 0xFF, Length: MaxPayloadSize},
		{Version: Version, Type: TypeMetrics, Flags: FlagEndOfSeq | FlagCritical, Length: 12},
	}
	for _, want := range cases {
		var b [HeaderSize]byte
		want.marshalInto(b[:])
		got := parseHeader(b[:])
		if got != want {
			t.Errorf("往返后 = %+v，期望 %+v", got, want)
		}
	}
}

// TestCodecBitsExtractedFromFlags 确认 codec id 是从 flags 的 b1..b2 取的，
// 不会被其他位污染。
func TestCodecBitsExtractedFromFlags(t *testing.T) {
	// 所有非 codec 位都置 1，codec 位置 0 → 应当仍解出 CodecJSON。
	h := Header{Flags: ^FlagCodecMask}
	if c := h.Codec(); c != CodecJSON {
		t.Errorf("codec = %d，期望 CodecJSON(0)；其他 flag 位污染了 codec 字段", c)
	}
}

// TestWriterIsConcurrencySafe 用 -race 验证并发写不会让帧交错。
//
// frp 的 Dispatcher 把写错误整个丢掉（pkg/msg/handler.go:138 的 `_ = WriteMsg`），
// 半死连接会静默吞消息；我们至少要保证并发下帧边界是完整的。
func TestWriterIsConcurrencySafe(t *testing.T) {
	// net.Pipe 是同步的，需要一个并发的读端。
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	const writers = 8
	const perWriter = 25
	const total = writers * perWriter

	w := NewWriter(c1)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				// 每个 writer 写不同长度的 payload，交错会立刻暴露成解析错误。
				body := map[string]string{"w": strings.Repeat("ab", id+1)}
				if err := w.WriteMessage(TypeMetrics, uint32(id*1000+j), 0, body); err != nil {
					t.Errorf("写: %v", err)
					return
				}
			}
		}(i)
	}

	done := make(chan error, 1)
	go func() {
		r := NewReader(c2)
		for n := 0; n < total; n++ {
			fr, err := r.ReadFrame()
			if err != nil {
				done <- err
				return
			}
			var body map[string]string
			if err := Decode(fr, &body); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	wg.Wait()
	if err := <-done; err != nil {
		t.Fatalf("并发写导致帧交错：%v", err)
	}
}

// TestDecodeToleratesUnknownFields 确认线上解码容忍未知字段 ——
// 否则给消息加一个字段就成了破坏性变更。
func TestDecodeToleratesUnknownFields(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"known":  "值",
		"未来加的字段": 123,
	})
	if err != nil {
		t.Fatal(err)
	}
	fr := Frame{Header: Header{Type: TypeHello}, Payload: raw}

	var dst struct {
		Known string `json:"known"`
	}
	if err := Decode(fr, &dst); err != nil {
		t.Fatalf("Decode 不该因未知字段失败：%v", err)
	}
	if dst.Known != "值" {
		t.Errorf("Known = %q，期望 %q", dst.Known, "值")
	}
}

func TestDuplicateHandlerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("重复注册同一类型应当 panic（这是编程错误）")
		}
	}()
	d := NewDispatcher(nil)
	d.Handle(TypePing, func(Frame) error { return nil })
	d.Handle(TypePing, func(Frame) error { return nil })
}

// TestRemainderPreservesCoalescedBytes 守护一个真实的数据丢失隐患。
//
// Reader 内部是 16 KiB 的 bufio.Reader，一次 Read 可能把**帧之后的业务字节**
// 一起读进缓冲。读完帧后若从裸流继续拷贝，那些字节就被静默丢弃了 ——
// 表现为「偶发丢首包」，是最难查的一类缺陷。
//
// 触发条件恰恰是规格 §2.1 刻意追求的行为：把 StreamOpen 头与用户首包
// pipeline 在同一个包里发出（那是「0 额外 RTT」的来源）。
func TestRemainderPreservesCoalescedBytes(t *testing.T) {
	var buf bytes.Buffer

	// 模拟中继的 pipeline 写法：帧与业务字节在同一个缓冲里连续写出。
	if err := NewWriter(&buf).WriteMessage(TypeStreamOpen, 0, 0,
		map[string]string{"tunnel_id": "t-1"}); err != nil {
		t.Fatal(err)
	}
	const payload = "GET /api/hello HTTP/1.1\r\nHost: x\r\n\r\n"
	buf.WriteString(payload)

	src := bytes.NewReader(buf.Bytes())
	r := NewReader(src)

	fr, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if fr.Header.Type != TypeStreamOpen {
		t.Fatalf("帧类型 = %v", fr.Header.Type)
	}

	// 关键断言：业务字节已经在缓冲里了。
	if r.Buffered() == 0 {
		t.Fatal("测试前提不成立：业务字节应当已被一并缓冲")
	}

	// 从裸流读会丢字节 —— 这正是被修掉的 bug。
	lost, _ := io.ReadAll(src)
	if len(lost) == len(payload) {
		t.Skip("这个 Reader 实现没有预读，本测试的前提不成立")
	}

	// 从 Remainder 读则完整。
	r2 := NewReader(bytes.NewReader(buf.Bytes()))
	if _, err := r2.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r2.Remainder(bytes.NewReader(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("Remainder 读到 %q，期望 %q —— 被缓冲的业务字节丢了", got, payload)
	}
}

// TestRemainderPassesThroughWhenNothingBuffered 确认无缓冲余量时不多包一层。
func TestRemainderPassesThroughWhenNothingBuffered(t *testing.T) {
	var buf bytes.Buffer
	if err := NewWriter(&buf).WriteMessage(TypePing, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	// 用一个每次只吐一个字节的 reader，确保 bufio 读完帧后缓冲为空。
	r := NewReader(&byteAtATime{data: buf.Bytes()})
	if _, err := r.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	if r.Buffered() != 0 {
		t.Skipf("缓冲里还有 %d 字节，本测试的前提不成立", r.Buffered())
	}
	sentinel := bytes.NewReader([]byte("x"))
	if got := r.Remainder(sentinel); got != io.Reader(sentinel) {
		t.Error("无缓冲余量时应当原样返回底层 reader，不必多包一层")
	}
}

// byteAtATime 每次 Read 只返回一个字节，用于制造「缓冲恰好读完」的情形。
type byteAtATime struct {
	data []byte
	pos  int
}

func (b *byteAtATime) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = b.data[b.pos]
	b.pos++
	return 1, nil
}
