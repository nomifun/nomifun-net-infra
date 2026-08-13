package udpflow

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello udp payload")
	h := Header{
		Tunnel:   7,
		FlowID:   0xDEADBEEF,
		DstPort:  41820,
		FragLen:  uint16(len(payload)),
		TotalLen: uint16(len(payload)),
	}

	buf, err := h.AppendTo(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != HeaderSize+len(payload) {
		t.Fatalf("编码后 %d 字节，期望 %d", len(buf), HeaderSize+len(payload))
	}

	got, gotPayload, err := ParseFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnel != h.Tunnel || got.FlowID != h.FlowID || got.DstPort != h.DstPort {
		t.Errorf("头往返不一致：got %+v want %+v", got, h)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("载荷 = %q，期望 %q", gotPayload, payload)
	}
}

// TestAppendToReusesBuffer 确认 AppendTo 是 append 风格、可复用缓冲。
//
// frp 每包都 make([]byte, len(buf)) 拷一次（pkg/proto/udp/udp.go:29-37），
// 在高 pps 的媒体路径上这是纯粹的 GC 压力。
func TestAppendToReusesBuffer(t *testing.T) {
	buf := make([]byte, 0, 2048)
	h := Header{Tunnel: 1, FragLen: 4, TotalLen: 4}

	for i := 0; i < 100; i++ {
		buf = buf[:0]
		var err error
		buf, err = h.AppendTo(buf, []byte("ping"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if cap(buf) != 2048 {
		t.Errorf("缓冲被重新分配了（cap=%d，期望仍为 2048）", cap(buf))
	}
}

// TestParseFrameRejectsInconsistentFragFields 是安全关键的测试。
//
// 分片字段若不自洽，重组器会被诱导做越界写或无限等待。
// 必须在解析层就拒掉，而不是指望重组器自己小心。
func TestParseFrameRejectsInconsistentFragFields(t *testing.T) {
	// 构造原始字节，绕过 AppendTo 的自洽保证。
	mk := func(flags uint8, fragOff, fragLen, totalLen uint16, payloadLen int) []byte {
		b := make([]byte, HeaderSize+payloadLen)
		b[0] = Version
		b[1] = flags
		b[10] = byte(fragOff >> 8)
		b[11] = byte(fragOff)
		b[12] = byte(fragLen >> 8)
		b[13] = byte(fragLen)
		b[14] = byte(totalLen >> 8)
		b[15] = byte(totalLen)
		return b
	}

	cases := []struct {
		name string
		b    []byte
	}{
		{"FragLen 与实际载荷不符", mk(0, 0, 100, 100, 10)},
		{"TotalLen 小于 FragLen", mk(FlagFragmented, 0, 10, 5, 10)},
		{"FragOff+FragLen 越过 TotalLen", mk(FlagFragmented, 95, 10, 100, 10)},
		{"未置分片位但 FragOff 非零", mk(0, 5, 10, 10, 10)},
		{"未置分片位但 FragLen != TotalLen", mk(0, 0, 10, 20, 10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseFrame(tc.b); !errors.Is(err, ErrFragInconsistent) {
				t.Fatalf("应当返回 ErrFragInconsistent，得到 %v", err)
			}
		})
	}
}

// TestParseFrameFragOffsetCannotWrap 专门验证 FragOff+FragLen 用 int 运算，
// 不会因 uint16 回绕而通过校验。
//
// 若实现写成 h.FragOff+h.FragLen > h.TotalLen（uint16 运算），
// FragOff=65530 且 FragLen=10 会回绕成 4，从而骗过检查。
func TestParseFrameFragOffsetCannotWrap(t *testing.T) {
	b := make([]byte, HeaderSize+10)
	b[0] = Version
	b[1] = FlagFragmented
	// FragOff = 65530
	b[10], b[11] = 0xFF, 0xFA
	// FragLen = 10
	b[12], b[13] = 0x00, 0x0A
	// TotalLen = 100
	b[14], b[15] = 0x00, 0x64

	if _, _, err := ParseFrame(b); !errors.Is(err, ErrFragInconsistent) {
		t.Fatalf("FragOff 回绕必须被拒（uint16 运算会算成 4 从而通过），得到 %v", err)
	}
}

func TestParseFrameRejectsShortAndBadVersion(t *testing.T) {
	if _, _, err := ParseFrame(make([]byte, HeaderSize-1)); !errors.Is(err, ErrShortFrame) {
		t.Errorf("短帧应当返回 ErrShortFrame，得到 %v", err)
	}
	b := make([]byte, HeaderSize)
	b[0] = Version + 1
	if _, _, err := ParseFrame(b); !errors.Is(err, ErrVersionMismatch) {
		t.Errorf("版本不符应当返回 ErrVersionMismatch，得到 %v", err)
	}
}

func TestFragmentFlagHelpers(t *testing.T) {
	cases := []struct {
		flags                    uint8
		frag, last, noReassemble bool
	}{
		{0, false, false, false},
		{FlagFragmented, true, false, false},
		{FlagFragmented | FlagLastFrag, true, true, false},
		// 只置 LastFrag 而不置 Fragmented 是无意义组合，
		// LastFragment 必须返回 false 而不是被误判为末片。
		{FlagLastFrag, false, false, false},
		{FlagNoReassemble, false, false, true},
	}
	for _, tc := range cases {
		h := Header{Flags: tc.flags}
		if h.Fragmented() != tc.frag {
			t.Errorf("flags=%08b Fragmented()=%v，期望 %v", tc.flags, h.Fragmented(), tc.frag)
		}
		if h.LastFragment() != tc.last {
			t.Errorf("flags=%08b LastFragment()=%v，期望 %v", tc.flags, h.LastFragment(), tc.last)
		}
		if h.NoReassemble() != tc.noReassemble {
			t.Errorf("flags=%08b NoReassemble()=%v，期望 %v", tc.flags, h.NoReassemble(), tc.noReassemble)
		}
	}
}

func TestAppendToRejectsOversizePayload(t *testing.T) {
	h := Header{}
	if _, err := h.AppendTo(nil, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("超过 MaxPayload 的载荷应当被拒")
	}
}

// FuzzParseFrame 模糊测试数据报帧解析。
//
// 不变量：绝不 panic；成功时 len(payload) 必须等于 FragLen；
// 且分片字段必须自洽（FragOff+FragLen <= TotalLen）。
// 后者是安全关键——重组器信赖这个前置条件做缓冲写入。
func FuzzParseFrame(f *testing.F) {
	add := func(h Header, payload []byte) {
		b, err := h.AppendTo(nil, payload)
		if err == nil {
			f.Add(b)
		}
	}
	add(Header{Tunnel: 1, FragLen: 4, TotalLen: 4}, []byte("ping"))
	add(Header{Flags: FlagFragmented, FragOff: 0, FragLen: 8, TotalLen: 16}, []byte("01234567"))
	add(Header{Flags: FlagFragmented | FlagLastFrag, FragOff: 8, FragLen: 8, TotalLen: 16}, []byte("89abcdef"))
	add(Header{Flags: FlagNoReassemble, FragLen: 0, TotalLen: 0}, nil)
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize))
	f.Add(bytes.Repeat([]byte{0xFF}, HeaderSize+4))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := ParseFrame(data)
		if err != nil {
			if !errors.Is(err, ErrShortFrame) &&
				!errors.Is(err, ErrVersionMismatch) &&
				!errors.Is(err, ErrFragInconsistent) {
				t.Fatalf("未预期的错误类型：%v", err)
			}
			return
		}
		if int(h.FragLen) != len(payload) {
			t.Fatalf("FragLen=%d 但 payload 长 %d", h.FragLen, len(payload))
		}
		// 重组器依赖这个不变量做缓冲写入 —— 违反即是越界写。
		if int(h.FragOff)+int(h.FragLen) > int(h.TotalLen) {
			t.Fatalf("放过了越界分片：FragOff=%d FragLen=%d TotalLen=%d",
				h.FragOff, h.FragLen, h.TotalLen)
		}
	})
}

func TestAppendToDerivesLengthFieldsForUnfragmentedFrames(t *testing.T) {
	// 长度字段就是 len(payload)，而 payload 已经作为参数传进来了。
	// 要求调用方再填一遍，就是让同一个事实有两个来源 —— 忘填的帧会被
	// ParseFrame 拒收，而发送侧毫无察觉（包发了、计数加了、对端全丢）。
	// 写发送器时立刻踩中了这个陷阱，所以这里钉住推导行为。
	payload := []byte("一条普通的 UDP 载荷")

	// 刻意**不填** FragLen / TotalLen。
	frame, err := Header{Tunnel: 7, FlowID: 42, DstPort: 5004}.AppendTo(nil, payload)
	if err != nil {
		t.Fatalf("组帧失败：%v", err)
	}

	h, got, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("自己组的帧应当能被自己解析：%v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("载荷被改动：%q", got)
	}
	if int(h.FragLen) != len(payload) || int(h.TotalLen) != len(payload) || h.FragOff != 0 {
		t.Fatalf("长度字段没被推导出来：%+v", h)
	}
}

func TestAppendToRejectsSelfContradictoryFragments(t *testing.T) {
	// 分片帧的长度只有调用方知道，但矛盾的帧必须当场报错 ——
	// 发出去只会被对端拒收，而发送侧看不到任何异常。
	payload := make([]byte, 100)

	// FragLen 与实际载荷不符。
	if _, err := (Header{Flags: FlagFragmented, FragLen: 50, TotalLen: 200}).
		AppendTo(nil, payload); err == nil {
		t.Error("FragLen 与载荷长度不符时应当报错")
	}

	// 分片超出完整长度。
	if _, err := (Header{Flags: FlagFragmented, FragOff: 180, FragLen: 100, TotalLen: 200}).
		AppendTo(nil, payload); err == nil {
		t.Error("FragOff + FragLen 超过 TotalLen 时应当报错")
	}

	// 自洽的分片应当通过，且能被解析。
	frame, err := (Header{Flags: FlagFragmented, FragOff: 100, FragLen: 100, TotalLen: 200}).
		AppendTo(nil, payload)
	if err != nil {
		t.Fatalf("自洽的分片不该被拒：%v", err)
	}
	h, _, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("自洽的分片应当能被解析：%v", err)
	}
	if !h.Fragmented() || h.FragOff != 100 || h.TotalLen != 200 {
		t.Fatalf("分片字段被改动：%+v", h)
	}
}
