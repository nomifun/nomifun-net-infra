package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// FuzzFrame 对帧读取器做模糊测试。
//
// 这个 target 是 spec 的硬性要求，理由是：12 字节头加上「未知类型跳过 payload」
// 的规则，正是 fuzz 最擅长找出问题的形状 —— 长度字段与实际读取量一旦不一致，
// 流就会错位，而错位在正常测试里往往表现为「偶发解析失败」这种难查的症状。
// 语料库检入后，它会永久保护前向兼容这条契约。
//
// 不变量（对任意输入都必须成立）：
//   - 绝不 panic。
//   - 绝不因为一个声明的长度而分配超过 MaxPayloadSize。
//   - 若 ReadFrame 成功，则 len(Payload) 必须恰好等于 Header.Length。
//   - Serve 遇到未知类型必须继续，且不得把未知帧的 payload 当成下一个帧头。
func FuzzFrame(f *testing.F) {
	// 种子语料：覆盖每条已知路径。
	seed := func(h Header, payload []byte) {
		var b [HeaderSize]byte
		h.Version = Version
		h.Length = uint32(len(payload))
		h.marshalInto(b[:])
		f.Add(append(b[:], payload...))
	}

	seed(Header{Type: TypePing}, nil)
	seed(Header{Type: TypePong, Flags: FlagResponse}, nil)
	seed(Header{Type: TypeHello, CorrID: 1}, []byte(`{"agent_id":"a"}`))
	seed(Header{Type: Type(0x7FFF)}, []byte(`{"未来":1}`))                     // 未知，非 critical
	seed(Header{Type: Type(0x7FFE), Flags: FlagCritical}, []byte(`{"x":1}`)) // 未知，critical
	seed(Header{Type: TypeMetrics, Flags: FlagEndOfSeq}, []byte(`{}`))

	// 头声明的长度远大于实际数据 —— 截断路径。
	var trunc [HeaderSize]byte
	trunc[0] = Version
	binary.BigEndian.PutUint16(trunc[2:4], uint16(TypePing))
	binary.BigEndian.PutUint32(trunc[8:12], 1<<20)
	f.Add(trunc[:])

	// 长度超上限。
	var over [HeaderSize]byte
	over[0] = Version
	binary.BigEndian.PutUint32(over[8:12], ^uint32(0))
	f.Add(over[:])

	// 版本不匹配。
	f.Add([]byte{Version + 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})

	// 不足一个头。
	f.Add([]byte{Version, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// 路径一：逐帧读，检查 Payload 长度与 Header.Length 一致。
		r := NewReader(bytes.NewReader(data))
		for {
			fr, err := r.ReadFrame()
			if err != nil {
				// 所有错误都必须是我们定义的或标准 io 错误，不能是意外类型。
				if !errors.Is(err, io.EOF) &&
					!errors.Is(err, io.ErrUnexpectedEOF) &&
					!errors.Is(err, ErrPayloadTooLarge) &&
					!errors.Is(err, ErrVersionMismatch) {
					t.Fatalf("ReadFrame 返回了未预期的错误类型：%v", err)
				}
				break
			}
			if uint32(len(fr.Payload)) != fr.Header.Length {
				t.Fatalf("len(Payload)=%d 与 Header.Length=%d 不一致 —— 流会错位",
					len(fr.Payload), fr.Header.Length)
			}
			if fr.Header.Length > MaxPayloadSize {
				t.Fatalf("放过了超过上限的 Length=%d", fr.Header.Length)
			}
		}

		// 路径二：过 Dispatcher.Serve，确认未知类型不会让它 panic，
		// 且带 critical 的未知帧写回告时也不会崩。
		var out bytes.Buffer
		d := NewDispatcher(NewWriter(&out))
		d.Handle(TypePing, func(Frame) error { return nil })
		d.Handle(TypeHello, func(fr Frame) error {
			// 故意对任意 payload 尝试解码 —— Decode 必须优雅返错而不是 panic。
			var v map[string]any
			_ = Decode(fr, &v)
			return nil
		})
		_ = d.Serve(NewReader(bytes.NewReader(data)))
	})
}

// FuzzDecode 单独模糊 Decode，确认任意 payload 都不会让它 panic。
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{`))
	f.Add([]byte{0xff, 0xfe})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		fr := Frame{Header: Header{Type: TypeHello}, Payload: payload}

		var m map[string]any
		_ = Decode(fr, &m)

		var s struct {
			A int    `json:"a"`
			B string `json:"b"`
		}
		_ = Decode(fr, &s)
	})
}
