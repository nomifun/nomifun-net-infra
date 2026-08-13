package proto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Reader 从底层流里读取帧。
//
// Reader 不是并发安全的：一条流应当只有一个读 goroutine。
type Reader struct {
	br     *bufio.Reader
	hdrBuf [HeaderSize]byte

	// maxPayload 允许测试收紧上限；零值表示用 MaxPayloadSize。
	maxPayload uint32
}

// NewReader 包装 r。
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 16<<10)}
}

func (r *Reader) limit() uint32 {
	if r.maxPayload == 0 {
		return MaxPayloadSize
	}
	return r.maxPayload
}

// Buffered 返回已读入缓冲但尚未被消费的字节数。
func (r *Reader) Buffered() int { return r.br.Buffered() }

// Remainder 返回一个先吐出缓冲余量、再继续读底层流的 io.Reader。
//
// # 为什么必须有这个方法
//
// 本 Reader 内部是一个 16 KiB 的 bufio.Reader，一次 Read 可能把
// **帧之后的业务字节**一起读进缓冲。读完帧后若直接从裸流继续拷贝，
// 那些已经在缓冲里的字节就被静默丢弃了 —— 表现为「偶发丢首包」，
// 而这是最难查的一类缺陷。
//
// 触发条件恰恰是我们刻意追求的行为：规格 §2.1 要求把 StreamOpen 头与
// 用户首包 pipeline 在同一个包里发出（那是「0 额外 RTT」的来源）。
// 今天不咬人只是因为 QUIC 恰好把 StreamOK 单独成包、net.Pipe 从不合并写，
// 换一个承载（smux over TCP）或对端换个写法就会丢数据。
//
// 所以凡是「先用 Reader 读一个帧、再把同一条流交给拷贝循环」的地方，
// **必须**用本方法而不是原始流。
func (r *Reader) Remainder(underlying io.Reader) io.Reader {
	if n := r.br.Buffered(); n > 0 {
		// 已缓冲的部分优先吐出，之后接回底层流。
		return io.MultiReader(io.LimitReader(r.br, int64(n)), underlying)
	}
	return underlying
}

// Frame 是一个读到的完整帧。
//
// Payload 的底层数组由 Reader 拥有，在下一次 ReadFrame 调用后即可能被复用。
// 需要留存的调用方必须自己拷贝。
type Frame struct {
	Header  Header
	Payload []byte
}

// ReadFrame 读下一个帧。
//
// 关键的前向兼容契约：ReadFrame **不**因为类型未知而报错。它只负责把帧完整读出来；
// 判断类型是否认识、以及是否跳过，由 Dispatcher 完成（见 Dispatcher.Serve）。
// 这样才能保证未知类型的 payload 被正确消费掉、流不会错位。
func (r *Reader) ReadFrame() (Frame, error) {
	if _, err := io.ReadFull(r.br, r.hdrBuf[:]); err != nil {
		return Frame{}, err
	}
	h := parseHeader(r.hdrBuf[:])

	if h.Version != Version {
		return Frame{}, fmt.Errorf("%w: 收到 %d，期望 %d", ErrVersionMismatch, h.Version, Version)
	}

	// 先校验长度，再分配。顺序反了就是一次内存耗尽攻击面。
	if h.Length > r.limit() {
		return Frame{}, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, h.Length, r.limit())
	}

	var payload []byte
	if h.Length > 0 {
		payload = make([]byte, h.Length)
		if _, err := io.ReadFull(r.br, payload); err != nil {
			// payload 截断是致命的：流已经错位，无法恢复。
			if errors.Is(err, io.EOF) {
				return Frame{}, io.ErrUnexpectedEOF
			}
			return Frame{}, err
		}
	}
	return Frame{Header: h, Payload: payload}, nil
}

// Writer 把帧写进底层流。
//
// Writer 是并发安全的：多个 goroutine 可以同时 Write，帧不会交错。
type Writer struct {
	mu sync.Mutex
	w  io.Writer

	hdrBuf [HeaderSize]byte
}

// NewWriter 包装 w。
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// WriteFrame 写一个帧。payload 可以为 nil。
func (w *Writer) WriteFrame(h Header, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(payload), MaxPayloadSize)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	h.Version = Version
	h.Length = uint32(len(payload))
	h.marshalInto(w.hdrBuf[:])

	// 头与 payload 必须在同一把锁下写出，否则并发写会交错成乱码。
	if _, err := w.w.Write(w.hdrBuf[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteMessage 用当前 codec 编码 v 并作为一个帧发出。
func (w *Writer) WriteMessage(t Type, corrID uint32, flags uint8, v any) error {
	if v == nil {
		return w.WriteFrame(Header{Type: t, CorrID: corrID, Flags: flags}, nil)
	}
	// v1 只有 CodecJSON，故直接 json.Marshal。flags 里的 codec 位保持 0。
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: 编码 %s: %w", t, err)
	}
	return w.WriteFrame(Header{Type: t, CorrID: corrID, Flags: flags}, payload)
}

// HandlerFunc 处理一个已知类型的帧。
//
// 返回错误会终止 Dispatcher.Serve —— 只对真正无法继续的情况返错；
// 业务层面的失败应当回一个 TypeError 帧而不是杀掉连接。
type HandlerFunc func(Frame) error

// Dispatcher 把读到的帧按类型分派给注册的处理器。
//
// 未注册的类型会被**跳过并继续**，这是本协议前向兼容的核心机制。
type Dispatcher struct {
	handlers map[Type]HandlerFunc

	// w 用于对未知且 critical 的帧回 TypeUnsupported。可以为 nil。
	w *Writer

	// OnUnknown 在遇到未注册类型时被调用（可选），用于打点/日志。
	OnUnknown func(Header)
}

// NewDispatcher 创建一个分派器。w 可以为 nil（此时不回 TypeUnsupported）。
func NewDispatcher(w *Writer) *Dispatcher {
	return &Dispatcher{handlers: make(map[Type]HandlerFunc), w: w}
}

// Handle 注册 t 的处理器。重复注册同一类型会 panic —— 这是编程错误，
// 且必须在 Serve 之前完成（handlers map 在 Serve 期间不加锁读取）。
func (d *Dispatcher) Handle(t Type, fn HandlerFunc) {
	if _, dup := d.handlers[t]; dup {
		panic(fmt.Sprintf("proto: 类型 %s 重复注册处理器", t))
	}
	d.handlers[t] = fn
}

// UnsupportedPayload 是 TypeUnsupported 帧的 payload。
type UnsupportedPayload struct {
	// Type 是本端不认识的那个类型（十进制）。
	Type uint16 `json:"type"`
	// Reason 面向人类，用于控制台展示。
	Reason string `json:"reason"`
}

// Serve 循环读帧并分派，直到 r 返回错误（含 io.EOF）。
//
// 前向兼容契约在此落地：
//   - 已注册类型 → 调处理器。
//   - 未注册类型 → 跳过（payload 已由 ReadFrame 消费），累计打点，**继续循环**。
//   - 未注册且带 FlagCritical → 额外回一个 TypeUnsupported，但**仍然继续**。
//
// 干净的 io.EOF 会被转成 nil：对端正常关闭不是错误。
func (d *Dispatcher) Serve(r *Reader) error {
	for {
		fr, err := r.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		fn, known := d.handlers[fr.Header.Type]
		if !known {
			if d.OnUnknown != nil {
				d.OnUnknown(fr.Header)
			}
			if fr.Header.IsCritical() && d.w != nil {
				// 尽力回告，失败不影响继续读 —— 对端可能只是单向发。
				_ = d.w.WriteMessage(TypeUnsupported, fr.Header.CorrID, FlagResponse,
					UnsupportedPayload{
						Type:   uint16(fr.Header.Type),
						Reason: "本端不认识该帧类型；已跳过",
					})
			}
			continue
		}

		if err := fn(fr); err != nil {
			return fmt.Errorf("proto: 处理 %s: %w", fr.Header.Type, err)
		}
	}
}

// Decode 把帧的 payload 解成 v。
//
// 线上**绝不**用 DisallowUnknownFields：未知字段必须被容忍，否则给消息加字段
// 就成了破坏性变更。（配置文件解析则相反，那里必须严格。）
func Decode(fr Frame, v any) error {
	if len(fr.Payload) == 0 {
		return fmt.Errorf("proto: %s 的 payload 为空", fr.Header.Type)
	}
	if c := fr.Header.Codec(); c != CodecJSON {
		return fmt.Errorf("%w: codec id %d", ErrUnsupportedCodec, c)
	}
	if err := json.Unmarshal(fr.Payload, v); err != nil {
		return fmt.Errorf("proto: 解码 %s: %w", fr.Header.Type, err)
	}
	return nil
}
