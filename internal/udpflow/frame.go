// Package udpflow 实现中继与 agent 共用的 UDP 流会话表与数据报帧格式。
//
// # 为什么不复用 frp 的设计
//
// frp 的 UDP 路径有四个结构性问题，本包逐条修掉（证据见
// docs/research/14-architect-udp-firsthand.md）：
//
//  1. 全部 UDP 挤一条 TCP workConn（server/proxy/udp.go:50-52）。UDP 本身
//     不可靠无序，塞进可靠有序流是**语义错配**，队头阻塞由此而来，调参调不掉。
//     本包的帧设计面向 QUIC 不可靠数据报（RFC 9221），语义逐条对应。
//
//  2. 会话表**无上限**：键是源地址字符串，每个新源地址就 net.DialUDP 一个
//     新 socket（pkg/proto/udp/udp.go:75,117-124），回收只靠 30s 读超时。
//     向公网 UDP 端口从随机源端口喷包即可耗尽 fd。本包用容量上限 + LRU +
//     每源 IP 配额 + 建表限速四重约束。
//
//  3. 全局互斥锁跨 net.DialUDP 这个阻塞 syscall 持有（:116-126），
//     所有新会话建立被串行化。本包按源地址哈希分片，锁内不做 syscall。
//
//  4. 原始目的地址被丢弃（:64 传 nil），一条隧道无法承载多个 UDP 服务。
//     本包的帧头自带 TunnelID 与目的端口。
package udpflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// 数据报帧格式。
//
// 头是**变长**的：未分片 16 字节，分片时 20 字节。全部大端。
//
//	0:1   ver
//	1:1   flags
//	2:2   tunnel   uint16  隧道的连接内短标识（由控制面分配）
//	4:4   flowID   uint32  会话标识，由发起侧分配
//	8:2   dstPort  uint16  用户实际打到的中继入口端口（frp 把这个丢了）
//	10:2  fragOff  uint16  分片偏移（以字节计）
//	12:2  fragLen  uint16  本分片长度
//	14:2  totalLen uint16  完整数据报长度；等于 fragLen 时表示未分片
//	16:4  dgramID  uint32  **仅当 FlagFragmented 置位时存在**
//	N:M   payload
//
// # 为什么需要分片字段
//
// QUIC 数据报**必须装进单个 QUIC 包**，且 quic-go 不提供查询最大尺寸的 getter ——
// 只能从 *quic.DatagramTooLargeError.MaxDatagramPayloadSize 反应式获知，
// 且 PMTUD 完成前该值偏小。所以对超限的数据报要么分片要么丢弃：
// 实时媒体应当丢弃（分片会放大丢包影响），IoT 的大报文则可以分片。
//
// # 为什么必须有 dgramID，以及为什么它只在分片时出现
//
// 第一版的帧头**没有**这个字段，而注释却声称「帧格式两者都支持」——
// 那句话是错的。同一条流上两个大数据报同时在途时，它们的分片除了
// (fragOff, totalLen) 之外没有任何区分依据；两个**长度相同**的数据报
// 交错到达时，重组器会把甲的一半和乙的一半拼在一起交付。
// 那是静默数据损坏 —— 本仓库认定最坏的一类缺陷。
//
// 所以分片必须带一个数据报标识。取 uint32 而不是 uint16：
// uint16 在高速率下会在重组超时窗口内回绕，撞上一个仍在重组的同长度
// 数据报就又是静默损坏。多两个字节换掉一整类缺陷是便宜的。
//
// 它只在分片帧上出现，所以**绝大多数**数据报（未分片的）头仍是 16 字节 ——
// 不分片的实时媒体一个字节都不多付。
const (
	// HeaderSize 是未分片帧的头长度。
	HeaderSize = 16

	// FragHeaderSize 是分片帧的头长度（多一个 uint32 的 dgramID）。
	FragHeaderSize = 20

	// Version 是数据报帧格式版本。
	//
	// 2：分片帧多带一个 dgramID。v1 的分片是不可靠的（见上），
	// 所以不做向后兼容 —— 兼容一个会静默损坏数据的格式没有意义。
	Version uint8 = 2
)

// 帧 flags 位。
const (
	// FlagFragmented 表示这是一个分片，需要重组。
	FlagFragmented uint8 = 1 << 0

	// FlagLastFrag 与 FlagFragmented 同时置位时表示末片。
	FlagLastFrag uint8 = 1 << 1

	// FlagNoReassemble 是给实时路径的提示：接收方不要为它排队等重组，
	// 缺片就整体丢弃。
	FlagNoReassemble uint8 = 1 << 2
)

// MaxPayload 是单帧载荷上限。
//
// 65535 是 totalLen 字段的表示上限，也正好是 UDP 载荷的理论上限。
const MaxPayload = 0xFFFF

// Header 是解析后的数据报帧头。
type Header struct {
	Version  uint8
	Flags    uint8
	Tunnel   uint16
	FlowID   uint32
	DstPort  uint16
	FragOff  uint16
	FragLen  uint16
	TotalLen uint16

	// DgramID 区分同一条流上并发在途的多个数据报，仅在分片时有意义。
	//
	// 没有它，两个长度相同的数据报交错到达时重组器会把两者的分片
	// 拼在一起 —— 静默数据损坏。见包顶部的说明。
	DgramID uint32
}

// Fragmented 报告该帧是否为分片。
func (h Header) Fragmented() bool { return h.Flags&FlagFragmented != 0 }

// LastFragment 报告该帧是否为末片。
func (h Header) LastFragment() bool {
	return h.Flags&FlagFragmented != 0 && h.Flags&FlagLastFrag != 0
}

// NoReassemble 报告发送方是否要求缺片即丢弃（实时路径）。
func (h Header) NoReassemble() bool { return h.Flags&FlagNoReassemble != 0 }

// AppendTo 把帧头与载荷追加到 dst，返回增长后的切片。
//
// 采用 append 风格而非返回新切片，是为了让调用方复用缓冲、避免每包一次分配 ——
// frp 每包都 make([]byte, len(buf)) 拷一次（pkg/proto/udp/udp.go:29-37）。
//
// # 长度字段由这里推导，不要求调用方重复填写
//
// 非分片帧的 FragLen 与 TotalLen 就等于 len(payload)，而 payload 已经作为
// 参数传进来了。若要求调用方再填一遍，同一个事实就有了两个来源 ——
// 忘了填或填错的帧会被 ParseFrame 以「分片字段自相矛盾」拒收，
// 而发送侧毫无察觉：包发出去了、计数器还加了，只是对端全丢。
// 我第一版就是这样，写发送器时立刻踩中。所以这里直接推导。
//
// 分片帧（Flags 含 FlagFragmented）的三个字段由调用方给出 —— 只有它知道
// 完整数据报有多长。但这里会**校验**其自洽性并在矛盾时报错，
// 而不是发出一个注定被拒的帧。
func (h Header) AppendTo(dst []byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return dst, fmt.Errorf("udpflow: 载荷 %d 超过上限 %d", len(payload), MaxPayload)
	}

	if h.Fragmented() {
		if int(h.FragLen) != len(payload) {
			return dst, fmt.Errorf("%w: FragLen=%d 但载荷 %d 字节",
				ErrFragInconsistent, h.FragLen, len(payload))
		}
		if int(h.FragOff)+int(h.FragLen) > int(h.TotalLen) {
			return dst, fmt.Errorf("%w: FragOff=%d + FragLen=%d 超过 TotalLen=%d",
				ErrFragInconsistent, h.FragOff, h.FragLen, h.TotalLen)
		}
	} else {
		h.FragOff = 0
		h.FragLen = uint16(len(payload))
		h.TotalLen = uint16(len(payload))
	}

	var hdr [FragHeaderSize]byte
	hdr[0] = Version
	hdr[1] = h.Flags
	binary.BigEndian.PutUint16(hdr[2:4], h.Tunnel)
	binary.BigEndian.PutUint32(hdr[4:8], h.FlowID)
	binary.BigEndian.PutUint16(hdr[8:10], h.DstPort)
	binary.BigEndian.PutUint16(hdr[10:12], h.FragOff)
	binary.BigEndian.PutUint16(hdr[12:14], h.FragLen)
	binary.BigEndian.PutUint16(hdr[14:16], h.TotalLen)

	n := HeaderSize
	if h.Fragmented() {
		binary.BigEndian.PutUint32(hdr[16:20], h.DgramID)
		n = FragHeaderSize
	}

	dst = append(dst, hdr[:n]...)
	dst = append(dst, payload...)
	return dst, nil
}

// 解析错误。
var (
	ErrShortFrame       = errors.New("udpflow: 帧短于头长度")
	ErrVersionMismatch  = errors.New("udpflow: 数据报帧版本不匹配")
	ErrFragInconsistent = errors.New("udpflow: 分片字段自相矛盾")
)

// ParseFrame 从 b 解出帧头与载荷。
//
// 返回的 payload 是 b 的**子切片**，不做拷贝 —— 调用方若要留存必须自己拷。
// 这是热路径，每包一次分配是负担不起的。
func ParseFrame(b []byte) (Header, []byte, error) {
	if len(b) < HeaderSize {
		return Header{}, nil, ErrShortFrame
	}
	h := Header{
		Version:  b[0],
		Flags:    b[1],
		Tunnel:   binary.BigEndian.Uint16(b[2:4]),
		FlowID:   binary.BigEndian.Uint32(b[4:8]),
		DstPort:  binary.BigEndian.Uint16(b[8:10]),
		FragOff:  binary.BigEndian.Uint16(b[10:12]),
		FragLen:  binary.BigEndian.Uint16(b[12:14]),
		TotalLen: binary.BigEndian.Uint16(b[14:16]),
	}
	if h.Version != Version {
		return Header{}, nil, fmt.Errorf("%w: 收到 %d，期望 %d", ErrVersionMismatch, h.Version, Version)
	}

	// 分片帧的头多 4 字节。必须先按 flags 判断长度再切载荷 ——
	// 按固定长度切会把 dgramID 当成载荷的前 4 字节，
	// 而 FragLen 校验会把它当成「长度不符」拒掉，表现为「分片全部丢失」。
	hdrLen := HeaderSize
	if h.Fragmented() {
		if len(b) < FragHeaderSize {
			return Header{}, nil, fmt.Errorf("%w: 分片帧短于 %d 字节", ErrShortFrame, FragHeaderSize)
		}
		h.DgramID = binary.BigEndian.Uint32(b[16:20])
		hdrLen = FragHeaderSize
	}

	payload := b[hdrLen:]

	// 分片字段必须自洽，否则重组器会被诱导做越界写或无限等待。
	if int(h.FragLen) != len(payload) {
		return Header{}, nil, fmt.Errorf("%w: FragLen=%d 但实际载荷 %d 字节",
			ErrFragInconsistent, h.FragLen, len(payload))
	}
	if h.TotalLen < h.FragLen {
		return Header{}, nil, fmt.Errorf("%w: TotalLen=%d < FragLen=%d",
			ErrFragInconsistent, h.TotalLen, h.FragLen)
	}
	// FragOff+FragLen 不得越过 TotalLen。用 int 运算避免 uint16 回绕。
	if int(h.FragOff)+int(h.FragLen) > int(h.TotalLen) {
		return Header{}, nil, fmt.Errorf("%w: FragOff=%d + FragLen=%d 超过 TotalLen=%d",
			ErrFragInconsistent, h.FragOff, h.FragLen, h.TotalLen)
	}
	// 非分片帧必须是完整数据报。
	if !h.Fragmented() {
		if h.FragOff != 0 || h.FragLen != h.TotalLen {
			return Header{}, nil, fmt.Errorf("%w: 未置分片位但 FragOff=%d FragLen=%d TotalLen=%d",
				ErrFragInconsistent, h.FragOff, h.FragLen, h.TotalLen)
		}
	}
	return h, payload, nil
}

// Key 唯一标识一条 UDP 流。
//
// 用完整五元组而非 frp 的「仅源地址字符串」：后者导致一条隧道无法区分
// 打到不同入口端口的流量。netip.AddrPort 是可比较的值类型，
// 可以直接做 map 键且不分配 —— 比 *net.UDPAddr + String() 省掉每包一次字符串化。
type Key struct {
	// Src 是用户侧源地址。
	Src netip.AddrPort
	// DstPort 是用户打到的中继入口端口。
	DstPort uint16
	// Tunnel 是隧道短标识。
	Tunnel uint16

	// FlowID 只在 **agent 侧** 使用。
	//
	// 两侧识别同一条流的依据不同：中继侧有用户的源地址，用
	// (Src, DstPort, Tunnel) 就够；agent 侧收到的帧里**没有**源地址
	// （帧头装不下，也不该装 —— 那会让 agent 知道用户的真实地址），
	// 只能用 (Tunnel, FlowID)。
	//
	// 把两者放进同一个 Key 结构、各用其中一个子集，比给两侧各写一张表要好：
	// 容量上限、每源配额、建表限速、空闲回收这四重约束在两侧都需要，
	// 而它们已经在这张表里实现并测试过了。
	FlowID uint32
}

// String 用于日志。
func (k Key) String() string {
	if k.FlowID != 0 {
		return fmt.Sprintf("t%d/f%d→:%d", k.Tunnel, k.FlowID, k.DstPort)
	}
	return fmt.Sprintf("%s→:%d/t%d", k.Src, k.DstPort, k.Tunnel)
}
