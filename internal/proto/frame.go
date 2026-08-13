// Package proto 定义 NomiRelay 控制面的线协议：帧格式、消息类型与能力协商。
//
// 本包被 nfrelay 与 nfagent 共享，且不得依赖 internal/store —— agent 要能在
// 没有 SQLite 移植的平台（MIPS 路由器）上构建。
//
// # 前向兼容是硬性要求，不是优化
//
// frp 的做法是未知消息类型直接断连（golib/msg/json/process.go:249-252），
// 结果旧 frps 遇到新 frpc 的新消息会杀掉整条控制连接，零前向兼容。
// 本包的读取器遇到未知类型时跳过 payload 并**继续**，让 v1.3 的中继可以
// 永远跟 v1.0 的 agent 对话。这条规则由 FuzzFrame 与 TestUnknownTypeIsSkipped 守护。
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version 是当前线协议版本，出现在每个帧头的第 0 字节。
//
// 只有破坏性的线格式变更才递增它；新功能一律通过能力协商（见 Hello）加入，
// 这样 N-2 的 agent 仍然可用。
const Version uint8 = 1

// HeaderSize 是固定帧头的字节数。
const HeaderSize = 12

// MaxPayloadSize 是单帧 payload 的上限（1 MiB）。
//
// 读取器必须在**分配之前**校验这个上限，否则一个声称长度为 4 GiB 的恶意帧
// 就是一次内存耗尽攻击。
const MaxPayloadSize = 1 << 20

// ALPN 是 QUIC 与 TLS 承载协商用的 ALPN 标识。
const ALPN = "nomifun-relay/1"

// WSPath 是 WSS 承载（梯级 L3）的 HTTP 升级路径。
const WSPath = "/_nf/t/v1"

// 帧头 flags 位。
const (
	// FlagResponse 表示该帧是对某个 CorrID 的响应。
	FlagResponse uint8 = 1 << 0

	// FlagCodecMask 覆盖 b1..b2，保留给将来的二进制 codec。
	// v1 只用 CodecJSON。
	FlagCodecMask uint8 = 0b0000_0110
	// 显式带类型。const 组里**不会**继承上一行的类型（只有完全省略
	// `= value` 时才重复上一行），所以不写类型的话它是 untyped int ——
	// 而组里其他全是 uint8。读代码的人会以为它是 uint8，
	// 而它参与类型推导时的行为不同。staticcheck 的 SA9004 就是在讲这个。
	FlagCodecShift uint8 = 1

	// FlagEndOfSeq 标记一个多帧序列的最后一帧。
	FlagEndOfSeq uint8 = 1 << 6

	// FlagCritical 表示发送方要求对端理解该帧。
	// 未知且带此位时，接收方仍然**跳过**，但会回一个 TypeUnsupported。
	FlagCritical uint8 = 1 << 7
)

// Codec 标识 payload 的编码方式。v1 只实现 JSON。
type Codec uint8

const (
	// CodecJSON 是 v1 的唯一 codec。
	//
	// 选 JSON 而非 protobuf/CBOR 的理由：控制面低频，数据面根本不碰 codec，
	// 所以吞吐无关；JSON 在 tcpdump/slog/控制台原始帧面板里可读；默认容忍
	// 未知**字段**；且无需 codegen —— 当 Makefile 是唯一构建系统时这很重要。
	CodecJSON Codec = 0
)

// Type 是帧的消息类型。
type Type uint16

// 控制面消息类型。
//
// 编号一旦发布就不可复用：一个新版本把旧编号赋予新语义，会让 N-1 的对端
// 静默误解字节。废弃的编号留空。
const (
	// 0x0000–0x000F：连接级。
	TypeHello       Type = 0x0001 // agent → relay：版本、能力、身份
	TypeHelloOK     Type = 0x0002 // relay → agent：协商结果
	TypePing        Type = 0x0003
	TypePong        Type = 0x0004
	TypeGoAway      Type = 0x0005 // relay → agent：排空，带截止时间
	TypeError       Type = 0x000E
	TypeUnsupported Type = 0x000F // 回应一个未知且 critical 的帧

	// 0x0010–0x001F：隧道生命周期。
	TypeTunnelSet      Type = 0x0010 // relay → agent：期望隧道集合（全量）
	TypeTunnelState    Type = 0x0011 // agent → relay：单条隧道状态上报
	TypeTunnelRejected Type = 0x0012 // agent → relay：本地策略否决，带原因

	// 0x0020–0x002F：数据面建立。
	TypeStreamOpen Type = 0x0020 // relay → agent：这条新流属于哪个隧道
	TypeStreamOK   Type = 0x0021 // agent → relay：本地已连通，可以泵字节了

	// 0x0030–0x003F：遥测。
	TypeMetrics Type = 0x0030 // agent → relay：周期性计数器
)

// String 让类型在日志里可读。
func (t Type) String() string {
	switch t {
	case TypeHello:
		return "Hello"
	case TypeHelloOK:
		return "HelloOK"
	case TypePing:
		return "Ping"
	case TypePong:
		return "Pong"
	case TypeGoAway:
		return "GoAway"
	case TypeError:
		return "Error"
	case TypeUnsupported:
		return "Unsupported"
	case TypeTunnelSet:
		return "TunnelSet"
	case TypeTunnelState:
		return "TunnelState"
	case TypeTunnelRejected:
		return "TunnelRejected"
	case TypeStreamOpen:
		return "StreamOpen"
	case TypeStreamOK:
		return "StreamOK"
	case TypeMetrics:
		return "Metrics"
	default:
		return fmt.Sprintf("Type(0x%04x)", uint16(t))
	}
}

// Header 是解析后的固定 12 字节帧头。
//
// 线上布局（全部大端）：
//
//	0:1  ver
//	1:1  flags
//	2:2  type   uint16
//	4:4  corrID uint32   0 = 非请求响应的事件
//	8:4  length uint32   <= MaxPayloadSize
type Header struct {
	Version uint8
	Flags   uint8
	Type    Type
	CorrID  uint32
	Length  uint32
}

// Codec 取出 flags 里编码的 codec id。
func (h Header) Codec() Codec {
	return Codec((h.Flags & FlagCodecMask) >> FlagCodecShift)
}

// IsResponse 报告该帧是否为响应。
func (h Header) IsResponse() bool { return h.Flags&FlagResponse != 0 }

// IsCritical 报告发送方是否要求对端必须理解该帧。
func (h Header) IsCritical() bool { return h.Flags&FlagCritical != 0 }

// marshalInto 把帧头写进恰好 HeaderSize 字节的缓冲区。
func (h Header) marshalInto(b []byte) {
	b[0] = h.Version
	b[1] = h.Flags
	binary.BigEndian.PutUint16(b[2:4], uint16(h.Type))
	binary.BigEndian.PutUint32(b[4:8], h.CorrID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
}

// parseHeader 从恰好 HeaderSize 字节里解出帧头。
func parseHeader(b []byte) Header {
	return Header{
		Version: b[0],
		Flags:   b[1],
		Type:    Type(binary.BigEndian.Uint16(b[2:4])),
		CorrID:  binary.BigEndian.Uint32(b[4:8]),
		Length:  binary.BigEndian.Uint32(b[8:12]),
	}
}

// 协议层错误。
var (
	// ErrPayloadTooLarge 表示对端声称的 payload 超过 MaxPayloadSize。
	// 这是一个致命错误：长度字段已经不可信，无法安全地跳过。
	ErrPayloadTooLarge = errors.New("proto: payload 超过上限")

	// ErrVersionMismatch 表示帧头的版本不是本实现能处理的。
	ErrVersionMismatch = errors.New("proto: 线协议版本不匹配")

	// ErrUnsupportedCodec 表示 flags 里的 codec id 本实现不认识。
	ErrUnsupportedCodec = errors.New("proto: 不支持的 codec")
)
