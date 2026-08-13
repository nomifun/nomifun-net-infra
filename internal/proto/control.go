package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
)

// Capability 是一个能力标记。
//
// 能力协商是本协议演进的主要手段：破坏性线格式变更才动 Version，
// 新功能一律加能力标记，这样 N-2 的 agent 仍然可用，而不是被一刀切断。
type Capability string

const (
	// CapDatagram 表示该端支持 QUIC 不可靠数据报数据面（RFC 9221）。
	CapDatagram Capability = "udp.datagram"

	// CapUDPCookie 表示该端会参与无状态 cookie 交换，用于防 UDP 反射放大。
	CapUDPCookie Capability = "udp.cookie"

	// CapProxyProtoV2 表示该端能向本地服务发出 PROXY protocol v2 头。
	CapProxyProtoV2 Capability = "proxyproto.v2"

	// CapSNIRoute 表示该端理解基于 SNI 的透传路由。
	CapSNIRoute Capability = "sni.route"

	// CapPeerTunnel 为场景三预留：agent↔agent 的对等隧道。
	//
	// v1 不实现，但**现在就必须占位**：能力集事后加不破坏线协议，
	// 而 Kind 枚举事后加则是一次 schema 迁移。
	CapPeerTunnel Capability = "tunnel.peer"

	// CapHandlerBackend 为场景三预留：agent 自己终结的能力型后端
	//（截图 / PTY / 键鼠注入），而不是拨号到一个 TCP 目标。
	CapHandlerBackend Capability = "backend.handler"
)

// AgentCapabilities 返回本版本 nfagent 声明的能力集。
func AgentCapabilities() []Capability {
	return []Capability{CapDatagram, CapUDPCookie, CapProxyProtoV2, CapSNIRoute}
}

// RelayCapabilities 返回本版本 nfrelay 声明的能力集。
func RelayCapabilities() []Capability {
	return []Capability{CapDatagram, CapUDPCookie, CapProxyProtoV2, CapSNIRoute}
}

// Hello 是 agent 在控制流上发出的第一个帧。
type Hello struct {
	// ProtocolVersion 与帧头的 Version 独立：帧头版本管 framing，
	// 这个管语义层。
	ProtocolVersion uint32 `json:"protocol_version"`

	// AgentID 是中继签发的稳定标识。首次入网时为空，
	// 此时 EnrolToken 必须存在。
	AgentID string `json:"agent_id,omitempty"`

	// EnrolToken 仅在首次入网时出现，用后即废。
	EnrolToken string `json:"enrol_token,omitempty"`

	// Auth 是握手证明，见 Proof。AgentID 非空时必须存在。
	Auth *Proof `json:"auth,omitempty"`

	// Capabilities 是本端支持的能力集。
	Capabilities []Capability `json:"capabilities"`

	// 设备画像，供控制台的节点清单展示，并为场景三的设备台账预留。
	Version  string `json:"version"` // nfagent 版本
	OS       string `json:"os"`      // runtime.GOOS
	Arch     string `json:"arch"`    // runtime.GOARCH
	Hostname string `json:"hostname"`

	// MachineID 是首启生成并持久化的稳定机器标识（EasyTier 的做法值得抄）。
	// 它与 AgentID 的区别：AgentID 可被撤销重发，MachineID 标识物理机。
	MachineID string `json:"machine_id"`
}

// Proof 是 agent 的握手证明。
//
// 这个结构专门修 frp 的三个缺陷：
//   - frp 的 GetAuthKey 是**裸 MD5**（pkg/util/util/util.go:50-56），非 HMAC；
//   - 时间戳发了但**从不校验**（pkg/auth/token.go:64-69 全仓无时钟偏移检查），
//     所以抓到一对 (timestamp, signKey) 可以**永久重放**；
//   - 证明不绑定信道，中间人终止 TLS 后就能拿走凭据冒充。
type Proof struct {
	// UnixMilli 是发起方时钟。接收方拒绝偏移超过 MaxClockSkew 的证明。
	UnixMilli int64 `json:"ts"`

	// Nonce 是 16 字节随机值的 hex，进接收方的有界 LRU 防重放。
	Nonce string `json:"nonce"`

	// MAC 是 hex(HMAC-SHA256(agentKey, canonical)),见 ProofCanonical。
	MAC string `json:"mac"`
}

// MaxClockSkew 是握手证明允许的最大时钟偏移。
//
// 60 秒是在「容忍未装 NTP 的 IoT 设备」与「压缩重放窗口」之间取的折中。
// 配合 nonce LRU，实际重放窗口是 0 —— 偏移容忍只影响首次接受。
const MaxClockSkew = 60 * time.Second

// ProofCanonical 构造被 MAC 覆盖的规范字节串。
//
// exporter 应当是 tls.ConnectionState.ExportKeyingMaterial 的输出，
// 它把证明**绑定到本条 TLS 会话**：即使在时间窗内，把证明重放到另一条
// TLS 连接上也会失败，因为 exporter 不同。这是 frp 完全没有的一层。
func ProofCanonical(protocolVersion uint32, unixMilli int64, nonce, alpn string, exporter []byte) []byte {
	// 用长度前缀而非分隔符拼接，避免字段内容包含分隔符导致的歧义
	//（比如 nonce="a|b" 与 nonce="a", alpn="b" 撞车）。
	var b []byte
	appendField := func(s []byte) {
		b = strconv.AppendUint(b, uint64(len(s)), 10)
		b = append(b, ':')
		b = append(b, s...)
	}
	b = append(b, "nomirelay-proof-v1\n"...)
	appendField(strconv.AppendUint(nil, uint64(protocolVersion), 10))
	appendField(strconv.AppendInt(nil, unixMilli, 10))
	appendField([]byte(nonce))
	appendField([]byte(alpn))
	appendField(exporter)
	return b
}

// Sign 用 agentKey 生成证明的 MAC。
func (p *Proof) Sign(agentKey []byte, protocolVersion uint32, alpn string, exporter []byte) {
	mac := hmac.New(sha256.New, agentKey)
	mac.Write(ProofCanonical(protocolVersion, p.UnixMilli, p.Nonce, alpn, exporter))
	p.MAC = hex.EncodeToString(mac.Sum(nil))
}

// 握手校验错误。调用方应把它们映射到指标标签 outcome=...，
// 因为 nf_agent_handshakes_total{outcome} 本身就是安全看板。
var (
	ErrProofMissing  = errors.New("proto: 缺少握手证明")
	ErrProofStale    = errors.New("proto: 握手证明时间戳超出允许偏移")
	ErrProofBadMAC   = errors.New("proto: 握手证明 MAC 校验失败")
	ErrProofBadNonce = errors.New("proto: 握手证明 nonce 格式非法")
)

// Verify 校验证明。
//
// now 由调用方注入以便测试（testing/synctest 的假时钟）。
// 重放检查**不在这里**：nonce 的 LRU 是有状态的，属于调用方（见 ReplayGuard）。
func (p *Proof) Verify(agentKey []byte, protocolVersion uint32, alpn string, exporter []byte, now time.Time) error {
	if p == nil {
		return ErrProofMissing
	}
	// nonce 必须是 16 字节的 hex。长度不对就没必要往下算 HMAC。
	raw, err := hex.DecodeString(p.Nonce)
	if err != nil || len(raw) != 16 {
		return ErrProofBadNonce
	}

	skew := now.Sub(time.UnixMilli(p.UnixMilli))
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxClockSkew {
		return fmt.Errorf("%w: 偏移 %s", ErrProofStale, skew)
	}

	want := hmac.New(sha256.New, agentKey)
	want.Write(ProofCanonical(protocolVersion, p.UnixMilli, p.Nonce, alpn, exporter))
	got, err := hex.DecodeString(p.MAC)
	if err != nil {
		return ErrProofBadMAC
	}
	// 恒定时间比较。frp 在同一个仓库里两套标准：dashboard 用了
	// ConstantTimeEqString，而 visitor 路径（server/visitor/visitor.go:78）
	// 和 vhost basic auth（pkg/util/vhost/http.go:201,205）用的是裸 ==。
	if subtle.ConstantTimeCompare(got, want.Sum(nil)) != 1 {
		return ErrProofBadMAC
	}
	return nil
}

// HelloOK 是中继对 Hello 的响应。
type HelloOK struct {
	// AgentID 在首次入网时由中继签发；后续连接回显既有值。
	AgentID string `json:"agent_id"`

	// AgentKey 仅在首次入网时下发（hex 编码），agent 必须持久化。
	// 后续连接此字段为空。
	AgentKey string `json:"agent_key,omitempty"`

	// Capabilities 是双方能力集的**交集**。
	// 双方此后都只使用交集内的能力，新端必须向下降级而不是失败。
	Capabilities []Capability `json:"capabilities"`

	// MinSupportedProtocol 让 agent 知道自己是否过旧，
	// 控制台据此显示「代理端过旧，请升级到 ≥ X」而不是一个裸断连。
	MinSupportedProtocol uint32 `json:"min_supported_protocol"`

	// RelayVersion 用于控制台展示与兼容性判断。
	RelayVersion string `json:"relay_version"`

	// ServerUnixMilli 让 agent 能算出自己的时钟偏移并在 status 里报出来 ——
	// 时钟错是握手失败最常见的现场原因，让它可自查。
	ServerUnixMilli int64 `json:"server_unix_milli"`
}

// NegotiateCapabilities 求两个能力集的交集，结果按字典序排序以保证确定性。
func NegotiateCapabilities(local, remote []Capability) []Capability {
	out := make([]Capability, 0, min(len(local), len(remote)))
	for _, c := range local {
		if slices.Contains(remote, c) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// GoAway 是中继在排空时推给 agent 的帧。
//
// frp 的服务端**从不排空**（只有客户端有 GracefulClose），重启即断掉所有隧道。
type GoAway struct {
	// Reason 面向人类，进 agent 日志与控制台事件流。
	Reason string `json:"reason"`

	// DeadlineUnixMilli 是中继停止转发的时刻，agent 据此提前重拨备用中继。
	DeadlineUnixMilli int64 `json:"deadline_unix_milli"`

	// Reconnect 为 false 时 agent 不应重连本中继（例如凭据已被撤销）。
	Reconnect bool `json:"reconnect"`
}

// Error 是一个结构化的协议层错误帧。
type Error struct {
	// Code 是稳定的机器可读标识，不要在日志里做前缀匹配。
	Code string `json:"code"`
	// Message 面向人类。
	Message string `json:"message"`
	// Retryable 告诉对端这个失败是否值得重试。
	Retryable bool `json:"retryable"`
}

// 稳定的错误码。
const (
	ErrCodeAuthFailed    = "auth_failed"
	ErrCodeAgentTooOld   = "agent_too_old"
	ErrCodeRevoked       = "revoked"
	ErrCodeRateLimited   = "rate_limited"
	ErrCodeUnknownTunnel = "unknown_tunnel"
	// ErrCodeTargetDenied 表示 agent 的本地策略否决了这个目标。
	//
	// 必须与 ErrCodeInternal 分开：策略否决是**用户可行动**的已知原因
	//（他自己的白名单挡住了自己的隧道），且**永不可重试**。
	// 把它塞进 internal 会同时坑两处：控制台只能说「内部错误，请重试」，
	// 而重试永远不会成功；错误码看板里 internal 那一格本该是
	// 「原因未知」，掺进已知原因后就不再是信号了。
	ErrCodeTargetDenied = "target_denied"
	ErrCodeInternal     = "internal"
)

func (e *Error) Error() string {
	return fmt.Sprintf("proto: %s: %s", e.Code, e.Message)
}

// StreamOpen 由中继在新开的数据流上首先发出，告诉 agent 这条流属于哪个隧道。
//
// 这是 §2.1 那个「0 额外 RTT」的关键：中继**主动开流**并把这个头与用户首包
// 一起 pipeline 出去。frp 反过来——只有客户端能开流，所以它必须走
// ReqWorkConn → NewWorkConn → StartWorkConn 三次往返（1.5×RTT），
// 或者靠连接池预热（默认只暖 1 条，第 2 条并发就退化）。
type StreamOpen struct {
	// TunnelID 指明目标隧道。
	TunnelID string `json:"tunnel_id"`

	// SrcAddr / SrcPort 是真实客户端地址，供 agent 生成 PROXY protocol 头。
	SrcAddr string `json:"src_addr"`
	SrcPort uint16 `json:"src_port"`

	// DstAddr / DstPort 是用户实际打到的中继入口地址。
	// frp 在 UDP 路径上把这个信息丢了（pkg/proto/udp/udp.go:64 传 nil），
	// 导致一条隧道无法承载多个服务。
	DstAddr string `json:"dst_addr"`
	DstPort uint16 `json:"dst_port"`
}

// StreamOK 是 agent 在本地拨通后的确认。
type StreamOK struct {
	// LocalAddr 是 agent 实际连到的地址，回填给控制台便于排障。
	LocalAddr string `json:"local_addr"`
}

// AgentMetrics 是 agent 周期性上报的计数器（TypeMetrics，0x0030）。
//
// # 为什么必须有这条上报
//
// 中继只看得见**自己**这一侧。agent 侧的丢弃有一整类中继完全不知道：
// 拨本地目标失败、被本地策略否决、回向发送队列满、回向数据报超限、
// 回向分片重组失败。这些的用户可见症状是「下行统计都对，就是收不到回包」，
// 而在这条上报之前，**没有任何数字**能告诉运维为什么 ——
// agent 侧的计数器全都只存在于 agent 自己的内存里。
//
// TypeMetrics 这个帧类型在协议里早就定义了（frame.go:98，注释写着
// 「agent → relay：周期性计数器」），但**从来没有人发过它**。
// 那正是「实现了但没接上」的形状：类型有、String() 有、分派也有，
// 而生产路径上一个发送点都没有。
//
// # 为什么是「累计值」而不是「增量」
//
// 累计值对丢包与重连是幂等的：中继收到任意一帧都能算出当前状态，
// 漏掉几帧只影响曲线的分辨率，不会让总数错。增量则必须每一帧都不丢，
// 而这条上报走的是控制流（可靠），但 agent 重启会让计数从 0 开始 ——
// 那时中继看到的是一次「回退」，据此就能识别出重启，而不是把它当成负增长。
type AgentMetrics struct {
	// UptimeSeconds 是 agent 进程已运行的秒数。
	//
	// 用来识别重启：计数器回退 + uptime 变小 = 重启（而不是数据异常）。
	UptimeSeconds int64 `json:"uptime_seconds"`

	// UDP 是数据报路径的计数器。agent 没有 UDP 隧道时全为 0。
	UDP AgentUDPMetrics `json:"udp"`
}

// AgentUDPMetrics 是 agent 侧 UDP 数据面的累计计数。
//
// 字段与 internal/agent 的 UDPStats / udpflow.SenderStats /
// udpflow.ReassemblerStats 一一对应。**分原因而不是一个总丢弃数** ——
// 「拨号失败」要去看本地服务，「被策略否决」要去改策略，
// 「发送队列满」要去看承载带宽，三者的运维动作没有一处相同。
type AgentUDPMetrics struct {
	// 转发量。
	PacketsToLocal   int64 `json:"packets_to_local"`
	BytesToLocal     int64 `json:"bytes_to_local"`
	PacketsFromLocal int64 `json:"packets_from_local"`
	BytesFromLocal   int64 `json:"bytes_from_local"`

	// 活跃流数。
	Flows int64 `json:"flows"`

	// 下行（中继 → 本地）丢弃原因。
	Malformed     int64 `json:"malformed"`
	UnknownTunnel int64 `json:"unknown_tunnel"`
	Denied        int64 `json:"denied"`
	DialFailed    int64 `json:"dial_failed"`
	TableFull     int64 `json:"table_full"`
	RateLimited   int64 `json:"rate_limited"`
	WriteFailed   int64 `json:"write_failed"`
	// PendingDial 是「这条流正在拨号，本包丢掉」。持续上涨说明拨号很慢，
	// 多半是 backend.addr 写成了主机名而 DNS 不稳。
	PendingDial int64 `json:"pending_dial"`
	// BackendChanged 是「隧道的后端改了，在途流被拆掉」。
	BackendChanged int64 `json:"backend_changed"`

	// 回向（本地 → 中继）发送队列。**队列满与超限的动作方向相反** ——
	// 前者要加带宽/降码率，后者要等 PMTUD 学到新值。
	SendQueueFull int64 `json:"send_queue_full"`
	SendTooLarge  int64 `json:"send_too_large"`
	SendFailed    int64 `json:"send_failed"`
	SendFragments int64 `json:"send_fragments"`
	// SendMTUProbes 是「明知超限也发一次，看路径是不是变宽了」的次数。
	SendMTUProbes int64 `json:"send_mtu_probes"`

	// 下行分片重组。Overlapping 与 TooManyFrags 是**安全信号**，
	// 与 TimedOut 那种链路质量信号不是一类。
	ReasmCompleted   int64 `json:"reasm_completed"`
	ReasmFragments   int64 `json:"reasm_fragments"`
	ReasmTimedOut    int64 `json:"reasm_timed_out"`
	ReasmOverlapping int64 `json:"reasm_overlapping"`
	ReasmTooManyFrag int64 `json:"reasm_too_many_frag"`
}
