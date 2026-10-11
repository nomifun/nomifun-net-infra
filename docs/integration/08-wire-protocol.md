# 8. 线协议

这一章的目标：**让你能写出第二个 agent，不用本仓的 Go 二进制。**

Go 的 `internal/` 规则挡住了外部 import，所以在这份文档之前，除了本仓那个二进制
没人能接进来 —— 这是本项目「通用中继」定位上最硬的缺口。

> 所有数值都是从代码里逐字抽出来的，带出处。若你按本章实现却握不上手，
> 那是本章的缺陷，请提 issue 并附上 Hello 帧的十六进制转储。

## 8.1 承载与 ALPN

v1 有两个承载梯级：**L0 = QUIC/UDP**（首选）与 **L2 = TLS/TCP:443 + smux**（回退）。

第三方 agent **只实现 L0 就能工作**。L2 只在出口完全封锁 UDP 的网络里才需要，
它换的是承载而不是协议：帧格式、握手、信道绑定、数据面全部一字不改。
两处差别：

| | L0 | L2 |
|---|---|---|
| 传输 | QUIC，ALPN `nomifun-relay/1` | TCP → TLS 1.3（ALPN 同上）→ smux v2 |
| 不可靠数据报 | 有（RFC 9221） | **没有**。`SupportsDatagrams` 报 false，UDP 隧道被中继标成 degraded |
| 信道绑定 | `quic.ConnectionState().TLS` 的 exporter | `tls.Conn.ConnectionState()` 的 exporter，**同一个 label 与长度** |

smux 侧的参数两端必须一致：`Version=2`、`MaxFrameSize=32768`、
`MaxReceiveBuffer=4MiB`、`MaxStreamBuffer=512KiB`、keepalive 10s/30s
（`internal/carrier/smux.go`）。**拨号方是 smux client、中继是 server** ——
两端用同一个角色会让流 ID 撞号，症状是数据串台而不是一个干脆的错误。

> **L2 与共享入口共用 443/tcp**，靠 ALPN 区分。所以你必须真的协商
> `nomifun-relay/1`：没协商上的话中继会把连接当成业务流量交给网关，
> 而你会在一堆 HTTP 解析错误里挣扎。

| 项 | 值 | 出处 |
|---|---|---|
| ALPN | `nomifun-relay/1` | `internal/proto/frame.go:36` |
| 证书校验 | **只比 SPKI 指纹**，不校验名字与链 | agent 侧强制 `-pin` |
| 控制流 | agent 连上后**自己开**的第一条双向流 | — |
| 数据流 | **中继**开的双向流（每条被代理连接一条） | 这是 0 额外 RTT 的来源 |
| 下发流 | **中继**开的双向流，一次性，用来推隧道集合 | 见下方「中继开的流有两种」 |
| 数据报 | RFC 9221 不可靠数据报 | 见 8.6 |

`WSPath = "/_nf/t/v1"`（`frame.go:39`）是 L3（WSS+smux）梯级的升级路径，
**v1 未实现**，全仓零引用。不要实现它。

### 中继开的流有两种，必须按首帧类型分派

agent 侧 `AcceptStream` 拿到一条新流之后，**读第一帧的 type 再决定怎么处理**：

| 首帧 | 这条流是什么 | 你必须做什么 |
|---|---|---|
| `StreamOpen(0x0020)` | 一条被代理连接 | 拨本地目标，回 `StreamOK(0x0021)`，然后双向泵字节 |
| `TunnelSet(0x0010)` | 一次性的隧道集合下发 | 应用集合，**在同一条流上**回一帧 `TunnelRejected(0x0012)`，然后关流 |
| 其他 | — | 关掉这条流（并按 8.4 处理未知类型） |

出处：agent 侧 `cmd/nfagent/main.go:513-541`，中继侧 `cmd/nfrelay/runtime.go:1019-1037`。

两条硬约束，漏掉任何一条都会挂：

1. **`TunnelRejected` 必须回，即使一条都没否决**（那时回一个空对象 `{}`）。
   中继在那条流上带 **10 秒读期限**等这一帧；不回就是白等 10 秒，而且它
   永远不知道你到底接受了哪些隧道。
2. **中继只 `AcceptStream` 一次**（握手那条控制流），之后**不再接受 agent 主动
   开的流**——你开了会挂住。所以 agent→relay 的所有周期性消息（`Pong`、
   `Metrics`）都必须**复用握手那条控制流**。而那条流上**只能有一个写者**：
   QUIC 流是全双工，但两个协程同时写会把帧交错撕开，对端看到的是「协议解析
   失败」，与真正的协议不兼容长得一模一样。

## 8.2 帧头：固定 12 字节，全部大端

```
偏移  宽度  字段
 0     1    ver      协议帧头版本，**恒为 1**（proto.Version）
 1     1    flags    见下
 2     2    type     uint16，帧类型
 4     4    corrID   uint32，0 = 不是对某个请求的响应
 8     4    length   uint32，**载荷**长度（不含这 12 字节）
```

出处：`internal/proto/frame.go:140-147`（布局注释）与 `:167-184`（编解码）。

- `ver = 1`（`frame.go:24`）。**不要与数据报帧头的版本混为一谈**：那个是 **2**
  （见 8.6）。两个版本号相互独立，填错会被对端以「版本不匹配」整帧/整包丢弃。
- `HeaderSize = 12`（`frame.go:27`）
- `MaxPayloadSize = 1 << 20`（1 MiB，`frame.go:33`）—— 超过即协议错误

`flags` 的位：

| 位 | 名字 | 语义 | 出处 |
|---|---|---|---|
| b0 | `FlagResponse` | 这是一个响应帧 | `frame.go:44` |
| b1..b2 | `FlagCodecMask` | codec id，保留给将来的二进制 codec（v1 恒为 0 = JSON） | `frame.go:48` |
| b3..b5 | — | **未使用** | — |
| b6 | `FlagEndOfSeq` | 一个多帧序列的最后一帧 | `frame.go:56` |
| b7 | `FlagCritical` | 发送方要求对端必须理解这个帧 | `frame.go:60` |

载荷当前一律是 **JSON**（codec 0）。

`FlagCritical` 是 **b7（`1 << 7`）**，不是 b3 —— 本章此前写的是 b3。置错位的
后果是静默的：对端的 `Header.IsCritical()` 查的是 `1<<7`，于是它不会把你的
关键帧当关键帧，你也就收不到 `TypeUnsupported` 回执，而是什么都不发生。

## 8.3 帧类型全集

| 编号 | 名字 | 方向 | 语义 |
|---|---|---|---|
| `0x0001` | Hello | agent → relay | 版本、能力、身份 |
| `0x0002` | HelloOK | relay → agent | 协商结果 |
| `0x0003` | Ping | 双向 | 中继每 5 秒发一次，用于 RTT |
| `0x0004` | Pong | 双向 | 回显 seq |
| `0x0005` | GoAway | relay → agent | 排空，带截止时间。**定义齐全但 v1 零发送方、零处理方** |
| `0x000E` | Error | 双向 | 见 8.5 |
| `0x000F` | Unsupported | 双向 | 回应一个未知且 critical 的帧 |
| `0x0010` | TunnelSet | relay → agent | 期望隧道集合（**全量**，不是增量） |
| `0x0011` | TunnelState | agent → relay | 单条隧道状态上报 |
| `0x0012` | TunnelRejected | agent → relay | 本地策略否决，带原因 |
| `0x0020` | StreamOpen | relay → agent | 这条新流属于哪个隧道 |
| `0x0021` | StreamOK | agent → relay | 本地已连通，可以泵字节了 |
| `0x0030` | Metrics | agent → relay | 周期性计数器 |

出处：`internal/proto/frame.go:84-102`。

## 8.4 前向兼容：未知类型必须跳过，不能断连

收到不认识的类型时：

1. **跳过它**（按 `length` 丢弃载荷），继续读下一帧。**绝不关闭连接。**
2. 若该帧带 `FlagCritical`，额外回一个 `TypeUnsupported(0x000F)`，然后**仍然跳过**。

这条规则是双向的，也是这个协议能演进的唯一原因。本仓有 fuzz 覆盖它
（千万级执行无崩溃）。

## 8.5 握手

### Hello（agent → relay）

```json
{
  "protocol_version": 1,
  "agent_id": "agent-xxxxxxxxxxxx",   // 首次入网时省略
  "enrol_token": "nf_enrol_...",      // 仅首次入网
  "auth": { /* Proof，agent_id 非空时必须 */ },
  "capabilities": ["udp.datagram", "udp.cookie", "proxyproto.v2", "sni.route"],
  "version": "1.2.3",                 // 你的实现版本
  "os": "linux", "arch": "arm64",
  "hostname": "home-nas",
  "machine_id": "<32 位小写 hex>"
}
```

`protocol_version` 与帧头的 `ver` **独立**：帧头版本管 framing，这个管语义层。

`machine_id` 生成一次并持久化。它与 `agent_id` 的区别：后者可撤销重发，
前者标识物理机。**不要**从 `/etc/machine-id` 派生，也不要用 MAC —— 前者是宿主
机密（会外发进中继的库与备份），后者换网卡就变且能反查厂商。用 CSPRNG
生成 16 字节、hex 编码即可。

### Proof（鉴权证明）

```json
{"ts": 1735689600000, "nonce": "<hex>", "mac": "<hex>"}
```

时间戳的线上键名是 **`ts`**（`internal/proto/control.go:94`，Go 侧字段叫
`UnixMilli`）—— 本章此前写的是 `unix_milli`。照那个写出来的实现会让服务端
解出 `ts = 0`，偏移远超时钟窗，回一个 `auth_failed`，而错误文案指向
「时钟不对」：排查方向被完全带偏。

MAC = `HMAC-SHA256(agentKey, ProofCanonical(...))`，hex 编码。
`agentKey` 是中继在首次入网时下发的 `agent_key`（hex 字符串，**先 hex 解码成字节**
再当 HMAC 密钥）。

`ProofCanonical` 的**逐字节**布局（`internal/proto/control.go:114-130`）：

```
"nomirelay-proof-v1\n"          ← 域分隔串，含结尾换行
<len>:<protocol_version 十进制>
<len>:<ts 十进制>               ← 就是上面那个 ts
<len>:<nonce>
<len>:<alpn>                     ← "nomifun-relay/1"
<len>:<exporter>                 ← 见下
```

每个字段是 `长度(十进制ASCII) + ':' + 内容`，**没有字段间分隔符**。
用长度前缀而不是分隔符是刻意的：避免 `nonce="a|b"` 与 `nonce="a", alpn="b"` 撞车。

`exporter` 是 TLS exporter 信道绑定材料，把这份证明绑到**当前这一条** TLS 连接上：
偷到一份 Hello 也没法搬到另一条连接上重放。第三方实现**必须**算出同一份材料，
否则 MAC 不匹配、握手被拒。

按 RFC 5705 / TLS 1.3 exporter 取值（`internal/carrier/quic.go:202-219`）：

| 项 | 值 |
|---|---|
| label | `EXPORTER-nomirelay-carrier-v1` |
| context | **无**（不是空字符串，是「不提供 context」；Go 里传 `nil`） |
| 长度 | 32 字节 |

Go 里就是 `quicConn.ConnectionState().TLS.ExportKeyingMaterial("EXPORTER-nomirelay-carrier-v1", nil, 32)`。
其他语言找 TLS 栈的 exporter/`export_keying_material` 接口，注意区分
「context 缺席」与「context 为空串」—— 两者导出的材料**不同**。

拼进 canonical 的是那 32 个**原始字节**，不是 hex。

两个例外：

- **首次入网**（用 `enrol_token`）根本不带 `auth` 字段，所以绑定不参与 ——
  那时还没有密钥可签。令牌本身是一次性 bearer 凭据，它的防护是「用过即废」。
- **没有 TLS 的承载**上正确答案是**空材料**（长度 0，字段仍然写 `0:`）。
  v1 只有 QUIC 一个梯级，所以实践中总是 32 字节；L2/L3 梯级尚未实现（见
  [09-known-gaps.md](09-known-gaps.md)）。两端在同一条连接上必然得到同样的答案，
  这就是为什么「无 TLS → 空」是安全的，而**单侧**传空则会让每次重连都失败。

校验规则：
- 时钟窗 `MaxClockSkew = 60s`（`control.go:107`）。超出回 `auth_failed`。
- `nonce` 有格式要求且中继侧有有界 LRU 防重放。同一个 nonce 用第二次会被拒。

### HelloOK（relay → agent）

```json
{
  "agent_id": "agent-xxxxxxxxxxxx",
  "agent_key": "<hex>",          // **仅首次入网时下发**，必须持久化
  "capabilities": [ /* 双方能力集的**交集** */ ],
  "min_supported_protocol": 1,
  "relay_version": "dev"
}
```

能力用**交集**语义：此后双方只使用交集内的能力，新端必须**向下降级而不是失败**。

### Error

```json
{"code": "auth_failed", "message": "…", "retryable": false}
```

稳定错误码（`control.go:248-261`）：

| code | `retryable` | 什么时候 |
|---|---|---|
| `auth_failed` | **false** | 入网令牌无效/已用过（`session.go:539`） |
| `auth_failed` | **true** | 证明校验失败：MAC 不匹配、时钟超窗、信道绑定材料不对（`session.go:564`） |
| `auth_failed` | **true** | nonce 已被使用（`session.go:571`） |
| `agent_too_old` | false | 协议版本低于 `min_supported_protocol` |
| `revoked` | false | 凭据被撤销 **或** 中继查不到这个 agent |
| `rate_limited` | true | — |
| `unknown_tunnel` | — | 数据面：流指向一条不存在的隧道 |
| `target_denied` | — | agent 的本地策略拒了拨号目标 |
| `internal` | — | — |

> **同一个 `auth_failed` 下 `retryable` 有两种值，必须按它分叉。** 本章此前
> 写的是「一律 false」。照那个实现的 agent 会在一次时钟漂移或一次 nonce 撞车
> 之后**永久退出**，而那两件事都是瞬时的：校准时钟、换个 nonce、重新导出信道
> 绑定材料再试就好。本仓的 agent 正是按 `!retryable` 决定放弃的
>（`cmd/nfagent/main.go:227`），所以这个布尔值有真实后果。
>
> **`revoked` 不可区分两件事**：「真的被撤销」与「中继换了库/恢复了旧备份」
> 回的是同一个码。所以一个**已有凭据**的 agent 收到它**不应该退出**，
> 应当持续退避重试等中继恢复。本仓的 agent 就是这么做的（见 [4.4](04-agent.md)）。

## 8.6 UDP 数据报

走 QUIC 的 RFC 9221 不可靠数据报，自带一层帧头（全部大端）：

```
偏移  宽度  字段
 0     1    ver       **恒为 2**（udpflow.Version）—— 注意不是控制帧的 1
 1     1    flags
 2     2    tunnel    uint16  隧道短标识
 4     4    flowID    uint32
 8     2    dstPort   uint16  **原始目的端口**（一条隧道可承载多个 UDP 服务）
10     2    fragOff   uint16
12     2    fragLen   uint16
14     2    totalLen  uint16
16     4    dgramID   uint32  **仅当 FlagFragmented 置位时存在**
```

出处：`internal/udpflow/frame.go:43`（布局）与 `:196-209`（解析）。
`HeaderSize = 16`，分片时 `FragHeaderSize = 20`。

**`ver = 2`**（`internal/udpflow/frame.go:78`）。**数据报帧头的版本与控制帧头的版本是
两个独立的数**：控制帧是 1（`internal/proto/frame.go:24`），数据报帧是 2。数据报这边跳到
2 是因为 v1 的分片帧不带 `dgramID`，而少了它同一条流上两个等长报文交错到达会被
**静默拼混** —— 那种损坏没法兼容，所以直接换号、老版本一律拒收。

填错这个字节的现象是「UDP 隧道完全不通，而所有计数器都正常」：
`ParseFrame` 在版本不匹配时整包丢弃（`frame.go:210-212`），不回任何错误帧。

`flags`：

| 位 | 名字 | 语义 |
|---|---|---|
| b0 | `FlagFragmented` | 这是一个分片，需要重组 |
| b1 | `FlagLastFrag` | 与 b0 同时置位时表示末片 |
| b2 | `FlagNoReassemble` | 实时路径提示：接收方不要为它排队等重组 |

`dgramID` 必需：没有它，同一条流上两个等长报文交错到达会被拼混。

## 8.7 入网令牌

- 明文形状 `nf_enrol_<hex>`，库里存哈希。
- **一次性**：用过再用回 `auth_failed`（不可重试）。
- agent ID **派生自令牌哈希**，所以换令牌 = 换身份。
- 默认 TTL 15 分钟，可在签发时指定。

## 8.8 一个只有本章的人还缺什么

如实列出来：

- **`TunnelSet` / `StreamOpen` / `Metrics` 的载荷字段本章没有逐字段列出。**
  它们不影响握手，但影响你能不能真的转发流量。字段定义在
  `internal/proto/control.go` 与 `internal/tunnel/tunnel.go`（JSON tag 就是线格式）。
- **`nonce` 的确切格式约束**本章只说了「有要求」。看 `ErrProofBadNonce` 的判据。
- **`TunnelSet` 的载荷是一个隧道数组**（`[]*tunnel.Tunnel` 的 JSON），而
  `TunnelRejected` 的载荷是 `{隧道ID: 原因}` 的映射。本章不逐字段列隧道对象，
  见 `internal/tunnel/tunnel.go` 的 JSON tag。
- **没有官方的协议一致性测试套件。** 你只能靠本仓的 `nfrelay` 当对端来试。
- 本章的编号与常量**没有跨语言契约测试**守着（不像事件种类枚举那样）。
  改动线协议时它可能漂 —— 若你发现不一致，那就是缺陷。
