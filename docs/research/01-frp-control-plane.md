# Dossier 01 — frp 控制平面与线路协议

**Source tree**: `/mnt/hgfs/share/net-infra/frp` @ `d1928f96` (`git describe` → `v0.62.1-175-gd1928f96`; `version.go` 已打到 0.71.0), `go 1.25.0` (`go.mod:3`).
所有 `file:line` 均相对该目录。外部依赖 `github.com/fatedier/golib@v0.8.1` 与 `github.com/fatedier/yamux@v0.0.0-20250825093530-d0154be01cd6`(注意 `go.mod:78` 有 `replace github.com/hashicorp/yamux => github.com/fatedier/yamux`,frp 跑的是**自己的 yamux 分支**)已下载到 `/home/rika/go/pkg/mod/github.com/fatedier/` 并一并阅读。

> 任务书提到的 `pkg/msg/pack.go` / `pkg/msg/io.go` **在此版本不存在**。v1 的打包/拆包早已外移到 golib:`pkg/msg/ctl.go:20-43` 只是 `jsonMsg.NewMsgCtl()` 的薄壳,真正的 framing 在 `golib/msg/json/pack.go` 与 `golib/msg/json/process.go`。这本身是第一条教训:**核心线路协议不在仓库里**,想改 framing 得动上游库。

---

## 1. 消息集合与 v1 framing

`pkg/msg/msg.go:22-41` 定义 18 个类型字节,全是 ASCII 可打印字符:`TypeLogin='o'`, `TypeLoginResp='1'`, `TypeNewProxy='p'`, `TypeNewProxyResp='2'`, `TypeCloseProxy='c'`, `TypeNewWorkConn='w'`, `TypeReqWorkConn='r'`, `TypeStartWorkConn='s'`, `TypeNewVisitorConn='v'`, `TypeNewVisitorConnResp='3'`, `TypePing='h'`, `TypePong='4'`, `TypeUDPPacket='u'`, 加 5 个 NAT 打洞消息 `'i' 'n' 'm' '5' '6'`。`msgTypeMap`(`msg.go:43-62`)是唯一注册表,`init()` 逐条 `RegisterMsg`(`ctl.go:27-32`)。

字段语义要点:

- `Login`(`msg.go:76-93`):`RunID` 为空 = 新客户端;非空 = 断线重连,要求服务端顶替同 runID 的旧 Control。`PoolCount` 是**客户端把自己的池深度告知服务端**——池是服务端驱动的。`ClientSpec.AlwaysAuthPass`(`msg.go:66-73`)给内置 SSH 网关开的免认证后门,只在 `internal` 监听器上生效(`server/service.go:804-806`)。
- `NewProxy`(`msg.go:102-134`):一个大结构体塞了 tcp/udp/http/https/stcp/sudp/xtcp/tcpmux 全部字段,用注释分段。**没有 oneof,没有版本位**;加一种代理类型就往里加字段。
- `StartWorkConn`(`msg.go:154-161`):`SrcAddr/SrcPort/DstAddr/DstPort` 用于客户端侧重建 PROXY protocol 头(`client/proxy/proxy.go:185-198`);`ProxyName` 让客户端把这条 workConn 派发给对应 proxy。
- `UDPPacket`(`msg.go:186-190`):`Content []byte` + `LocalAddr/RemoteAddr *net.UDPAddr`,JSON tag 缩到 `"c"/"l"/"r"` ——这暗示作者知道每包 JSON 很贵。
- `ReqWorkConn`(`msg.go:152`)是空结构体,序列化成 `{}`。

**v1 线格式**(`golib/msg/json/pack.go:98-114`):

```
[1 byte typeByte][8 bytes int64 BigEndian length][length bytes JSON]
```

读取端 `golib/msg/json/process.go:242-277`:先 `c.Read(buffer)` 读 1 字节类型(注意不是 `io.ReadFull`),`typeMap` 里查不到就 `ErrMsgType` **直接断连**;再 `binary.Read(c, BigEndian, &length)`;`length > maxMsgLength` 报错。`maxMsgLength` 默认 **10240**(`golib/msg/json/msg.go:21`),frp 全仓库 `grep SetMaxMsgLength` **零命中**——即 v1 控制消息硬上限 10 KiB。

对抗性评估:
1. **9 字节头 + JSON**。`Ping{}` 上线是 11 字节,其中 9 字节是头。`int64` 长度字段配 10 KiB 上限,浪费 5 个字节。
2. **零前向兼容**。未知 typeByte = 断连(`process.go:249-252`)。旧 frps 收到新 frpc 的新消息类型会直接杀掉控制连接,而不是忽略。新工具**必须**用 "unknown type → skip payload" 语义。
3. **每消息 2 次堆分配**(`process.go:243` 的 1 字节 buf + `process.go:267` 的 payload buf),`binary.Read` 走 reflect。UDP 中继按包走这条路 = 每个 datagram 一次 JSON unmarshal + base64 解码(`Content []byte` 在 encoding/json 里是 base64)+ 多次分配。对 S1 的音视频这是灾难级。
4. `UDPPacketSize` 默认 1500(`pkg/config/v1/client.go:98`, `server.go:123`),base64 后约 2 KB,勉强塞进 10 KiB;但任何想开大 MTU / 聚合的想法都被 10 KiB 上限锁死。

## 2. wire v1 vs v2

v2 是新增的、**默认关闭**的并行协议:`WireProtocol` 默认 `"v1"`(`pkg/config/v1/client.go:149`)。

- **协商入口**:客户端先写 magic `"FRP\x00\x02\r\n"`(`pkg/proto/wire/wire.go:42`, `client/control_session.go:143-145`)。服务端 `wire.CheckMagic`(`wire.go:155-167`)用 `libnet.NewSharedConnSize(conn, 8)` 偷看 8 字节,不匹配就把 SharedConn 回放给 v1 路径(`server/service.go:563-592`)。每连接自动探测,零配置。
- **帧格式**(`wire.go:63-107`):`[uint16 type][uint16 flags][uint32 length][payload]`,8 字节头,`flags != 0` 直接拒绝(保留位),`DefaultMaxFramePayloadSize = 64*1024`(`wire.go:40`)。
- **消息帧**:`FrameTypeMessage = 16`,payload 前 2 字节是 uint16 消息类型再接 JSON(`pkg/msg/wire_v2.go:170-193`)。所以 v2 控制消息头 = 8 + 2 = **10 字节**,比 v1 的 9 字节还多 1 字节。v2 的收益不在头部大小。
- **v2 真正带来的四件事**:
  1. **能力协商**:`ClientHello`/`ServerHello`(`wire.go:175-213`, `FrameType 1/2`)交换 `Message.Codecs`、`Message.UDPPacketCodecs`、`Crypto.Algorithms` + 随机数。服务端 `NewServerHello` 选定后回 `ServerHello`(`server/service.go:645-679`)。这就是 frp 一直缺的 flag-day 逃生舱。
  2. **二进制 UDP 编码** `binary-v1`(`wire.go:39`, `pkg/msg/udp_binary.go`):flags 位图 + family/ip/port/zone + 裸 payload(`udp_binary.go:29-96`),`MaxUDPPayloadSize = 65507`。彻底干掉 base64+JSON。`NewUDPPacketReadWriter`(`udp_binary.go:319-338`)按协商结果选 codec,v1 下强制拒绝 codec(`:322-324`)。
  3. **AEAD 控制通道**:`NewAEADCryptoReadWriter`(`pkg/util/net/conn.go:278-323`)用 HKDF-SHA256 从 `auth.EncryptionKey()` 派生**双向独立密钥**,info 串包含算法与方向(`conn.go:267-271, 337-339`),salt 是握手 transcript hash(`pkg/proto/wire/crypto.go:148-155`)。这把 v1 那个 `libcrypto.NewReader/NewWriter`(`conn.go:245-258`,无 AEAD、无 transcript 绑定)升级成了正经东西。注释还诚实地写明"end-of-stream 未认证"(`conn.go:274-277`)。
  4. **64 KiB 帧上限**替代 10 KiB。
- **v2 的约束**:workConn 上禁止 ClientHello(`server/service.go:852-854`),workConn 与 control 的 wireProtocol 必须一致(`server/service.go:861-863`)。也就是说 v2 的 hello 只在控制连接上付一次 RTT,workConn 不付——设计正确。

**判断**:v2 的**帧格式 + hello 协商 + 二进制 UDP codec** 直接抄。v2 的"两套 codec 并存 + `wireProtocol` 配置项 + 到处 `switch wireProtocol`"(`pkg/msg/handler.go:79-88`, `udp_binary.go:319-338`, `server/service.go:773-784`)是历史包袱,新项目**只做一套**。

## 3. 连接建立:connector + TLS 首字节 0x17

`client/connector.go` 的 `Connector` 接口只有 `Open/Connect/Close`(`:40-44`)。`Open()` 建底层连接:quic 走 `quic.DialAddr` + `NextProtos=["frp"]`(`:104-139`);`TCPMux` 关则 `Open()` 直接返回 nil,每次 `Connect()` 都是**真 TCP 连接**(`:141-143`, `:180`);`TCPMux` 开(**默认 true**,`pkg/config/v1/client.go:154`)则建一条 TCP 后 `fmux.Client(conn, cfg)`,`MaxStreamWindowSize = 6MB`(`:150-161`)。`Connect()` 于是变成 `muxSession.OpenStream()`(`:172-177`)。

`realConnect()`(`:183-251`)是全部传输变体的汇聚点:tcp / websocket / wss / kcp,通过 `libnet.DialOption` + `AfterHook` 链装配,`wss` 特意把 websocket hook 的 priority 设成 110 让它跑在 TLS(100)之后(`:225-227`)。websocket payload 强制 `BinaryFrame`,注释解释了为什么(yamux 字节流不是 UTF-8,合规中间件会 UTF-8 校验后断连,`pkg/util/net/dial.go:48-52`)——**这个坑值得记下来**。

**0x17 首字节**:`FRPTLSHeadByte = 0x17`(`pkg/util/net/tls.go:26`)。客户端在 TLS ClientHello 前写这一个字节(`pkg/util/net/dial.go:12-21`)。服务端 `CheckAndEnableTLSServerConnWithTimeout`(`tls.go:28-56`)偷看 1 字节:
- `0x17` → `tls.Server(c, ...)`,**吞掉**该字节(`:42-45`);
- `0x16`(真 TLS 记录类型 handshake)→ `tls.Server(sc, ...)`,SharedConn 回放该字节(`:46-48`);
- 否则明文,除非 `tlsOnly` 则拒(`:49-54`)。

0x17 选得巧:它是 TLS `application_data` 记录类型,永远不会是真握手的首字节,所以能当带外标记做端口复用而不用真嗅探。**但 `DisableCustomTLSFirstByte` 自 v0.50 起默认 true**(`pkg/config/v1/client.go:184`),所以现代 frpc **根本不发 0x17**,走的是 0x16 分支。服务端仍无条件接受 0x17(`tls.go:42`)——即 frps **可被主动探测指纹**:发一个 0x17 看是否进入 TLS 握手。同时 `NewClientTLSConfig` 在没配 CA 时 `InsecureSkipVerify = true`(`pkg/transport/tls.go:150-152`),frps 默认用自签 RSA-2048 十年证书(`tls.go:37-58`)。**结论:frp 的"默认 TLS"只有加密没有服务端认证,MITM 门槛为零。**

**判断**:0x17 机制 **drop**(用 ALPN 或真 SNI/magic 嗅探替代)。`InsecureSkipVerify=true` 默认 **必须 drop**——新工具在 web console 里让服务端把自签证书指纹下发/绑定(SPKI pinning),或直接走 ACME。

## 4. 端口复用与 vhost 嗅探

`server/service.go:244-251`:bind 端口先套 `mux.NewMux(ln)`,再 `DefaultListener()`。注册的匹配器(按 `(priority, needBytesNum)` 排序,`golib/net/mux/mux.go:76-81`):

| priority | bytes | 用途 | 代码 |
|---|---|---|---|
| 0 | 4 | websocket `GET /~!frp` 前缀 | `server/service.go:289-292` |
| 1 | HTTP | vhost HTTP(仅当 `bindPort == vhostHTTPPort`) | `:313-314` |
| 1 | HTTPS | vhost HTTPS(同端口时) | `:330-331` |
| 2 | 1 | frp TLS(`0x17` 或 `0x16`) | `:351-354` |
| — | — | 默认:frp 明文控制/工作连接 | `:249` |

**致命细节**:`maxNeedBytesNum` 是所有 listener 的**全局最大值**(`mux.go:71-73`),而 `handleConn` 对**每条**连接都 `io.ReadFull(rd, data)` 读满这么多字节(`mux.go:189-198`),超时硬编码 `DefaultTimeout = 10s`(`mux.go:31`)。只要注册了 HTTP 匹配器,连 frp 明文控制连接也要先凑满 HTTP 嗅探窗口才能被派发。frp 靠 v1 Login 消息(几百字节 JSON)天然够大而侥幸过关。**新工具若做端口复用,必须用惰性 peek(bufio.Reader.Peek / 分级 peek),而不是按全局最大值 ReadFull。**

## 5. 登录、重连、心跳

`client/control_session.go:49-104` 是登录全流程:`connector.Open()` → `Connect()` → `buildLoginMsg`(带上 `previousRunID`,`:117`)→ `exchangeLogin` → 用 `loginResult.crypto` 包一层加密 RW(`:86-92`,注意 ssh-tunnel 类型跳过加密)→ 组 `SessionContext`。`exchangeLogin`(`:136-209`)在 v2 下顺序是:magic → ClientHello 帧 → Login 消息 → ServerHello 帧 → LoginResp;读取带 10 秒 deadline(`:171`)。

服务端 `RegisterControl`(`server/service.go:766-843`):runID 空则 `util.RandID()` 生成 **16 位十六进制 = 64 bit crypto/rand**(`pkg/util/util/util.go:31-48`);校验 auth;`NewControl`;`ctlManager.Add` → `WaitForHandoff()` → `Activate`。`Control` 有完整状态机 `created/pending/running/closing/closed`(`server/control.go:378-386`)+ `controlID` 区分同 runID 的世代(`:414-417`)+ `handoffBarrier` 串行化顶替(`:498-511`, `:551-560`)。**这套世代管理是 frp 多年踩坑的结晶,值得完整抄。**

**runID 是 bearer token,而且默认不校验**:`RegisterWorkConn` 先按 runID 查到 Control(`server/service.go:856`),再调 `VerifyNewWorkConn`(`:878`);但 token auth 的实现是 `if !slices.Contains(additionalAuthScopes, AuthScopeNewWorkConns) { return nil }`(`pkg/auth/token.go:82-91`),而 `AdditionalScopes` 无默认值(`pkg/config/v1/client.go:195` 且 `Complete()` `:206-209` 不填)。**默认配置下,拿到 64-bit runID 的任何人都能注入 workConn。** 新工具:workConn 必须在多路复用会话内部开流,天然继承会话认证,不存在"用 ID 认领连接"。

**重试**:首次登录 `loopLoginUntilSuccess(10s, LoginFailExit)`(`client/service.go:262`),FastBackoff `1s × 2, jitter 0.1, max 10s`(`:360-366`)。但 **`LoginFailExit` 默认 true**(`pkg/config/v1/client.go:88`)——首启失败直接进程退出(`client/service.go:263-268`)。对 S2 工厂机器人、S1 家用主机开机竞速网络,这是**明确的错误默认值**。重连路径 `keepControllerWorking`(`:277-306`)是好的:1 分钟窗口内前 3 次 200ms 快速重试,之后指数退避到 20s。

**心跳**:`TCPMux` 开启时 `HeartbeatInterval/Timeout` 默认双双 **-1**(`pkg/config/v1/client.go:156-163`),服务端 `heartbeatWorker` 见 `HeartbeatTimeout <= 0` 立即返回(`server/control.go:640-642`)。也就是**默认配置下应用层心跳完全关闭**,存活性全靠 yamux keepalive:`KeepAliveInterval = 30s`(`client/connector.go:151`, `server/service.go:716`)+ `ConnectionWriteTimeout = 10s`(`yamux/mux.go:67`)。死对端检测 ≈ 40 秒。`client/control.go:189-200` 的 `handlePong`/`lastPong` 与 `server/control.go:771-794` 的 `handlePing` 在默认配置下是死代码。对 S1(家宽上行抖动)40 秒黑洞不可接受。

## 6. workConn 流程与连接池——量化

`msg.Dispatcher`(`pkg/msg/handler.go:109-171`):`sendCh` 缓冲 100,一个 `sendLoop` 一个 `readLoop`,handler 按 `reflect.TypeOf` 分发。三个缺陷:
- `sendLoop` **完全丢弃写错误**(`:138` `_ = d.rw.WriteMsg(m)`),半死连接静默吞消息。
- `Send` 在 `sendCh` 满时**无限阻塞**(`:157-163`),没有 ctx/超时。
- `RegisterHandler` 无锁改 map(`:166-168`),只因全部注册发生在 `Run()` 之前才安全。

`pkg/transport/message.go` 的 `MessageTransporter` 用 `(msgType, laneKey)` 双层 map 在**单条控制连接**上做请求/响应关联(`:63-79`, `:107-122`),注释自称"类似 HTTP2"(`client/control.go:73-75`)。这是**在一个流复用器之上又手搓了一个流复用器**——直接 drop。

### 打开一条被代理连接要几个往返?

设 R = 中继↔frpc(家庭 NAT 后)的 RTT。

**未池化**(`poolCount` 有效值 0):
1. 用户连接到达 → `HandleUserTCPConnection` → `GetWorkConnFromPool`(`server/proxy/proxy.go:147`)→ `ctl.GetWorkConn`(`server/control.go:595`)。
2. `workConnCh` 空 → `default` 分支发 `ReqWorkConn`(`server/control.go:613-617`)。**[frps→frpc, 0.5R]**
3. frpc `handleReqWorkConn`(`client/control.go:124-162`)→ `connectServer()` → `muxSession.OpenStream()`。yamux `OpenStream` 发 SYN window-update 后**立即返回,不等 ACK**(`yamux/session.go:196-205`),仅在 inflight SYN 超 `AcceptBacklog=256` 时阻塞(`:168-173`)。**故开流本身 0 RTT。**
4. frpc 在该流上写 `NewWorkConn`。**[frpc→frps, 0.5R]**
5. frps `handleConnection` 读到(`server/service.go:511`)→ `RegisterWorkConn` → `ctl.workConnCh <- conn`(`server/control.go:329-336`)。
6. `GetWorkConnFromPool` 拿到后立刻 `WorkConn.Start` 写 `StartWorkConn`(`server/proxy/proxy.go:176-183`, `:57-62`)。**[frps→frpc, 0.5R]**
7. frpc `ReadMsgInto(&startMsg)`(`client/control.go:146-151`)→ 派发到 proxy → `libnet.Dial` 本地服务(`client/proxy/proxy.go:216-219`,10s 超时)→ `libio.Join`。

**未池化 = 3 条控制消息 = 1.5 × R + 本地 dial RTT**,数据才开始流动。

**池化**:`ctl.worker()` 启动时一次性发 `poolCount` 个 `ReqWorkConn`(`server/control.go:689-694`)。用户连接到来时 `GetWorkConn` 从 channel 直接取(`:606-612`),然后**立刻补发一个 `ReqWorkConn`**(`:635`)。剩下只有第 6 步。

**池化 = 1 条控制消息 = 0.5 × R + 本地 dial RTT**。省下整整 1 个 R。

**但默认只暖了 1 条**:`PoolCount` 客户端默认 1(`pkg/config/v1/client.go:153`),`MaxPoolCount` 服务端默认 5(`pkg/config/v1/server.go:186`),有效值 `min(1,5)=1`(`server/control.go:446`)。channel 容量 `poolCount + workConnPoolCapacityOffset(=10)`(`server/control.go:49, 457`),满则**丢弃**新 workConn(`:333-336`)。所以默认下第 2 个并发连接就要付满 1.5R。手机打开一个网页 = 6 个并发连接 = 5 个付 1.5R。**这就是 frp 首屏慢的根因,不是带宽问题。**

另有 `for i := 0; i < pxy.poolCount+1; i++` 的重试环(`server/proxy/proxy.go:150`):池里的连接可能已被家庭 NAT 空闲超时打死,写 `StartWorkConn` 失败就换下一条。这是池化的代价。

### 判断:control conn + on-demand workConn 该保留吗?

**Drop。** 论据是从代码里读出来的,不是审美:

1. 默认配置下 frp **已经**在跑 yamux(`client/connector.go:150-161`, `server/service.go:714-735`),所谓"连接池"池的是 yamux **流**,不是 TCP 连接。而 yamux 开流成本 = 12 字节 SYN + 0 RTT 等待(`yamux/session.go:196-205`)。**池化在保护的东西已经不贵了**;它保护的只是 `ReqWorkConn`→`NewWorkConn` 这一个往返,而这个往返之所以存在,纯粹因为**只有客户端能开流**。
2. yamux 是对称的:服务端 `fmux.Server(...)` 返回的 Session 同样有 `OpenStream()`。把方向翻过来——**服务端主动开流并把 StartWorkConn 头与用户首包一起 pipeline 出去**——`ReqWorkConn`/`NewWorkConn`/`StartWorkConn` 三消息全部消失,新连接建立成本降到 **0 额外 RTT**,连接池、`workConnPoolCapacityOffset`、`poolCount+1` 重试环、`RegisterWorkConn` 的 runID 认领与其全部安全问题一起被删掉。
3. `MessageTransporter`(`pkg/transport/message.go`)和 `msg.Dispatcher` 的 laneKey 分发,在有真复用器的世界里是纯赘余。控制 RPC 走一条专用流即可。

**唯一要保留 workConn 概念的地方**:非复用传输(frp 的 `tcpMux=false` 路径,`client/connector.go:141-143`)。新工具不提供这个模式即可。

---

## 7. Go 重写成本与 2026 年选型

- **多路复用**:`hashicorp/yamux` 语义清楚、`OpenStream` 零 RTT、可调 `MaxStreamWindowSize`(frp 调到 6MB,`connector.go:154`,默认才 256KiB —— `yamux/const.go:126`,长肥管道必调)。但 frp 用的是**自己的 fork**(`go.mod:78`),说明上游有未合并的修复。**推荐:QUIC 作为一等传输(`quic-go` v0.60 已在 frp 依赖里,`go.mod:20`),yamux-over-TCP 作为穿透回退。** 理由直指 S1:QUIC 每个 stream 独立丢包恢复,且 `DATAGRAM` 扩展能把音视频 UDP 真正当不可靠包送,而 frp 现在把 UDP 塞进一条 TCP/yamux 流(`server/proxy/udp.go:106-107, 225-236`;`client/proxy/udp.go:110-168`)——**队头阻塞 + 强制重传,音视频延迟必崩**。这是 frp 对 S1 最大的结构性缺陷。
- **framing**:抄 wire v2 的 `[u16 type][u16 flags][u32 len]`(`pkg/proto/wire/wire.go:63-107`),但把控制消息负载从 JSON 换掉(protobuf 或 CBOR),并把"未知类型 → 跳过 payload"写进读取器。stdlib `encoding/binary` + `io.ReadFull` 足够,不需要库。
- **握手/加密**:直接用 stdlib `crypto/tls` + ALPN(`"nomifun/1"`),别再手搓 AEAD 帧层。frp 的 `NewAEADCryptoReadWriter`(`pkg/util/net/conn.go:278-323`)是因为它必须支持明文 TCP/KCP 传输才存在的;若强制 TLS/QUIC,这一整个模块(含 HKDF、transcript hash、`crypto.go` 190 行)归零。**这是最大的一笔成本节省。**
- **重试/退避**:frp 的 `wait.FastBackoffManager`(`client/service.go:284-305`)语义好(快重试窗口 + 指数退避 + jitter),自己实现约 60 行,或用 `k8s.io/apimachinery/pkg/util/wait`。
- **端口复用嗅探**:自己写惰性 peek,别抄 `golib/net/mux`(全局 ReadFull 缺陷,见 §4)。`net/http` 的 `Protocols` + `SetUnencryptedHTTP2(true)`(`server/service.go:303-305`)说明 Go 1.25 stdlib 已能直接吃 h2c,vhost 反代不用第三方。
- **可直接抄形状的小件**:`ContextConn`(`pkg/util/net/conn.go:56-75`)、`CloseNotifyConn`(`:134-173`)、`StatsConn`(`:175-212`,但 `Read/Write` 的计数器非原子递增而 `Close` 读它,有竞态)、`WrapReadWriteCloserConn`(`:77-132`)、`wrapQuicStream.Close()` 里 `CancelRead(0)` + `Stream.Close()` 的双向关闭补丁(`:240-243`,这个坑不踩会流泄漏)。
- **控制会话世代管理**:`server/control.go` 的 `controlState` 状态机 + `controlID` + `handoffBarrier`(`:378-386, 414-417, 498-511, 542-580`)是重写时最容易低估的部分,**照抄**。

## 8. 对 S1 / S2 的逐项裁决

| frp 机制 | 证据 | S1 服务对接 | S2 反向代理 | 裁决 |
|---|---|---|---|---|
| 控制连接 + 按需 workConn | `server/control.go:595-637` | 1.5R 首字节延迟 | 同 | **Drop**,改服务端主动开流 |
| 连接池 `poolCount` | `server/control.go:689-694`, 默认 1 (`client.go:153`) | 只暖 1 条,并发即退化 | 同 | **Drop**(前提改对) |
| yamux TCPMux 默认开 | `connector.go:150-161` | 好,但 UDP 队头阻塞 | 好 | **Adapt**:QUIC 优先 |
| UDP over 单条流 + JSON/base64 | `client/proxy/udp.go:110-168`, `msg.go:186-190` | **不可用**(音视频) | 无所谓 | **Drop**,用 QUIC DATAGRAM |
| wire v2 二进制 UDP codec | `pkg/msg/udp_binary.go` | 好但仍在可靠流上 | — | **Steal 编码,弃载体** |
| wire v2 帧 + Hello 协商 | `wire.go:63-107, 175-213` | 好 | 好 | **Adopt** |
| 0x17 TLS 首字节 | `pkg/util/net/tls.go:26-56` | 指纹泄露 | 同 | **Drop**,用 ALPN |
| `InsecureSkipVerify=true` 默认 | `pkg/transport/tls.go:150-152` | 可 MITM | 可 MITM | **Drop**,证书指纹绑定 |
| `LoginFailExit=true` 默认 | `pkg/config/v1/client.go:88` | 开机竞速即退出 | **机器人变砖** | **Drop** |
| 默认关应用层心跳 | `client.go:156-163`, `control.go:640` | 40s 黑洞 | 40s 黑洞 | **Drop**,保留 10s 级心跳 |
| runID 认领 workConn 且默认不校验 | `service.go:856-884`, `token.go:82-91` | 可注入 | 可注入 | **Drop**(会话内开流即免疫) |
| `golib/net/mux` 全局 ReadFull 嗅探 | `mux.go:71-73, 189-198` | 短首包挂 10s | 同 | **Adapt**,惰性 peek |
| Control 世代/handoff 状态机 | `server/control.go:378-580` | 重连正确性 | 重连正确性 | **Adopt(照抄)** |
| websocket BinaryFrame 强制 | `pkg/util/net/dial.go:48-52` | 过网关必需 | 过网关必需 | **Adopt** |
| `NewProxy` 单巨型结构体 | `msg.go:102-134` | 难演进 | 难演进 | **Drop**,按类型分离 |
| `Dispatcher.Send` 无超时/吞写错误 | `handler.go:138, 157-163` | 可挂死 | 可挂死 | **Drop** |
