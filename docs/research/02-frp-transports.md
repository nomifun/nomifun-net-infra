# Dossier 02 — frp 的传输/载体层（transport/carrier）

调研对象：`/mnt/hgfs/share/net-infra/frp`，commit `d1928f96` (2026-08-05)，`go 1.25.0`，`quic-go v0.60.0`、`xtaci/kcp-go/v5 v5.6.13`、`hashicorp/yamux`（被 `replace` 成 `fatedier/yamux`，见 `go.mod:78`）。
评判基线：S1 = 手机（公网）→ 中继 → 家用 NAT 后的桌面服务器，走 HTTP + WebSocket + UDP，音视频通话是目标；S2 = 工厂机器人只会配「中继 IP + 端口」，零客户端软件。

---

## 1. 载体协议全集与它们真正的实现位置

白名单只有 5 个值：`pkg/config/v1/validation/validation.go:25-31` → `tcp / kcp / quic / websocket / wss`。默认 `tcp`（`pkg/config/v1/client.go:148`）。

**服务端**：`server.Service` 为每种载体挂一个 `net.Listener` 字段（`server/service.go:80-101`），全部汇入同一个 `HandleListener` 循环（`server/service.go:684-741`），最终都变成 `handleConnection(ctx, net.Conn, internal)`。这是 frp 传输层最值得抄的一点：**载体差异在 `Accept()` 之前就被抹平，控制面只认 `net.Conn`**。

- `tcp`：`bindPort` 上 `net.Listen("tcp")` → 交给 `mux.NewMux` 嗅探复用器（`server/service.go:238-251`），frp 自己拿 `muxer.DefaultListener()`。
- `kcp`：独立 `kcpBindPort` 的 UDP 端口，`netpkg.ListenKcp`（`server/service.go:255-262`，实现在 `pkg/util/net/kcp.go:30-65`）。因为是 UDP，官方示例明确写 `kcpBindPort = 7000` 可与 `bindPort` 同值（`conf/frps_full_example.toml:9-11`）。
- `quic`：独立 `quicBindPort`，`quic.ListenAddr` + `NextProtos=["frp"]`（`server/service.go:264-277`）。QUIC 走**专用**的 `HandleQUICListener`（`server/service.go:743-764`），直接 `AcceptStream` → `netpkg.QuicStreamToNetConn`，**不经过 yamux、不经过 TLS 嗅探**。
- `websocket`：不是独立端口，而是在 TCP 嗅探复用器上注册前缀 `"GET /~!frp"`（10 字节，`server/service.go:289-293`；路径常量 `pkg/util/net/websocket.go:15`）。`NewWebsocketListener` 用 `golang.org/x/net/websocket` 起一个内嵌 `http.Server`，把升级后的 conn 塞进 `acceptCh`（`pkg/util/net/websocket.go:27-58`）。注意它显式设 `PayloadType = websocket.BinaryFrame` 并留了注释解释原因：隧道载荷是 yamux 裸字节流，默认 text 帧会被合规中间件做 UTF-8 校验后掐断（`pkg/util/net/websocket.go:34-39`，客户端对称处理在 `pkg/util/net/dial.go:48-52`）。**这个坑值得直接继承。**
- `wss`：**frps 根本不支持**。官方 e2e 测试自己写着 "frps only supports ws, so there should be a proxy to terminate TLS before frps"（`test/e2e/v1/basic/client_server.go:115-116`），测试用另一个 frpc 的 `https2http` 插件卸载 TLS（同文件 `:127-136`）。客户端确实实现了 `wss`（TLS 优先级 100 → websocket 优先级 110，`client/connector.go:223-227`），但服务端 TCP 嗅探器看到的第一字节是 `0x16`，会被路由到 `httpsMuxer` 或 frp 自己的 `tlsListener`，之后 `handleConnection` 期待 frp 消息却收到 HTTP Upgrade → 失败。**结论：`wss` 是「必须外挂 nginx/Caddy」的伪载体，文档没说清。**

**客户端**：`client/connector.go` 一个文件搞定所有载体。`Open()` 建立底层承载（QUIC conn 或 yamux session），`Connect()` 出一条流（`client/connector.go:100-181`）。`Connector` 接口只有 `Open/Connect/Close` 三个方法（`client/connector.go:40-44`）——**抽象干净，直接抄**。

关键结构（值得照搬的形状）：

```go
type Connector interface { Open() error; Connect() (net.Conn, error); Close() error }
// Open(): quic → quic.DialAddr 存 quicConn；tcp/ws/wss/kcp → realConnect + yamux.Client 存 muxSession；
//         TCPMux=false → 什么都不做，Connect() 每次新建真实连接
// Connect(): quicConn != nil → OpenStreamSync；muxSession != nil → OpenStream；否则 realConnect()
```

`realConnect()`（`client/connector.go:183-251`）把载体差异塞进 `golib/net` 的 **DialOption + 带优先级的 AfterHook 链**：`websocket` → hook(websocket, prio 10) + hook(0x17, prio 10) + TLS(prio MaxUint64)，即「先 WS 握手，再在 WS 里跑 TLS」；`wss` → TLS(prio 100) + websocket(prio 110)，即「先 TLS，再在 TLS 里跑 WS」。这个「优先级排序的 hook 链」（`golib/net/dial.go:69-82`）是本层最优雅的设计，用一套代码表达了两种嵌套顺序。

---

## 2. TLS：`enable` / `force` / 0x17 消歧字节 / mTLS

**默认值（v0.50.0 起）**：`tls.enable = true`、`tls.disableCustomTLSFirstByte = true`（`pkg/config/v1/client.go:182-185`）。

**0x17 消歧字节**。常量 `FRPTLSHeadByte = 0x17`（`pkg/util/net/tls.go:26`）。客户端在 TLS 握手前多写一个 `0x17`（`pkg/util/net/dial.go:12-22`）。服务端 `CheckAndEnableTLSServerConnWithTimeout`（`pkg/util/net/tls.go:28-57`）用 `SharedConnSize(c, 2)` 预读 1 字节后三分支：

| 首字节 | 处理 | 说明 |
|---|---|---|
| `0x17` | `tls.Server(c, ...)`（用原 conn，字节已被吃掉） | frp 自定义前缀 |
| `0x16` | `tls.Server(sc, ...)`（用 SharedConn，字节被回放） | 真实 TLS ClientHello |
| 其他 | `tlsOnly` 为真则报错，否则明文 `sc` | `transport.tls.force` |

`tlsOnly` 就是 `svr.cfg.Transport.TLS.Force`（`server/service.go:701-703`）。而 `Force` 在配置补全阶段被隐式打开：只要设了 `trustedCaFile`，`c.TLS.Force = true`（`pkg/config/v1/server.go:194-196`）——一个「设了 CA 就自动强制 TLS」的贴心默认。

`0x17` 存在的唯一理由写在代码注释里：`// tls first byte can be 0x16 only when vhost https port is not same with bind port`（`server/service.go:351-354`）。也就是说，当 `bindPort == vhostHTTPSPort` 时，`0x16` 会被 vhost 的 SNI 复用器抢走，frp 控制连接必须用 `0x17` 才能被认出来。

> **对抗性发现 A（严重，且无校验）**：默认 `disableCustomTLSFirstByte = true` 意味着 frpc **不发** `0x17`，只发 `0x16`。而 `bindPort == vhostHTTPSPort` 时 `httpsMuxer` 以 priority 1 注册（`server/service.go:330-331`）、`tlsListener` 以 priority 2 注册（`server/service.go:351`），排序规则是 priority 升序、同 priority 再按 needBytes 升序（`golib/net/mux/mux.go:76-81`），所以 `0x16` 必然命中 `httpsMuxer`。**即「443 端口复用」+「默认 TLS 配置」= 控制连接被吞。** 必须每个客户端显式写 `transport.tls.disableCustomTLSFirstByte = false`，而 `pkg/config/v1/validation/` 下没有任何一处交叉校验这个组合（`validation/server.go:48-53` 只校验端口范围，`validation/client.go:143-175` 只校验协议白名单）。

> **对抗性发现 B（安全）**：`NewClientTLSConfig` 在 `caPath == ""` 时设 `base.InsecureSkipVerify = true`（`pkg/transport/tls.go:150-152`），而服务端在没配证书时用 `newRandomTLSKeyPair()` 自签（`pkg/transport/tls.go:100-102`）。所以 **frp 的「默认开启 TLS」是纯机会性加密，零服务端身份认证**；主动 MITM 可以在中间解密并拿到 `Login` 里的 token。QUIC 路径同样如此（`client/connector.go:111-119`，且 `tls.enable=false` 对 QUIC 无效——照样建 TLS 配置）。

**mTLS**：服务端 `caPath != ""` → `ClientAuth = RequireAndVerifyClientCert` + `ClientCAs`（`pkg/transport/tls.go:118-123`）；客户端 `certFile`/`keyFile` → `base.Certificates`（`pkg/transport/tls.go:131-137`）。QUIC 监听器 clone 同一个 `tlsConfig`（`server/service.go:266-267`），**所以 mTLS 对 QUIC 同样生效**——这点做得对。

---

## 3. 端口复用与协议嗅探

复用器是 `github.com/fatedier/golib/net/mux`，仅 266 行（`golib/net/mux/mux.go`）。模型：

```go
mux := mux.NewMux(ln)                 // server/service.go:244
mux.Listen(priority int, needBytesNum uint32, fn MatchFunc) net.Listener
mux.ListenHTTP(p)  // needBytes 3, 匹配 GET/HEA/POS/PUT/DEL/CON/OPT/TRA/PAT/PRI  (rule.go:19-39)
mux.ListenHTTPS(p) // needBytes 1, 匹配 data[0]==0x16                            (rule.go:11-16)
mux.DefaultListener()                 // 兜底
```

`handleConn` 对每条连接：设 `SetKeepAlivePeriod`（`mux.go:179-187`）→ `NewSharedConnSize(conn, maxNeedBytesNum)` → `io.ReadFull` 读满 **全局最大** 前缀长度（`mux.go:189-197`，超时 `DefaultTimeout = 10s`，`mux.go:29-32`）→ 按排序遍历 matcher → 命中则把 SharedConn 投给对应 listener 的 channel。

frps 在 `bindPort` 上注册的规则集（按最终排序）：

1. priority 0，10 字节，`"GET /~!frp"` → websocket（`server/service.go:289-293`）
2. priority 1，1 字节，`0x16` → vhost HTTPS SNI 复用器（仅当 `bindPort == vhostHTTPSPort`，`server/service.go:328-331`）
3. priority 1，3 字节，HTTP method → vhost HTTP 反代（仅当 `bindPort == vhostHTTPPort`，`server/service.go:313-320`）
4. priority 2，1 字节，`0x17 || 0x16` → frp TLS 控制连接（`server/service.go:351-354`）
5. default → frp 明文控制连接（含 wire v2 magic `"FRP\x00\x02\r\n"`，7 字节，`pkg/proto/wire/wire.go:42`，"FRP" 不在 HTTP method 表里所以安全落到兜底）

复用开关是隐式的：`cfg.BindAddr == cfg.ProxyBindAddr && cfg.BindPort == cfg.VhostHTTPPort` 才置 `httpMuxOn`（`server/service.go:228-235`）。`tcpmuxHTTPConnectPort` 则**不参与**这个复用器，它自己 `net.Listen` 一个独立端口（`server/service.go:190-203`），走 `vhost.Muxer` + `http.ReadRequest` 解析 `CONNECT`（`pkg/util/tcpmux/httpconnect.go:52-70`）。vhost HTTPS 侧的嗅探是真正解析 ClientHello 取 SNI，手法很聪明：用 `tls.Server(readOnlyConn{reader}, &tls.Config{GetConfigForClient: ...})` 借 stdlib 解析后故意让握手失败（`pkg/util/vhost/https.go:38-70`）。

> **对抗性发现 C**：`maxNeedBytesNum` 是**全局**的（`mux.go:71-73`）。注册了 websocket 规则后，**所有**落到 `bindPort` 的连接都必须先吐出 10 字节才会被分派。任何「服务端先说话」或「客户端首包 < 10 字节后等回复」的协议在这个端口上会挂满 10 秒再被关掉。加上 `wire.CheckMagic` 又要阻塞读 7 字节（`pkg/proto/wire/wire.go:155-162`，超时 `connReadTimeout = 10s`，`server/service.go:62`），单条恶意连接可以占住 goroutine + 2 个 buffer 约 20 秒，且代码里没有任何 accept 并发上限。

> **对抗性发现 D**：`KCPListener` 的 `acceptCh` 是无缓冲 channel，单 goroutine 生产（`pkg/util/net/kcp.go:38-63`），消费者一慢就阻塞整个 KCP accept 循环；`closeFlag` 是裸 `bool`，声明在 `kcp.go:27`、由 accept goroutine 读（`kcp.go:48`）、由 `Close()` 写（`kcp.go:76-77`）——data race。

---

## 4. QUIC / KCP 调参与默认值出处

**QUIC**：只暴露 3 个参数，`QUICOptions{KeepalivePeriod, MaxIdleTimeout, MaxIncomingStreams}`（`pkg/config/v1/common.go:38-42`），默认 `10s / 30s / 100000`（`pkg/config/v1/common.go:44-48`，客户端在 `client.go:164` 调 `Complete()`，服务端在 `server.go:193`）。两端各自把它填进 `quic.Config`（`client/connector.go:129-133`；`server/service.go:268-272`）。两个环境变量在 `init()` 里被硬写（`server/service.go:69-77`）：`QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true`、`QUIC_GO_DISABLE_ECN=true`（注释：ECN "may cause issues on certain operating systems"）。

> **对抗性发现 E**：frp **完全没有**碰 quic-go 的流控与 MTU 旋钮。`quic-go v0.60.0` 的 `Config` 里 `InitialStreamReceiveWindow / MaxStreamReceiveWindow / InitialConnectionReceiveWindow / MaxConnectionReceiveWindow / InitialPacketSize / DisablePathMTUDiscovery / Allow0RTT / EnableDatagrams` 都存在（`quic-go@v0.60.0/interface.go:124-177`），frp 一个都没用（全仓 grep 无命中）。对比它给 yamux 显式设了 `MaxStreamWindowSize = 6 * 1024 * 1024`（`client/connector.go:154`、`server/service.go:719`）——**QUIC 路径的高 BDP 吞吐是没调过的**。
> 更要紧的是 **`EnableDatagrams` 未启用**：frp 的 QUIC 只是「可靠有序流的多路复用器」，RFC 9221 不可靠数据报完全没用上。

**KCP**：参数全是硬编码，没有任何配置项。服务端 `kcp.ListenWithOptions(addr, nil, 10, 3)` → 无加密 + FEC dataShards=10/parityShards=3（约 30% 冗余带宽），listener 读写缓冲 4 MB（`pkg/util/net/kcp.go:31-36`）；每条 accept 的连接 `SetStreamMode(true) / SetWriteDelay(true) / SetNoDelay(1, 20, 2, 1) / SetMtu(1350) / SetWindowSize(1024, 1024) / SetACKNoDelay(false)`（`kcp.go:54-59`）。客户端拨号在 golib：同样 `(nil, 10, 3)`、`SetNoDelay(1,20,2,1)`、`SetMtu(1350)`，但 **`SetWindowSize(128, 512)`**（`golib/net/dial.go:106-122`）。注意这个**服务端 1024/1024 vs 客户端 128/512 的不对称**，且没有任何注释解释。KCP 没有加密（block=nil），完全依赖上层 TLS-over-KCP（`server/service.go:382-383` 走 `HandleListener(..., false)`，即照样跑 `CheckAndEnableTLSServerConnWithTimeout`）。

**yamux**：`fmux.DefaultConfig()` + `KeepAliveInterval = tcpMuxKeepaliveInterval`（默认 30s，`pkg/config/v1/client.go:155`）+ `MaxStreamWindowSize = 6MB`，两端对称（`client/connector.go:150-159`、`server/service.go:715-720`）。`tcpMux` 开启时应用层心跳被自动关掉（`HeartbeatInterval/Timeout = -1`，`pkg/config/v1/client.go:156-159`；服务端 `pkg/config/v1/server.go:187-192`）——**「有 mux keepalive 就不要应用层心跳」这条决策值得抄**。

---

## 5. frpc 出站代理（HTTP / HTTPS / SOCKS5 / NTLM）

`transport.proxyURL`，默认读环境变量 `http_proxy`（`pkg/config/v1/client.go:152`）。解析用 `libnet.ParseProxyURL`（`client/connector.go:208`，实现 `golib/net/util.go:7-19`：`url.Parse` 取 `Scheme`/`Host`/`User`）。白名单 `{"socks5","http","https","ntlm"}`（`golib/net/dial_option.go:33`，校验在 `golib/net/dial.go:46-51`）。

机制：`WithProxy` 把「真实目标地址」换成代理地址（`golib/net/dial.go:54-57`），并注册一个 **priority 0**（最先执行）的 AfterHook 做隧道协商（`dial_option.go:120-160`）：

- `http` → 手写 `CONNECT http://<addr>` + `Proxy-Authorization: Basic ...`，`http.ReadResponse` 检查 200（`dial_option.go:279-303`）
- `https` → 先对代理做 `tls.Client` + `HandshakeContext`（ServerName 未设时从代理地址推导，`dial_option.go:305-330`），再复用 http 的 CONNECT
- `socks5` → 借 `golang.org/x/net/proxy.SOCKS5`，用一个假 dialer 把已有 conn 喂进去（`dial_option.go:252-277`）——**这个「用 funcDialContext 包住已建连接」的技巧很好用**
- `ntlm` → CONNECT → 407 → 解 `Proxy-Authenticate: Negotiate` challenge → `ntlmssp.NewAuthenticateMessage` 重发（`dial_option.go:332-386`，依赖 `github.com/Azure/go-ntlmssp`）

> **对抗性发现 F**：`proxyURL` 对 **quic 静默失效**——`Open()` 在 QUIC 分支直接 return，从不走 `realConnect()`（`client/connector.go:104-139`），配置了也不报错。对 **kcp** 更糟：`dstAddr` 被换成代理地址后 `dial()` 走 `dialKCPServer`（`golib/net/dial.go:99-100`），等于用 KCP 去 UDP-拨一个 HTTP 代理，必然失败但错误信息毫无提示。配置注释只写了 "it only works when protocol is tcp"（`conf/frpc_full_example.toml:113`），代码零校验。

---

## 6. 对 S1/S2 的逐项裁决

| 机制 | S1 | S2 | 裁决 |
|---|---|---|---|
| `Connector` 三方法抽象 + 载体在 Accept 前抹平 | ✔ | ✔ | **抄** |
| TCP + yamux（6MB 窗口、keepalive 替代心跳） | 可用 | 可用 | **抄，作为兜底载体** |
| QUIC（仅 stream，无 datagram） | 半成品 | 可用 | **改造后采纳**（见 §7） |
| KCP（硬编码 FEC 10/3、无配置、无加密、accept 有 race） | 差 | 差 | **丢弃**。它解决的「高丢包下 TCP 崩」问题 QUIC 用 BBR/PMTUD 做得更好，且 KCP 的 30% FEC 冗余对家用上行是净损失 |
| `websocket`（ws-in-TCP，binary frame） | ✔ | — | **抄**，作为「只放 443/被 CDN 挡」的逃生通道 |
| `wss`（服务端不实现） | ✘ | ✘ | **丢弃 frp 的做法**，改为服务端原生实现（见 §7） |
| `0x17` 消歧字节 | — | — | **丢弃**。它是「共享端口 + 自签 TLS」时代的补丁，现在 **ALPN** 干净得多 |
| golib/mux 前缀嗅探（全局 maxNeedBytes、10s 阻塞） | 风险 | 风险 | **改造后采纳**：保留「一个 443 端口分派多协议」的能力，但换成 ALPN-first + 有界预读 |
| vhost HTTPS SNI 嗅探（借 stdlib 解 ClientHello） | ✔ | ✔ | **抄这个技巧** |
| `tcpmux httpconnect` 独立端口 | — | 可用 | 采纳但低优先级；S2 的机器人不会发 CONNECT |
| UDP 代理走**单条可靠有序** workConn（`server/proxy/udp.go:50, 106-107, 137, 188`，包体 `msg.UDPPacket`） | **✘ 致命** | — | **必须丢弃**（见 §7） |
| 出站 HTTP/HTTPS/SOCKS5/NTLM 代理 hook 链 | ✔ | — | **抄**，尤其 socks5 的 funcDialContext 技巧；但要覆盖 QUIC 或明确报错 |
| 默认 `InsecureSkipVerify = true` | ✘ | ✘ | **丢弃**。改成 pinned-key / 自签 CA 分发（见 §7） |

---

## 7. 具体建议：QUIC-first 还是 TCP+yamux？

**结论：双载体，QUIC 为首选、TCP-in-TLS-in-(可选)WebSocket 为强制兜底，二者共享同一个 `Connector` 抽象与同一个 `443`。不要三载体，不要 KCP。**

理由逐条对齐问题里的四个约束：

**(a) 媒体路径的 head-of-line blocking。** 这是 frp 最大的架构债：UDP 代理把每个 UDP 包塞成 `msg.UDPPacket` 走**一条**可靠有序的 work conn（`server/proxy/udp.go:50` 的注释 "there are always only one workConn at the same time"，收发队列 `:106-107`，读循环 `:137`）。TCP+yamux 下，一个丢包会 stall 该连接上**所有**代理；QUIC 下 stream 级独立，但**同一条 UDP 代理内部**仍然是单 stream 有序 → 音视频照样被重传拖死。所以「QUIC vs TCP」根本不是关键，关键是 **UDP 必须走不可靠通道**。方案：`quic.Config{EnableDatagrams: true}`（字段已在 `quic-go@v0.60.0/interface.go:174`，对端能力可读 `ConnectionState.SupportsDatagrams`，`interface.go:198-202`），UDP 代理走 `SendDatagram/ReceiveDatagram`，控制面/HTTP/TCP 走 stream。这一条就把 QUIC 从「和 TCP 差不多」变成「不可替代」。降级路径：对端不支持 datagram 时退回 stream 语义并在控制台明确标注「媒体质量降级」。

**(b) 家用上行丢包。** QUIC 在用户态做 loss recovery + PMTUD + 可插拔拥塞控制，且 frp 没调的窗口参数我们要调（`InitialStreamReceiveWindow`/`MaxConnectionReceiveWindow`，参照 frp 给 yamux 设 6MB 的思路，`client/connector.go:154`）。KCP 的 FEC 10/3 表面上抗丢包，但对**上行受限**的家宽是白送 30% 带宽，且 frp 连一个配置项都没暴露（`pkg/util/net/kcp.go:31`）——不值得移植。

**(c) 只放 443 的企业网 / (d) CDN + nginx 前置。** 这是 QUIC-only 的死穴，也是必须保留 TCP 分支的唯一硬理由：UDP/443 在很多企业出口、以及绝大多数 CDN 回源链路上不通。frp 的答案（`wss` 让用户自己外挂 nginx，`test/e2e/v1/basic/client_server.go:115-116`）不可接受。我们要**服务端原生实现 wss**：一个 TCP:443 监听器 → 先 ALPN 分流（`h3` 不适用，但 `http/1.1` vs 自定义 `nomi/1`）→ 拿到 `http/1.1` 的走标准 `http.Server`，在 handler 里同时提供 web 控制台、vhost 反代、以及 `/~tunnel` 的 WebSocket 升级；拿到自定义 ALPN 的直接进隧道控制面。这样：CDN/nginx 前置只需转发 WebSocket（标准能力），企业网只用 443/TCP，控制台和隧道共用一个端口一张证书。

**载体选择的运行时形状**（建议）：客户端并发 race QUIC(UDP:443) 与 TLS/WS(TCP:443)，先成功者赢，另一条保留为热备并周期性重探——这是 frp 完全没有的（它是静态 `transport.protocol` 单选，`pkg/config/v1/client.go:106`）。产品化 web 控制台正好可以把「当前载体 / RTT / 丢包 / 是否降级」可视化，这是相对 frp 的差异化卖点。

**库选型（2026-08 事实核查）**：`golang.org/x/net/quic` 仍然自我声明 "This package is a work in progress. It is not ready for production usage."，且明确列出 "0-RTT is not supported / Path MTU discovery is not implemented / Performance is untuned"（`golang.org/x/net@v0.56.0/quic/doc.go:5-44`）。**必须用 `quic-go`**（frp 用 v0.60.0）。多路复用用 `hashicorp/yamux`（注意 frp 都不敢用上游，`go.mod:78` replace 到 `fatedier/yamux`——建议直接评估 fork 或自研 32 字节头的帧层）。WebSocket 建议 `coder/websocket` 或 `gorilla/websocket` 而非 frp 用的 `golang.org/x/net/websocket`（后者是 legacy，API 陈旧）。出站代理直接抄 `golib/net/dial_option.go` 的 hook 链形状，但 SOCKS5 继续借 `golang.org/x/net/proxy`。

**安全默认值（对 frp 的直接修正）**：绝不 `InsecureSkipVerify = true`（`pkg/transport/tls.go:151`）。首次配对时由服务端下发自签 CA 或做 SPKI pinning，`tls.Config.VerifyPeerCertificate` 自己校验；ALPN 固定为版本化字符串（frp 用裸 `"frp"`，`server/service.go:267`，无版本位）；`Force TLS` 默认 true 而不是 false（frp 默认 false，`conf/frps_full_example.toml:43`）。

**S2 的额外说明**：机器人只配「IP + 端口」，所以它走的一定是服务端裸 TCP/UDP 端口转发（frp 的 `type = "tcp"` + `remotePort`），完全不涉及本层载体选择——载体只影响 relay↔desktop 段。这意味着**S2 对载体的唯一要求是「新连接建立的额外 RTT 要小」**：frp 用 `poolCount` 预建 work conn 来遮掩这个 RTT（`pkg/config/v1/client.go:124`，默认 1，服务端上限 `maxPoolCount=5`，`pkg/config/v1/server.go:186`）。QUIC 下 `OpenStreamSync` 本地即返回、无握手 RTT，**pool 机制可以整体删掉**——这是 QUIC-first 带来的实质架构简化，也是我最看重的第二个理由。

### 目标形状（code shape）

```go
// carrier 层唯一接口：比 frp 的 Connector 多一个 Datagram 面。
type Carrier interface {
    Name() string                                     // "quic" | "tls" | "ws"
    OpenStream(ctx context.Context) (net.Conn, error) // 可靠有序，对应 frp 的 Connect()
    Datagrams() (DatagramPipe, bool)                  // QUIC-only；bool=false 时调用方降级
    Health() CarrierStats                             // 暴露给 web 控制台：RTT / loss / degraded
    Close() error
}
type DatagramPipe interface { Send([]byte) error; Recv() ([]byte, error) }

// 服务端单端口 443 分派：ALPN 优先，SNI/前缀嗅探只作为 legacy 兜底。
// tls.Config.NextProtos = []string{"nomi/1", "h2", "http/1.1"}
//   "nomi/1"    -> 隧道控制面（直接 net.Conn，无 0x17 补丁）
//   h2/http1.1  -> http.Server{ web 控制台 + vhost 反代 + /~tunnel WebSocket 升级 }
// UDP:443 上并行跑 quic.Listener，ALPN 同样为 "nomi/1"。

// 客户端 race：两条腿同时拨，先握手成功者上线，另一条降为热备。
func Dial(ctx context.Context, cfg Config) (Carrier, error) // 内部 errgroup + 首个成功者 win
```

关键取舍：`Datagrams()` 返回 `(pipe, false)` 时，UDP 代理**退回 frp 的老路**（`msg.UDPPacket` over stream，`server/proxy/udp.go:106-137`）并在控制台打「媒体降级」标记——保证功能不丢，但让质量损失可见。这正是 frp 缺失的一层：它只有降级后的那条路，且用户无从得知。

---

## 8. 遗留的设计问题（需架构师裁决）

1. UDP datagram 路径要不要自己做 FEC/NACK（QUIC datagram 是纯不可靠，无重传）？还是把媒体可靠性完全推给应用层（WebRTC）？
2. 单端口 443 同时承载 web 控制台 + vhost 反代 + 隧道，控制台被 DoS 时隧道是否要有独立后门端口？
3. 载体 race（QUIC vs TCP）的状态机放在客户端还是由服务端下发策略？后者需要控制面先建立，有鸡生蛋问题。
4. mTLS/证书分发的产品化路径：frp 靠手工分发 `ca.crt`（`pkg/transport/tls.go:81-94` 只支持单个 CA 文件）；我们要不要内置 ACME + 设备注册码换证书？
5. wire 协议是否从 day 1 就上版本协商（frp 的 `MagicV2 = "FRP\x00\x02\r\n"` + ClientHello/ServerHello 是后加的，`pkg/proto/wire/wire.go:42`、`server/service.go:645-679`），避免以后再补 magic 字节。
