# 架构师第一手核验：frp UDP 数据面缺陷清单

> 由我（架构师）亲自阅读 frp v0.71.0 源码得出，不经二手转述。
> 版本证据：`frp/pkg/util/version/version.go:17` → `version = "0.71.0"`；`frp/go.mod` → `go 1.25.0`。
> 这条路径是场景一（手机↔家庭桌面，含音视频 UDP）的成败点，故单独核验。

## 涉及文件

- `frp/server/proxy/udp.go`（275 行，服务端 UDP 代理）
- `frp/pkg/proto/udp/udp.go`（153 行，双向转发与 NAT 会话表）

## 已确认的报告结论

| 结论 | 证据 |
|---|---|
| 单代理只有一条 workConn，全部 UDP 流量挤一条 TCP | `server/proxy/udp.go:50-52` 注释 "there are always only one workConn at the same time"；`:202-203` 新 workConn 到来即关旧的 |
| `sendCh`/`readCh` 各缓冲 1024 | `server/proxy/udp.go:106-107` |
| 加密/压缩/限速包在整条 workConn 流上 | `server/proxy/udp.go:207-223`（`libio.WithEncryption` / `WithCompression` / `limit.NewReader`） |
| `udpPacketSize` 决定读缓冲，超出即截断 | `pkg/proto/udp/udp.go:56` `pool.GetBuf(bufSize)`；`:59` `ReadFromUDP(buf)` 单次读满即止 |

## 报告未提及、我新发现的缺陷

### 1. 背压不对称——下行会阻塞隧道读循环（最严重）

上行（用户→隧道）**会丢包**，这是对的：

```go
// pkg/proto/udp/udp.go:66-69
select {
case sendCh <- udpMsg:
default:            // 满则丢弃 ← 实时媒体的正确行为
}
```

下行（隧道→用户）**会阻塞**：

```go
// server/proxy/udp.go:140
pxy.readCh <- m     // 无 default，channel 满时阻塞整个 workConnReaderFn
```

`readCh` 满 → 读 goroutine 卡住 → 不再从 workConn 读 → TCP 接收窗口关闭 → **反压传导回家庭侧，把媒体流变成排队**。实时音视频必须丢弃而非排队。新实现两个方向都必须是有界队列 + 丢弃策略，且丢弃要计数上报。

### 2. NAT 会话表无上限——fd 耗尽型 DoS

客户端侧会话表：

```go
// pkg/proto/udp/udp.go:75    udpConnMap := make(map[string]*net.UDPConn)
// pkg/proto/udp/udp.go:117   udpConn, ok := udpConnMap[udpMsg.RemoteAddr.String()]
// pkg/proto/udp/udp.go:119   udpConn, err = net.DialUDP("udp", nil, dstAddr)
```

键是**用户源地址字符串**，每个新源地址就 `net.DialUDP` 一个新 socket，**map 与 fd 数量都没有任何上限**。回收只靠 30s 读超时（`:90`、`:144`）与出错删除（`:81-83`）。

攻击面：向中继的 UDP 端口从随机源端口喷包 → 家庭侧客户端每包开一个 fd → 30 秒窗口内耗尽文件描述符。**中继是公网暴露的，这个必须修**。新实现需要：会话数硬上限 + LRU 淘汰 + 每源 IP 配额 + 建表速率限制。

### 3. 全局互斥锁跨阻塞 syscall 持有

```go
// pkg/proto/udp/udp.go:116-126
mu.Lock()
... net.DialUDP(...)   // 阻塞系统调用在锁内
mu.Unlock()
```

所有新会话的建立被串行化。新实现用分片 map（按源地址哈希）或 `sync.Map` + 单飞（singleflight）建表。

### 4. 原始目的地址在服务端被丢弃

```go
// pkg/proto/udp/udp.go:64
udpMsg := NewUDPPacket(buf[:n], nil, remoteAddr)   // laddr 传 nil
```

`LocalAddr` 恒为 nil，即"用户打到中继的哪个地址/端口"这一信息不过隧道。单端口单目标时无妨，但**多路复用（一条隧道承载多个 UDP 服务）就做不到**。新实现的数据面帧头必须携带目标标识。

### 5. UDP 的 Proxy Protocol 把头塞进数据报载荷

```go
// pkg/proto/udp/udp.go:129-138
finalBuf := make([]byte, len(ppBuf)+len(buf))   // PP 头 + 原始载荷，同一个数据报
```

除非本地服务专门解析，否则这是**在污染业务数据报**；且只在首包加（`!ok` 分支），本地服务无法可靠区分。UDP 传递客户端真实源地址应走带外元数据（我们的帧头），不要污染载荷。

### 6. 硬编码 500ms 启动延迟

```go
// server/proxy/udp.go:186
time.Sleep(500 * time.Millisecond)   // "Sleep a while for waiting control send the NewProxyResp"
```

用 sleep 代替握手同步。新实现应显式等待"代理就绪"事件。

### 7. workConn 60s 读超时依赖对端在数据通道里发心跳

```go
// server/proxy/udp.go:119
_ = payloadConn.SetReadDeadline(time.Now().Add(60 * time.Second))
```

心跳与业务数据混在同一条帧流（`:134` 的 `case *msg.Ping`）。新实现应把保活放在控制面/传输层（QUIC 自带），数据面只走数据。

## 对新实现的直接约束（由上述推导）

1. **数据面帧头必须自带目标标识 + 会话标识**，不能像 frp 那样把地址塞进 JSON 消息体、且丢掉 LocalAddr。
2. **两个方向都是有界队列 + 显式丢弃 + 丢弃计数指标**，实时路径永不阻塞。
3. **会话表有硬上限、LRU、每源 IP 配额、建表限速**，分片降锁竞争。
4. **不要在 UDP 路径上做压缩**（`WithCompression` 对已压缩的媒体是纯开销与延迟）。
5. **UDP 不应与 TCP 挤同一条可靠有序流**——这是 frp 队头阻塞的根因。候选：QUIC 不可靠数据报（RFC 9221）、或独立鉴权的裸 UDP 旁路通道。
6. 真实源地址走**带外帧头元数据**，不污染载荷。

## 我亲自核实的 quic-go 数据报事实（决定上述第 5 条能否成立）

来源：<https://pkg.go.dev/github.com/quic-go/quic-go>（页面显示 v0.61.0，2026-07-21 发布；
页面横幅提示「not in the latest version of its module」→ 定版前需再查最新 tag）。

- **支持 RFC 9221 不可靠数据报**，README 明确列出。
- API 在 `*quic.Conn` 上（v0.53.0 起 `Connection` 接口变为具体类型 `*quic.Conn`）：
  ```go
  func (c *Conn) SendDatagram(p []byte) error
  func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error)
  ```
- 开启：`quic.Config{EnableDatagrams: true}`，**两端都必须开**；协商结果查
  `conn.ConnectionState().SupportsDatagrams.{Local,Remote}`。
- 语义（官方 doc comment 原文要点）：**无投递保证、丢失不重传、载荷必须装进单个 QUIC 包、
  当可用包尺寸突然下降时数据报可能在发出前被丢弃**。
- **顺序无保证**（RFC 9221 的 DATAGRAM 帧本身无序；quic-go 文档未作有序承诺）。
- DPLPMTUD（RFC 8899）默认开启，探到路径 MTU 后可用尺寸会上调；
  `Config.InitialPacketSize` 是下界（≥1200），`DisablePathMTUDiscovery` 可关探测。
- FIPS 140-3 模式需 Go 1.26+（v0.60 起）。

### 由此得出的两条硬性设计约束

1. **没有查询最大数据报尺寸的 getter。** 唯一途径是反应式——发送失败时从
   `*quic.DatagramTooLargeError{MaxDatagramPayloadSize int64}` 读取（该类型 v0.41.0 引入）。
   ⇒ 实现必须：首次发送探测 → 缓存当前上限 → 超限时按该值重新分片或丢弃 →
   收到新的 `DatagramTooLargeError` 就更新缓存。**不能在代码里写死 MTU 常量。**
2. **必须在 `SupportsDatagrams.Remote` 为 false 时优雅降级**（对端旧版本或走回退承载时），
   降级路径要在控制台明示「当前 UDP 走可靠流承载，延迟不保证」。

### 这为什么正好解决 frp 的病根

frp 把 UDP 塞进一条**可靠有序**的 TCP 流（`server/proxy/udp.go:50-52` 单 workConn），
而 UDP 本身是**不可靠无序**的——语义错配才是队头阻塞的根因，调参调不掉。
QUIC 不可靠数据报的语义（不可靠、无序、不重传）与 UDP **逐条对应**，
是结构性修正而非优化。这是选择 QUIC 作主承载最有力的论据。

## 顺带记录：frp 的依赖选择（`frp/go.mod`）

- `go 1.25.0`；`quic-go v0.60.0`；`xtaci/kcp-go/v5 v5.6.13`；`gorilla/websocket v1.5.0`
- `pelletier/go-toml/v2`、`prometheus/client_golang v1.19.1`、`pires/go-proxyproto`、`samber/lo`、`spf13/cobra`
- e2e 用 `onsi/ginkgo/v2` + `gomega`
- **注意**：yamux 被 replace 成 fork —
  `replace github.com/hashicorp/yamux => github.com/fatedier/yamux v0.0.0-20250825093530-d0154be01cd6`
  上游 yamux 不够用是一个信号，选型时需查清 fork 修了什么（很可能是流控/窗口或内存占用）。
