# NomiRelay 设计规格（v1）

- 日期：2026-08-07
- 仓库：`/home/rika/src/nomifun-net-infra`，模块 `github.com/nomifun/nomifun-net-infra`
- 状态：**规范性文档**。v1 的实现与测试以此为准；字段名、常量、状态名不得偏离。
- 证据基线：`/mnt/hgfs/share/net-infra/{frp@v0.71.0, EasyTier}` 实读源码 + `docs/research/` 下 16 份设计档案。

## 0. 一句话定位

NomiRelay 是一个**通用网络中继器**：把家庭/工厂内网里的 HTTP、WebSocket、TCP、UDP 服务，
经一台公网中继暴露给手机与 IoT 设备，并配一个中文优先、可写入的 Web 控制台。

它吸收 frp 的反向代理形态与 EasyTier 的中继信任模型，但在三处做结构性修正（§2）。

## 1. 需求与范围

### 1.1 目标场景

| 编号 | 场景 | 形态 |
|---|---|---|
| **S1** | 服务对接 | 公网手机 → 中继 → 家庭 NAT 后的桌面服务器，走 HTTP/WebSocket/UDP |
| **S2** | 反向代理 | 工厂机器人**只填中继 IP + 端口** → 指定远端桌面，机器人侧零客户端软件 |

S2 的硬约束来自真实设备：nomifun 的 ESP32 机器人只能用**裸 IPv4 明文 http/ws**，不做 SNI、
不校验证书，配主机名会**启动失败**（`nomifun-tauri/crates/backend/nomifun-app/src/lan_endpoint.rs:20-98`）。
因此「只填 IP+端口」不是偏好，而是设备能力上限。

### 1.2 v1 非目标

- **不做 P2P/NAT 打洞**。S2 的机器人用不上；S1 由中继承载。留 `Exposure: p2p` 枚举位与
  `Path`/`PathDialer` 接口缝，v2 加入不改线协议。**不引入 `pion/ice`**。
- **不做 L3/TUN overlay**。那是 EasyTier 的赛道。
- **不实现 `bridge-protocol-v1`**。与既有 `nomifun-bridge-server` 并存，互不干涉。
- **不做场景三**（AI 手机驱动多端远控）。但必须预留 §11 的接缝。
- **单租户**（schema 预留 `tenant_id`）、**单中继实例**（agent 支持多中继地址列表与故障切换）。

### 1.3 已由所有者拍定的决策

1. 与 `nomifun-bridge-server` **并存**，不实现其协议。
2. **双模式按隧道逐条选**：`tls ∈ {passthrough, gateway}`，与 `kind ∈ {service, reverse}` 正交。
3. S2 **接受裸端口开放**；源 IP 白名单与每端口密钥是**可选加固**。
4. v1 **内置 TURN**，但 TURN 只服务**将来的浏览器 WebRTC 与第三方客户端**。
5. v1 单租户，schema 预留非空 `tenant_id`。
6. v1 单中继，**agent 必须支持中继地址列表 + 自动切换**。
7. **中继拥有 Tunnel 记录，agent 拥有本地目标白名单并对其一票否决**。

### 1.4 一个必须记录的事实修正

内置 TURN 曾被设想为 S1 音视频的解法。核实后**不成立**：nomifun-tauri **没有 WebRTC**
（`grep -c webrtc Cargo.lock` → 0），其音视频今天是**裸 Opus over WebSocket**
（`crates/backend/nomifun-robot/src/protocol/binary.rs`），且已做成传输无关接缝
（`src/link.rs`、`src/lan_source.rs` 注释明确写了「加中继是一个新的 source 实现，这里零改动」）。

**因此分工是**：nomifun 的 Opus/WS 链路由中继当作**普通隧道**承载在可靠流上（立刻可用、零侧改造）；
TURN 作为标准件服务将来的浏览器 WebRTC；通用 UDP 数据报路径服务 IoT 的**非媒体** UDP。
三者各有其用，不重复建设。

## 2. 三处结构性修正（相对 frp）

这是本项目存在的技术理由，全部由实读 frp 源码得出。

### 2.1 新连接建立从 1.5×RTT 降到 0 额外 RTT

frp 开一条被代理连接要走 `ReqWorkConn` → `NewWorkConn` → `StartWorkConn` 三条控制消息
= **1.5×RTT**（`server/control.go:595-637`）。连接池可降到 0.5R，但客户端 `poolCount`
**默认只有 1**（`pkg/config/v1/client.go:153`），所以第 2 条并发连接就退化。
手机开一个网页 6 条并发连接，其中 5 条付满 1.5R——**这是 frp 首屏慢的根因，不是带宽问题**。

修正：yamux/QUIC 的流是**对称的**，服务端同样能 `OpenStream()`。让**中继主动开流**并把
隧道头与用户首包一起 pipeline 出去，三条消息全部消失，连接池、`workConnPoolCapacityOffset`、
`poolCount+1` 重试环、以及 `runID` 认领 workConn 的整套安全问题一并删除。

### 2.2 UDP 从「可靠有序流」改为「不可靠数据报」

frp 把全部 UDP 塞进**一条** TCP workConn（`server/proxy/udp.go:50-52` 注释
"there are always only one workConn at the same time"）。UDP 本身不可靠无序——
**语义错配才是队头阻塞的根因，调参调不掉**。

修正：QUIC 不可靠数据报（RFC 9221）的语义与 UDP **逐条对应**。已核实
（<https://pkg.go.dev/github.com/quic-go/quic-go>）：`Conn.SendDatagram`/`ReceiveDatagram`，
`quic.Config{EnableDatagrams:true}` 两端都要开，查
`ConnectionState().SupportsDatagrams.{Local,Remote}`；语义为不可靠、**无序**、不重传、
必须装进单个 QUIC 包。

**没有查询最大数据报尺寸的 getter**——只能从 `*quic.DatagramTooLargeError.MaxDatagramPayloadSize`
反应式获知。故实现必须探测→缓存→超限时重新分片或丢弃→按新值更新缓存，**不得写死 MTU 常量**。

### 2.3 中继从「哑注册表」改为「权威存储」

frp 里**客户端**拥有代理配置，中继只是注册表——这正是它的中继控制台
**只有一个写操作**（`DELETE /api/proxies?status=offline`，`server/http/controller.go:224-232`）的根因。

修正：中继拥有 Tunnel 记录，控制台可直接 CRUD。agent 是被 Tunnel 引用的对等体，
但对**本地目标**保留一票否决（§7.3）。

## 3. 对象模型

### 3.1 三个正交概念，不许混用同一个词

```
Tunnel   期望状态（配置）。控制台创建，中继持久化。
Session  观测状态（运行时）。中继统计，自然老化。
Agent    被 Tunnel 引用的依赖，不是 Tunnel 的容器。
```

frp 把配置与运行时混在一张表，这才是它需要「清理离线」按钮的原因。
**Session 的消失绝不意味 Tunnel 被删除。**

### 3.2 Tunnel 的正交分解

frp 的 8 种代理类型大部分是**假差异**：客户端侧 tcp/http/https/stcp/tcpmux
**共用同一个实现**（`client/proxy/general_tcp.go:23-34`），stcp 与 sudp 服务端实现
逐字节相同（`server/proxy/{stcp,sudp}.go:43-46`），8 个校验分支里 5 个是空的 `return nil`
（`pkg/config/v1/validation/proxy.go:129-135,156-166`）。

分解为：

```go
type Tunnel struct {
    ID       string        // 服务端生成
    Slug     string        // 人类可读，URL 里可见，唯一
    TenantID string        // v1 恒为单一值，非空保留
    Kind     Kind          // service | reverse            ← 方向
    TLS      TLSMode       // passthrough | gateway        ← 中继是否解密
    Exposure Exposure      // port | shared | private      ← p2p 留位，v1 不实现
    L4       L4            // tcp | udp
    Router   *Router       // 仅 Exposure==shared
    Policy   *Policy       // 源 IP 白名单、端口密钥、限速、配额
    Backend  Backend       // addr | unix | handler        ← handler 为 S3 预留
    State    State
}
```

`Kind` 与 `TLS` 是**两个正交轴，绝不共用 "mode" 这个标签**。

映射表：

| frp | NomiRelay |
|---|---|
| `tcp` | `{exposure:port, l4:tcp}` |
| `udp` | `{exposure:port, l4:udp}` |
| `http` | `{exposure:shared, l4:tcp, tls:gateway, router:{kind:http}}` |
| `https`（SNI 透传） | `{exposure:shared, l4:tcp, tls:passthrough, router:{kind:tls-sni}}` |
| `tcpmux/httpconnect` | `{exposure:shared, router:{kind:http-connect}}` |
| `stcp` / `sudp` | `{exposure:private, l4:tcp/udp}` |
| `xtcp` | `{exposure:p2p}` — v1 不实现 |

这个分解**免费带来 frp 表达不出的组合**：`{exposure:port, l4:tcp, policy:{allowCIDRs}}`
正是 S2 要的「端口暴露 + IP 白名单」，而 frp 的 tcp 类型压根没有 auth 字段
（`pkg/config/v1/proxy.go:264-268`）。

### 3.3 状态机

```
Tunnel.State: draft → pending → active → degraded → stopped
                                    ↘ error
                                    ↘ rejected_by_agent   ← agent 本地策略否决，原因上报控制台
```

`rejected_by_agent` 是本设计新增的状态，用于解决「中继拥有配置」与
「agent 拥有目标策略」两种信任模型的冲突（`docs/research/13-gaps.md` §3）。

## 4. 组件划分

```
cmd/nfrelay/     公网中继：监听器、控制面、网关、TURN、控制台、SQLite 存储
cmd/nfagent/     边缘代理：承载层 + 本地拨号器，无 SQLite
internal/proto/  线协议：帧格式、控制消息、能力协商（两端共享）
internal/carrier/  承载抽象：QUIC / TLS+smux / WSS+smux 统一为 Carrier 接口
internal/store/  仅 nfrelay：SQLite + goose 迁移 + 时序 rollup
internal/gateway/ 仅 nfrelay：L7 反代、SNI 分流、ACME
internal/turnsrv/ 仅 nfrelay：pion/turn 包装 + 计量
web/             控制台前端（React），embed 进 nfrelay
```

**为什么是两个二进制而不是一个带子命令**：`modernc.org/sqlite` 的官方移植列表
**不含 MIPS**（linux 386/amd64/arm/arm64/loong64/ppc64le/riscv64/s390x + darwin/windows/freebsd/openbsd）。
MIPS 路由器只能构建 `nfagent`。`make check` 必须用 `go list -deps` 断言
**agent 代码不得 import store**，否则 MIPS 构建会静默变红。

## 5. 承载层与线协议

### 5.1 承载梯级（并行探测，竞速取胜者，缓存并在控制台显示当前梯级）

| 梯级 | 承载 | 突破什么 |
|---|---|---|
| L0 | QUIC/UDP 配置端口，ALPN `nomifun-relay/1` | 正常网络 |
| L1 | QUIC/UDP:443 | 只放行 443 的出口过滤 |
| L2 | TLS/TCP:443 + smux | UDP 被完全封锁 |
| L3 | WSS:443，HTTP/1.1 Upgrade，`/_nf/t/v1`，**二进制帧** + smux | 敌视 ALPN 的中间盒、MITM 代理 |

L3 **必须用二进制帧**：frp 的 `pkg/util/net/websocket.go:34-39` 记录了中间盒会对文本帧
做 UTF-8 校验并杀掉隧道（yamux/smux 字节流不是有效 UTF-8）。

CDN 前置**只允许 gateway 模式**：CDN 会终止 TLS，passthrough 的端到端性质已不成立，
控制台必须拒绝 `passthrough` + CDN 的组合。

### 5.2 控制面帧格式

固定 12 字节大端头：

```
0:1  ver = 1
1:1  flags   b0 response | b1..2 codec id | b6 end-of-seq | b7 critical
2:2  type    uint16
4:4  corrID  uint32   (0 = 非请求响应的事件)
8:4  length  uint32   (<= 1<<20)
12:N payload
```

**前向兼容是硬性要求**，不是优化。读取器：`io.ReadFull(hdr[:12])` → **先**检查
`length > maxFrameLen` 再分配 → 未知 `type` 则 `io.CopyN(io.Discard, r, length)` 并
**继续，绝不关闭连接**。未知且带 `b7 critical` 时额外回 `TypeUnsupported(0x000F)`，但仍然跳过。

对比：frp v1 的 framing 是 `[1B type][8B int64 length][JSON]`，未知 type **直接断连**
（`golib/msg/json/process.go:249-252`），零前向兼容——旧 frps 遇到新 frpc 的新消息会杀掉控制连接。

**codec 用 JSON**（`encoding/json`）。控制面低频，数据面根本不碰 codec，所以吞吐无关；
JSON 在 `tcpdump`/`slog`/控制台原始帧面板里可读，默认容忍未知**字段**，且无需 codegen
（Makefile 是唯一构建系统时这很重要）。`flags` 的 b1–2 预留 codec id，将来加二进制是增量的。

线上**绝不**用 `DisallowUnknownFields`；配置文件上**必须**用。

### 5.3 数据面

**TCP 流**：中继主动 `OpenStream()`，把隧道标识与用户首包 pipeline 出去（§2.1）。

**UDP 数据报**：帧头必须自带**目标标识 + 会话标识**。frp 在服务端把 `LocalAddr` 传 `nil`
（`pkg/proto/udp/udp.go:64`），原始目的地址不过隧道，导致一条隧道无法承载多个 UDP 服务。

两个方向**都是有界队列 + 显式丢弃 + 丢弃计数**。frp 的上行会丢
（`pkg/proto/udp/udp.go:66-69` 有 `default` 分支）但**下行会阻塞**
（`server/proxy/udp.go:140` 的 `pxy.readCh <- m` 无 `default`）——channel 满则读 goroutine
卡住，TCP 接收窗口关闭，反压传导回家庭侧，把媒体流变成排队。实时路径必须丢弃而非排队。

丢弃必须**按阶段分类计数**：`公网→流队列`、`流→承载(inflight 上限)`、`承载→本地(内核错误)`。
「我们丢了包」没用；「我们在承载 inflight 上限处丢的」才告诉你该调哪个参数。

## 6. UDP 会话表（修 frp 的 fd 耗尽型 DoS）

frp 客户端侧的会话表键是用户源地址字符串，每个新源地址就 `net.DialUDP` 一个新 socket，
**map 与 fd 数量都没有任何上限**（`pkg/proto/udp/udp.go:75,117-124`），回收只靠 30s 读超时。
向中继 UDP 端口从随机源端口喷包 → 家庭侧每包开一个 fd → 30 秒内耗尽文件描述符。
**中继是公网暴露的，这必须修。**

另外它把全局互斥锁跨 `net.DialUDP` 这个阻塞 syscall 持有（`:116-126`），所有新会话建立被串行化。

NomiRelay 的会话表：

- 键 = 完整 5 元组（含目标标识），不是仅源地址。
- **硬上限** + LRU 淘汰 + **每源 IP 配额** + 建表**速率限制**。
- **分片 map**（按源地址哈希）降锁竞争，锁内不做阻塞 syscall。
- 真实源地址走**带外帧头元数据**。frp 把 PROXY protocol 头塞进 UDP **载荷**
  （`pkg/proto/udp/udp.go:129-138`）且只在首包加，等于污染业务数据报。
- **UDP 路径不做压缩**（对已压缩的媒体是纯开销与延迟）。

## 7. 安全设计

### 7.1 逐条对着 frp 的缺陷设计

| frp 的问题 | 证据 | NomiRelay |
|---|---|---|
| `GetAuthKey` 是**裸 MD5** 而非 HMAC | `pkg/util/util/util.go:50-56` | `HMAC-SHA256(agent_key, canonical(ver‖ts‖nonce‖alpn‖exporter))` |
| 时间戳发了但**从不校验** → 抓一对可**永久重放** | `pkg/auth/token.go:64-69`，全仓无时钟偏移检查 | 拒绝 \|ts − now\| > 60s，指标 `outcome="stale"` |
| 无 nonce、无重放账本 | 同上 | 16 字节 nonce 进有界 LRU，键 `(agent_id, nonce)`，TTL = 2×窗口 |
| 无信道绑定 | — | 把 `tls.ConnectionState.ExportKeyingMaterial` 混入 MAC，换 TLS 会话重放即失败 |
| `InsecureSkipVerify = true` **默认** → 默认 TLS 只加密不认证，MITM 门槛为零 | `pkg/transport/tls.go:150-152` | ACME，或显式 SPKI 指纹绑定并在控制台呈现 |
| `runID` 是 bearer token 且 workConn 校验**默认关闭** | `server/service.go:856`，`pkg/auth/token.go:82-91` | 会话内开流，天然继承会话认证，不存在「用 ID 认领连接」 |
| yamux 在**认证之前**装好，`MaxStreamWindowSize=6MiB` → 单条未认证连接即可内存放大 DoS | `server/service.go:719` | 认证前限单流、握手截止时间**先于**任何缓冲分配、accept 信号量、认证后才放大窗口 |
| `LoginFailExit = true` **默认** → 开机网络竞速即进程退出（机器人变砖） | `pkg/config/v1/client.go:88` | 永远重试，指数退避（§见 agent 设计） |
| 端口复用嗅探对**每条**连接按全局最大值 `io.ReadFull`，硬编码 10s 超时 → 短首包挂 10 秒 | `golib/net/mux/mux.go:71-73,189-198` | **惰性分级 peek**（`bufio.Reader.Peek`） |
| SSRF：`localIP` 可写 `169.254.169.254` 且校验是 `return nil` | `pkg/config/v1/validation/proxy.go:129-135` | agent 持有权威目标策略，**每次 dial 都查已解析地址**（防 DNS 重绑定） |
| vhost basic auth 用 `==` 非恒定时间比较 | `pkg/util/vhost/http.go:201,205` | 全部走 `crypto/subtle` |
| `webServer.port=7500` 一行即得**监听 0.0.0.0 的无鉴权控制台** | `pkg/util/net/http.go:48` + `server.go:117`，且校验从不要求凭据 | 首启生成 128 位密码，非 loopback 拒绝空凭据启动（§8.2） |

### 7.2 双模式与「域名路由必须能读明文」这个错误假设

原本以为透传模式无法做主机名路由。**这个假设是错的：SNI 是明文。**
透传模式下客户端在发布时注册主机名，中继读 ClientHello 的 SNI 做分流，
**一个字节都不解密**——等于零明文访问的 L7 式路由。

frp 的 https 代理正是这么干的：用一个假的 `readOnlyConn` 骗 `tls.Server` 吐出
`ClientHelloInfo`，只取 SNI 不终止 TLS（`pkg/util/vhost/https.go:39-71`）。
一次 peek 同时拿到 `ServerName` 与 `SupportedProtos`。

**必须写进设计的告警**：ECH（Encrypted ClientHello）会破坏这一点。保留两条兜底：
ALPN token，或一隧道一专用端口。

需要改写请求头、路径路由、或检查响应的，**一律是 gateway 模式，没有例外**。

### 7.3 共享端口判别顺序

```
0. 专用端口绑定           → 立即拼接，不 peek           ← S2 的 ESP32 走这条
1. PROXY protocol v1/v2   → 仅当监听器被标记为可信
2. 首字节                 0x16 → TLS；可打印 ASCII → 明文 HTTP；否则按端口默认
3. ALPN acme-tls/1        → 永远本地终止（TLS-ALPN-01）
4. SNI                    → 查 (port, sni)，由隧道的 tls 字段决定透传或网关
5. 明文 Host + 路径前缀
6. 拒绝                   → 回真正的 unrecognized_name 告警，不是裸关闭
```

`net/http` 的 `ServeMux` 主机模式**只支持字面量**，不支持 `*.example.com`，
所以 gateway 的多租户 vhost 路由需要手写 Host 路由器（最长后缀通配 + 路径前缀 + 显式优先级）。

### 7.4 S2 的暴露面：诚实处理

所有者已决定**接受裸端口开放**。设计上：

- 源 IP 白名单与每端口密钥是**可选加固**，默认不强制。
- 控制台在**创建时**给出由真实配置算出的暴露面摘要
  （`0.0.0.0:8443 · 来源 IP: 任意 · 应用层鉴权: 无`），仅当 `0.0.0.0/0` 且既无白名单又无密钥时
  要求打字确认；**运行期**只留一个窄列徽章（受限/开放/开放·已接受），不弹模态、不重复吐司。
- **学习模式**：中继记录命中新监听器的前 N 个不同源 IP，控制台一键「固定为允许列表」。
  这是相对 frp 最有价值的产品化补位。用户拒绝后记录姓名与时间戳，徽章转为信息态，**停止再问**。
- **「端口即密码」必须被明确否决**：随机高位端口只有约 16 位熵，Shodan 级扫描器可轻易枚举。
  这是隐蔽性而非安全控制。locale 文件中**不得出现**任何「端口即密钥」字样。
- `kind=reverse` 的端口租约**默认不过期**——机器人的 `IP:端口` 是在工厂手工填一次的，
  到期就是变砖。过期是 opt-in。

### 7.5 UDP 放大与反射

frp 的服务端 UDP 无任何按源状态，回包写给 `udpMsg.RemoteAddr`（`pkg/proto/udp/udp.go:51`），
伪造源地址即可把中继变成反射器，且因为没有按源计量，它连自己的放大倍数都**测不出来**。

NomiRelay：S1（我们自己的客户端）要求 **QUIC-Retry 式无状态 cookie**——
32 字节 HMAC over `(src_ip, src_port, listener, epoch)`，回显后才装映射。
S2 的裸设备做不了 cookie 交换，改为按 CIDR 门禁 **加** 每 5 元组的出入字节比上限。
该比值上限**按隧道可配、默认在已有 CIDR 白名单时关闭**，并在控制台显示实时比值——
因为机器人拉视频的正常比值本身就不对称（下行远大于上行）。

## 8. 控制台

### 8.1 信息架构

| 导航 | 用途 |
|---|---|
| **概览** | 实时磁贴：隧道上/下、会话数、吞吐、**p50/p95 RTT、丢包率**、直连/中继比；近期事件流 |
| **隧道** | CRUD 表格，产品重心。详情三个页签：实时 / 配置 / 历史 |
| **代理端** | 每 agent：版本、OS/架构、承载梯级、last-seen、轮换入网令牌、踢下线 |
| **媒体中继** | TURN 分配、中继字节数、凭据 TTL |
| **诊断** | 实时日志尾随、端口可达性检查、审计日志、支持包下载 |
| **设置** | 监听器、TLS/ACME、鉴权、留存、备份。每个字段显示生效值**与来源** |

表格一行必须回答**「我从哪进，落到哪」**：
`https://api.example.com → agent "home-desktop" 127.0.0.1:8080`。
frp 的一行是 `name/type/status`，公网端点要用户自己从拼接的字符串里凑出来。

**S1 与 S2 是同一个对象的不同 `kind`**——我们不是在做两个产品。
TURN 分配**故意不是 Tunnel**（它不由控制台创建），单独一屏。

### 8.2 首启与鉴权

frp 的反面教材：凭据双空即放行一切（`pkg/util/net/http.go:48`），
校验从不要求凭据（`validation/common.go:24-35`），`Complete()` 又把地址覆盖成 `0.0.0.0`
（`server.go:117`），README 教 admin/admin（`conf/frps_full_example.toml:71-72`）。

NomiRelay：任何请求打到未配置的中继都落到 `/setup`。存储层从源头拒绝空凭据（`CreateAdmin` 不接受空用户名/短密码），
首启由运维自选一个 ≥12 位的口令、以 argon2id 存哈希，**磁盘上不落任何明文口令**。

> **与本节初版的偏离（v1 实际实现）**：初版规定「生成 24 字符密码并以 0600 写入
> `<datadir>/initial-admin-password`、拒绝空凭据在非 loopback 监听下启动、首次登录强制
> 轮换」。v1 走的是另一条路（TOFU 首启 + 运维自选口令 + 磁盘不落明文），四条都没实现。
> 这是一次**未记录的设计换向**，在此如实记账：写一份明文口令到磁盘本身是一个新的
> 泄露面（它会进备份、进快照），而「非 loopback 拒绝启动」会打死本仓自带
> docker-compose 的既有形态。真正仍然缺失的是**首启窗口**的保护 —— 谁先到谁是管理员，
> 见 README 的诚实清单。会话密钥持久化在 data dir（EasyTier 每次启动 `Key::generate()`，
重启即失效所有会话）。CSRF 用 Go 1.26 的 `CrossOriginProtection` + Origin/Referer 校验。
**Host 头校验**（防 DNS 重绑定）：不匹配则 421。这道闸包住**整个**控制台监听器，
内嵌 SPA 的 `/` 也在其内 —— 只挡 `/api/` 会留下「页面 200 载入正常、所有 API 421」
的半开状态，界面上无任何解释；而给别名 Host 返回完整 index.html 还会泄露产品名与
带哈希的资源名。421 的响应体自己给出修法（浏览器导航给纯文本、程序化调用给 JSON
信封，`code: misdirected_host`）。

`-console-hosts` 的条目与绑定地址入白名单时**剥端口、小写、丢弃通配与未指定地址**：
两个消费者（Host 校验与 Origin 校验）都在查表前剥端口，键不剥就静默失效；
而剥完为空串的条目（`":9443"` 这类笔误）会放行所有不带 Host 头的请求。

`GET|HEAD /healthz` **在这道闸之外**：编排探针（k8s httpGet 默认拿 Pod IP 当 Host）
不可能知道运维配了什么白名单，421 会让它把健康的中继反复重启。这不削弱防护 ——
该端点不鉴权、无副作用，攻击者直连就能拿到同样字节。写方法不在豁免内。

### 8.3 双模式呈现

创建时是**两张并排单选卡，绝不是下拉框**，各自写明得到什么、失去什么：

| | 直通 passthrough | 网关 gateway |
|---|---|---|
| TLS 私钥位置 | 你的服务器 | **中继** |
| 中继可见明文 | 否 | 是 |
| ACME 自动证书 | ✗ | ✓ |
| Host/路径路由，多隧道共用 443 | ✗（一端口一隧道） | ✓ |
| 注入鉴权 / 改写请求头 | ✗ | ✓ |
| 后端拿到真实客户端 IP | 仅 PROXY protocol | XFF + PROXY |
| 状态码/路径/每请求延迟指标 | ✗ | ✓ |

诚实机制：网关独有字段在透传下**置灰并给出原因**，不隐藏，让用户学到代价。
实时页签在透传下渲染一句字面说明：
「直通模式下中继不解析应用层，故无状态码/路径指标。可用：连接数、字节、RTT。」
透传下后端拿到的客户端 IP **真的是 unknown**——如实呈现，不悄悄伪造。
切换模式必须走 diff 预览 + 确认（证书开始签发、私钥移到中继、这些头会被注入），**绝不静默切换**。

**透传模式不是无条件可选的。** 当目标是 nomifun-tauri 的服务时，透传**永远不能工作**：
它的 `host_guard_middleware` 挂在路由器之外，会 403 掉任何域名型 `Host`/`Origin`
（§12.1），而透传模式按定义不能改写请求头。所以控制台必须在检测到目标为
nomifun-tauri 类服务（或用户选择了「需要改写 Host」的模板）时，
**把透传卡片置灰并说明原因**，而不是让用户选完再撞一堵 403 的墙。

### 8.4 遥测（frp 完全没有的部分）

frp 的遥测词汇**只有字节数与连接数**（`web/frps/src/types/proxy.ts:109-116`），
无延迟、无抖动、无丢包，对 S1 的音视频毫无用处。且历史只在内存、重启即失
（`pkg/metrics/mem/types.go:24` 的 `ReserveDays = 7`）。

NomiRelay 每隧道：p50/p95/p99 承载 RTT、丢包率、吞吐、活跃会话、新会话/秒、错误/秒。
UDP 另加：pps 双向、**按阶段分类的丢弃**、乱序计数与最大乱序深度、平滑后的到达间隔抖动、
分片率与重组超时、以及**当前生效的数据报 MTU**（从 `DatagramTooLargeError` 学到的值）——
必须显示，因为 PMTUD 完成前它偏小，不显示就没人能解释「为什么大包失败小包正常」。

**RTT 必须存直方图桶（`le_us`）而不是 p95 列**：p95 的 p95 在算术上是错的。

留存用 SQLite rollup：1m→48h、5m→30d、1h→400d。

实时数据走**一个 SSE 端点按 topic 多路复用**（`GET /api/events`，事件类型 `hello`/`metric`/
`session`/`state`/`log`）。多路复用不是过度设计：HTTP/1.1 浏览器每源约 6 连接上限，
一个图表一个 `EventSource` 会把仪表盘拖死。中继**采样而非排队**——慢客户端丢 `metric` 帧
并累加计数器，在界面上显示为流健康点，与数据面同一条「永不阻塞」法则。

**因此控制台与网关必须是两个独立监听器。** SSE 需要 HTTP/2 才能摆脱每源 6 连接的限制，
而 S2 的 ESP32 只说明文 HTTP/1.1、不做 ALPN 协商，网关侧必须用
`http.Protocols` 把入站钉在 HTTP/1。两个要求互斥，共用一个监听器做不到 ——
控制台监听器启用 HTTP/2，网关监听器钉 HTTP/1。这一条也顺带改善了安全边界：
管理面与数据面不共享端口。

### 8.5 前端选型：与 nomifun-tauri 对齐

同一个人维护两个仓，分歧的代价不是「学一个库」而是**丢掉反射**——
哪个 Arco prop 做服务端分页、主题 token 在哪、locale key 怎么拿到类型。

React 19 + TypeScript strict + Vite + **Arco Design** + **UnoCSS** + **swr** + i18next + bun。

选 Arco 而非 shadcn/Tailwind 的四条理由（按权重）：**表格深度**（Arco `Table` 自带受控服务端
分页、固定/可拉伸列、可展开行、选择、虚拟滚动，shadcn 给的是无头 TanStack Table，
外壳/分页/空态/骨架要写七遍）；**zh-CN 质量**（Arco 是字节出品，zh-CN 是**源语言**而非贡献翻译，
`Pagination` 原生读作「共 N 条」）；**暗色模式**（一个属性翻转 `body[arco-theme=dark]` 重新 token 化
一切，Tailwind 的 `dark:` 要你永远手写每一对明暗）；**开箱的设计完成度**
（`Descriptions`/`Statistic`/`Result`/`Empty` 正是管理控制台 60% 的构成）。

图表用 **uPlot**：Recharts 在架构上被否决（SVG + 每点一个 React 元素，
600 样本×4 系列每帧要 reconcile 数千节点，1Hz 就掉帧）；ECharts 快但 1MB+，只在报表页懒加载。
uPlot ~50KB canvas，更新路径就是对预建实例 `u.setData(arrays)`，完全不经 VDOM。
模式：每指标一个定长 `Float64Array` 环形缓冲，SSE 回调写入环，
一个 rAF 节流的 effect **无论事件速率**最多 ~10Hz 调一次 `setData`。

TS 配置比兄弟项目**更严**：加 `noUncheckedIndexedAccess`、`exactOptionalPropertyTypes`、
`verbatimModuleSyntax`，并把 `noUnusedLocals/Parameters` 翻成 true。
兄弟项目为了完成大规模移植放宽了这些；这里是全新代码，严格是现在免费、以后再也不免费的东西，
而我们会**大量索引指标环形缓冲**。

**Schema 共享：只生成类型，不生成校验器。** Go 是唯一真相源，`make gen-api-types` 产出
committed 的 `web/src/api/types.gen.ts`（这样 `bun dev` 永不需要 Go 工具链）。
有意思的校验是命令式与跨字段的（端口冲突、`passthrough`+ACME、CDN+passthrough），
codegen 不出来——生成的 zod schema 只会编码规则的弱一半却**暗示它编码了全部**。
权威校验是一次往返：`POST /api/tunnels:validate` 作为 dry-run 绑到提交。
这正好修掉 frp store API 的缺陷：控制台接受一个中继later 会拒绝的端口，
表现为隧道进 `error` 相而不是写入时 400。

OpenAPI **发布规范但手写客户端**：`make openapi` 产出 committed 的 `openapi.json` 供第三方与
CLI 消费，并作为 `make api-diff` 漂移门禁；客户端约 150 行手写。生成客户端输在三点：
约 25 个封闭端点不值得每操作的样板；产物不与 swr key 组合；**OpenAPI 对 SSE 没有一等模型**，
而那是我们最重要的通道。

## 9. 配置与存储

### 9.1 分层来源与溯源

```
默认值(Complete)  <  文件(relay.toml)  <  存储(SQLite)  <  环境变量
```

并行维护一张 `map[string]source` 记录每个键**最后由哪一层设置**，在控制台显示。
frp 回答不了「这个值为什么是这样」，而每一次支持对话都从这里开始。

**基础设施**（监听器、TLS、鉴权后端、留存）只在文件里，控制台**只读**并显示
「文件管理 /etc/nomirelay/relay.toml:42」+「复制为控制台副本」动作。
**隧道与 agent** 只在存储里，由控制台/API 拥有。
**绝不把控制台的改动回写进用户的 YAML/TOML**——那是每个配置 UI 丢注释与格式的地方。

写入走 `POST /api/config:validate` 然后 `:apply`，**坏文档永远到不了磁盘**。
frp 的 `PUT /api/config` 是 `os.WriteFile` 无解析无校验无备份
（`client/config_manager.go:68-77`），粘贴一个语法错误就让下次启动直接失败。

三段式严格分离：`Complete()` 填零值、可变、幂等、无 I/O、不返错；
`Validate() error` 纯函数、用 `errors.Join` 返回**所有**失败以便控制台一次高亮全部坏字段；
`Clone()` 深拷贝，热重载先构候选、Complete、Validate，再原子换。

### 9.2 时序表

```sql
tunnel_sample_1m(tunnel_id, bucket,
  bytes_in, bytes_out, pkts_in, pkts_out, conns_ok, conns_err,
  loss_ppm,            -- 用整数避免浮点漂移
  rtt_sum_us, rtt_max_us,
  samples,             -- 折叠计数，上卷时重新求均值需要
  PRIMARY KEY (tunnel_id, bucket)) WITHOUT ROWID;

tunnel_rtt_hist_1m(tunnel_id, bucket, le_us, count,
  PRIMARY KEY (tunnel_id, bucket, le_us)) WITHOUT ROWID;
```

SQLite 打开参数：`WAL` + `synchronous=NORMAL` + `busy_timeout=5000` + `foreign_keys=ON`；
一个 `SetMaxOpenConns(1)` 的写句柄 + 一个读池，从根上消除 `SQLITE_BUSY` 这一类 bug。

## 10. 依赖集

| 模块 | 版本 | 为什么 |
|---|---|---|
| `github.com/quic-go/quic-go` | v0.61.0 | 主承载：RFC 9221 数据报、原生流、连接迁移；已绕过 GO-2026-5676 |
| `github.com/xtaci/smux` | v1.5.57 | L2–L4 梯级的多路复用器。**必须留在 v1 导入路径**，其 `v2.0.x` 是 2019 年的 `+incompatible` 标签，比 v1 还老 |
| `github.com/coder/websocket` | v1.8.15 | L3 承载，`NetConn` 喂给 smux。**不用 `gorilla/websocket`**：v1.5.3（2024-06）后两年无 tag，且 v1.5.3 本身是把 v1.5.2 回滚回 v1.5.0 |
| `github.com/pires/go-proxyproto` | v0.15.0 | 外部 LB 后保真客户端 IP；v0.15.0 新增 UDP PROXY。注意它把 `DefaultPolicy` 改成 REQUIRE，须按监听器设策略 |
| `github.com/pion/turn/v5` | v5.0.12 | 内置 TURN。它**从不自己开 socket**（由我们传入 `net.PacketConn`），这正是计量挂钩点；内置 `LongTermTURNRESTAuthHandler` 与 coturn `use-auth-secret` 逐字节兼容。**不暴露带宽计数器也不能枚举分配**，必须包一层计数的 `RelayAddressGenerator` |
| `github.com/pion/stun/v3` | v3.1.6 | 中继自检公网地址 |
| `modernc.org/sqlite` | v1.56.0 | CGO-free 存储。**必须按其 go.mod 精确锁定 `modernc.org/libc`**（上游 issue #177）。避开已撤回的 v1.42.0/v1.34.3/v1.33.0/v1.29.4/v1.20.1/v1.16.0–v1.17.2 |
| `github.com/pressly/goose/v3` | v3.27.3 | embed `.sql` 迁移 + `WithLocker`。避开撤回的 v3.21.0；**绝不读它的 `VERSION` 常量**（仍写着 v3.18.0） |
| `github.com/knadh/koanf/v2` | v2.3.6 | 分层配置与溯源 |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | TOML 解析，运维可编辑 |
| `github.com/go-playground/validator/v10` | v10.30.3 | DTO 边界的结构体标签校验 |
| `github.com/caddyserver/certmagic` | v0.25.4 | 多租户按需证书。`DecisionFunc` 真实签名是 `func(ctx context.Context, name string) error`（README 已过时）。**它内置的限速器是排队器不是闸门**（`acmeclient.go` 调 `rl.Wait` 而非 `Allow`，粒度是 CA + 账户），且**没有失败负缓存**；`SubjectQualifiesForPublicCert` 也**不**拒公网 IP 字面量（`certificates.go:586` 只调 `SubjectIsInternal`）。所以四道闸门必须自带 —— 见 `internal/acmecert`。*（2026-08-08 按 v0.25.4 源码更正：原文写「不内置限速器」有误）* |
| `golang.org/x/crypto` | v0.54.0 | argon2id；≥v0.52.0 是 SSH 公告簇的硬要求；**绝不 import `x/crypto/openpgp`**（GO-2026-5932） |
| `golang.org/x/time` | v0.15.0 | 控制面与 ACME 决策的令牌桶 |
| `github.com/prometheus/client_golang` | v1.24.1 | 指标。**不要碰它的 `api/…` 子包**（上游声明那里的破坏性变更不触发大版本） |
| `github.com/kardianos/service` | v1.3.0 | 跨平台服务安装。低速但未归档，仍是事实选择 |
| `github.com/spf13/cobra` | v1.10.2 | 两个二进制的 CLI |

**不引入**：`chi`/`gin`/`echo`（`ServeMux` 的方法+通配路由已覆盖 chi 唯一卖点，
而我们的服务器同时是控制台 API 与数据面网关，需要裸 `net.Conn`，框架的私有 context 会污染每个签名）；
`gorilla/mux`；`armon/go-socks5`（依赖钉在 2016 年的 commit）；**`pion/ice`**（P2P 是 v2 才做，
现在引入等于背一个用不上的依赖）；OTel（几十个模块塞进 MIPS 路由器二进制，
且其收益需要这些部署不会跑的 collector）。

`crypto/tls` 在 Go 1.26 的默认曲线已含后量子 `X25519MLKEM768`——
**`CurvePreferences` 保持 nil**，手动设置反而会静默关掉它。

## 11. 场景三的前向兼容接缝

场景三暂缓，但架构不得foreclose 它。现在预留（都是零成本，事后补则是破坏性变更）：

1. **`Kind` 枚举保留 `peer`**：S3 需要 **agent↔agent** 流，而当前所有 Tunnel 都是
   「公网入口→agent」。不现在留就是一次 schema 迁移。
2. **`Backend` 保留 `handler` 变体**：S3 的后端是 agent **自己终结的能力**
   （截图/PTY/键鼠注入），而不是拨号到一个 TCP 目标。
3. **登录 hello 里保留 `agent.capabilities[]`**：事后加会破坏线协议。
4. **控制面从第一天就支持向 agent 推送指令**。frp 的服务端 API 是**纯只读**
   （`server/api_router.go` 全为只读或删代理），服务端插件是单向钩子——
   这是它做不了场景三的死穴。我们的控制面本来就要推送配置，S3 复用同一条通道。

## 12. 与 nomifun-tauri 的集成约束

接入时有三个会直接导致 403 或启动失败的硬约束，实现与联调必须先满足：

1. **桌面 LAN 口（默认 25808）有 DNS-rebind 守卫**：任何 `Host` 或 `Origin` 只要是**域名**
   就直接 403，只放行 IP 字面量与 `localhost`（`crates/backend/nomifun-app/src/desktop.rs:1205,1710-1730`）。
   且该中间件挂在**路由器之外**，在 `validate_origin` 运行之前就拒绝——
   所以**改后端的 `allowed_origins` 配置救不了**转发过来的公网主机名。
   网关模式必须同时把 `Host` 与 `Origin` 改写为 IP 字面量形式，这样做之后后端反而零配置。

2. **ESP32 机器人只能用裸 IPv4 明文 http/ws**，配主机名会启动失败
   （`crates/backend/nomifun-app/src/lan_endpoint.rs:20-98`）。入口在 `/robot/*`。

3. **`/ws` 握手校验 Origin**，依次比对 `Host`、首个 `X-Forwarded-Host`、`NOMIFUN_ALLOWED_ORIGINS`
   （`crates/backend/nomifun-realtime/src/handler.rs:29-35`）。

**网关模式的请求头改写表**（`B` = 后端 `ip:port`，`P` = 公网主机名，`C` = 唯一真实客户端 IP）：

| 头 | 动作 | 值 |
|---|---|---|
| `Host` | 设置 | `B` |
| `Origin` | 入站有则设置 | `http://B` |
| `X-Forwarded-Host` | 设置为单值 | `P` |
| `X-Forwarded-For` | **先删再设为单值，不做列表追加** | `C` |
| `X-Real-IP` | 先删再设 | `C` |
| `X-Forwarded-Proto` | 设置 | 公网侧 scheme |
| `Forwarded`、`X-Client-IP`、`CF-Connecting-IP`、`True-Client-IP` | 删除 | — |

必须先删再设的理由：nomifun-tauri 从 `X-Forwarded-For`/`X-Real-IP` 取客户端 IP
且**没有可信代理白名单**（`crates/backend/nomifun-auth/src/extract.rs:13-32`）。
若中继做列表追加，等于把伪造源 IP 的能力送给公网。

另有一个会坏功能的细节：`crates/backend/nomifun-robot/src/link.rs:34` 的 `vision_base`
是**交回设备的 HTTP 基地址**，经中继时必须是中继的公网 URL 而非 LAN IP，否则视觉上传全断。

## 13. 运维

- **单静态二进制**，`CGO_ENABLED=0` 全平台。前端 `//go:embed all:dist` + `http.FileServerFS`，
  并抄 frp 的 `//go:build noweb` 逃生舱 + Makefile 在 `web/dist` 缺失时自动加 tag，
  这样新克隆里 `go build ./...` 永不中断。保留 `--assets-dir` 覆盖。
  **不做逐请求 gzip**（frp 会把已压缩资源再 gzip 一遍）——预压缩并协商 `.br`/`.gz`。
- **构建矩阵**：linux/{amd64,arm64,arm(GOARM=7/5),386,riscv64,loong64,mips,mipsle,mips64le}、
  windows/{amd64,arm64}、darwin/{amd64,arm64}、freebsd/amd64；mips 用 `GOMIPS=softfloat`。
  **MIPS 只构建 `nfagent`**（无 SQLite 移植）。
- **构建门禁只有一个入口：本地 `make`**。`make check` = fmt+vet+lint+test。
  **本仓不使用 GitHub Actions**（组织铁律）。
- **优雅关闭必须排空**：停止 accept → readiness 转红而 liveness 保持绿 →
  推 `Draining{deadline}` 控制帧让 agent 重拨 → 等 `min(deadline, 全连接关闭)` →
  `http.Server.Shutdown` → 关闭。默认 30s。frp 的服务端**从不排空**。
- **零停机重载**：监听器存在按 `(proto, addr, port)` 的 map 里；`SIGHUP` 或控制台 apply 时
  diff 期望与实际，只关被移除的、只绑新增的，**已建立的连接不受影响**。
  校验后原子换，保留 last-known-good，坏的 apply 是一个带事件的 no-op 而不是一次故障。
- **备份**：`VACUUM INTO 'snapshot.db'` 做一致热快照，不停服。恢复拒绝 schema 版本比二进制新的备份。

### 13.1 发布签名：不能用 cosign keyless

`make dist` 产出 `SHA256SUMS`，但它是在**构建同一台机器上**生成的，
所以只防传输损坏、不防构建机被攻陷。

**cosign 的 keyless 模式在本仓不可用**：它依赖 CI 提供的 OIDC 身份来签发短时证书，
而本仓禁用 GitHub Actions（组织铁律），没有那个身份来源。

因此签名走**离线密钥**：`make sign` 在一台与构建机分离的机器上用长期密钥对
`SHA256SUMS` 做 detached 签名（minisign 或 cosign 的 `--key` 模式均可，
定版前需实测确认工具可用性）。密钥**绝不出现在构建机上**。
一键安装脚本必须在执行任何东西**之前**校验签名，校验失败即中止。

### 13.2 默认监听端口与最低防火墙开放

这是运维第一页就要回答的问题，不能留给用户猜：

| 端口 | 协议 | 用途 | 是否必须对公网开放 |
|---|---|---|---|
| 8443/udp | QUIC | agent 承载 L0 | 是 |
| 443/udp | QUIC | agent 承载 L1（突破只放行 443 的出口） | 建议 |
| 443/tcp | TLS + smux | agent 承载 L2/L3，以及 gateway 模式的业务入口 | 是 |
| 3478/udp + 5349/tcp | STUN/TURN | 内置 TURN（供将来的浏览器 WebRTC） | 按需 |
| TURN 中继端口段 | udp | TURN 分配的中继端口，范围可配且必须有界 | 按需 |
| 9443/tcp | HTTPS | **控制台，独立监听器**（HTTP/2，见 §8.4） | 建议仅内网或 VPN 可达 |
| 每条 `exposure: port` 隧道各自的端口 | tcp/udp | 业务入口（S2 的机器人打这里） | 按隧道 |

**最低可用集**：`443/tcp` + `8443/udp` + 控制台端口。其余按需。

## 14. 测试策略

- 标准库 `testing` + `testing/synctest`（假时钟）+ `httptest` + `fstest` + `net.Pipe()`
  + 一个内存 `net.PacketConn`；默认 `-race`。
- **帧解析器必须有 fuzz target**：12 字节头加上「未知类型跳过」的规则正是 fuzz 擅长找的形状，
  语料库回归则永久保护前向兼容。
- **不抄 frp 的 ginkgo/gomega e2e 栈**（两棵依赖树 + 一个遮蔽栈迹的 DSL）；
  它唯一真实的好处是结构化 `BeforeEach` 夹具，用 `t.Cleanup` + 表驱动即可达到。也不用 testify。
- `test/e2e` 下放一个纯 Go 夹具，`//go:build e2e`，在 loopback 上拉起真实 relay + agent + echo server，
  驱动 S1（HTTP+WS+UDP 过隧道）与 S2（裸端口→网关）。`make e2e` 与 `make test` 分开。

## 15. Agent 设计

agent 的配置 schema、生命周期状态机、承载梯级探测与防抖、本地目标策略、
协调循环、自更新与 `nfagent status`，详见 `docs/research/16-agent-design.md`。

其中已落地为代码的部分：本地目标策略见 `internal/policy`（含 SSRF 与 DNS 重绑定防护）。

## 16. 尚未设计、必须在实现前补上的部分

批判（`docs/research/13-gaps.md`）指出以下空白，此处显式记账，避免被当成已决：

- **多中继 / 高可用**：v1 单实例。但 §13 的排空帧会让 agent「重拨兄弟中继」，
  而**中继集合成员如何得知尚未定义**。v1 的落法：agent 配置里是一个有序的中继地址列表，
  由用户自己填；不做服务发现，不做状态同步。
- **IPv6 姿态**：TURN 的监听建议钉 `udp4`/`tcp4`（pion/turn 的 `StrictAddressFamily`
  与 Chrome/Safari 的组合未经实测），但国内运营商会下发 IPv6-only / 464XLAT。
  需要在实现阶段实测后定稿。
- **DNS / 通配域名的配置体验**：gateway 模式要求用户把通配记录指向中继，
  这一步的引导尚未设计。
- **审计日志留存策略**、**Go 侧错误消息的 i18n**、
  **配置重载对已建立会话的语义**（§13 只定义了监听器的 diff，未定义隧道定义变更时
  正在跑的会话该保留还是断开）。
- **`kind=reverse` 的无代理端路径**：中继自己作为出网拨号器直连目标。
  这条路径**不经过 agent**，因此 §7.1 的目标策略必须在中继侧再实现一份，
  否则 SSRF 防线在这条路上是缺失的。

## 附：主要证据索引

研究档案位于 `docs/research/`：frp 控制面(01)、承载(02)、七层(03)、UDP 路径(04)、
代理分类学(05)、服务端运维(06)、配置与控制台(07)、EasyTier 转发(08)、NAT 穿透(09)、
Go 选型(10)、Web 控制台(11)、安全与运维(12)、完整性批判(13)、
架构师第一手 UDP 核验(14)、TURN 与双模式(15)、Agent 设计(16)。
