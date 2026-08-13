# 04 · frp 的 UDP 数据面：逐行拆解、五大短板复核、以及一份能打赢它的 Go 设计

审阅对象：`/mnt/hgfs/share/net-infra/frp`，commit `d1928f96`（版本 0.71.0，`go.mod:3` 声明 `go 1.25.0`）。
所有结论均来自实际源码阅读与本机实测（Go 1.26.5 / linux-amd64 / i9-14900K）。

---

## 1. 数据面全貌（服务端）

`server/proxy/udp.go` 是整条 UDP 路径的心脏，274 行，结构极其朴素：

- `Run()` 先从 `UDPPortManager` 取端口（`:80`），然后 `net.ListenUDP("udp", addr)`（`:97`）。**一个 udp 代理 = 公网上一个 UDP 端口**，之后对该端口上的报文**没有任何鉴权、限速前置或来源校验**。
- 三个 channel 在 `:106-108` 建好：`sendCh` 1024、`readCh` 1024、`checkCloseCh` 无缓冲。1024 是硬编码，不可配置。
- 结构体注释 `:50-52` 写得很直白：`// there are always only one workConn at the same time / get another one if it closed`。**整个代理的所有用户、所有源地址的 UDP 报文，全部复用同一条 workConn。**
- `workConnReaderFn`（`:111-153`）：每轮先 `SetReadDeadline(now+60s)`（`:119`），读一条 `msg.Message`；`*msg.Ping` 丢弃续读（`:134-136`），`*msg.UDPPacket` 则 **`pxy.readCh <- m`（`:140`）阻塞投递**。
- `workConnSenderFn`（`:156-182`）：从 `sendCh` 取消息 `payloadConn.WriteMsg(udpMsg)`（`:165`），写失败即关闭 workConn。
- workConn 获取循环（`:184-243`）：起手 `time.Sleep(500 * time.Millisecond)`（`:186`），然后 `GetWorkConnFromPool`（`:188`）→ 按需叠加加密（`:207`）、压缩（`:215`）、限速（`:219`）→ `msg.NewUDPPacketReadWriter(...)` 选定编解码（`:227`）→ 起 reader/sender 两个 goroutine（`:235-236`）→ **`_, ok := <-pxy.checkCloseCh`（`:237`）整个循环挂在这里等 workConn 死掉**。
- 最后 `udp.ForwardUserConn(udpConn, readCh, sendCh, int(serverCfg.UDPPacketSize))`（`:250`）。

### 会话（session）是怎么被"追踪"的？答案：服务端根本没有会话表

`pkg/proto/udp/udp.go:43-71` 的 `ForwardUserConn` 全文只有两件事：

```go
// 出向：把 readCh 里的包按包内携带的 RemoteAddr 原样打回公网
for udpMsg := range readCh { udpConn.WriteToUDP(buf, udpMsg.RemoteAddr) }   // :46-52
// 入向：读一个包 → 包装成 UDPPacket（RemoteAddr = 公网源地址）→ 非阻塞投 sendCh
n, remoteAddr, err := udpConn.ReadFromUDP(buf)                              // :59
udpMsg := NewUDPPacket(buf[:n], nil, remoteAddr)                            // :64
select { case sendCh <- udpMsg: default: }                                  // :66-69
```

也就是说 frps 是**完全无状态**的：会话身份 = 每个包里回传的完整 `*net.UDPAddr`。好处是 frps 零内存、零淘汰逻辑；代价是（a）每包线上多背 7～19 字节地址、（b）无法做 per-flow 限速/配额/迁移、（c）**恶意方可以伪造 `RemoteAddr` 让 frps 向任意第三方 IP 发包——frps 从不校验回程地址是否曾经出现过**（`:51` 无任何白名单检查）。这是一个可被利用的反射通道。

真正的会话表在**客户端**：`Forwarder`（`pkg/proto/udp/udp.go:73-152`）维护 `udpConnMap map[string]*net.UDPConn`（`:75`），key 是 `udpMsg.RemoteAddr.String()`（`:117`）。每个新 key 就 `net.DialUDP` 一个新 socket（`:119`）并起一个 `writerFn` goroutine（`:148`）。回收靠 `writerFn` 里的 `SetReadDeadline(now+30s)`（`:90`）读超时后 `defer` 删 key + `Close()`（`:80-85`），另有一处写成功后的续期（`:144`）。

客户端侧问题密集：`mu` 声明为 `sync.RWMutex`（`:74`）但**从未 `RLock`**，每个包都吃一次全局写锁（`:116`）；key 用 `.String()`，每包一次字符串分配（`:117`）；`udpConnMap` **无上限**——公网端口无鉴权 + 每个新源地址一个 socket + 一个 goroutine，攻击者用随机源端口即可把 frpc 的 fd 与 goroutine 打满；两处 `SetReadDeadline` 由不同 goroutine 并发设置同一 conn（`:90` 与 `:144`）。PROXY protocol 的实现更粗暴：把头**前置进 UDP 载荷本身**（`:129-138`），破坏了 datagram 边界语义。

`LocalAddr` 字段（`pkg/msg/msg.go:188`）在数据面**永远是 nil**（`:64`、`:96` 都传 nil），却仍在两套编解码里占据分支逻辑——纯协议冗余。

---

## 2. 编码层：v1 JSON 与 v2 二进制

`pkg/msg/msg.go:186-190`：
```go
type UDPPacket struct {
	Content    []byte       `json:"c,omitempty"`
	LocalAddr  *net.UDPAddr `json:"l,omitempty"`
	RemoteAddr *net.UDPAddr `json:"r,omitempty"`
}
```
`Content []byte` 走 `encoding/json` → **base64**，固定 4/3 膨胀。v1 帧头来自 `golib`：1 字节 type + **8 字节 BigEndian 长度** + JSON body（`~/go/pkg/mod/github.com/fatedier/golib@v0.8.1/msg/json/pack.go:51-66`）。且 `defaultMaxMsgLength int64 = 10240`（`msg/json/msg.go:23`），读侧 `length > maxMsgLength` 直接返回 `ErrMaxMsgLength`（`process.go:47-49`）。

**实测数据**（`go test ./pkg/msg -run TestUDPPacketV2FrameSizes -v`，测试代码 `pkg/msg/udp_benchmark_test.go:73-83`）：

| 载荷 | v2-JSON 帧 | v2-binary 帧 | JSON 膨胀 |
|---|---|---|---|
| 64 B (ipv4) | 152 | 85 | +137% |
| 512 B | 748 | 533 | +46% |
| 1200 B | 1664 | 1221 | **+38.7%** |
| 1472 B | 2028 | 1493 | +37.8% |

**编解码 CPU**（`-bench .../payload-1200/ipv4-remote -benchmem`）：

| 操作 | JSON | binary | 倍数 |
|---|---|---|---|
| 编码 | 1310 ns/op, 5 allocs | 552 ns/op, 3 allocs | 2.4× |
| **解码** | **6481 ns/op, 14 allocs** | **617 ns/op, 7 allocs** | **10.5×** |

v2 二进制体布局（`pkg/msg/udp_binary.go:78-88`）：`flags(1)` → 可选 LocalAddr → RemoteAddr → `payloadLen(2 BE)` → payload。地址编码 `putBinaryUDPAddr`（`:170-181`）= `family(1) | ip(4或16) | port(2 BE) | zoneLen(1) | zone(n)`，IPv4 共 8 B、IPv6 共 19+ B。外层是 `pkg/proto/wire/wire.go:98-107` 的 8 字节帧头（`type(2) | flags(2) | length(4)`）+ 2 字节 v2 消息类型（`udp_binary.go:280-283`）。1200 B 载荷合计 8+2+1+8+2+1200 = 1221，与实测吻合。

**为什么默认关闭**：`pkg/config/v1/client.go:149` `c.WireProtocol = util.EmptyOr(c.WireProtocol, "v1")`；`NewUDPPacketReadWriter`（`udp_binary.go:319-338`）在 v1 下若指定 codec 直接报错。二进制 codec 只在 ClientHello/ServerHello 协商成功后生效（`wire.go:220-221` 提供能力、`crypto.go:69-71` 选择、`client/control_session.go:197` 与 `server/service.go:677` 落地）。`conf/frpc_full_example.toml:107` 明确写 "default is v1. v2 requires frps support and must be enabled explicitly."——**双端都要手动开，任一端漏配即回退到 JSON。**

---

## 3. 五大短板复核（逐条给出更精确的严重程度）

**短板 1（单 workConn / HOL）— 复核成立，且比描述更糟。**
默认 `tcpMux = true`（`pkg/config/v1/client.go:154`、`server.go:183`）。`client/connector.go:139-160` 只建**一条** TCP 连接并 `fmux.Client` 包成 yamux session，`Connect()`（`:172-178`）返回的所有 workConn 都是这条 TCP 上的 stream。所以 UDP 报文不只是与自己排队——它与**该 frpc 上所有其它代理**共享一条 TCP 的字节序。一次 HTTP 大文件下载触发的 TCP 重传就能让音频整批延迟。Go 的 `net` 默认开 TCP_NODELAY（全仓 grep `SetNoDelay` 只命中 KCP：`pkg/util/net/kcp.go:56,102`），所以问题不是 Nagle，而是**可靠有序流对实时媒体的重传放大 + 跨代理队头阻塞**。换 `transport.protocol = "quic"` 只能消除跨 stream HOL（`client/connector.go:166-171` 走 `OpenStreamSync`），单流内的有序重传仍在——**frp 全仓 0 处使用 `SendDatagram` / `EnableDatagrams`**（grep 无命中），RFC 9221 完全没用上，尽管依赖里就是 `quic-go v0.60.0`（`go.mod:18`）。

**短板 2（JSON/base64）— 成立**，量化见上表：字节 +38.7%、解码慢 10.5×、每包 14 次分配。

**短板 3（udpPacketSize 定长截断）— 成立，且存在无声配置陷阱。**
默认 1500（`pkg/config/v1/client.go:98`、`server.go:123`），`conf/frps_full_example.toml:143-145` 要求两端一致。`pool.GetBuf(1500)` 返回**恰好 len=1500** 的切片（`golib/pool/pool.go:29-52`），`ReadFromUDP` 于是把超长 datagram **静默截断**（Go 不报错，多余字节丢弃），下游收到一个损坏的包。更糟：`pkg/config/v1/validation/` 里 grep 不到任何 `UDPPacketSize` 校验，用户把它设成 9000 时，v1 路径上 base64 后的 JSON 会突破 `maxMsgLength = 10240`（有效上限约 7.6 KB），读侧返回 `ErrMaxMsgLength` → reader 退出 → workConn 被拆掉重建（`server/proxy/udp.go:120-128`）。一个配置项就能让 UDP 隧道周期性抖断。

**短板 4（无分组 LB / 健康检查）— 成立。**
`UDPProxyConfig`（`pkg/config/v1/proxy.go:290-294`）只有 `RemotePort`；`LoadBalancer` 字段虽在 `ProxyBaseConfig:129` 里被解析，但 `server/proxy/` 中 `LoadBalancer.Group` 的使用只出现在 `http.go:88`、`https.go:82`、`tcpmux.go:59`、`tcp.go:51`——`udp.go` 与 `sudp.go` 里一个都没有，**配置被静默忽略**。健康检查类型白名单是 `{"", "tcp", "http"}`（`pkg/config/v1/validation/proxy.go:49`），无 UDP 探活。

**短板 5（xtcp 只监听 TCP）— 成立，且是最可惜的一处。**
`client/visitor/xtcp.go:64` `net.Listen("tcp", ...)`，`handleConn` 最终是 `libio.Join(userConn, muxConnRWCloser)`（`:194`）——纯字节管道。而打洞成功后手里握着的明明是 `*net.UDPConn`：KCP 路径 `net.DialUDP` + `NewKCPConnFromUDP` + yamux（`:337-364`），QUIC 路径 `quic.Dial(ctx, listenConn, raddr, tlsConfig, &quic.Config{...})`（`:409-417`）。**QUIC session 就在 `qs.session` 里，只要加 `EnableDatagrams: true` 并暴露 `SendDatagram`，原生 UDP 立刻能走 P2P。** frp 没做，于是 UDP 在 frp 里**永远**过中继。sudp 也一样：frps 侧只是 `libio.Join(local, userConn)`（`server/proxy/proxy.go:344`），两段独立 TCP 各有一次 HOL，frps 连统计都做不了（`server/proxy/sudp.go` 全文 51 行，只调 `startVisitorListener`）。

**额外发现（不在原五条内）**

- **D6 阻塞投递**：`server/proxy/udp.go:140` 与 `client/proxy/udp.go:125` 的 `readCh <- m` **无 default**。readCh 满 1024 时读循环停摆，连 Ping 都读不到，60 s 后 `SetReadDeadline`（`:119`）超时把 workConn 拆掉。这是拥塞下"UDP 隧道整条抖断"的直接机制。
- **D7 启动黑洞**：`time.Sleep(500 * time.Millisecond)`（`:186`）——代理上线后 0.5 s 内公网来的包全丢，且每次 workConn 重连都重走。
- **D8 反射面**：`ForwardUserConn` 的 `WriteToUDP(buf, udpMsg.RemoteAddr)`（`pkg/proto/udp/udp.go:51`）不校验该地址是否为已知来源。

---

## 4. 设计：NRP datagram 路径

### 4.1 线上帧格式

**载体 A：裸 UDP 旁路（自带鉴权与加密），16 字节明文头 + AEAD**

```
off  len  field                 说明
0    1    ver:4 | type:4        ver=1; type 0=DATA 1=PING 2=PONG 3=BIND 4=BIND_ACK 5=CLOSE 6=FRAG
1    1    flags                 b0 FRAG  b1 ECHO_REQ  b2 KEYUPDATE  b3 MIGRATED
2    2    epoch     u16 BE      密钥世代，rekey 时 +1
4    4    tunnelID  u32 BE      relay↔agent 隧道句柄（BIND 时由 relay 下发）
8    4    flowID    u32 BE      一条 NAT 会话的紧凑句柄，替代 frp 的完整 UDPAddr
12   4    seq       u32 BE      per-(tunnel,flow) 单调递增；充当 nonce 材料 + 重放窗口 + 丢包统计
--- [0,16) 全部作为 AEAD 的 AAD，明文不加密 ---
16   N    ciphertext            AEAD(key, nonce, aad=header[0:16], plaintext=payload)
16+N 16   tag
```
nonce 12 B = `salt(5, 会话派生) || epoch(2) || dir(1) || seq(4)`，零额外线上字节。`FRAG` 置位时在头后插 4 B：`fragID u16 | idx u8 | cnt u8`。
**固定开销：32 B/包**（16 头 + 16 tag）。对比 frp v1-JSON 在 1200 B 载荷上的 464 B，减少 93%。

**载体 B：QUIC DATAGRAM（RFC 9221），8 字节头，无需自带加密**
```
off len field
0   1   ver:4|type:4
1   1   flags
2   4   flowID u32 BE
6   2   seq16  u16 BE      仅用于抖动/丢包统计与去重
8   N   payload            明文，QUIC 已提供 AEAD 与连接标识
```

### 4.2 消除队头阻塞：明确选型

**主路径 = QUIC DATAGRAM（quic-go `Conn.SendDatagram` / `ReceiveDatagram`，`connection.go:3026` / `:3047`）。** 理由：不重传、不排序、与控制面 stream 共用一条连接与一次握手、复用 QUIC 的 PMTUD 与 Linux GSO（quic-go v0.60 已内置），并且天然拿到连接迁移。
**必须知道的两个坑（源码级）：**
1. `datagramQueue.Add` 在发送队列达 `maxDatagramSendQueueLen = 32` 时**会阻塞等待**（`datagram_queue.go:13,44-67`）。因此 `SendDatagram` **只能**在专用发送 goroutine 里调用，业务侧永不直接触碰。
2. 接收侧在 `maxDatagramRcvQueueLen = 128` 时静默丢弃（`datagram_queue.go:14,96-108`）——这正是实时媒体想要的行为，但意味着 `ReceiveDatagram` 循环里不许做任何阻塞工作。

多并行 stream 方案：**放弃**。yamux 与 QUIC 的 stream 都是可靠有序，只是把 HOL 从"跨代理"缩小到"单 flow"，无法消除重传放大。裸 UDP 旁路：**保留为 fallback**，用于 QUIC 被中间设备阻断（部分企业网封 UDP/443 之外的 UDP）的场景，并复用同一套 BIND/token 鉴权。

### 4.3 NAT 会话表

```go
type flowKey struct {                 // 可比较值类型，可直接做 map key，零分配
    proxyID uint32
    peer    netip.AddrPort            // net/netip，不用 *net.UDPAddr
}
type flow struct {
    id      uint32
    key     atomic.Pointer[flowKey]   // 支持迁移
    lastRx  atomic.Int64              // 单调时钟 nanos
    txSeq   atomic.Uint32
    rxWin   replayWindow              // 64-bit 滑窗
    q       chan []byte               // cap = 16
    lru     *list.Element
}
type shard struct { mu sync.RWMutex; byKey map[flowKey]*flow; byID map[uint32]*flow; lru *list.List }
type table struct { shards [16]shard; perIP map[netip.Addr]int32 }
```
- **读用 `RLock`，仅新建/淘汰用 `Lock`**（frp 每包吃写锁，`pkg/proto/udp/udp.go:116`）。16 shard 按 `fnv32(key)&15` 分片。
- 收包用 `ReadMsgUDPAddrPort` 直接拿 `netip.AddrPort`，避免 frp 每包一次 `.String()` 分配（`:117`）。
- **分级空闲超时**：有 PING/高包率的媒体流 120 s；普通 UDP 30 s；单请求型（DNS 等）10 s。惰性判定 + 每 5 s 一次 sweep。
- **内存上限硬约束**：默认 `maxFlows = 65536`，每 flow 含 map 桶与 16 槽队列约 ≤ 320 B → **≈ 21 MB**。达上限时按 LRU **淘汰最旧**而非拒绝新会话（拒绝新会话会让攻击者用旧表项锁死服务）。
- **每源 IP 配额** `perIP ≤ 64`，超过直接丢包 —— 这是 frp 完全缺失的（无上限 map + 每 key 一个 socket 一个 goroutine）。
- **回程地址校验**：只向表内存在的 `flowKey` 发包，堵掉 frp 的反射面（`pkg/proto/udp/udp.go:51`）。

**通话中途换源端口**（家用 NAT 30 s 重绑、WiFi↔5G 切换），三级策略：
1. **有我方客户端（S1 / nomifun-tauri / IoT）**：客户端头里始终带 BIND_ACK 下发的 `flowID`，换端口后 AEAD 校验通过即把 `flow.key` 原子换成新地址、置 `MIGRATED` 标志、local 侧 socket 不变 → 桌面服务看到的源端口不变，通话不中断。等价于 QUIC connection migration。**推荐路径。**
2. **零客户端但载荷是 RTP（S2 的部分场景）**：可选开启 SSRC 粘滞——读 RTP 头偏移 8..11 的 SSRC，以 `(proxyID, ssrc)` 为二级 key 做 flow 迁移。需显式开关，因为它要求 relay 窥探载荷（与 SRTP 兼容：SSRC 在明文头里）。
3. **兜底**：新 key = 新 flow，local 侧新建 socket。这是 frp 现在的语义（`pkg/proto/udp/udp.go:117-125`），必须在文档里写明"对端会看到新源端口"。

### 4.4 MTU 算术（逐候选载体显式计算）

| 载体 | 计算 | 安全内层载荷 |
|---|---|---|
| 裸 UDP / IPv4，MTU 1500 | 1500 − 20 − 8 = 1472；减 16 头 + 16 tag | **1440** |
| 裸 UDP / IPv6，MTU 1500 | 1500 − 40 − 8 = 1452；减 32 | **1420** |
| 裸 UDP / PPPoE 1492 (IPv4) | 1492 − 28 − 32 | **1432** |
| QUIC DGRAM / IPv4，PMTU 后 | 1472 − (flags 1 + DCID 4 + PN 4 + tag 16) − DATAGRAM 帧头 3 − 内层 8 | **≈ 1436** |
| QUIC DGRAM，DCID 最坏 20 B | 1472 − 41 − 3 − 8 | **≈ 1420** |
| QUIC DGRAM，**PMTUD 完成前** | `InitialPacketSize = 1280`（`internal/protocol/params.go:12`）→ 1280 − 25 − 3 − 8 | **≈ 1244** |
| WireGuard 风格封装 (对照 EasyTier) | 1500 − 20 − 8 − 32 − 内层 IP/UDP 28 | 1412 |
| TCP/TLS 流（frp 现状） | 无 MTU 限制，但 1200 B 载荷实测占线 1664 B | — |

**结论：对外统一宣称并强制 1200 B 内层 datagram 上限**（与 WebRTC/QUIC 工业实践一致，也低于所有上表数字，避开 PMTU 黑洞）；超过 1200 的走 `FRAG`（4 B 头，最多 4 片，重组超时 200 ms、重组表纳入同一内存上限）。**同时必须动态读取 quic-go 的 `DatagramTooLargeError.MaxDatagramPayloadSize`（`errors.go:96-98`）来自适应**，绝不硬编码——因为握手初期只有 ~1244 B。frp 的 `udpPacketSize` 是单一全局定长且两端必须手工对齐（`conf/frps_full_example.toml:143-145`），这是必须丢弃的设计。

### 4.5 背压与丢弃：精确落点

实时媒体的铁律是**丢，绝不阻塞**。四个落点，全部非阻塞且带计数器：

1. **relay 公网 socket → flow 队列**：`flow.q` cap=16（20 ms 包间隔 ≈ 320 ms 缓冲）。满则**丢队头**（drop-head）而非丢新包——旧音频帧已无价值。frp 这一处已经是丢（`pkg/proto/udp/udp.go:66-69`），是唯一做对的地方。
2. **flow 队列 → 载体发送 goroutine**：per-tunnel 单 goroutine，对本隧道所有 flow 做加权轮询防饿死；自维护 `atomic.Int32 inflight`，> 24 时直接丢，**保证永不进入 quic-go `datagramQueue.Add` 的阻塞分支**（`datagram_queue.go:44-67`）。
3. **载体接收 → local socket**：直接 `WriteToUDP`，内核缓冲满时由内核丢，只累加 error 计数。
4. **硬规则**：数据面代码里禁止出现不带 `default` 的 channel 发送。frp 恰恰在两处犯规（`server/proxy/udp.go:140`、`client/proxy/udp.go:125`），代价是 workConn 周期性被 60 s 读超时拆掉。

### 4.6 Go 实现成本与 2026 选型

- `net/netip`：flowKey 用 `netip.AddrPort`（可比较、无指针、无分配）。
- `net.UDPConn.ReadMsgUDPAddrPort` 替代 `ReadFromUDP`，去掉每包 `*net.UDPAddr` 分配。
- **批量收发是低延迟高 PPS 的关键**：Go 1.26 stdlib 仍无 `recvmmsg`/`sendmmsg`，需 `golang.org/x/net/ipv4|ipv6` 的 `ReadBatch`/`WriteBatch`。frp 是逐包 `ReadFromUDP`（`pkg/proto/udp/udp.go:59`）。
- **GSO/GRO**：quic-go v0.60 已内置 Linux `UDP_SEGMENT` 支持；自研裸 UDP 旁路要追平需自己写 setsockopt。这是"主路径选 QUIC DATAGRAM 而非自研裸 UDP"的一个隐性大优势。
- AEAD：抄 frp 的 CPU 探测思路（`pkg/proto/wire/crypto.go:26` 用 `golang.org/x/sys/cpu`，`crypto.go:37-40` 在 aes-256-gcm 与 xchacha20-poly1305 间选择）。
- 缓冲池：**不要**抄 `golib/pool` 的 1k/2k/5k/16k 分档（`pool/pool.go:29-52`）——1.4 KB 包会拿到 2 KB 桶。固定 2048 B 单档 `sync.Pool` 更简单也更省。

### 4.7 RTP 该不该走通用中继？—— 明确建议：分三层，媒体面走 WebRTC + TURN

**(a) 信令/控制/普通 API 走我们的中继**（HTTP/WS/自定义 datagram）。这是中继的强项。
**(b) 音视频媒体面：默认 WebRTC，中继内置标准 TURN（RFC 5766/8656）服务端**，与控制面共享鉴权（用设备 token 换 TURN 短期凭证）。Go 侧用 `github.com/pion/turn/v4` 与 relay 同进程共存。四条理由，最后一条是决定性的：
1. ICE 会先试 P2P。家用 NAT 多为 endpoint-independent mapping，直连成功率高；中继只兜底，公网带宽成本从 O(全部会话) 降到 O(打洞失败会话)。
2. TURN 是既成标准，浏览器/libwebrtc/Android/pion 全部开箱支持。S1 的手机端零协议工作量；自研 datagram 协议要在每个平台写并维护客户端。
3. SRTP 端到端加密，中继不解密、不看载荷，合规与隐私更好讲。
4. **拥塞控制。** WebRTC 有 GCC/transport-cc，能按丢包与延迟自适应降码率。自研 UDP 中继若不做拥塞控制，弱网下会打满上行并放大丢包；而做了拥塞控制，等于重写一个 WebRTC。这不是我们该花的预算。
**(c) 自研 datagram 中继保留给"非媒体 UDP"**：S2 的机器人私有 UDP 指令、游戏协议、DNS、IoT 心跳、QUIC-in-relay。包小、无码率自适应需求，通用中继完全够用，且这才是 frp 真正的空白（frp 在这里也只有一条 TCP workConn）。

顺带：TURN 的 ChannelData 头只有 4 B，比我们 16 B 头更省——若某场景确实要自研通道承载 RTP，应优先考虑直接实现 TURN channel 语义而非另造一套。

### 4.8 采纳 / 改造 / 丢弃

| frp 机制 | 判定 | 依据 |
|---|---|---|
| per-remotePort `ListenUDP` + 端口管理器（`server/proxy/udp.go:80,97`） | **采纳** | S2 要求"relay IP + port"直达，零客户端 |
| 单 workConn 承载全部 UDP（`:50-52`） | **丢弃** | 跨代理 HOL + 重传放大 |
| 每包回传完整 `RemoteAddr` 做无状态会话（`pkg/proto/udp/udp.go:64,117`） | **改造** | 换 32-bit flowID + relay 侧有状态表；省 7–19 B/包，换来迁移、配额、反射防护 |
| v1 JSON/base64（`pkg/msg/msg.go:186-190`） | **丢弃** | +38.7% 字节、解码慢 10.5× |
| v2 二进制地址编码（`udp_binary.go:170-181`） | **改造** | 思路正确，但地址只在 BIND 传一次，不进每包 |
| 全局定长 `udpPacketSize`（`client.go:98`，`conf/frps_full_example.toml:143-145`） | **丢弃** | 静默截断 + 无校验 + 双端手工对齐 |
| sudp（visitor 侧本地 ListenUDP，中继不暴露公网端口，`client/visitor/sudp.go:54`） | **采纳** | S1 私密模式很有价值；但两跳 TCP（`server/proxy/proxy.go:344`）换成 datagram |
| nathole 打洞（STUN + 行为探测 + QUIC/KCP 会话，`client/visitor/xtcp.go:252-318`） | **采纳并修复** | 打洞后必须能直接跑 datagram（`EnableDatagrams` + `SendDatagram`），而非只 `net.Listen("tcp")`（`:64`） |
| PROXY protocol 前置进 UDP 载荷（`pkg/proto/udp/udp.go:129-138`） | **丢弃** | 污染 datagram 边界；改用 BIND 元数据或独立 type |
| 固定 30 s 读超时清 map（`:90,144`） | **改造** | 分级 idle timeout + LRU + 硬上限 + per-IP 配额 |
| 启动 `Sleep(500ms)`（`server/proxy/udp.go:186`） | **丢弃** | 用就绪信号/条件变量替代 |
