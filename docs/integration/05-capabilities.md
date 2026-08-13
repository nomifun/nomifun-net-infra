# 5. 能力矩阵：哪些组合真的能用

隧道是五个轴的正交分解：`kind × tls × exposure × l4 × router`。
**放行 ≠ 可用** —— `Validate` 放行的组合远多于数据面真正实现的组合。

这一章给你一张能照着填的表，而不是枚举笛卡尔积。

## 5.1 先看结论：只有两条代码路径

| 路径 | 触发条件 | 有什么 | 没有什么 |
|---|---|---|---|
| **独立监听器**（`internal/relay`） | `exposure=port` | 每隧道限速、`max_conns`、`max_conns_per_ip`、`allow_cidrs`、7 个计数器 | **任何 TLS 与 HTTP 能力**（`tls` 轴被完全忽略） |
| **判别器 + L7 网关**（`internal/gateway`） | `exposure=shared` | TLS 终止、Host/路径路由、请求头改写、ACME | **`policy` 里除 `allow_cidrs` 外全部不生效** |

选哪条路径的唯一开关是 `exposure`。其余四个轴都是在这两条路径**内部**做选择。

## 5.2 实际可用的五种形态

| # | 配置 | 客户端怎么访问 | 适合 |
|---|---|---|---|
| 1 | `exposure=port, l4=tcp, tls=passthrough` | `<中继IP>:<port>` 裸 TCP | 只能填 IP+端口的设备；任意 TCP 协议 |
| 2 | `exposure=port, l4=udp, tls=passthrough` | `<中继IP>:<port>` 裸 UDP | 实时媒体、游戏、DNS |
| 3 | `exposure=shared, tls=gateway, router={kind:http, domains:[...]}` | `https://域名/` | 手机/浏览器访问家里的 HTTP/WebSocket 服务 |
| 4 | `exposure=shared, tls=passthrough, router={kind:tls-sni, domains:[...]}` | `https://域名/`，**中继不解密** | 端到端加密、客户端证书、自己管证书 |
| 5 | `exposure=shared, tls=gateway, router={kind:http, catch_all:true}` | `http://<中继IP>/` | 只发 IP 型 Host 的设备的默认落点 |

**其余组合要么被 Validate 拒，要么静默降级。** 下面逐条说清。

## 5.3 每个轴的取值与真实语义

### `exposure` —— 唯一真正分叉的轴

| 值 | 状态 |
|---|---|
| `port` | ✅ 可用。独立监听器。 |
| `shared` | ✅ 可用。需要中继启动时带 `-shared`，否则状态报 `error` 并说明。 |
| `private` | ⚠ **死枚举**。Validate 放行，但**一个监听器都不会建**，而状态显示 `active`（绿点）、总览计入 TunnelsUp。客户端一律 connection refused。控制台向导造不出来，只有直接调 API 或声明式配置会踩到。**不要用。** |
| `p2p` | ❌ Validate 拒绝（v1 未实现，枚举位为将来预留）。 |

### `tls` —— 只在 `exposure=shared` 下有意义

| 值 | `exposure=shared` | `exposure=port` |
|---|---|---|
| `passthrough` | ✅ 字节级搬运，中继不解密 | ✅ （唯一正确的选择） |
| `gateway` | ✅ 中继终止 TLS，可做 Host/路径路由与头改写 | ⚠ **被完全忽略** |

> **`exposure=port` + `tls=gateway` 是一个陷阱。** Validate 放行它，但独立监听器
> 做的是纯裸 TCP 拼接 —— 不做 TLS 握手、一个字节都不解析。而控制台会把端点渲染成
> `https://<中继IP>:<port>`，暴露面摘要里「应用层鉴权」显示「已配置」。
> 浏览器打开那个地址会报 `ERR_SSL_PROTOCOL_ERROR`（除非你的后端自己就在说 TLS）。
>
> 要 TLS 终止只能用 `exposure=shared`。

### `l4`

| 值 | 状态 |
|---|---|
| `tcp` | ✅ 两条路径都支持 |
| `udp` | ✅ **只有 `exposure=port`**。共享入口是 TCP 监听器，不承载 UDP。 |

UDP 隧道要求承载支持不可靠数据报。承载不支持时状态如实报 `degraded`
并说明「UDP 暂不可用」，**绝不**悄悄塞进一条可靠流（frp 就是那样做的）。

### `router` —— 只在 `exposure=shared` 下读

| `kind` | 语义 | 配 `tls` |
|---|---|---|
| `http` | 按 Host + path 路由，中继解析 HTTP | 必须 `gateway` |
| `tls-sni` | 按 SNI 路由，**不解密** | 必须 `passthrough` |

字段：

- `domains` —— 支持通配。三段域名 `a.b.c` 的匹配链是 `[a.b.c, *.b.c, *]`
  （**没有** `*.c`；四段才有 `*.c.d`）。两段域名 `example.com` 的链是 `[example.com, *]`。
  所以注册 `*.c` 这种形态永远匹配不到三段主机名。
- `locations` —— 路径前缀，仅 `kind=http`。
- `host_rewrite` —— 改写发给后端的 Host。**没有格式校验**，且不影响拨号目标。
- `catch_all` —— 这个端口的默认落点。

> **`catch_all` + `tls=gateway` 对二进制协议客户端会退化成裸 TCP 代理。**
> 首字节既不是 `0x16`（TLS）也不是可打印 ASCII 的客户端 —— 带长度前缀或魔数的
> 自定义二进制协议、DTLS、自研帧头 —— 会落到判别器的 default 分支，
> 然后被**原样拼接**到后端：没有 HTTP 解析、没有头改写、没有限速。
>
> SSH 与 MySQL **不**走这条：SSH 的首字节是可打印 ASCII（`SSH-2.0-…`），
> 会进明文分支然后被 404 拒；MySQL 是**服务端先说话**，客户端不发首字节，
> 于是它在 peek 超时之后被拒。
> 别把 `catch_all` 指向一个不该被任意协议访问的后端。

### `kind`

| 值 | 状态 |
|---|---|
| `service` | ✅ |
| `reverse` | ✅ —— 但**数据面一次都没读过这个字段**，与 `service` 行为完全相同。它目前只影响控制台的展示与向导措辞。 |
| `peer` | ❌ Validate 拒绝（场景三预留）。 |

v1 里**所有** kind 都必须有一个 agent 承载。「中继自己拨号」没有实现，
见 [9.2](09-known-gaps.md#92-刻意的设计决定)。

### `backend`

| `kind` | 状态 |
|---|---|
| `addr` | ✅ `host:port`，TCP 与 UDP 都行 |
| `unix` | ✅ 只支持 TCP；**绕过 agent 的本地目标策略**（路径不是 IP，策略无从判断） |
| `handler` | ❌ Validate 拒绝（进程内测试用） |

**回源腿的 scheme 硬编码为 `http`** —— 网关模式接不了 https 后端。
要接 https 后端只能用形态 4（`passthrough` + `tls-sni`）。

### `policy`

| 字段 | `exposure=port` | `exposure=shared` |
|---|---|---|
| `allow_cidrs` | ✅ | ✅ |
| `max_conns` | ✅ | ✅（语义见下）|
| `max_conns_per_ip` | ✅ | ✅（语义见下） |
| `bytes_per_second` | ✅ | ✅ |
| `packets_per_second` | ✅（见下） | ❌ **不生效**（TCP/HTTP 上无诚实含义） |
| `realtime_datagram` | ✅（UDP：超限即丢而不是分片） | — |

> **共享入口上 `max_conns` 的语义与独立监听器不同**：那边一条连接算一个额度，
> 网关（HTTP）路径上一个**在飞请求**算一个额度（升级后的 WebSocket 整段算一条），
> 而 SNI 直通/明文兜底的 splice 路径按**连接**算、与独立监听器一致。
> 差异是承载形态决定的：共享入口上一条 keep-alive 连接可以换 Host 落到别的隧道。
> 另外 `max_conns: 0` 在共享入口上是「不设每隧道上限」，兜底的是共享端口自己的
> 512；独立监听器上 0 是「这条隧道 512」。详见
> [9. 已知缺口](09-known-gaps.md)。

> **`packets_per_second` 在 TCP 上限的是「每次 read」而不是「包」。**
> 每次底层 `Read` 只申请 1 个额度，与读到多少字节无关。所以填 100 等于
> 「每秒最多 100 次读」，吞吐会被压到远低于 `bytes_per_second`。
> 这个字段的设计目标是 UDP 小包洪水；**TCP 隧道上不要配它。**

## 5.4 TCP 限速看不到丢弃计数是正常的

TCP 路径的限速表现为**变慢**（反压自然传播到发送方窗口），不是丢弃 ——
字节流丢掉中间一段就是把连接搞坏。所以 TCP 隧道的「超限速被丢弃」一格**恒为 0**。

要验证限速生效请看吞吐，不要看丢弃计数。UDP 上才会有丢弃计数
（等一秒的音频包到达时已经没有价值）。

## 5.5 共享入口的两道请求级检查

这两条是在共享入口上**每个请求**都会跑的，因为连接级的判定约束不了请求级的路由
（判别器每连接判一次隧道，而网关每请求重查路由）：

1. **`allow_cidrs` 每请求重查。** 否则一条 keep-alive 连接上换个 Host 就能访问
   白名单本该拒绝的隧道。
2. **`tls=passthrough` 的隧道拒绝从网关路径服务。** 否则用另一条 gateway 隧道的
   SNI 建 TLS、再把 Host 换成 passthrough 隧道的域名，它的后端就会收到
   **解密并改写过**的明文 HTTP —— 而选 passthrough 的意图恰恰是「中继绝不看明文」。

两条都返回 404（与「未注册域名」同一个回复，不确认存在性），
并各有一个独立计数器：`allow_cidrs` 的请求级拒绝计进 `gateway_denied_cidr`，明文降级拦截计进 `denied_passthrough`（两者都在 `/api/snapshot` 的 `shared` 段里）。
**这两个数字与判别器那个连接级的 `denied_cidr` 是三回事**：判别器每连接判一次，网关每请求重查 —— 请求级的数涨说明有人在同一条连接上换 Host 试别的隧道。两者都经实测复现过，且有回归判据。
