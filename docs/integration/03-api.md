# 3. API 与服务间集成

控制台前端消费管理员 API；Desktop 另外通过一次性邀请兑换接入，并用本连接专属
bearer 凭据查询与撤销连接。二者的权限不同。Desktop 不需要保存中继管理员密码。

## 3.1 先说结论：可行，但代价要清楚

服务间集成（你的程序驱动中继，不是人点浏览器）是可行的，三步就够。但先看代价：

- **通用管理员 API 没有 API key / mTLS 或角色分权。** 驱动任意管理员操作的集成方持有管理员口令。
  同一个会话还能 `POST /api/config:apply` 删掉全部隧道、下载含全量配置的支持包。
  没有角色、没有只读凭据、没有按端点分权。
- **Desktop 专用接入是例外。** 短时中继邀请只授权接入；兑换后的控制凭据只授权该连接的 GET/DELETE，不能创建其他隧道或读取完整支持包。见 [Desktop 接入](10-desktop-connect.md)。
- **会话 12 小时硬过期，没有滑动续期、没有 refresh 端点。** 你的程序必须每
  ≤12h 重登一次。
- 登录端点有限速（见 3.5）。把「每次调用都重登」写进循环会撞上它。

## 3.2 三步配方（同机 / loopback）

```bash
B=http://127.0.0.1:9443

# 1) 登录。CSRF 令牌**直接在响应体里**，不用去读 Cookie。
CSRF=$(curl -s -c jar -X POST "$B/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ops","password":"..."}' | jq -r .csrf_token)

# 2) 只读：只要 cookie jar。GET/HEAD 不校验 CSRF、不校验 Origin。
curl -s -b jar "$B/api/snapshot"

# 3) 写：cookie + CSRF 头 + 一个 Origin 头。
curl -s -b jar -X POST "$B/api/tunnels" \
  -H 'Content-Type: application/json' \
  -H "X-NFR-CSRF: $CSRF" \
  -H 'Origin: http://127.0.0.1:9443' \
  -d '{"slug":"home-api","exposure":"port","listen_port":9090,
       "backend":{"kind":"addr","addr":"127.0.0.1:8080"}}'
```

实测过的返回：步骤 3 缺 CSRF 头 → `403 {"code":"csrf","message":"缺少 CSRF 令牌"}`；
Origin 是别的主机名 → `403`。两者与「没登录」（401）可区分。

## 3.3 跨机形态：有一个会让你查错方向的坑

反代/跨机时你会想给中继发一个域名型 Host。此时**必须手工写 `Cookie:` 头**，
不能靠 cookie jar：

> **坑：`curl -b jar` 配 `-H 'Host: ...'` 会静默不发 Cookie。**
> curl 按 **Host 头**做 cookie 域匹配，而不是按 URL 主机。于是一个 Cookie 都不发，
> 你看到的是 **401**。
> 症状具有误导性：它既不是「没登录」（你确实登录了），也不是 Host 校验失败
> （那会是 421）。实测确认过这个行为。

正确写法：

```bash
# 中继必须带 -console-hosts=relay.example.com（否则一切 421，见 2.3）
# 会话 Cookie 是 HttpOnly，curl 把它存成 `#HttpOnly_` 前缀行 ——
# 用 grep -v '^#' 过滤 jar 会把它一起滤掉（我第一次就是这么错的）。
TOK=$(awk '/nfr_session/{print $NF}' jar)

curl -s -H 'Host: relay.example.com' -H "Cookie: nfr_session=$TOK" \
     "$B/api/snapshot"                                    # → 200

curl -s -H 'Host: relay.example.com' -H "Cookie: nfr_session=$TOK" \
     -H "X-NFR-CSRF: $CSRF" -H 'Origin: https://relay.example.com' \
     -H 'Content-Type: application/json' \
     -X POST -d '{...}' "$B/api/tunnels"                  # → 200
```

**Origin 校验只比主机名**，不比 scheme 与端口。所以反代后面写
`Origin: https://relay.example.com` 对着一个明文回源口也是通的（实测确认）。

### Go 客户端的一个额外陷阱

`net/http` **忽略** `req.Header.Set("Host", …)`。必须设结构体字段：

```go
req.Host = "relay.example.com"   // 对
// req.Header.Set("Host", ...)   // 静默无效
```

Rust 的 `reqwest` 用 `.header(HOST, …)` 正常。

## 3.4 Cookie 与会话

> `LoginResponse.must_rotate` **恒为 false**。后端没有任何路径把它置 1
> （唯一的 `CreateAdmin` 调用点传 false，`SetAdminPassword` 只会清零）。
> 「强制首次改密」在 v1 不存在 —— 而 `internal/console` 的包注释还写着有，
> 那是文档错误。不要围绕这个字段写逻辑。

| | 明文形态（默认） | 加固形态（`-console-behind-tls-proxy`） |
|---|---|---|
| 会话 Cookie 名 | `nfr_session` | `__Host-nfr_session` |
| `Secure` | 否 | 是 |
| CSRF Cookie 名 | `nfr_csrf`（**两种模式下都不变**） | 同 |

会话 Cookie 是 `HttpOnly`；CSRF Cookie **刻意不是**（双提交模式要求前端能读它）。

CSRF Cookie 的名字刻意**不**随模式改名：前端按字面量找它，跟着改名需要前端同时
认两个名字，而那是一处没有测试守着的跨语言耦合。

> **坑：声明了 `-console-behind-tls-proxy` 但前面其实没有 TLS。**
> 浏览器因为 `Secure` 而不保存 Cookie，现象是**登录返回 200、下一个请求 401**，
> 而两侧日志都显示成功。诊断依据是设置页的 `console_session_hardening` 一项。

## 3.5 限速与繁忙：三种「不是密码错」的失败

未鉴权端点（`POST /api/login`、`POST /api/setup`）有两道闸。它们都**刻意不回 401**，
因为回 401 会让你去查密码，查错方向。

| 状态码 | `code` | 什么时候 | 怎么办 |
|---|---|---|---|
| 401 | `bad_credentials` | 真的用户名或密码错 | 查凭据 |
| 429 | `throttled` | 同源 IP 尝试过于频繁 | 按 `Retry-After` 等 |
| 503 | `hash_busy` | 密码哈希并发闸满（`POST /api/login`、`/api/setup`、`/api/password` 三条路径口径一致） | 按 `Retry-After: 5` 重试 |

限速参数：**每源 IP 突发 10 次、之后每 30 秒补 1 次**（稳定 2 次/分钟）。
**成功登录会清掉该源 IP 的失败预算**，所以正常使用碰不到上限。
IPv6 按 /64 归并。限速**排在解析请求体之前**，所以畸形请求体也扣配额。

反代形态下所有请求的源 IP 都是反代，于是那个桶事实上是全局桶。这是正确的降级，
但意味着经反代来的攻击会与你共用配额。见 [9. 已知缺口](09-known-gaps.md)。

实测：连打 20 次错口令 → 前 10 次 401、之后全部 `429` 带 `Retry-After: 29`。

## 3.6 声明式整份配置

`POST /api/config:validate` 与 `POST /api/config:apply`，请求体都是
`{"doc": "<JSON 文本>"}`（两层，因为前端给的是一个可粘贴的编辑框内容）。

文档形状：

```json
{"version": 1, "tunnels": [ /* 期望的**完整**集合 */ ]}
```

**不在清单里的现存隧道会被删除。** 这是「声明式」的含义，也是这两个端点唯一
不可逆的部分。

- `:validate` 是**真正的干跑**，一个字节都不写。返回的 diff 逐条列出将被
  新建/更新/删除的 slug。
- `:apply` 的校验是一道**全量的门**：任何一条不合法就整份拒绝、什么都不动。
- 但**写入本身不是原子的**（存储层没有跨隧道的事务口子）。写到一半失败会返回
  `500 {"code":"partial_apply","applied":N}`。文档描述的是终态，
  **直接重跑同一份是安全的**。
- 文档里的 `id` / `short_id` / `state` 一概不认：前两个由中继分配
  （接受外来 id 等于允许一份文档覆盖一条它没提到的隧道），
  第三个是运行时观测。
- 未知字段是 400（拼错的键不会被静默忽略）。第一个 JSON 对象之后还有内容也是 400。

## 3.6b 写隧道时一定要知道的四件事

这四条都经实测确认，每一条都能让你**以为成功了但结果不对**。

### ① `PUT` 是整体替换

请求体里没写的字段会被写成**零值并落库**。漏写 `listen_port` → 被清零 →
下一次 ApplyTunnels 换一个内核随机端口并回写 → `exposure=port` 的客户端
（端口写在固件里的设备）全部失联。

**正确做法：先 GET、改字段、整份 PUT 回去。** 见
[4.6](04-agent.md#46-隧道重绑) 的示例。

### ② 带 `id` 的 `POST` 是 upsert，不是创建

存储层是 `ON CONFLICT(id) DO UPDATE`，而处理器只在 `id` 为空时才生成新 id。
所以对同一个 `id` POST 两次，第二次**静默覆盖**第一条并回 200 —— 没有 409。
只有 `slug` 与 `listen_port` 的唯一约束会挡。

**要创建就别给 `id`。**

### ③ `state` 会被客户端的值短暂污染

`POST {"state":"active"}` **会进库并回显在响应体里**（实测确认）。但窗口比
「一秒」小得多：**没有「每秒重算」这回事**（`RefreshStates` 只在 agent 上下线
与逐跳探测时被调）。真正的机制是 POST/PUT 在**返回之前**就同步跑了一次
`ApplyTunnels` → `refreshStates`，所以库里那个被污染的 `state` 在响应写出前
就已经被纠正 —— 窗口接近于零。

结论方向不变，甚至更强。两件事成立：

- **POST/PUT 响应体里的 `state` 不可信** —— 它是你传的值或 `draft`，不是运行时真值。
  要读真状态请重新 GET（或读 `/api/snapshot`）。
- 别传 `state`。它是运行时**观测**，不是期望值。

声明式配置那条路（`config:apply`）**主动清掉** `state`，所以它连这个窗口都没有。

> **一个残留的例外**：`refreshStates` 对 `rejections` / `routeErrors` 里的隧道
> 直接跳过（那两处的原因更具体，不该被通用判定覆盖）。所以对**那几条**隧道，
> 客户端传进去的 `state` 不会被纠正。别传它。

### ④ 响应里的两个字段不可信

| 字段 | 什么时候不可信 |
|---|---|
| ~~`short_id`（PUT 响应）~~ | **已修**。此前存储层只在 `t.ShortID == 0` 时才管这个号，而 PUT 请求体不带它 → 走 `allocShortID` 拿一个当时**空闲**的号，UPDATE 子句又不写这一列，于是响应里那个号从未落库；后果是延迟发生的（下一条新建的隧道会真的拿到它，你手里那份响应事后变成别人的标识）。现在存储层无条件用库里的号，响应与库一致。 |
| `listen_port`（POST 响应，原本传 0） | 端口分配发生在 ApplyTunnels 里、对另一份从库重读的对象赋值，处理器手里的对象不会被更新；而该字段有 `omitempty` → **响应里根本没有这个键**。要拿分配到的端口请重新 GET。 |

### 顺带：`fields[].path` 不可用于表单绑定

`:validate` 与 400 响应里的 `fields[].path` 是**关键词猜的**（对错误串做子串匹配），
而遍历的是一个 Go map —— **迭代顺序随机**。同一个请求体连发多次，同一条错误的
`path` 可能一次是 `"backend"`、一次是 `"kind"`（实测 6 次里 4/2 分布）。

**只读 `message`，不要用 `path` 做稳定的字段绑定。**

## 3.7 Desktop 专用接入 API

管理员端点沿用管理员 Cookie，会改变状态的 POST/DELETE 同时要求 CSRF 与 Origin：

| 方法与路径 | 用途 |
|---|---|
| `GET /api/desktop/preflight` | v2 部署配置预检；不证明公网可达 |
| `POST /api/pairing-invites/v2` | 创建短时一次性邀请，逐台绑定公开业务地址 |
| `GET /api/desktop-connections` | 列出 Desktop 连接状态 |
| `GET /api/desktop-connections/{id}` | 查看单连接 |
| `DELETE /api/desktop-connections/{id}` | 撤销该连接及其业务入口 |

Desktop 使用专用 bearer 凭据调用：

| 方法与路径 | 凭据与边界 |
|---|---|
| `POST /api/bootstrap/desktop/v2` | 一次性邀请，JSON 体内包含持久保存的随机 `attempt_id` |
| `POST /api/bootstrap/desktop/v2:cancel` | 原邀请与原 `attempt_id`，取消尚未完成或结果未知的配对尝试；已兑换时必须匹配保存的尝试标识 |
| `GET /api/desktop-connections/{id}` | 兑换得到的本连接 `control_token` |
| `DELETE /api/desktop-connections/{id}` | 同一控制凭据，仅能撤销它所属的连接 |

`POST /api/pairing-invites` 与 `POST /api/bootstrap/desktop` 保留 v1 兼容；v1 固定
后端 `127.0.0.1:25808`，v2 固定专属回环后端 `127.0.0.1:25811`。
生成配对串必须使用服务端返回的 `bootstrap_url`，不能用当前管理浏览器 origin。
完整字段、重试语义、状态与 HTTPS 反代路径见 [第 10 章](10-desktop-connect.md)。
取消不受入网凭据到期限制，未兑换且已到期的邀请也可取消；重复取消成功返回已撤销的
连接对象。Desktop 必须确认服务端撤销成功后再删除本地 pending 记录与原凭据。
实现见 `internal/console/routes.go:64` 与 `internal/console/desktop_connections.go:13`。

## 3.8 事件流（SSE）

`GET /api/events`。事件种类是**稳定标识**，会进数据库、SSE 与控制台筛选器。
全集见 `internal/store/metrics.go` 的 `Kind*` 常量与 `web/src/api/types.ts` 的
`EVENT_KINDS` —— 两者有一条跨语言契约测试逐项比对，所以它们不会漂。

服务端**实际会下发**的类型只有 5 个：`hello`（连接建立时一帧）、`metric`（1Hz）、
`health`（每 15 秒一帧）、`state`（隧道/agent 变化时）、`session`（会话开关）。
常量里还定义了 `log`，但它在生产代码里**一次都没有发布点** —— 日志只在 stderr，
SSE 上拿不到。

`Last-Event-ID` 被**完全忽略**：`sse.go` 里有一个 `lastEventID()` 解析函数，但它没有任何调用点（`sse.go:354` 的 `var _ = lastEventID` 是它唯一的引用，存在只为压住「未使用」报错）。处理器既不读这个头也不落日志 —— 所以 EventSource 自动重连期间丢掉的帧是**静默**丢失，没有任何迹象。
每帧都带 `id:`，浏览器重连会自动带上它，但服务端不补发 —— 断连期间的事件永久丢失
且没有任何提示。

**要求不丢事件的一方必须在重连后自己补拉** `GET /api/events/recent?since=<最后见到的 id>`。

订阅者队列深度 32，满了就**丢帧**（绝不阻塞）。`health` 帧里的 `dropped`
就是这个计数 —— 它不为 0 就说明你漏了事件。
