# 7. 运维

## 7.1 健康检查：三件必须分清的事

| 端点 | 它证明什么 | 它**不**证明什么 |
|---|---|---|
| `GET /healthz` | HTTP 栈活着 | 入口绑上了、数据库能读、agent 在线 |
| `/nfrelay -version` | 二进制能执行 | 上面任何一条 |

**`/healthz` 是 liveness，不是 readiness。** 它恒返回 `{"ok":true}`，
即使所有入口都没绑上、agent 全掉线、数据库读失败。把它当 readiness 探针
会让中继被放进负载均衡后所有请求都失败。

v1 **没有** readiness 端点。要判「能否接流量」请读 `GET /api/snapshot` 的
`totals.tunnels_up`（需要鉴权）。

**编排怎么配：**

```yaml
# k8s —— httpGet 默认拿 Pod IP 当 Host，而 /healthz 刻意在 Host 白名单闸门之外，
# 正是为了让这条能用。
livenessProbe:
  httpGet: { path: /healthz, port: 9443 }
```

> ⚠ 保持 `-console` 默认值（`127.0.0.1:9443`）再配容器/k8s 探针会**一直失败**，
> 而在容器里 `curl 127.0.0.1:9443/healthz` 是通的 —— 因为探针从 Pod IP 打进来。
> 容器里要用 `-console 0.0.0.0:9443`，并靠编排层限制可达性（见 [2.2](02-deployment.md)）。

> ⚠ 自带 `docker-compose.yml` 的 healthcheck 探的是 `-version`，**不是** `/healthz`。
> 镜像是 distroless（没有 shell、没有 curl），容器内没有任何 HTTP 客户端可用。
> 所以容器可能长期显示 healthy 而服务其实已经不可用。真正的健康检查要从容器外探。

## 7.2 优雅关闭：`-drain` 覆盖的比名字听起来少

`-drain`（默认 30s）**只**约束控制台 HTTP 服务器的 `Shutdown`。紧接着承载会话被
**无条件**关掉 —— 业务连接没有自己的排空窗口。

所以：

- 设 `-drain 5m` 不会让在途的隧道连接跑完。SIGTERM 之后用户的 TCP/WS 连接
  被立刻 reset。
- 实际耗时取决于**有没有人开着控制台页面**：控制台的 SSE 是长连接，
  `Shutdown` 会等它，于是有人挂着页面就烧满 30 秒，没人挂着就几乎瞬间退出。
  同一台机器上两次 SIGTERM 的耗时可以差 30 倍，而差别只在这个。
- `GoAway` 控制帧（带排空截止时间）**定义齐全但零发送方、零处理方**。

要平滑切换只能靠多中继 + agent 的 `-relay` 多候选故障切换。

容器里记得 `stop_grace_period`（自带的 compose 已设 40s）—— Docker 默认只给
10 秒就 SIGKILL，短于可能的 30 秒排空，会截断停机日志。

## 7.3 备份与恢复

数据库在 `<data-dir>/relay.db`（SQLite，WAL 模式）。

**没有备份入口。** `store.Backup` 有实现、有测试、**零调用点** ——
控制台里没有按钮，也没有子命令，进程不会自己定期备份。

```bash
# 带外备份（宿主机上，需要自己装 sqlite3）
sqlite3 /var/lib/nomirelay/relay.db "VACUUM INTO '/backup/relay-$(date +%F).db'"
```

> ⚠ 容器里这条走不通：镜像是 distroless，只有 `/nfrelay` 与 `/nfagent` 两个文件 ——
> 没有 shell、没有 sqlite3，也不能 `docker exec` 进去拷。只能在宿主机上对着卷跑，
> 或先停容器再拷。
>
> ⚠ **WAL 模式下热拷 `relay.db` 会拿到半新半旧的库。** 要么用 `VACUUM INTO`，
> 要么停进程。

**恢复没有任何流程** —— 只能手工把文件放回去。而且旧二进制打开新 schema 的库时
迁移会静默 no-op，没有护栏。降级前请自己确认 schema 版本（支持包里有）。

## 7.4 可观测性：有什么、没什么

| 出口 | 给什么 | 鉴权 |
|---|---|---|
| stderr 日志 | 全部（结构化 slog，`-log-level`） | — |
| `GET /api/snapshot` | 权威运行时状态（1Hz 刷新的那份） | 需要 |
| `GET /api/events` (SSE) | 事件流（5 种类型，见 [3.7](03-api.md#37-事件流sse)） | 需要 |
| `GET /api/events/recent` | 事件历史（库里，30 天） | 需要 |
| `GET /api/settings` | 生效配置 + **来源** | 需要 |
| `GET /api/tunnels/{id}/samples` | 时序 + RTT 分位数 | 需要 |
| `POST /api/tunnels/{id}:test` | 逐跳探测 | 需要 |
| `GET /api/diagnostics/support-bundle` | 脱敏后的全量摘要 | 需要 |

**没有 Prometheus `/metrics`。** 代码注释里以现在时提到 `nf_*` 指标名，
而 `go.mod` 里没有 `prometheus/client_golang` —— 那些注释是设计意图不是现状。

**共享入口的计量只在 `/api/snapshot` 的 `shared.*` 里**，控制台 SPA 上一处都不显示。
排查「443 上到底发生了什么」（`no_route` / `bad_gateway` / `at_capacity` /
`denied_cidr` 分级计数）必须直接读那个 JSON。

## 7.5 时序数据：48 小时之外读不到

`/api/tunnels/{id}/samples` 只查 `tunnel_sample_1m`，而那张表**只留 48 小时**。

5 分钟与 1 小时的上卷表（`tunnel_sample_5m` 留 30 天、`tunnel_sample_1h` 留 400 天）
**被写、被剪枝，但全仓没有任何读取点**。所以 `from` 传多早都拿不到 48 小时以前的数据。

> ⚠ **UDP 隧道与共享入口隧道的历史曲线永远空白。** 采样循环只遍历 TCP 独立
> 监听器（`exposure=port` + `l4=tcp`）。实时数字（snapshot / SSE `metric`）是对的，
> 但详情页的历史图与 `samples` 接口的 `samples` **数组**返回空。
>
> **同一个响应里的 `rtt` 那一块仍然有值**：RTT 直方图是按 agent 测的、按隧道写的
>（`recordRTTSamples` 遍历**所有**隧道，不按 L4 或 exposure 分流），
> 所以只要这条隧道的 agent 在线且承载 Ping 测到过，`rtt.p50_us/p95_us/p99_us`
> 就是真值。别把「看到非零 RTT」当成「UDP 采样是好的」而转去怀疑前端。

RTT 存的是**累积直方图桶**而不是 p95 列 —— 分位数不能被平均，
把每分钟的 p95 再平均成每小时的 p95 在算术上是错的。

## 7.6 支持包

`GET /api/diagnostics/support-bundle` —— 一份**脱敏后的 JSON**，用途是发给别人看。

含：版本、schema 版本、生效配置及来源、隧道与 agent 摘要、近期 200 条事件、
判别与网关计数、TURN 分配数、以及「哪几个可选接口装上了」。

**不含数据库快照**，刻意的：库里有 agent 密钥的**明文**（HMAC 校验需要密钥本身）、
argon2id 口令哈希、会话与 CSRF 令牌、入网令牌哈希、TURN 长期密钥 ——
一份 DB 快照就是这台中继的完整沦陷。

脱敏两层：键名白名单（`secret`/`key`/`token`/`password`/`credential`/`cookie`）
+ 对**自由文本**的形状匹配（`nf_enrol_*`、长十六进制串）。后者挡的是
「将来某处不小心把令牌写进自由文本」。

形状匹配覆盖的字段是：事件的 `message`、配置项的 `value`、隧道的 `reason`、
agent 的 `hostname` —— 判据是「内容不由用户直接决定」。
**用户自己配的值不脱敏**：后端地址、域名、slug 原样带出去，因为它们是排障必需的
原文，而用户知道自己往里填了什么。

> 那道键名白名单有个反作用：一个名字里恰好带 `cookie` 的**纯诊断项**也会变成
> 「（已脱敏）」。中继在启动时会自检并对每一处告警（`WarnRedactedDiagnostics`）——
> 若你看到那条告警，说明有个诊断项在最需要它的那次排障里会看不见。

下载动作会**留痕**（它是一次外发，与签发 TURN 凭据同类）。

## 7.7 日志里必须立刻看的几条

| 日志 | 含义 |
|---|---|
| `控制台绑在非回环地址且未声明前置 TLS 反代` | 管理员口令正在明文过网络 |
| `入网凭据仍未落盘` | agent 离永久失联只差一次重启 |
| `状态目录在易失文件系统上` | 同上（OpenWrt 的 `/var` → tmpfs） |
| `签发失败，开始静默期` | ACME 已经打过 CA 并被拒，配额已扣 |
| `ACME 用的是 staging 环境` | 签出的证书浏览器不信 |
| `拒绝把 tls=passthrough 的隧道从网关路径服务出去` | 有人在试明文降级绕过 |
| `登录被限速` / `登录被并发闸拒绝` | 有人在打这台机器 |

## 7.8 升级

- **没有版本协商之外的兼容保证**。`HelloOK.min_supported_protocol` 让 agent 知道
  自己是否过旧；过旧时回不可重试的 `agent_too_old`。
- 新 agent 连旧中继：能力集取**交集**，新端向下降级而不是失败。
- **验签今天对任何真实发布都会失败**：`release/nomirelay-release.pub` 是占位公钥，
  私钥不存在（生成于 `/tmp`、随构建环境消失）。要用先 `make keygen` 换掉公钥
  并把指纹写进 README。

## 7.9 资源上界

每一项都有硬上限，而且是有断言的：

| 项 | 上界 | 由什么决定 |
|---|---|---|
| argon2 峰值内存 | ~128 MiB | `argonConcurrency=2` × 64 MiB（有断言钉住乘积） |
| 登录限速跟踪表 | 4096 个源 IP | 满了之后新 IP 落进共享溢出桶 |
| UDP 会话表 | 容量上限 + LRU + 每源 IP 配额 + 建表限速 | 四重约束 |
| 分片重组器 | 并发数 + 字节总量 + 超时 + 分片条数 + 重叠即拒 | 五重有界 |
| SSE 订阅者队列 | 每订阅者 32 帧，满了丢帧（绝不阻塞） | `health` 帧的 `dropped` 报告丢了多少 |
| 事件表 | 30 天 | `PruneEvents` |
| 会话 | 12 小时硬过期 | 无滑动续期 |

`LimitNOFILE` 在 systemd 单元里设的是一个**真实数字**（1048576）而不是
`infinity` —— 后者会关掉那道能提前发现 fd 泄漏的护栏。
