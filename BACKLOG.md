# BACKLOG — 距离最终版本的未完成事项

> 生成于 2026-10-11。综合 `docs/integration/09-known-gaps.md`、`docs/integration/05-capabilities.md`、
> `docs/integration/08-wire-protocol.md`、`web/src/api/client.ts` 与代码内预留枚举整理。
>
> 全仓**没有** TODO/FIXME 注释——未完成事项以三种形式存在：Validate 拒绝的预留枚举、
> 文档声明、死代码占位。
>
> **使用方式**：每条附 `file:line` 锚点；动手前先核实锚点仍然成立（行号会漂移，
> 以符号名搜索为准）。完成一条就删掉对应行，并同步 `docs/integration/` 里受影响的章节
> （行为变更必须同步文档，过期文档算 bug——见 AGENTS.md）。
>
> 同级兄弟仓库（与本仓库同目录）的位置：

| 仓库 | 路径 | 用途 |
|---|---|---|
| frp | `../net-infra/frp`（检出 v0.71.0） | `docs/research/` 行号锚点、`clienthello.go` 手法出处 |
| EasyTier | `../net-infra/EasyTier`（main） | `docs/research/` 行号锚点 |
| nomifun-desktop（原 nomifun-tauri） | `../nomifun-desktop` | dossier 11 的 `ui/...` 锚点、gateway host-guard 对照源码 |

缺失时重建：`git clone https://github.com/fatedier/frp ../net-infra/frp && git -C ../net-infra/frp
checkout v0.71.0`；`git clone https://github.com/EasyTier/EasyTier ../net-infra/EasyTier`。
frp 固定 v0.71.0 是为了让 `docs/research/` 里的行号锚点对得上；nomifun-desktop 是私有
兄弟项目，用你自己的远端地址克隆到 `../nomifun-desktop`。

## A. 数据面 / 协议缺口

| # | 项 | 现状与锚点 | 备注 |
|---|---|---|---|
| A1 | L3 承载梯级（WSS:443 + smux） | 未实现。突破敌视 ALPN 的中间盒/MITM 代理的唯一手段；`go.mod` 无 `coder/websocket`。`WSPath = "/_nf/t/v1"` 常量为它预留（`internal/proto/frame.go:39`） | dossier §10 选型：coder/websocket v1.8.15，二进制帧强制 |
| A2 | L1 承载梯级（QUIC/UDP:443） | 未实现。仅覆盖「放行 443/udp 但封其他 UDP 端口」的少见网络，优先级低于 A1 | `docs/integration/09-known-gaps.md` §9.1 |
| A3 | `exposure=p2p`（v2 打洞） | Validate 拒绝，枚举位预留（`internal/tunnel/tunnel.go:72,363`） | 依赖 NAT 穿透设计，未立项 |
| A4 | `kind=peer`（场景三 agent↔agent 对等隧道） | Validate 拒绝（`internal/tunnel/tunnel.go:38,355`）；`CapPeerTunnel` 能力位已预留（`internal/proto/control.go:38`） | 场景三：远程桌面/手机直连 |
| A5 | `backend=handler`（agent 自终结能力型后端：截图/PTY/键鼠） | Validate 拒绝（`internal/tunnel/tunnel.go:105,473`）；`CapHandlerBackend` 已预留（`internal/proto/control.go:42`） | 场景三配套 |
| A6 | `exposure=private` 死枚举 | Validate 放行、状态显示 active、计入 TunnelsUp，但**一个监听器都不建**，客户端全被拒。要么实现要么改为拒绝——当前是最危险的坑 | `docs/integration/05-capabilities.md:37`；`docs/integration/09-known-gaps.md` §9.1 |
| A7 | `exposure=port` 上 `tls` 轴被忽略 | `tls=gateway` + `exposure=port` 被放行但纯裸 TCP 拼接；控制台却渲染 `https://` 端点、暴露面显示「已配置」 | `docs/integration/05-capabilities.md:45-52` |
| A8 | `kind` 轴（service/reverse）数据面零读取 | 两者转发行为完全相同，kind 只影响展示 | `docs/integration/05-capabilities.md:95` |
| A9 | 回源腿 scheme 硬编码 `http` | 网关模式接不了 https 后端，只能走 passthrough+tls-sni 形态 | `docs/integration/05-capabilities.md:109` |
| A10 | `LossPPM` 丢包率无测量点 | 字段只被写库再读出，从未赋非零值；界面三处恒显示「—」 | `docs/integration/09-known-gaps.md` §9.1 |
| A11 | `packets_per_second` 语义不诚实 | TCP 上限的是「每次 read」而非包；共享入口上完全不生效（刻意不报错以兼容既有配置） | `docs/integration/09-known-gaps.md` §9.1 |
| A12 | 外网视角复测 `from_internet` | 需外部回声服务；当前如实回「未实现」步骤（`internal/console/endpoints.go:250-259`） | 中继自测公网地址在 NAT 回环失败网络里会得出错误结论 |
| A13 | 二进制 codec | 帧头 `FlagCodecMask`（b1-b2）预留，v1 恒 JSON | `docs/integration/08-wire-protocol.md:92` |
| A14 | L2 上的 UDP 隧道 | smux 无不可靠数据报，隧道标 `degraded`——固有局限，L3 落地后仍在 | `docs/integration/09-known-gaps.md` §9.1 |
| A15 | **共享端口 512 判别器槽位可被远程占死** | 判别器在 `Accept` 后、`Decide` 前占槽，`Handle` 返回才还；网关分到的 `Handle` 要等连接关闭才返回——512 条「发完一个请求就挂着」的空闲 keep-alive 连接即可占死整个共享端口，ACME 挑战与 L2 承载一并被关。无需鉴权、无需负载，`scripts/verify/slot_exhaustion.py` 可复核；已有 `IdleTimeout` 缓解但未根治（55 秒内发一个廉价请求就能一直占着）。**发布阻断项**。 | 修法要三样：判别期生命额度、按 action 类别换额度（给 ACME/承载留位）、端口容量可配；`ActionCarrier` 让一条 L2 agent 会话只占一槽 |
| A16 | 采样 5m/1h 上卷表零读取点 | `internal/store/metrics.go:366-395` 持续写入+剪枝，但唯一读路径 `QuerySamples`（`internal/console/routes.go:553`）只查 `tunnel_sample_1m`——历史查询实际只剩 48h 窗口，30d/400d 留存是死数据 | 要么 samples API 按区间选表，要么删掉死表（移植自旧「诚实清单」） |
| A17 | `-drain` 不排空业务连接 | `cmd/nfrelay/main.go:361-369`：`Shutdown(shutdownCtx)` 只作用于控制台 HTTP，随后 `sessions.CloseAll` 无条件断所有隧道连接 | 要么扩到数据面连接，要么在 `docs/integration/07-operations.md` 写明是已知代价 |

## B. 控制面 / 管理 API 缺口

| # | 项 | 现状与锚点 | 备注 |
|---|---|---|---|
| B1 | `POST /api/diagnostics:selftest` 中继自检 | 路由未注册，前端调用得 404（`web/src/api/client.ts:333`） | 前端 Diagnostics 页已留位 |
| B2 | RBAC / 只读 API key / 角色 | 无。管理员会话是全权，12h 硬过期、无滑动续期、无 refresh 端点 | `docs/integration/09-known-gaps.md` §9.1 |
| B3 | `openapi.json` + 漂移门禁 | 旧设计规格 §8.5 要求的 `make openapi` / `api-diff` / `gen-api-types` 三目标均不存在（规格已移除，见 Git 历史） | `docs/integration/09-known-gaps.md` §9.1 |
| B4 | Prometheus `/metrics` | 无拉取式指标出口；`client_golang` 不在 go.mod；代码注释里的 `nf_*` 指标名是设计意图 | `docs/integration/09-known-gaps.md` §9.1 |
| B5 | SSE 断线补发 | `Last-Event-ID` 完全未读，`lastEventID()` 是死代码（`internal/console/sse.go:354`）；断线静默丢事件、刷新清空会话网格 | `docs/integration/09-known-gaps.md` §9.1 |
| B6 | 首启窗口未保护 | `POST /api/setup` 未鉴权，谁先到谁是管理员；限速只压速率 | `docs/integration/09-known-gaps.md` §9.1 |
| B7 | 数据库备份/恢复路径 | `store.Backup` 有实现有测试但零调用入口；旧二进制开新 schema 静默 no-op 无护栏 | `docs/integration/09-known-gaps.md` §9.1 |
| B8 | 多租户 | `tenant_id` 列已在 agents/tunnels 等表保留，但 `admins`、`console_sessions` 两表没有——真做需补迁移 | `docs/integration/09-known-gaps.md` §9.3 |
| B9 | `config:apply` 非原子 | `internal/console/configdoc.go:356`：`partial_apply` 错误返回时库已部分写入，无回滚；前端已知会刷新（`web/src/pages/Settings.tsx:131-137`） | 要么事务化，要么显式列为已知代价（移植自旧「诚实清单」） |
| B10 | 强制首登改密链路缺后端触发 | 前端有 `web/src/pages/RotatePassword.tsx` 页、`web/src/App.tsx:88` 的 `must_rotate` 门与双语文案，后端 `MustRotate` 字段存在但恒 false——整条链路不可达 | 要么接上（首启 setup 后置 1），要么移除死 UI |

## C. 安全 / 发布缺口

| # | 项 | 现状与锚点 |
|---|---|---|
| C1 | 落库敏感字段 KEK 封装 | v1 未实现，靠库文件 0600 兜底（`internal/store/migrations/00001_init.sql:19`，旧设计规格 §7） |
| C2 | 发布签名密钥是占位 | `release/nomirelay-release.pub` 为占位公钥、私钥不存在；真实发布前必须 `make keygen`（`release/README.md:5`） |
| C3 | ACME DNS-01 | 没有，通配域名签不了证书。注意这是**权衡过的决定**（防 `*.example.com` 任意子域被签发），要做得先重新论证签发闸门 | `docs/integration/09-known-gaps.md` §9.2 |
| C4 | TURN 只绑 udp4/tcp4 | IPv6-only/464XLAT 客户端连不上（`docs/integration/09-known-gaps.md` §9.3） |

## D. 文档债 / 注释漂移

（2026-10-11 修缮已清：`web/src/api/client.ts` 支持包注释、`internal/console` 包注释的
「强制首次改密」断言、AGENTS.md/CLAUDE.md/scripts/README.md 乱码、`/mnt/hgfs` 与
`/home/rika` 机器路径、`评估报告` 本地依赖、`nomifun-tauri` 旧名与失效 `ui/` 路径。）

## 远景（未立项）

多中继 HA、IPv6 完整姿态（已知 TURN 只绑 udp4/tcp4，见 C4）、`exposure=p2p` 打洞
（枚举位已预留，见 A3）。

## E. 刻意的设计决定（不要当缺口「修」）

读 `docs/integration/09-known-gaps.md` §9.2 的理由再动：中继自己拨号（SSRF 防线不能缺）、
共享入口只宣告 HTTP/1.1、控制台不读 XFF、无登录全局限速桶、TCP 限速变慢不丢弃、
拒绝 RFC 6062 TURN TCP 分配、无 DNS-01、HSTS 条件下发、控制台不挂子路径。

## F. 建议消化顺序

1. **A15** — 唯一的发布阻断项：512 槽位耗尽，先做。
2. **A6** — 死枚举收口，一次提交的事。
3. **B1 / B5 / B3** — 前端已留位的小件：selftest、SSE 补发、openapi 门禁。
4. **A1（L3）** — MITM 代理网络的唯一解，有 dossier 选型背书。
5. **B2 / B7 / B4** — 管理面成熟化：RBAC、备份入口、Prometheus。
6. **C1 / C2** — 发布前必须：KEK 封装、`make keygen` 换真密钥。
7. **场景三全家桶（A3+A4+A5）** — 需要先做 remote desktop/手机直连的协议设计。
8. **A7-A12** — 数据面诚实性收尾，按痛点驱动。
