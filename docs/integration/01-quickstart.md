# 1. 五分钟上手

目标：让一个 HTTP 服务从公网可达。全程在一台机器上也能跑通（用 loopback 冒充内网）。

## 1.1 构建

```bash
make ui && make build     # 前端 + 两个二进制（合计约 25MB：nfrelay ≈18MB、nfagent ≈7MB）
```

没装 bun 也能只构建后端：`make build` 会在 `web/dist` 缺失时自动加 `noweb` tag，
此时 `/` 返回一句说明而 API 仍然可用。

## 1.2 起中继

```bash
./bin/nfrelay -data-dir ./data
```

它会打印两样你马上要用的东西：

```
  控制台：http://127.0.0.1:9443
  首次使用请打开控制台完成初始化（创建管理员）。

  承载地址：192.168.1.10:8443
  证书指纹：uAPK2wSCAnAGyP0YJnsNDzMhHeG6Xoh5WDDNdwv7wng=
```

**指纹要记下来** —— agent 用它钉住中继的公钥，没有「跳过校验」的选项。

## 1.3 初始化

打开 `http://127.0.0.1:9443`，创建管理员（口令至少 12 位）。

> **谁先到谁是管理员。** `POST /api/setup` 未鉴权，而中继起来到你去初始化之间
> 是一个窗口。如果控制台绑在非 loopback 上，别人可能先到。
> 起来之后**立刻**初始化，或者先只绑 loopback。见 [9. 已知缺口](09-known-gaps.md)。

## 1.4 先让 agent 入网，再建隧道

顺序是刻意的：**入网命令不是建隧道给的**。它来自签发入网令牌那一步。

首启向导第三步「接一个目标」会签发一枚令牌并给出一条**可直接复制**的命令；
之后想再要一条，去「代理端」页签发（API 是 `POST /api/enrol-tokens`，
响应字段 `install_cmd`，默认 15 分钟有效）。

> **建隧道向导里的「预览」给的是占位符**：
> `nfagent -relay <中继地址> -pin <证书指纹> -token <入网令牌>`
>（`internal/console/endpoints.go:147-148`）。它只用于核对命令的形状，
> 直接跑会因为参数是字面的尖括号而启动失败。

```
nfagent -relay 192.168.1.10:8443 -pin uAPK2w… -token nf_enrol_6d1ece95…
```

在**被暴露服务所在的机器**上贴上它。建议同时加 `-state-dir`：

```bash
nfagent -relay 192.168.1.10:8443 -pin uAPK2w… -token nf_enrol_6d1ece95… \
        -state-dir /var/lib/nfagent
```

不加也能跑（会按平台默认路径挑一个），但显式指定能避免 [4.2](04-agent.md#42-状态目录这一节决定它能不能重启)
里那个「换了运行用户就重新入网」的坑。

agent 上线之后再回控制台建隧道。**只有一个 agent 在线时新隧道会自动绑定它**；
有两个及以上时中继不猜，隧道会报 `error` 并在原因里让你显式指定一个
（`cmd/nfrelay/runtime.go` 的 `bindUnassigned` 与 `refreshStates`）。

## 1.5 访问

客户端完全不需要知道隧道的存在：

```bash
curl http://192.168.1.10:9090/api/hello
```

隧道存在 SQLite 里，**跨重启自动恢复**。agent 的凭据也落盘，所以它重启后自动重连。

## 1.6 隧道状态该怎么读

| 状态 | 含义 | 下一步 |
|---|---|---|
| `active` | 入口在听，agent 在线 | 正常 |
| `pending` | 入口在听，**还没有 agent** | 等 agent 上线（会自动绑定），或显式指定 `agent_id` |
| `degraded` | 指定的 agent 不在线 | 看 agent 侧日志；ID 变了的话见 [4.6](04-agent.md#46-隧道重绑) |
| `error` | 中继侧起不来（端口被占、缺 `-shared`、多个 agent 无法判断意图） | 看 `state_reason`，它会说清 |
| `stopped` | 被显式停用 | — |

`state_reason` 总是给出人话原因。一条不解释的红点是缺陷，请提 issue。

## 1.7 出了问题先看这三个

1. **逐跳探测**：控制台隧道详情页的「测试」按钮（或 `POST /api/tunnels/{id}:test`）。
   它逐跳报告，并且**如实标出测不到的跳**（显示为「—」而不是绿勾）。
2. **事件流**：控制台首页的事件列表。`tunnel.stream_denied` 意味着 agent 的
   本地策略拒了目标 —— 那是最常见的「配置看起来对但不通」。
3. **支持包**：`GET /api/diagnostics/support-bundle`。一份脱敏后的 JSON 摘要，
   可以直接发给别人看。见 [7. 运维](07-operations.md)。
