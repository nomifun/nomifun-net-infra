# 2. 部署与端口

## 2.1 端口

Desktop 生产接入可直接使用独立的
[`docker-compose.desktop-https.yml`](../../docker-compose.desktop-https.yml)。它在下面
通用端口之外增加 TCP `9444` 的公开 HTTPS bootstrap，并把 TCP `80` 交给 Caddy
签发 bootstrap 域名证书；完整前提见 [第 10 章](10-desktop-connect.md)。

| 端口 | 协议 | 谁连 | 必需？ |
|---|---|---|---|
| `8443` | **UDP**（QUIC） | agent 连中继 | 必需（`-bind`） |
| `9443` | TCP | 控制台，**默认只绑 loopback** | 必需（`-console`） |
| 每条隧道各自的 | TCP/UDP | 你的客户端与设备 | 按隧道配置 |
| `443` | TCP | 共享入口（域名/路径路由、TLS 终止） | 可选（`-shared`） |
| `80` | TCP | ACME HTTP-01 备份路径 | 可选（`-acme-http`） |
| `3478` / `5349` | UDP/TCP | 内置 TURN/STUN | 可选（`-turn-public-ip`） |
| `49160`-`49400` | **UDP** | TURN 为每个分配绑的中继端口（客户端与对端直接发到这里） | 启用 TURN 时**必需** |
| `443` | **TCP** | 共享入口（`-shared`）**以及 agent 的 L2 承载回退**，靠 ALPN 区分 | 想支持封了 UDP 的 agent 网络时必需 |

承载端口是 **UDP**。这一条最容易配错防火墙 —— 放行 TCP/8443 不会让任何 agent 连上，
而 agent 侧看到的只是「连接中继失败，稍后重试」。

## 2.2 控制台是明文 HTTP

它没有 TLS。默认只绑 loopback，所以流量不出机器 —— 那是正确的默认，不是疏漏。

远程访问只有两条路：

```bash
# 路 1（推荐）：SSH 隧道。控制台仍然只绑 loopback，什么都不用改。
ssh -L 9443:127.0.0.1:9443 relay-host

# 路 2：前置一个做 TLS 终止的反代，并**显式声明**它。
./bin/nfrelay -console 127.0.0.1:9443 \
              -console-behind-tls-proxy \
              -console-hosts relay.example.com
```

`-console-behind-tls-proxy` 才会给会话 Cookie 加 `Secure` 与 `__Host-` 前缀。

它是一个**显式断言**，而不是去看 `X-Forwarded-Proto`：那是可伪造的请求头，
拿它做安全决策与本仓数据面的立场直接冲突（网关把 XFF/XFP 当作不可配置的不变量在剥）。

**两个方向都会咬人：**

| 你做了什么 | 会发生什么 |
|---|---|
| 绑非 loopback，**没**声明反代 | 管理员口令、会话 Cookie、CSRF 令牌**明文过网络**。启动时有一条显著 WARN。 |
| 声明了反代，但前面**其实没有** TLS | 浏览器因 `Secure` 而不保存 Cookie。现象是**登录 200、下一个请求 401**，两侧日志都显示成功。 |

第二种的诊断依据是设置页的 `console_session_hardening` 一项。它刻意不叫
`console_cookie_secure` —— 支持包按键名脱敏，含 `cookie` 的键会变成「（已脱敏）」，
于是最需要它的那次排障恰好看不见。

启动时中继会按四种组合各打一条日志，级别不同：

| 组合 | 级别 | 说的是什么 |
|---|---|---|
| 回环 + 已声明反代 | Info | 正常 |
| 非回环 + 已声明反代 | WARN | 反代回源那一段仍然是明文 |
| 非回环 + 未声明反代 | WARN | 最危险的一格：管理员口令会明文过网络 |
| 回环 + 未声明反代 | Debug | 默认形态。**默认 `-log-level info` 下看不到它** |

**自带的 docker-compose 每次启动都会打那条 WARN。** 它用 `-console=0.0.0.0:9443`
且没声明反代，而端口只发布到 `127.0.0.1`（见 `docker-compose.yml` 的 `ports:`）。
进程内**无法**区分「绑 0.0.0.0 + 编排层限制可达」与「真的裸奔在公网」——
所以那个形态下这条告警是预期噪声。

**不要**为了消掉它去加 `-console-behind-tls-proxy`：前面没有 TLS 时那会给会话
Cookie 加 `Secure`，浏览器于是不保存它，现象是「登录返回 200、下一个请求 401」。

## 2.3 Host 白名单（DNS 重绑定防护）

控制台校验 `Host` 头，不匹配回 **421 Misdirected Request**。这是 DNS 重绑定防护：
不校验的话，一个解析到 127.0.0.1 的恶意域名可以让浏览器带着你的 Cookie 访问
loopback 上的控制台。

默认放行 `localhost` / `127.0.0.1` / `[::1]` / `::1` 与 `-console` 里的具体绑定地址。
用别的名字访问就要加进白名单：

```bash
-console-hosts relay.example.com,alt.example.com
-console-hosts relay.example.com:9443      # 带端口也认
```

条目**可以带端口**，两种写法都行（入表时会剥掉端口、小写化、丢弃通配与未指定地址）。

> 这一条在某个版本之前是坏的：带端口的条目做键、查表却剥端口，于是 `-console-hosts
> relay.example.com:9443` 会让**整个 flag 静默失效**（两种 Host 写法都 421）。
> 运维会以为自己配好了防护，实际是把自己关在门外。现已修复并有回归判据。

**这道闸包住整个监听器，SPA 的 `/` 也在其内。** 别名 Host 下 `/` 也返回 421，
而 421 的响应体自己说明怎么修（浏览器导航给纯文本，程序化调用给 JSON 信封，
`code: misdirected_host`）。

不这样做的话失败是「半开」的：页面 200 载入正常而所有 `/api/*` 421，
你会看到一个渲染完整却什么都点不动的控制台，界面上零解释。

**`GET|HEAD /healthz` 在这道闸之外。** 编排探针（k8s `httpGet` 默认拿 Pod IP 当 Host、
Docker healthcheck 同理）不可能知道你配了什么白名单，421 会让它把一个健康的中继
反复重启。写方法不在豁免内。

## 2.4 容器与 systemd

```bash
docker compose up -d
sudo install -m 0644 deploy/nfrelay.service /etc/systemd/system/   # 中继
sudo install -m 0644 deploy/nfagent.service /etc/systemd/system/   # agent（另一台机器）
```

两个单元都用 `StateDirectory=` 让 systemd 建目录并设属主，`ProtectSystem=strict`
下那是唯一可写的地方。差别：中继要 `CAP_NET_BIND_SERVICE`（绑低端口），
**agent 一个能力都不需要**（只做出站连接），所以它的 `CapabilityBoundingSet` 是空的。

agent 的 `ExecStart` 里 `-state-dir` 显式指向 `/var/lib/nfagent`，不靠默认值 ——
`ProtectSystem=strict` 下写错路径的报错是 EROFS，比 EACCES 更难认。

## 2.5 控制台挂不到反代子路径下

前端构建的 `base` 是 `/`，`BrowserRouter` 没有 `basename`，API 路径与 SSE 都是
`/api/...` 字面量，产物引用 `/assets/*.js` 与 `/theme-boot.js`。

所以控制台**只能**用独立主机名或独立端口，**不能**挂在 `https://ops.example.com/relay/`
下面。按常规反代习惯部署会拿到白屏。
