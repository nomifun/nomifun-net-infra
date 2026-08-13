# 6. 网关契约：我的后端会收到什么

只在 **`exposure=shared` + `tls=gateway`** 下适用。`tls=passthrough` 与
`exposure=port` 走字节级拼接，**完全不过这张表**（见 6.6，那一节比这一节更要紧）。

## 6.1 请求头改写表

这张表**不可配置**。唯一的旋钮是 `router.host_rewrite`。

| 头 | 网关做什么 | 后端看到 |
|---|---|---|
| `Host` | 无条件改写 | **后端自己的 `ip:port`**（或 `host_rewrite` 的值）；`backend.kind=unix` 时没有 `ip:port` 可用，退化成字面 `localhost`（不带端口） |
| `Origin` | 入站带了才改写；scheme 硬编码 `http` | `http://<后端 ip:port>`，unix 后端下是 `http://localhost` —— 做精确 Origin 字符串比对的后端两种都要接受 |
| `X-Forwarded-Host` | 设为公网 Host | 你的公网域名 —— **这是公网主机名唯一的载体** |
| `X-Forwarded-Proto` | 设为公网侧 scheme | `https` 或 `http` |
| `X-Forwarded-For` | **先删再设为单值** | 一个真实客户端 IP（不是链） |
| `X-Real-IP` | 先删再设 | 同上 |
| `Forwarded` | **无条件删除** | 缺席 |
| `X-Client-IP` / `CF-Connecting-IP` / `True-Client-IP` 等 CDN 私有头 | **无条件删除** | 缺席 |

响应侧**一个字节都不改** —— 包括 `Location`。

## 6.2 四条会咬人的后果

### ① 后端不能用 `Host` 拼绝对 URL

`Host` 是后端自己的内网地址。用它拼重定向、OAuth 回跳、页面里的绝对链接，
结果是浏览器被 302 到 `http://192.168.1.50:8080/...` —— 公网上打不开。

**改用 `X-Forwarded-Host` + `X-Forwarded-Proto`。**

### ② 靠 `Origin` 做 CSRF / WebSocket 来源校验的后端会失效

后端看到的 `Origin` 永远是 `http://<内网 ip:port>`，**你的公网域名一次都不会出现**。

两种表现都很难查：要么所有请求都被判成同源（白名单形同虚设），
要么你把公网域名加进白名单却仍然被拒。

同时校验 `Origin` 与 `Referer` 的后端更糟：`Origin` 说内网地址、`Referer` 说公网
URL，严格实现会因为两者不同源而 403，而日志里看不出是中继改的。

**接非 nomifun 的后端时优先用 `tls=passthrough`**（形态 4），
或者让后端改用 `X-Forwarded-Host` 判来源。

> 这张改写表是为上游 `nomifun-tauri` 的 host guard 设计的（它把域名型
> Host/Origin 一律 403）。对第三方后端它是一次**静默的安全控制削弱**。
> 这一点在规范性规格里被写成了「网关必须执行的改写表」，那是文档层的耦合。

### ③ 合法的上游代理链会被抹掉

`X-Forwarded-For` 恒为**单个** IP，而且在 CDN → LB → nfrelay 这种链路下那个 IP 是
**上游代理**的地址，不是真实客户端。基于客户端 IP 的地理/风控/白名单会在所有用户
身上得出同一个结论。

「先删再设单值」本身是对的（frp 是追加，于是攻击者填的值会留在链首被后端信任），
代价就是丢掉合法链路。要还原真实来源请用 `-shared-trust-proxy-protocol`
（注意它**只覆盖共享入口那一个端口**，独立端口的隧道不受影响）。

### ④ 回源腿的 TCP 连接身份不是客户端身份

每隧道复用 4 条空闲连接。手机 A 建的连接会被手机 B 的请求复用 ——
连接级会话、连接级限流、per-connection 认证全部会串。

**每个请求自己判身份**，用 `X-Forwarded-For`。

## 6.3 回源腿

| 项 | 值 |
|---|---|
| scheme | **硬编码 `http`** —— 接不了 https 后端 |
| 协议 | HTTP/1.1（共享入口的 ALPN 只宣告 `http/1.1`） |
| 传输 | 走 QUIC 隧道流，不是普通 TCP |
| 空闲连接 | 每隧道 4 条 |
| 流式 | `FlushInterval=-1`，不缓冲（SSE / 流式响应可用） |

只宣告 `http/1.1` 是刻意的：WebSocket 升级需要 `ResponseWriter` 支持 Hijack，
而 h2 的不支持。

## 6.4 WebSocket

`101 Switching Protocols` 与双向帧都通，走 Hijack。

注意 6.2② —— 大多数 WebSocket 库默认做 Origin 校验，而它会失效。

## 6.5 共享入口的判别顺序

一条连接到达共享端口时逐级 peek：

1. **独占绑定**（不 peek）—— 无配置入口，见 [9.2](09-known-gaps.md)
2. **PROXY protocol**（若开了 `-shared-trust-proxy-protocol`）
3. **首字节**：`0x16` → TLS 分支；可打印 ASCII → 明文 HTTP 分支；其余 → 默认分支
4. **ALPN `acme-tls/1`** → ACME 挑战
5. **SNI** → 按域名找隧道；命中 `passthrough` 就 splice，命中 `gateway` 就终止 TLS。
   **SNI 只按域名匹配，忽略 `router.locations`** —— 路径分流要等解密之后的 L7 才做，
   所以一条 SNI 命中、但路径不匹配任何 `locations` 的请求会在解密后落到
   `catch_all` 或 404
6. **明文 Host + 路径前缀** → 按 (域名, **最长**路径前缀) 找隧道。
   Host 是 IP 字面量、`localhost`、或压根缺失时**不查域名表**，直接落到第 7 级
7. **端口默认绑定**（`catch_all`）

每一级失败时客户端看到的东西不同：SNI 未注册 → TLS `unrecognized_name` 告警
（不是裸关闭）；明文 Host 未注册 → 404；没有 `catch_all` 且都不命中 → 连接关闭。

## 6.6 不走这张表的两种形态

| 形态 | 后端收到什么 |
|---|---|
| `tls=passthrough`（共享入口） | **原样的 TLS 字节**。中继不解密、不改写。 |
| `exposure=port` | **原样的裸字节**。 |

> **⚠ 这两种形态下后端会原样收到攻击者填的 `X-Forwarded-For`。**
> 头清洗只发生在网关路径上。如果你的后端从 XFF 读客户端 IP 做判定，
> 在这两种形态下那个判定是**可被任意伪造**的。
> 后端还会看到公网域名的 `Host`（而不是内网地址）—— 行为与网关模式完全相反。

## 6.7 `proxyproto.v2` 能力协商上了也不代表在用

握手的能力交集里会出现 `proxyproto.v2`（agent 与中继两侧都声明了它），
agent 的启动日志也会把它打出来 —— 但**全仓没有任何写入点**：
agent 不会向本地服务发 PROXY 头。
（顺带纠正一个容易有的印象：控制台**不展示**能力集，`AgentStatus` 只暴露
`supports_datagram` 一项，所以「控制台显示协商成功」这件事本身也不会发生。）

把后端配置成「从 PROXY protocol 头读客户端地址」会让它把业务首包当 PROXY 头解析
失败并断开，或一直等一个永远不来的头。**不要依赖这个能力。**

## 6.8 TLS 与证书

| 情况 | 结果 |
|---|---|
| 开了 `-acme` 且域名逐字注册过 | 自动签发的可信证书 |
| 开了 `-acme` 但域名是通配（`*.example.com`） | **永远签不出** → 回落自签 → 浏览器报证书错误 |
| **没开** `-acme` 而开了 `-shared` | 仍然终止 TLS，用那张给 agent 承载用的**自签**证书 → 浏览器一律报错 |

最后一格容易误判成「TLS 没配上」。设置页的 `gateway_cert` 会显示
「自签（浏览器会报证书错误）」。

默认 CA 是 **staging**（刻意反 certmagic 的默认）—— staging 签出的证书浏览器
**不信**。启动时有一条显式 WARN，但它只在启动那一刻的日志里。
确认流程无误后用 `-acme-ca https://acme-v02.api.letsencrypt.org/directory`。

## 6.9 TURN

```bash
curl -s -b jar -H "X-NFR-CSRF: $CSRF" -H 'Origin: http://127.0.0.1:9443' \
  -X POST -d '{"user_id":"alice","ttl_seconds":600}' \
  http://127.0.0.1:9443/api/turn/credentials
```

返回可直接喂给 `RTCPeerConnection` 的 `iceServers`（不返回裸凭据 —— 让调用方
自己拼 `turn:` URI 是在请他犯错，RFC 7065 明确要求不得用通用 URI 解析器解析它）。

限制：

- **只绑 `udp4`/`tcp4`** —— IPv6-only / 464XLAT 网络的客户端**连不上**。
- **拒绝 RFC 6062 的 TCP 分配**（理由见 [9.2](09-known-gaps.md)）。
  浏览器的「TURN over TCP」指客户端腿走 TCP，与分配的传输协议无关，所以不受影响。
- 签发凭据要**管理员会话**（没有分权），`user_id` 是自由字符串、不参与授权。
- 与 coturn 的 `use-auth-secret` 逐字节兼容。
