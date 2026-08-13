# Dossier 03 — frp 的 L7 HTTP/HTTPS 能力

来源仓库：`/mnt/hgfs/share/net-infra/frp`，`git describe` = `d1928f96` / v0.71.0，`go.mod:3` 声明 `go 1.25.0`。
本机 Go 为 1.26.5（`/usr/local/go`），stdlib 引用均以该版本为准。

评估对象：S1（公网手机调用家用 NAT 后台的 HTTP + WebSocket + UDP）、S2（工厂机器人只配「中继 IP + 端口」反代到指定桌面服务）。

---

## 1. 两条完全不同的数据路径

frp 的 L7 只有 **一条真 L7 路径**（`type=http`），另一条（`type=https`）是纯 SNI 四层转发。

### 1.1 `type=http`：真正的反向代理

frps 在 `vhostHTTPPort` 上起一个标准 `http.Server`，Handler 就是 `HTTPReverseProxy`（`server/service.go:296-324`）。值得注意的是它显式开了 h2c：

```go
protocols.SetHTTP1(true); protocols.SetUnencryptedHTTP2(true)   // service.go:303-305
server := &http.Server{Handler: rp, ReadHeaderTimeout: 60*time.Second, Protocols: protocols}
```

核心是 `httputil.ReverseProxy`（`pkg/util/vhost/http.go:57-139`），用的是新式 `Rewrite` 钩子而非 `Director`。三个设计点值得抄：

1. **假 URL.Host 作为连接池 key**（`http.go:81-85`）：
   ```go
   req.URL.Host = rc.Domain + "." + b64(rc.Location) + "." + b64(rc.RouteByHTTPUser) + "." + b64(endpoint)
   ```
   `http.Transport` 按 `URL.Host` 做 idle-conn 池化，于是「同一条路由」的请求能复用同一条 work conn。`Transport` 的 `DialContext` 被换成 `rp.CreateConnection(...)`（`http.go:108-110`），从 ctx 里取 `*RequestRouteInfo` 再回查路由表拿 `CreateConnFn`（`http.go:169-185`）。这是「用 stdlib Transport 管连接生命周期 + 自定义拨号器」的经典写法，Go 里几乎零成本。
2. **绝对 URI 代理模式**（`http.go:111-124`）：若首行是 `GET http://example.com/`，`Transport.Proxy` 返回 `req.URL`，于是 frps 可以当正向 HTTP 代理用。S2 若机器人被配成「HTTP proxy = 中继 IP:port」，这条路能直接用。
3. **ModifyResponse 对 101 也生效**：stdlib 在 `reverseproxy.go:574-580` 是先 `modifyResponse` 再 `handleUpgradeResponse`，所以 `responseHeaders` 对 WebSocket 握手响应同样注入。

### 1.2 WebSocket：frp 自己没写 Hijack，靠 stdlib

vhost 包里唯一的 `Hijack` 在 `http.go:208-229`，那是 **CONNECT** 方法的处理（`ServeHTTP` 在 `http.go:282-286` 分流），拿到裸 conn 后 `req.Write(remote)` + `libio.Join(remote, client)`。

WebSocket Upgrade 完全由 stdlib 托管：`reverseproxy.go:482` 先剥 hop-by-hop 头，`:495-498` 再把 `Connection: Upgrade` / `Upgrade: websocket` 加回去，后端返回 101 时 `:820-880` 的 `handleUpgradeResponse` 做 `ResponseController.Hijack()` + 双向 copy。frp 的 e2e 测试正是走这条路（`test/e2e/v1/basic/http.go:443-494`，`gorilla/websocket` 打到 `vhostHTTPPort`）。

**结论：新工具的 WS 支持不需要写一行 Hijack 代码**，只要不把 `ReverseProxy` 换成手写 pipe 就行。这对 S1 是决定性的省力点。

### 1.3 `type=https`：只解析 ClientHello，不终止 TLS

`GetHTTPSHostname`（`https.go:39-51`）用 `libnet.NewSharedConn` 做「读了还能重放」的 conn，再 `readClientHello`（`https.go:53-71`）——手法很妙：构造一个假的 `readOnlyConn`（`https.go:79-90`，`Write` 直接返回 `io.ErrClosedPipe`），调 `tls.Server(...).Handshake()`，在 `GetConfigForClient` 回调里把 `*tls.ClientHelloInfo` 抄走，然后无视必然失败的 handshake error。**零手写 TLS 解析，纯 stdlib**。

失败时 `vhostFailed`（`https.go:73-77`）再起一次 `tls.Server(c, &tls.Config{}).Handshake()`，让 stdlib 发出 `unrecognized_name` alert——比直接 RST 友好得多。

代价是：`HTTPSProxyConfig` 字面上只有 `ProxyBaseConfig + DomainConfig`（`pkg/config/v1/proxy.go:369-372`）。也就是说 **`type=https` 完全没有** `locations` / `hostHeaderRewrite` / `requestHeaders` / `responseHeaders` / `httpUser` / `routeByHTTPUser` / X-Forwarded-*。想要 L7 语义又要 HTTPS，frp 的官方答案是把 TLS 终止推到客户端：`plugin = https2http`（`pkg/plugin/client/https2http.go:42-56`），用 `crtPath`/`keyPath` 起 `ServeTLS`（`http_common.go:76-97`），证书缺失就自签（`pkg/transport/tls.go:96-113` → `newRandomTLSKeyPair`），并额外做了 SNI/Host 不一致返回 421 的检查（`internal/httpsserver:48-59`）。

**全仓库 grep `acme|autocert|letsencrypt|lego` 结果为空**——frp 从不签证书。

---

## 2. 路由表：host + location + httpUser

`Routers` 是 `map[domain]map[httpUser][]*Router`（`router.go:105-118`）。

- **冲突检测**：`Add` 先查 `exist(domain, location, httpUser)`（`router.go:132-134`），三元组完全相同即返 `ErrRouterConfigConflict`（`router.go:101`）。这个错误一路冒泡到 `HTTPProxy.Run`（`server/proxy/http.go:97-100`），frpc 收到 `NewProxyResp.Error` 后进入 `ProxyPhaseStartErr` 并 30s 后重试（`client/proxy/proxy_wrapper.go:50,147-151`）。
- **location 匹配**：`slices.SortFunc` 按 location **降序**（`router.go:153-155`），命中用 `strings.HasPrefix(path, vr.location)`（`router.go:210`）。降序排序近似实现了「最长前缀优先」。
- **通配走查**（`router.go:217-245`）：精确 host → 逐层把最左 label 换成 `*`（`test.a.example.com` → `*.a.example.com` → `*.example.com`）→ 最后 `"*"` 兜底。`for len(hostSplit) >= 3` 刻意阻止 `example.com` 落到 `*.com`。
- **routeByHTTPUser**：`getExactOrAllUsersLocked`（`router.go:247-258`）先按精确 user 查，再回落到 `httpUser == ""`（= match all）。user 从 `Proxy-Authorization`（代理模式）或 `Authorization` 取（`http.go:231-246`）。这让「同一个域名 + 同一路径，按 Basic Auth 用户名分发到不同的家庭桌面」成为可能——**这是 S1/IoT 多租户场景最值钱的一个机制**。
- 测试覆盖很扎实：`router_test.go:63-189` 把「精确胜通配」「更具体通配胜宽通配」「两段域名不进通配走查」都钉住了。

`Muxer`（`vhost.go:56-224`）是 https / tcpmux 共用的四层版：`vhostFunc` 抽 host → `getListener` → 把 conn 塞进 per-route 的 `chan net.Conn`（`vhost.go:218-223`），`Listener.Accept` 再消费（`vhost.go:238-258`）。`handle` 一开始压 30s deadline（`service.go:64`, `vhost.go:169`），路由成功后清掉（`vhost.go:211`）。

---

## 3. 头部改写与来源透传

| 能力 | 配置字段 | 实现位置 | `type=https` 可用？ |
|---|---|---|---|
| Host 改写 | `hostHeaderRewrite` | `http.go:69-71`（L7）；`vhost.go:248-256`（四层 hook，实际未装） | 否 |
| 请求头注入 | `requestHeaders.set` | `http.go:87-89` | 否 |
| 响应头注入 | `responseHeaders.set` | `http.go:94-102` | 否 |
| XFF / XFH / XFP | 恒开 | `http.go:60-61` + stdlib `SetXForwarded` | 否 |
| Proxy Protocol v1/v2 | `transport.proxyProtocolVersion` | frpc 侧 `client/proxy/proxy.go:195-198` | 是（连接级） |

三处硬伤，逐个点名：

1. **`HeaderOperations` 只有 `Set`**（`pkg/config/v1/common.go:133-141`）。没有 `add`（多值追加），没有 `remove`/`unset`。任务描述里的「add/remove」在 v0.71 里**不存在**。想删掉 `Authorization` 再转发给内网服务？做不到。
2. **XFF 无条件信任下游**。`http.go:60` 把 `r.In.Header["X-Forwarded-For"]` 原样复制进 outreq，然后 `SetXForwarded()`（stdlib `reverseproxy.go:82-99`）在其后追加真实 peer IP。stdlib 在 Rewrite 模式下本来已经 `Del("X-Forwarded-For")`（`reverseproxy.go:504-507`）把它清干净了，frp 主动加回来。攻击者伪造 `X-Forwarded-For: 10.0.0.1` → 内网服务若取 **第一个** 元素做 IP 白名单，直接被绕过。**新工具必须加 `trustedProxies` 白名单，默认丢弃入站 XFF。**
3. **`X-Forwarded-Proto` 永远是 `http`**。frps 的 vhost HTTP server 不带 TLS，`r.In.TLS == nil`（stdlib `reverseproxy.go:94-98`）。后端无法知道手机端用的是 https，OAuth redirect / cookie `Secure` 全会算错。
4. **Proxy Protocol 与连接复用相冲**。PP header 是 **连接级** 的，在 frpc 收到 `StartWorkConn` 时一次性生成（`client/proxy/proxy.go:195-198`，`pkg/util/net/proxyprotocol.go:25-33`）。但 work conn 的池化 key 里 **不含客户端地址**（`http.go:81-85`），`MaxIdleConnsPerHost: 5`（`http.go:106`）。手机 A 打开的连接被手机 B 的请求复用时，本地服务从 PP header 读到的 **仍是手机 A 的 IP**。另外 `HTTPProxy.GetRealConn` 调 `GetWorkConnFromPool(rAddr, nil)`（`server/proxy/http.go:122`），dst 恒为 nil（`server/proxy/proxy.go:172-175`）。→ **`type=http` + proxyProtocol 是个陷阱，新工具应当在 L7 场景下禁用它，只用 XFF/`Forwarded`。**

## 4. HTTP Basic Auth

`httpUser`/`httpPassword`（`proxy.go:321-322`）→ `RouteConfig.Username/Password`（`server/proxy/http.go:62-63`）→ `checkRouteAuthByRequest`（`http.go:187-206`）。代理模式查 `Proxy-Authorization` 返 407 + `Proxy-Authenticate`，普通模式查 `Authorization` 返 401 + `WWW-Authenticate`（`http.go:268-280`）。

问题：`user == rc.Username && passwd == rc.Password` 是**非常量时间字符串比较**（`http.go:201,205`），且密码在 frpc.toml 里明文、经 `msg.NewProxy.HTTPPwd`（`proxy.go:337`）明文上报。tcpmux 侧同样（`pkg/util/tcpmux/httpconnect.go:87`）。**新工具用 `subtle.ConstantTimeCompare` + 服务端存 bcrypt/argon2 哈希**，成本几乎为零。

## 5. subdomain 与自定义域名

- 拼接极其朴素：`subDomain + "." + serverCfg.SubDomainHost`（`server/proxy/proxy.go:217-229`），custom domains 与 subdomain 合并成一个 domain 列表，逐个注册。
- 客户端校验：两者不能都空（`validation/proxy.go:74-79`）。
- 服务端校验（`validation/proxy.go:81-100`）：
  - customDomain 不得是 `subDomainHost` 的后缀（防止绕过 subdomain 分配）；
  - `subDomainHost == ""` 时拒绝 subdomain；
  - subdomain 里不许含 `.` 或 `*`。
- **真正的「占用」检测只发生在 `Routers.Add`**（`router.go:132`）——即先到先得，没有任何持久化的域名所有权/预留概念。frps 重启后全部重新抢占。`server/control.go:872` 只管 proxy **名字**重复。
- 没有 `*.foo` 形式的 subdomain 分配（被 `*` 检查挡住），也没有「子域名池/配额/审批」。**对产品化 Web 控制台这是必须自建的一块。**

## 6. 健康检查：完全在客户端

`pkg/util/health/` 不存在；实现在 `client/health/health.go`。

- `Monitor` 支持 `tcp`（Dial 后立刻 Close，`health.go:152-165`）与 `http`（GET 期望 2xx，`health.go:167-185`）；`Type` 校验只允许 `""|tcp|http`，且 http 必须给 `path`（`validation/proxy.go:49-57`）。
- 只在 `HealthCheck.Type != "" && LocalPort > 0` 时启用（`client/proxy/proxy_wrapper.go:123-129`）→ **plugin 型后端（`https2http`、`static_file`、`socks5`…）拿不到健康检查**。
- 初始 `pw.health = 1`（不健康，`proxy_wrapper.go:124`），所以 **本地服务没起来时该 proxy 根本不会注册到 frps**——这个默认行为很正确。
- 失败路径：`statusFailedCallback` → `pw.close()` → 发 `msg.CloseProxy`（`proxy_wrapper.go:187-193`）→ frps 侧 `HTTPProxy.Close` 执行 `closeFuncs`，把路由或 group 成员摘掉（`server/proxy/http.go:93-104,161-166`）。轮询周期 3s（`proxy_wrapper.go:48`）+ `healthNotifyCh` 立即唤醒（`proxy_wrapper.go:237`）。
- 弱点：`doHTTPCheck` 用全局 `http.DefaultClient`（`health.go:174`），共享连接池、跟随重定向；`checkWorker` 用 `time.Sleep(interval)` 而非 ticker（`health.go:137`），故实际周期 = interval + 检查耗时，抖动明显。恢复时 `failedTimes` **从不清零**（`health.go:129` 只 ++），一旦累计到 `maxFailed`，之后任何一次失败都会立刻摘除——即 `maxFailed` 只对首次生效。

**frps 自己不探活。** 后端死了但 frpc 进程活着且健康检查没配 → frps 会继续路由，直到 `CreateConnection` 失败走 `ErrorHandler` 返 404/504（`http.go:128-138`）。

## 7. loadBalancer.group

支持 group 的类型：**tcp**（`server/proxy/tcp.go:51-65`）、**http**（`http.go:88-95`）、**https**（`https.go:82-89`）、**tcpmux**（`tcpmux.go:59-61`）。
**不支持**：udp / stcp / xtcp / sudp——而且 `validation/` 里 grep `LoadBalancer` 为空，**配了也不报错，静默失效**。对 S1 的音视频 UDP 通道意味着零负载均衡、零 HA。

两种实现形态：

- **listener 型**（https / tcp / tcpmux）：`baseGroup`（`server/group/base.go:13-77`）。第一个 proxy 真正 `Listen`，后续 proxy 共享同一个 `acceptCh`，各拿一个虚拟 `*Listener`（`listener.go:18-49`）。选择策略 = **多 goroutine 抢同一个 channel**，即 OS 调度决定，不是 round-robin。最后一个 listener 关闭时 `close(acceptCh)` + 关真 listener + `cleanupFn`（`base.go:63-77`）。
- **callback 型**（http）：`HTTPGroup`（`server/group/http.go:50-191`）注册的是 `map[proxyName]CreateConnFunc`。**严格 round-robin**：`g.index.Add(1) % len(g.pxyNames)`（`http.go:139-147`）。为了配合连接池，还多了 `chooseEndpoint`（`http.go:160-179`）先选出 proxy 名，写进 `URL.Host` 的第四段（`vhost/http.go:81-85`），再由 `createConnByEndpoint`（`http.go:181-191`）拨号——**这就是「round-robin 同时保持 keep-alive 亲和」的实现**，值得抄。
- 鉴权/一致性：首个成员定义 domain/location/routeByHTTPUser，后来者不一致返 `ErrGroupParamsInvalid`，`groupKey` 不一致返 `ErrGroupAuthFailed`（`http.go:99-107`；`group.go:21-29`）。`groupRegistry` + `errGroupStale` 重试环（`registry.go:97-136`，`http.go:30-39`）解决了「group 正被删除时又来注册」的竞态。
- 弱点：round-robin 无权重、无 least-conn、无 EWMA；`chooseEndpoint` 的错误在 Rewrite 里被丢弃（`vhost/http.go:76` `endpoint, _ =`），退化成 `CreateConnFn`；`Routers.Del` 只清 `[]*Router`，不删空的 `indexByDomain[domain]` 条目（`router.go:162-184`），长期动态注册会缓慢泄漏 map 条目。

## 8. 其它必须知道的边界

- **后端永远是 HTTP/1.1**。`Transport`（`http.go:104-125`）没设 `Protocols`/`ForceAttemptHTTP2`，且 `req.URL.Scheme = "http"`（`http.go:63`）。frps 前端开了 h2c，但 frps→frpc→本地服务是 h1。→ **`type=http` 无法承载 gRPC / RFC 8441 WebSocket-over-H2**。对 nomifun 这类可能用 gRPC 流的场景是硬墙，只能退回 `type=https` 四层。
- `ResponseHeaderTimeout` 默认 60s（`http.go:50-52`，`pkg/config/v1/server.go:120`），SSE / 长轮询若 60s 内不吐 header → 504（`http.go:131-134`）。
- `Muxer.handle` 在 `vhost.go:187` 直接 `v.failHook(sConn)`，**无 nil 检查**。当前两个构造函数都装了 failHook（`https.go:35`、`httpconnect.go:47`），但新增一种 muxFunc 而忘记 `SetFailHookFunc` 就会 panic 在路由未命中路径上——最难测到的那条路径。
- 控制台 API 是**只读**的：`/api/v2/proxies` 只有 GET，没有 POST/PUT/DELETE（`server/http/controller_v2_test.go:846-848`）。frp 的真理来源是 frpc.toml。**「产品化 Web 控制台」这块 frp 基本没有可抄的东西，必须自己设计声明式 API + 下发。**
- 自定义 404 页：`Custom404Page` → 全局变量 `vhost.NotFoundPagePath`（`service.go:222`，`resource.go:27,58-59`），**每次 404 都同步读一次文件**（`resource.go:58`），是个廉价的 DoS 放大点。

---

## 9. 对新 Go 工具的判定

### S1（手机 → 家用桌面，HTTP + WS + UDP）

**Must-have**：`ReverseProxy`+`Rewrite` 骨架（WS 免费）、host+path 路由与冲突检测、Host 改写、XFF/`Forwarded`（**带 trustedProxies**）、按路由的连接池 key、404/504 错误页、`responseHeaders`（CORS 用）。
**Nice-to-have**：`routeByHTTPUser`（多住户很香，但可后置）、group round-robin（家庭只有一台桌面）、绝对 URI 代理模式、CONNECT。
**Drop**：连接级 Proxy Protocol（与池化冲突）、`type=https` 的四层-only 语义（见下）。

### S2（机器人只有 IP:port）

L7 vhost 基本用不上——机器人不会发对的 `Host`。真正对应的是 `"*"` catch-all 路由（`router.go:243-244`）或干脆 L4 端口映射。**S2 的答案是「端口 → 固定后端」的静态映射 + 可选 `tcpmux`，不是 vhost。** 但 catch-all + `hostHeaderRewrite` 是个不错的兼容层：机器人发 `Host: 192.168.1.5`，中继器改写成后端期望的 Host。

### 要不要终止 TLS（ACME / Let's Encrypt）？

**反方（frp 的立场）**：不终止 = 端到端加密，中继运营者看不见明文，责任面最小；无需管证书生命周期、无需 80/443 challenge 端口、无 renew 失败导致全站挂掉的单点；SNI 转发实现只有 90 行（`https.go`）。对「我不信任中继」的家庭用户，这是唯一可接受的姿态。

**正方**：不终止 TLS 就 **彻底放弃 L7**——没有 path 路由、没有 header 注入、没有 WS 级观测、没有 `routeByHTTPUser`、`X-Forwarded-Proto` 永远错。而 S1 的手机端要求「公网 https 域名 + 有效证书」，让每个家庭桌面自己搞证书（frp 的 `https2http` + 自签，`transport/tls.go:99-105`）等于让手机吃证书错误。IoT 设备的 TLS 栈往往连自定义 CA 都装不了。

**推荐：双模，默认终止。**

```
listener 443
  ├─ SNI 属于「托管域」(*.relay.example.com 或用户已验证的 custom domain)
  │    → 本地 ACME 证书 → TLS 终止 → 走 L7 路由（path/header/WS/auth/observability）
  └─ 否则（passthrough 模式显式声明，或 SNI 未托管）
       → ClientHello 嗅探后 splice 到后端，零解密
```

- 终止侧用 `crypto/tls` + **`golang.org/x/crypto/acme/autocert`**（`GetCertificate` + `HostPolicy` 直接接路由表）或 `caddyserver/certmagic`（要 DNS-01 通配符、分布式证书存储时选它）。2026 年这两者都是稳的；不要手写 ACME。
- 嗅探侧照抄 `readClientHello` 的 `GetConfigForClient` 技巧（`https.go:53-71`）+ `libnet.NewSharedConn`；Go 里等价物是自己写 40 行 buffered-replay conn，或直接用 `tls.Config.GetConfigForClient` 在同一个 `tls.Server` 里分流（终止模式下更自然：`GetCertificate` 拿不到证书就 fallback 到 passthrough 分支）。
- **同时开 h2 + HTTP/1.1**（`NextProtos: {"h2","http/1.1"}`），并把后端 Transport 也配 `Protocols`/`ForceAttemptHTTP2`，避免 frp 的 gRPC 死路。
- 用 `Forwarded` (RFC 7239) 为主、XFF 兼容，`X-Forwarded-Proto` 按真实前端协议写。

### Go 重写成本估计

vhost 全包 ~600 行 Go（`http.go` 287 + `vhost.go` 272 + `router.go` ~180 + `https.go` 91 + `resource.go` 87）。核心逻辑（Routers + ReverseProxy 装配 + SNI 嗅探）**一个人 3-5 天可达功能对等**，因为重活全在 stdlib：`httputil.ReverseProxy`（WS/101、hop-by-hop、buffer pool）、`http.Transport`（池化）、`crypto/tls`（ClientHello）。要额外自建的是：ACME（autocert，1 天）、trustedProxies + 常量时间 auth（半天）、声明式路由 API + 控制台（这才是真正的工作量）、header add/remove 语义、least-conn/EWMA 负载均衡、frps 侧主动健康检查。

---

## 10. 待架构师决策的开放问题

1. 路由的真理来源在哪：中继端数据库（控制台可写）还是客户端配置上报（frp 模型）？这决定了域名所有权、配额、审批能不能做。
2. 托管域 + ACME 的 DNS 控制权归谁？通配符证书需要 DNS-01，家庭用户自带域名时用 HTTP-01 还是要求 CNAME 委派？
3. `type=https` passthrough 是否保留？保留则控制台对这类流量只有字节数，没有请求级可观测性。
4. UDP（S1 音视频）要不要 group/健康检查？frp 完全没有，而这是家庭上行抖动场景最需要的（多路径/多中继冗余）。
5. 后端 HTTP/2（gRPC）是 v1 目标还是 v2？决定 work conn 是「一请求一流」还是要在 tunnel 内跑 yamux/h2 多路复用。
