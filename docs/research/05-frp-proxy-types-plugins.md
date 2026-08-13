# frp 代理类型分类学与客户端插件系统 — 设计输入档案

调研对象：`/mnt/hgfs/share/net-infra/frp`（module `github.com/fatedier/frp`，`go.mod:3` → `go 1.25.0`）。
所有结论均来自实读源码，行号为该工作树中的实际行号。

评判基准：
- **S1 服务对接**：公网手机 → 中继 → 家庭 NAT 后的桌面服务器，需 HTTP + WebSocket + UDP（音视频，延迟敏感）。
- **S2 反向代理**：工厂机器人只能配置「中继 IP + 端口」，零客户端软件，定向到指定远端桌面。

---

## 1. 类型注册表模式（这部分值得抄）

frp 的 8 个代理类型不是一个巨大的 switch，而是「**类型字符串 → reflect.Type → 配置结构体**」的注册表：

```go
// pkg/config/v1/proxy.go:230-250
const ( ProxyTypeTCP ProxyType = "tcp"; ... ProxyTypeSUDP ProxyType = "sudp" )
var proxyConfigTypeMap = map[ProxyType]reflect.Type{
    ProxyTypeTCP: reflect.TypeFor[TCPProxyConfig](), ... }
// pkg/config/v1/proxy.go:252-260
func NewProxyConfigurerByType(t ProxyType) ProxyConfigurer {
    pc := reflect.New(proxyConfigTypeMap[t]).Interface().(ProxyConfigurer)
    pc.GetBaseConfig().Type = string(t); return pc }
```

反序列化走两遍：先用 `typedEnvelope{Type, Plugin}` 嗅探 `type` 字段，再把整段 JSON 解到具体结构体上（`pkg/config/v1/decode.go:39-70`），插件段单独二次分派（`decode.go:100-125`）。`TypedProxyConfig` 用嵌入接口 + 自定义 `UnmarshalJSON/MarshalJSON` 让上层拿到强类型（`proxy.go:196-214`）。

`ProxyConfigurer` 接口只有 5 个方法（`proxy.go:216-226`）：`Complete()`、`GetBaseConfig()`、`Clone()`、`MarshalToMsg(*msg.NewProxy)`、`UnmarshalFromMsg(*msg.NewProxy)`。**Complete/Validate/Clone 三段式**是 frp 配置层最干净的部分：`Complete()` 填默认值（`proxy.go:154-161`，`localIP` 默认 `127.0.0.1`），校验独立在 `pkg/config/v1/validation/`，`Clone()` 做深拷贝以支持热重载。

**服务端也是注册表**，但键是 `reflect.Type` 而非字符串：

```go
// server/proxy/proxy.go:43-47
var proxyFactoryRegistry = map[reflect.Type]func(*BaseProxy) Proxy{}
func RegisterProxyFactory(t reflect.Type, f func(*BaseProxy) Proxy)
// 各实现在 init() 里自注册，如 server/proxy/tcp.go:26-28
RegisterProxyFactory(reflect.TypeFor[*v1.TCPProxyConfig](), NewTCPProxy)
// server/proxy/proxy.go:560-567 查表
factory := proxyFactoryRegistry[reflect.TypeOf(configurer)]
```

**判决：采纳**（registry + Complete/Validate/Clone），但**丢掉 reflect**。Go 1.25 下用泛型工厂 `map[string]func() ProxyConfig` 即可，`reflect.New` 只是为了省几行样板代码，代价是 IDE 跳转、编译期检查全失效。

---

## 2. 八种类型的真实差异（大部分是假差异）

| 类型 | 独有配置字段 | 服务端做了什么 | 端口 |
|---|---|---|---|
| tcp | `remotePort`（`proxy.go:264-268`） | `net.Listen("tcp")` + 端口管理器（`server/proxy/tcp.go:49-89`） | 独占 |
| udp | `remotePort`（`proxy.go:290-293`） | `net.ListenUDP` + 单 workConn 泵（`server/proxy/udp.go:78-254`） | 独占 |
| http | `locations/httpUser/httpPassword/hostHeaderRewrite/requestHeaders/responseHeaders/routeByHTTPUser` + `DomainConfig`（`proxy.go:316-327`） | 向共享 `HTTPReverseProxy` 注册路由，**不监听**（`server/proxy/http.go:55-112`） | 共享 `vhostHTTPPort` |
| https | **只有** `DomainConfig`（`proxy.go:369-372`） | 向 SNI muxer 注册，返回一个虚拟 listener（`server/proxy/https.go:78-91`） | 共享 `vhostHTTPSPort` |
| tcpmux | `multiplexer/httpUser/httpPassword/routeByHTTPUser` + `DomainConfig`（`proxy.go:403-411`） | 向 HTTP CONNECT muxer 注册（`server/proxy/tcpmux.go:48-102`） | 共享 `tcpMuxHTTPConnectPort` |
| stcp | `secretKey/allowUsers`（`proxy.go:444-449`） | `VisitorManager.Listen` 内存 listener（`server/proxy/stcp.go:43-46`） | 无 |
| sudp | `secretKey/allowUsers`（`proxy.go:508-513`） | 与 stcp **逐字节相同**，只有日志字符串不同（`server/proxy/sudp.go:43-46`） | 无 |
| xtcp | `secretKey/allowUsers/natTraversal`（`proxy.go:474-482`） | 只在 NAT 打洞控制器注册，把 sid 写回 workConn（`server/proxy/xtcp.go:51-86`） | 无 |

三个致命的「其实没差别」证据：

1. **客户端侧 5 个类型共用一个实现**：`client/proxy/general_tcp.go:23-34` 把 `TCPProxyConfig / HTTPProxyConfig / HTTPSProxyConfig / STCPProxyConfig / TCPMuxProxyConfig` 全部注册到同一个 `NewGeneralTCPProxy`。也就是说 tcp/http/https/stcp/tcpmux 在客户端**完全等价**，差异 100% 在服务端的暴露方式。
2. **stcp 与 sudp 服务端实现字面重复**：`server/proxy/stcp.go:43-46` 与 `server/proxy/sudp.go:43-46` 都只调 `startVisitorListener(...)`，后者仅传了不同的日志字符串。sudp 的 "UDP" 语义完全靠客户端侧的 `msg.UDPPacket` 编解码实现（`server/proxy/proxy.go:329-345` 里那段 `proxyType == "sudp"` 的混合编解码桥接是唯一的服务端特殊处理，本身就是版本兼容补丁）。
3. **`msg.NewProxy` 是一个扁平的 union struct**，注释直接承认字段互斥：`// tcp and udp only`（`pkg/msg/msg.go:114`）、`// http and https only`（`:117`）、`// stcp, sudp, xtcp`（`:128`）、`// tcpmux`（`:132`）。线协议层面根本没有类型多态，只有一个 33 字段的大结构体。

### 校验规则：形同虚设

`ValidateProxyConfigurerForClient` 是 8 分支 type switch（`validation/proxy.go:102-127`），但其中 **5 个分支是空实现**：tcp、udp、stcp、xtcp、sudp 的客户端校验全部 `return nil`（`validation/proxy.go:129-135, 156-166`）；服务端同样 5 个空实现（`:196-202, 229-239`）。真正的校验只有：
- 基础项：`name` 非空、`proxyProtocolVersion ∈ {"", v1, v2}`、`bandwidthLimitMode ∈ {client, server}`、健康检查类型（`validation/proxy.go:28-57`）；
- `localPort` **仅在未配置插件时**必填（`validation/proxy.go:43-47`）——这是插件与本地端口互斥的唯一强制点，呼应 `proxy.go:65-67` 的注释 "If this value is set, the LocalIP and LocalPort values will be ignored"；
- 域名类：`subdomain` 与 `customDomains` 不可同时为空（`:74-79`），子域不得含 `.`/`*`、不得与 `subDomainHost` 冲突（`:81-100`）；
- 能力门禁：`http` 需服务端开 `vhostHTTPPort`（`:213-219`）、`https` 需 `vhostHTTPSPort`（`:221-227`）、`tcpmux` 需 `tcpMuxHTTPConnectPort`（`:204-211`）；
- `multiplexer` 只允许 `httpconnect` 一个值（`proxy.go:395-399` 常量表只有一个成员；`validation/proxy.go:142-144` 白名单）。

**评价**：8 分支中 5 个空实现，说明这个 type switch 是纯样板。新工具应把校验挂在「能力」上而不是「类型」上（见 §6）。

---

## 3. stcp/sudp/xtcp 的授权机制（secretKey + allowUsers）

线协议：`msg.NewProxy.Sk` + `AllowUsers`（`pkg/msg/msg.go:129-130`）由被访问端上报；访问端发 `msg.NewVisitorConn{RunID, ProxyName, SignKey, Timestamp, UseEncryption, UseCompression}`（`pkg/msg/msg.go:163-170`）。

服务端只有 ~40 行实现（`server/visitor/visitor.go:49-109`）：

```go
// server/visitor/visitor.go:78-86
if util.GetAuthKey(l.sk, timestamp) != signKey { return 认证失败 }
if !slices.Contains(l.allowUsers, visitorUser) && !slices.Contains(l.allowUsers, "*") { return 不允许 }
```

`allowUsers` 为空时默认只允许同一用户（`server/proxy/proxy.go:202-206`，xtcp 同逻辑在 `server/proxy/xtcp.go:58-62`），`"*"` 是通配。认证通过后可选加密/压缩，**加密密钥直接就是 secretKey**（`visitor.go:88-97`），然后把连接塞进内存 listener，由 `startCommonTCPListenersHandler` 泵到 workConn（`server/proxy/proxy.go:207-214, 232-265`）。

### 对抗性发现（有证据）

- **`GetAuthKey` 是裸 MD5，不是 HMAC**：`pkg/util/util/util.go:50-56` → `md5(token || decimal(timestamp))`。长度扩展攻击面 + MD5 碰撞面。
- **visitor 路径没有时间戳新鲜度校验**：`visitor.go:78` 只比较 `GetAuthKey(sk, timestamp)` 与 `signKey`，而 `timestamp` 由请求方自带。登录路径同样只做等值比较（`pkg/auth/token.go:64-68`），**任何被抓到的 (timestamp, signKey) 对可以永久重放**。
- **比较不恒定时间**：`visitor.go:78` 用 `!=` 而非 `util.ConstantTimeEqString`（该工具函数确实存在，`pkg/auth/token.go:65` 就在用）——同一代码库里两套标准。
- **`allowUsers` 只是字符串匹配**，`visitorUser` 来自控制连接的登录用户（`server/service.go:887-913`），且为兼容老版本，**`runID` 为空时直接以空用户放行**（`server/service.go:912` 的 `return admit("", wireProtocol, "")`），注释自己标了 `TODO(deprecation)`（`server/service.go:895`）。

### S1/S2 判决

- **stcp/sudp 对 S2 直接判死**：visitor 必须是另一个 frpc 进程，本地 `bindAddr/bindPort` 监听（`pkg/config/v1/visitor.go:29-48`）。机器人零客户端软件 ⇒ 不可用。
- **xtcp 对 S1 有价值但不能作为主路径**：它把服务端降级为信令面（`server/proxy/xtcp.go:63-84` 只转发 sid），P2P 成功时延迟最优；但需要 visitor 侧软件，且 `XTCPVisitorConfig` 自带 `fallbackTo/fallbackTimeoutMs/maxRetriesAnHour/minRetryInterval`（`pkg/config/v1/visitor.go:143-155`）——**打洞不可靠是写进配置结构里的既成事实**。
- **secretKey + allowUsers 的模型本身值得抄**（对象级密钥 + 主体白名单），但必须换成 HMAC-SHA256 + 时间窗 + nonce 重放缓存。

---

## 4. tcpmux 的 HTTP CONNECT 路由

`pkg/util/tcpmux/httpconnect.go`：

- 用 `libnet.NewSharedConn` 预读首个请求，`http.ReadRequest` 解析，非 `CONNECT` 直接报错（`:52-71`）；
- 路由键 = `Host`（经 `CanonicalHost` 规范化）+ `Proxy-Authorization` 里的 basic 凭据（`:65-69, 108-127`）；
- `passthrough=false` 时服务端自己回 `200 OK` 再转发裸流；`true` 时把 CONNECT 请求原样透给后端（`:73-82, 122-126`）；
- 复用 `vhost.Muxer` 的 `CheckAuth/SuccessHook/FailHook` 钩子（`:45-48`）。

**对抗性发现**：认证比较是 `username == reqUsername && password == reqPassword`（`httpconnect.go:87`），非恒定时间；同仓库的 http_proxy 插件却用了 `util.ConstantTimeEqString` + 200ms 延迟（`pkg/plugin/client/http_proxy.go:158-162`）。

**判决：对 S1/S2 都 drop。** tcpmux 的价值只在「多个 TCP 服务共享一个端口且客户端愿意说 HTTP CONNECT」。S2 的机器人只会裸 TCP；S1 的手机用 HTTP/WS 更自然。它其实就是「L7 路由器 = HTTP-CONNECT」的一个实例，在新模型里应表达为 `router: http-connect`，而不是一个顶层类型。

---

## 5. HTTP/HTTPS 的服务端实现（S1 的关键）

- **http**：不监听端口，只往共享 `HTTPReverseProxy` 注册 `(domain, location, routeByHTTPUser)` 路由（`server/proxy/http.go:55-112`），每请求通过 `CreateConnFn = pxy.GetRealConn` 从 workConn 池取连接（`:114-151`）。路由表是「域名 → httpUser → location 列表（按 location 降序排序取最长前缀）」（`pkg/util/vhost/router.go:36-70, 98-125`），带通配符逐级回退 `a.b.c → *.b.c → *`（`:127-155`）。
  - **脏点**：为了让 `http.Transport` 能复用连接，它把 `domain + base64(location) + base64(routeByHTTPUser) + base64(endpoint)` 拼成假的 `req.URL.Host`（`pkg/util/vhost/http.go:81-85`）。能用，但是一个字符串编码的路由键黑客手法。
  - WebSocket 走 `httputil.ReverseProxy` 的 upgrade 透传（`vhost/http.go:57-139` 未做特殊处理，依赖 Go 1.20+ 的自动 upgrade 支持）；`ResponseHeaderTimeout` 默认 60s（`vhost/http.go:50-52, 104-106`）。
- **https**：服务端**完全不终止 TLS**，只嗅探 ClientHello 的 SNI 做分流（`pkg/util/vhost/https.go:39-71`，用一个假的 `readOnlyConn` 骗 `tls.Server` 吐出 `ClientHelloInfo`）。这意味着 **证书必须放在家里的客户端上**（配 `https2http` 插件），或者用户自己在服务上装证书。

**判决：http 的 L7 路由 adopt（S1 主路径），https 的「只分流不终止」adapt。** 对消费级产品，中继端必须能做 ACME/autocert 自动签发（`golang.org/x/crypto/acme/autocert`）——把证书运维推给家里那台机器是产品化的毒药。SNI passthrough 应保留为可选模式（端到端加密需求）。

---

## 6. 客户端插件系统

### 注册与实例化

```go
// pkg/plugin/client/plugin.go:37-55
var creators = make(map[string]CreatorFn)
type CreatorFn func(PluginContext, v1.ClientPluginOptions) (Plugin, error)
func Register(name string, fn CreatorFn)   // 重名 panic
func Create(name string, ctx PluginContext, opts v1.ClientPluginOptions) (Plugin, error)
// pkg/plugin/client/plugin.go:66-71
type Plugin interface { Name() string; Handle(context.Context, *ConnectionInfo); Close() error }
// pkg/plugin/client/plugin.go:57-64
type ConnectionInfo struct { Conn io.ReadWriteCloser; UnderlyingConn net.Conn
    ProxyProtocolHeader *pp.Header; SrcAddr, DstAddr net.Addr }
```

各插件在 `init()` 里自注册（如 `http2http.go:25-27`），配置侧同名常量 + `reflect.Type` 表在 `pkg/config/v1/proxy_plugin.go:26-50`。实例化点：`client/proxy/proxy.go:109-121`（`Run()` 时 `plugin.Create`），调用点：`client/proxy/proxy.go:202-210`（有插件则插件接管，直接 return，不再 dial 本地端口）。

对于「服务器型」插件（需要 `net.Listener` 的），frp 提供了内存 listener 适配器：`Listener.PutConn` 把 workConn 塞进 64 容量的 channel（`plugin.go:73-112`），插件侧起 `http.Server{}.Serve(listener)`（`http_common.go:60-97`）。**这个 Conn→Listener 适配器模式是整个插件系统最值得抄的一块**。

**硬限制**：`client/proxy/proxy.go:98-100` 注释直言 "It's only validate for TCP protocol now"。实测 `grep -c proxyPlugin client/proxy/{udp,sudp,xtcp}.go` → **全部 0**。**UDP 类代理无法使用任何插件**。

### 十个插件逐个过（含 S1/S2 判决）

| 插件 | 实现要点 | 判决 |
|---|---|---|
| `http2http` | `httputil.ReverseProxy` 转发到 `localAddr`，明文（`http2http.go:35-52`） | **adapt**：能力应内建，不是插件 |
| `http2https` | 同上但上游 https，`InsecureSkipVerify: true` 硬编码（`http2https.go:44-46`） | adapt，必须加 `skipVerify/caFile` 开关 |
| `https2http` | 客户端终止 TLS（本地证书 `crtPath/keyPath`），转发明文；带 `SetXForwarded()` 与 misdirected-request 检查（`https2http.go:35-59`，`internal/httpsserver/httpsserver.go:31-59`） | **port**：S1 端到端加密路径必需 |
| `https2https` | 两端 TLS，上游同样 `InsecureSkipVerify: true`（`https2https.go:44-46`） | port（低优先级） |
| `http_proxy` | 完整正向 HTTP 代理：读 7 字节嗅探 `CONNECT`，非 CONNECT 走 `http.Server`，支持 `Proxy-Authorization` basic + 恒定时间比较 + 200ms 失败延迟（`http_proxy.go:74-101, 138-191`） | **drop**：S1/S2 都不需要出网代理；且它把家庭网络变成开放代理 |
| `socks5` | 包一层 `armon/go-socks5`（`socks5.go:38-57`）。该依赖 pin 在 2016 年的 commit：`go.mod:6` `v0.0.0-20160902184237-e75332964ef5` | **drop**（或延后）：同上，且依赖已死 |
| `static_file` | `gorilla/mux` + `http.FileServer` + gzip + basic auth（`static_file.go:41-69`） | **borderline**：产品化「一键分享文件夹」有卖点，但 `gorilla/mux`（`go.mod:10`）纯属浪费，Go 1.22+ `http.ServeMux` 够用 |
| `tls2raw` | 客户端终止 TLS 后转裸 TCP，支持 PROXY protocol 头（`tls2raw.go:57-85`） | **port**：S2 的加密变体（机器人不支持 TLS 时由中继侧终止） |
| `unix_domain_socket` | `net.DialUnix` + PROXY protocol + `libio.Join`（`unix_domain_socket.go:52-69`） | **port**：~20 行，暴露 Docker socket / 桌面 IPC 很实用 |
| `virtual_net` | 把 workConn 交给 TUN 控制器做 L3 转发（`virtual_net.go:48-67`，`pkg/vnet/controller.go:242-259`）。需要 root 创建 TUN（`pkg/vnet/tun_linux.go:35-44`），受 feature gate 保护（`validation/client.go:59-64`） | **drop**：这是 EasyTier 的赛道，用它自己的实现，不要在中继里塞半个 mesh |

### 插件系统的具体缺陷（每条都有证据）

1. **`http2http` 静默丢失客户端 IP**。它的 rewrite 只调 `rewriteHTTPPluginRequest`（`http2http.go:42-48`），既没有 `SetXForwarded()` 也没有拷贝 `X-Forwarded-For`——而它的三个兄弟都做了（`http2https.go:50-52`、`https2http.go:44-45`、`https2https.go:50-51`）。`httputil.ReverseProxy` 在 `Rewrite` 模式下**不会**自动补 XFF，所以家里的服务只能看到 frps 的地址。同时它建 bridge 时传 `useSourceRemoteAddr=false`（`http2http.go:49`），而 https2http 传 `true`（`https2http.go:52`）。
2. **`http2http` 的 `localAddr` 根本没被校验**。`ValidateClientPluginOptions` 的 type switch 有 6 个 case（`validation/plugin.go:23-39`），**唯独漏了 `*v1.HTTP2HTTPPluginOptions`**，而其余三个 HTTP 家族插件都有 `localAddr is required`（`:41-60`）。配置里写 `type: http2http` 不写 `localAddr` → 通过校验 → 运行期每个请求都打到空 host。
3. **`virtual_net` 在控制器缺失时泄漏连接**：`virtual_net.go:49-52` 判断 `VnetController == nil` 后直接 `return`，**没有 `connInfo.Conn.Close()`**，workConn 永久挂着。
4. **`InsecureSkipVerify: true` 无法关闭**（`http2https.go:45`、`https2https.go:45`），配置结构体里也没有对应字段（`proxy_plugin.go:141-149`）。
5. **插件与 UDP 完全绝缘**（见上），意味着 S1 的音视频路径拿不到任何插件能力。

---

## 7. UDP 路径：S1 的最大风险区

frp 的 udp 代理在服务端是「**单条 workConn 上的多路复用**」：

```go
// server/proxy/udp.go:50-52
// there are always only one workConn at the same time
// get another one if it closed
workConn net.Conn
```

所有外部 UDP 源共享这一条 TCP（或 QUIC/KCP）workConn，帧格式是 `msg.UDPPacket{Content, LocalAddr, RemoteAddr}`（`pkg/msg/msg.go:186-190`）。后果：

- **队头阻塞**：workConn 若是 TCP，一个丢包会拖住所有音视频流。
- **静默丢包**：`sendCh` 满时 `select { case sendCh <- m: default: }` 直接丢弃，无计数无日志（`pkg/proto/udp/udp.go:66-69`；反向同样，`:97-101`）。channel 深度硬编码 1024（`server/proxy/udp.go:106-107`）。
- **会话表按源地址 keyed，30s 读超时回收**（`pkg/proto/udp/udp.go:90, 119-124, 144`），没有显式容量上限。
- **启动有 500ms 硬编码睡眠**（`server/proxy/udp.go:184-186`：`time.Sleep(500 * time.Millisecond)` 等 NewProxyResp）。
- **每包一次 `make([]byte, len(buf))` 拷贝**（`pkg/proto/udp/udp.go:29-37`）。

**判决：drop 这个设计。** 新工具的 UDP 中继必须是**独立数据面**：中继侧 `net.ListenUDP` + 到家侧的 QUIC 数据报（RFC 9221，`quic-go` 已支持；frp 已依赖 `quic-go v0.60.0`，`go.mod:20`）或 DTLS，每个 5 元组一条独立流，绝不共享一条有序流。丢包必须计数并上报到 web 控制台。

---

## 8. 为新 Go 工具提议的正交模型

frp 的 8 类型可以无损分解为三个独立维度：

```
Tunnel = (Exposure) × (L4) × (Router?) × (Auth) × (Backend)
```

```go
type Tunnel struct {
    Name     string
    Exposure Exposure   // "port" | "shared" | "private" | "p2p"
    L4       L4         // "tcp" | "udp"
    Router   *Router    // 仅 Exposure=="shared" 时有效
    Auth     *Auth      // secretKey/allowUsers/mTLS，任意 Exposure 可用
    Backend  Backend    // addr / unix / handler(内建能力)
    Transport TransportOpts // 加密、压缩、限速、PROXY protocol、健康检查
}
type Exposure string  // port: 独占端口; shared: 共享端口+L7分流; private: 需授权的内部端点; p2p: 打洞
type Router struct {
    Kind    RouterKind // "http" | "tls-sni" | "http-connect"
    Domains []string; Subdomain string
    Locations []string           // 仅 http
    TLS     *TLSTermination      // nil=SNI passthrough; 非 nil=中继侧 ACME 终止
    Rewrite *HTTPRewrite         // hostHeaderRewrite / req+resp headers
    Auth    *BasicAuth           // httpUser/httpPassword/routeByHTTPUser
}
```

映射表（frp → 新模型）：

| frp | 新模型 |
|---|---|
| `tcp` | `{exposure: port, l4: tcp, remotePort: N}` |
| `udp` | `{exposure: port, l4: udp, remotePort: N}` |
| `http` | `{exposure: shared, l4: tcp, router: {kind: http, domains, locations, auth}}` |
| `https`（SNI 透传） | `{exposure: shared, l4: tcp, router: {kind: tls-sni, domains}}` |
| `https` + `https2http` 插件 | `{exposure: shared, l4: tcp, router: {kind: http, tls: {mode: passthrough}}, backend: {tlsTerminate: local}}` |
| `tcpmux/httpconnect` | `{exposure: shared, l4: tcp, router: {kind: http-connect, domains, auth}}` |
| `stcp` | `{exposure: private, l4: tcp, auth: {secretKey, allowUsers}}` |
| `sudp` | `{exposure: private, l4: udp, auth: {secretKey, allowUsers}}` |
| `xtcp` | `{exposure: p2p, l4: tcp, auth: {secretKey, allowUsers}}` |

**8 → 4 个枚举值 + 3 个 router kind，且每个维度可独立组合**。副作用是免费获得 frp 没有的组合：`{exposure: port, l4: tcp, auth: {allowIPs}}`（S2 需要的「端口暴露 + IP 白名单」，frp 里 tcp 类型压根没有 auth 字段，见 `proxy.go:264-268`）、`{exposure: shared, router: {kind: http, tls: {mode: acme}}}`（中继侧自动证书）。

场景落点：
- **S1**：HTTP/WS 走 `{shared, tcp, router: http}`（复用 §5 的路由表 + `httputil.ReverseProxy`）；UDP 走 `{port, udp}` 但换成 §7 的独立 QUIC 数据报数据面。
- **S2**：`{port, tcp, auth: {allowCIDRs}}`，零客户端软件；若要多机器人共享一个中继端口，用 `{shared, tcp, router: tls-sni}` 或直接按源 IP 分流（新增 `router.kind: source-ip`，frp 完全没有这个能力）。

### 要抄的具体机制
- 类型注册表 + `Complete/Validate/Clone` 三段式（`proxy.go:154-161, 216-226`）——但用泛型不用 reflect。
- Conn→Listener 内存适配器（`plugin/client/plugin.go:73-112`），让任何 `http.Server`/`net.Listener` 消费者接入隧道。
- 域名路由表：httpUser 二级索引 + location 最长前缀 + 通配符逐级回退（`vhost/router.go:98-155`）。
- SNI 嗅探（`vhost/https.go:39-71`）与 `SharedConn` 预读回放（`tcpmux/httpconnect.go:108-127`）。
- PROXY protocol 传递真实源地址（`client/proxy/proxy.go:195-198, 229-236`），S2 里让桌面服务看见机器人真实 IP。
- 对象级 `secretKey` + 主体 `allowUsers` 白名单（`visitor.go:78-86`）——换 HMAC。
- `RemotePort=0` 时的随机端口 + 「保留端口」粘性（`server/ports/ports.go:99-122`），配合 `allowPorts`/`maxPortsPerClient`（`server/service.go:174-175`、`server/control.go:852-854`）。

### 要丢的
- 8 类型分类学与 33 字段的 `msg.NewProxy` union（`pkg/msg/msg.go:102-134`）——线协议用 typed envelope（type + 类型内 payload）。
- `reflect` 驱动的配置/工厂查表（`proxy.go:241-260`、`server/proxy/proxy.go:43-47`）。
- 单 workConn 的 UDP 多路复用（`server/proxy/udp.go:50-52`）。
- 裸 MD5 + 无时限的挑战（`util.go:50-56`、`visitor.go:78`）。
- `http_proxy` / `socks5` / `virtual_net` 三个插件。
- `gorilla/mux`（`go.mod:10`）与 `armon/go-socks5`（`go.mod:6`）依赖。

### 2026 年的 Go 实现成本
- L7 路由 + WS：`net/http` + `httputil.ReverseProxy`（Rewrite 模式，别忘 `SetXForwarded()`），零第三方。
- 证书：`golang.org/x/crypto/acme/autocert`（中继侧自动签发，frp 完全没做）。
- 控制面：单条 QUIC 连接 + 每隧道一条 stream（`quic-go`，已在 frp 依赖里），替掉 frp 的 workConn 池 + `hashicorp/yamux`（`go.mod:12`）。
- UDP 数据面：QUIC datagram (RFC 9221)。
- 配置：TOML/YAML → typed envelope（frp 用 `pelletier/go-toml/v2` + 自研 `jsonx`，`decode.go:29-33`）。
- 移植量估算：注册表 + 4 种 exposure + http/tls-sni router + 5 个保留插件 ≈ 3.5–5k 行 Go（不含 web 控制台），比 frp 现有的 8 类型 × 双端实现少一半。

---

## 9. 留给架构师的开放问题

1. TLS 终止放中继（ACME，产品化友好）还是放家里（端到端加密）？两者都要就得同时实现 `router.tls.mode ∈ {acme, passthrough, provided}`。
2. S2 的多租户分流：靠独占端口（简单，但端口是稀缺资源且 `maxPortsPerClient` 需要配额系统）还是靠 `source-ip` 路由（省端口，但机器人出口 IP 可能变）？
3. UDP 数据面用 QUIC datagram（需要中继和家侧都是自己的软件，S1 成立）还是 DTLS/裸 UDP+自研序列号？音视频是否需要 FEC/抖动缓冲，还是完全交给上层（WebRTC）？
4. `virtual_net` 这条 L3 mesh 路线是否彻底交给 EasyTier，还是留一个 `exposure: mesh` 的扩展点？
5. `allowUsers` 的主体模型：沿用「用户名字符串」还是升级为设备身份（公钥指纹 / mTLS 客户端证书）？后者对 IoT/nomifun-tauri 更自然，但需要一套设备注册流程与 web 控制台配合。
