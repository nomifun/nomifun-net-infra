# 10. Desktop 接入与手机访问

本章描述当前 v2 接入契约和独立的 HTTPS 部署模板。代码入口是
[`internal/console/desktop_connections.go`](../../internal/console/desktop_connections.go)、
[`cmd/nfrelay/desktop_connections.go`](../../cmd/nfrelay/desktop_connections.go)，
控制台入口是「连接 Desktop」（`/desktop-connect`）。产品使用说明还包括 Desktop
与 Mobile 操作，统一入口见 [NomiFun Portal](https://www.nomifun.com/zh/docs/guides/net-infra/)。

## 10.1 三个产品的权限与操作顺序

1. 中继管理员在控制台「连接 Desktop」检查部署，填写 Desktop 名称和它独立的公开访问地址，创建短时、一次性的**中继配对码**。
2. 用户在 Desktop 的「连接与设备」（Connections & Devices）连接中继，粘贴配对码。Desktop 兑换邀请，保存本连接的控制凭据，托管 `nfagent`。用户无需复制管理员密码或手工启动网络代理端。
3. 用户在 Desktop 创建**手机设备邀请**，交给 Mobile。Mobile 使用 Desktop 身份认证访问公开业务地址。手机设备信任、到期与撤销由 Desktop 管理。

中继邀请不赋予 Desktop 管理其他隧道的权限；本连接的控制凭据只允许查询与撤销本连接。
解除中继连接会撤销相应邀请和网络代理端、关闭公开业务入口。它不会代替 Desktop
撤销手机设备信任。中继中的「代理端」指网络进程 `nfagent`，不指 AI Agent。

## 10.2 四种地址

| 地址 | 示例 | 使用者与配置来源 |
|---|---|---|
| 管理地址 | `http://127.0.0.1:9443` | 管理员；本机访问或 SSH 隧道 |
| 公共接入地址 | `https://relay.example.com:9444/api/bootstrap/desktop/v2` | Desktop 兑换中继邀请；`-desktop-bootstrap-url` 显式配置 |
| 代理端承载地址 | `relay.example.com:8443` | `nfagent`；`-advertise` 显式配置，QUIC 使用 UDP |
| Desktop 业务地址 | `https://home-desktop.example.com` | Mobile 与远程客户端；创建邀请时逐台填写 |

管理员即使通过 localhost 或 SSH 隧道登录，中继配对码也只使用服务端返回的
`bootstrap_url`。控制台不会从 `window.location.origin` 猜配对地址。生产业务地址
需要独立的 HTTPS 域名；同一中继上的另一台 Desktop 使用另一个域名。

v2 的网络后端固定为 Desktop 专属回环监听 `127.0.0.1:25811`，承载已认证的远程入口；
v1 仍使用 `127.0.0.1:25808`。共享 HTTPS 网关根据域名选择对应隧道，并重写 backend Host。
公网 URL、网关 TLS、Desktop 的 Host/Origin 和认证检查必须按双方契约联合验证，
不能把旧的端口模式响应直接改成一个 HTTPS 字符串。

## 10.3 生产 HTTPS 部署模板

使用仓库根目录的 [`docker-compose.desktop-https.yml`](../../docker-compose.desktop-https.yml)，
这是独立部署文件，**不要与默认 `docker-compose.yml` 合并启动**。
默认配置继续用于通用中继，它没有开放 Desktop 的完整公网接入路径。

前提是 Linux Docker 主机能够接收以下流量，并且 DNS 指向这台主机：

| 公网端口 | 容器 | 用途 |
|---|---|---|
| UDP `8443` | `nfrelay` | QUIC 网络代理端承载 |
| TCP `443` | `nfrelay` | 每台 Desktop 的共享 HTTPS 业务入口，以及 ALPN 区分的 L2 承载回退 |
| TCP `9444` | `desktop-bootstrap` / Caddy | 中继邀请兑换及单连接控制 API 的 HTTPS 入口 |
| TCP `80` | Caddy | `relay.example.com` 的 ACME HTTP-01 挑战 |
| 本机 TCP `9443` | `nfrelay` | 管理控制台；只发布到主机 `127.0.0.1` |

`relay.example.com` 和 `home-desktop.example.com` 都需正确解析；存在 AAAA 记录时
IPv6 路径也必须可达。此模板要求公开接入端口 `9444` 可用。只有 `443` 可用的网络
需要另行设计入口前置或部署到另一地址，不能将 Caddy 与 nfrelay 同时绑定同一个 `443`。

在 Bash 中设置真实值后启动：

```bash
export RELAY_HOST=relay.example.com
export ACME_EMAIL=ops@example.com
# 可选：作为控制台第一台 Desktop 的建议值；后续 Desktop 在表单中更换域名。
export DESKTOP_PUBLIC_URL=https://home-desktop.example.com
docker compose -f docker-compose.desktop-https.yml config
docker compose -f docker-compose.desktop-https.yml up -d --build
docker compose -f docker-compose.desktop-https.yml logs -f nfrelay desktop-bootstrap
```

通过 SSH 管理：

```bash
ssh -L 9443:127.0.0.1:9443 relay-host
# 然后在浏览器访问 http://127.0.0.1:9443
```

模板把管理员控制台保留在本机 HTTP，未设置 `-console-behind-tls-proxy`；因此 SSH
访问的登录 Cookie 不会因错误的 Secure 声明而失效。Caddy 只公开精确的 bootstrap 与取消配对 POST
与单连接 GET/DELETE 路径，其他路径返回 404，包括登录、创建邀请和完整连接列表。
完整的 API 鉴权仍由 nfrelay 执行，反代路径匹配不替代 bearer 或管理员会话检查。

TLS 分为两个签发范围：

- Caddy 通过 HTTP-01 获取 `relay.example.com` 证书，禁用其 TLS-ALPN 挑战，因为公网 `443` 属于 nfrelay。
- nfrelay 的 `-shared=0.0.0.0:443 -acme` 通过 TLS-ALPN-01 为已经登记的 Desktop 域名获取证书；模板显式使用生产 ACME 目录，默认 staging 证书不满足生产预检。

Caddy 的配置依据见其官方 [ACME issuer 文档](https://caddyserver.com/docs/caddyfile/directives/tls#issuers)。
持久化全部三个数据卷；删除 relay 数据卷会丢失身份、隧道和承载证书，删除 Caddy 数据卷
会丢失其证书缓存和 ACME 账户。Desktop 业务 TLS 在中继终止，中继运营方属于可信边界，
能看到解密后的 HTTP/WebSocket 流量；网络承载到 Desktop 的数据由已认证 carrier 传输。

## 10.4 接入预检与状态含义

`GET /api/desktop/preflight` 使用管理员会话，返回：

```json
{
  "protocol_version": 2,
  "bootstrap_url": "https://relay.example.com:9444/api/bootstrap/desktop/v2",
  "default_business_url": "https://home-desktop.example.com",
  "ready": true,
  "checks": [
    {"code":"bootstrap_url","ok":true,"message":"..."},
    {"code":"carrier_address","ok":true,"message":"..."},
    {"code":"shared_https","ok":true,"message":"..."}
  ]
}
```

`ready` 只表示生效配置满足发码条件。它不进行 DNS、公网 TLS、Mobile 策略或业务调用
验收。未配置公共接入地址、用了不合适的承载地址、未启用生产共享 HTTPS 时阻止发码。

控制台每五秒更新连接状态：

| 状态 | 含义与后续动作 |
|---|---|
| `waiting` | 等待 Desktop 兑换邀请；把配对码交给对应 Desktop |
| `expired` | 邀请未兑换且已到期；生成新邀请 |
| `pending` | 配置已保存，等待网络代理端上线；检查 Desktop 托管进程与网络 |
| `transport_ready` | 隧道 active 且代理端会话存活；继续验证 Desktop 身份、手机认证和业务访问 |
| `error` | 查看 `reason`、日志与逐跳探测，按具体原因恢复 |
| `revoked` | 已解除，重新接入需创建新的邀请 |

`transport_ready` 不显示为「手机已连接」。Desktop 与手机必须分别报告实际认证和业务
结果。支持包与逐跳探测可辅助定位，但本机探测成功不证明公网可达。

## 10.5 v2 配对与单连接控制契约

管理员写操作沿用 [第 3 章](03-api.md) 的 Cookie、`X-NFR-CSRF` 与 Origin 规则。

```http
POST /api/pairing-invites/v2
Content-Type: application/json

{"ttl_seconds":600,"note":"Home Desktop","business_url":"https://home-desktop.example.com"}
```

响应含 `id`、`token`、`relay`、`pin`、`listen_port`、`expires_at`、
`protocol_version:2`、`bootstrap_url`、`business_url`。`listen_port` 在生产共享模式
代表公开业务端口；普通界面不让用户配置 Desktop 本地监听端口。生产不使用随机独立
TCP 业务入口。开发模式才允许 `listen_port:0` 自动选择本机端口。

配对码为 `nomifun-relay-pair:v2:` 加上如下 JSON 的 UTF-8 base64url 无 padding 编码：

```json
{"bootstrap_url":"https://relay.example.com:9444/api/bootstrap/desktop/v2","invite":"<one-time token>","expires_at":"<RFC3339>"}
```

v1 envelope 继续保持原字段，不能在严格的 v1 解码器下直接新增能力字段。

Desktop 生成并在发请求前持久保存 32 字节随机尝试标识，编码为 64 字符 hex：

```http
POST /api/bootstrap/desktop/v2
Authorization: Bearer <invite>
Content-Type: application/json

{"attempt_id":"<64 hexadecimal characters>"}
```

响应包括 v1 基础字段、`protocol_version:2`、`l2_port`、`control_url`、`control_token`、`state`、
`reason`，以及固定 v2 backend 的 `tunnel`。保存成功后再托管 nfagent。

`control_token` 的格式为 `nf_desktop_` 加 64 字符 hex；它不是无前缀的 64 字符值。
`control_url` 使用公共接入 origin 和 `/api/desktop-connections/{invite_id}` 路径。
网络超时或响应丢失后只能使用原来保存的 `attempt_id` 重试；改变尝试标识不会再次
获得这枚邀请的使用权。邀请、入网凭据和控制凭据是敏感内容，不写进截图、工单或日志。

`l2_port` 是共享 TLS 承载的端口；生产模板为 `443`，没有共享入口则为 `0`（不可回退）。
Desktop 将该值传给 `nfagent -l2-port`，不能把生产回退固定禁用。自定义部署必须保持
共享 listener 与公网映射端口一致；本机测试可以使用实际的临时共享端口。

### 结果未知或入网凭据到期时取消配对

Desktop 已持久保存尝试但尚未保存 `control_token` 时，网络超时可能使客户端不知道
邀请是否已兑换。入网凭据已经到期时，也可能无法再次获取 bootstrap 响应。这两种
情况使用原邀请和原尝试标识取消，不通过重新兑换领取凭据来实现解除：

```http
POST /api/bootstrap/desktop/v2:cancel
Authorization: Bearer <original invite>
Content-Type: application/json

{"attempt_id":"<the original 64 hexadecimal characters>"}
```

未兑换的邀请可以取消，包括已到期的邀请。已兑换的邀请必须匹配服务端保存的同一个
`attempt_id`；另一尝试不能取消它。取消不受入网凭据过期限制，也不会延长它的有效期。
成功返回 `DesktopConnection`，其中 `revoked:true`、`state:"revoked"`；使用原凭据
重复取消也成功。邀请、关联网络代理端和业务入口按照正常撤销路径解除。

Desktop 的解除操作必须先确认此取消请求成功，再删除本地 pending 记录、原邀请和
尝试标识。网络故障使取消结果未知时保留这些记录，以便重试；若本地凭据已经丢失，
管理员在中继控制台解除相应连接。公开反代必须允许精确的
`POST /api/bootstrap/desktop/v2:cancel`，不能只开放兑换路径。

### 已保存连接的控制凭据

Desktop 用 `Authorization: Bearer <control_token>` 对 `control_url` 发 GET 查询、
发 DELETE 撤销，只能操作这一个连接。管理员可通过 Cookie/CSRF 对同一个 URL 查询
或撤销。DELETE 返回连接对象，包含最终 `state` 与 `revoked`，不是 `{ok:true}`。
管理员完整列表为 `GET /api/desktop-connections`，响应为 `{"connections":[...]}`。

部分运行时应用失败不能把 HTTP 200 解释为业务已经连通；读取响应的 `state`/`reason`
并继续查连接状态。邀请入库与运行时监听建立是不同阶段。

## 10.6 本机开发与验收边界

仅测试结果未知且凭据真实到期的取消路径时，可在本机测试模式追加
`-desktop-dev-enrol-ttl=2s`。该参数在生产模式不允许缩短 TTL；生产入网有效期仍为 15 分钟。

仅在本机明确启用：

```bash
./nfrelay -data-dir ./data-desktop-test \
  -bind 127.0.0.1:18443 -advertise 127.0.0.1:18443 \
  -console 127.0.0.1:19443 \
  -desktop-bootstrap-url http://127.0.0.1:19443/api/bootstrap/desktop/v2 \
  -desktop-dev-insecure
```

业务 URL 留空时自动选择本机 HTTP 端口。这枚配对码只能用于同一台主机上的 Desktop；
不能发给另一台电脑或真实手机。本机回环 HTTP 的流程测试不证明公网 HTTPS 部署。

生产交付至少需要记录以下实测，只有通过的项才标为已验收：

1. 通过 localhost/SSH 管理后生成的码仍指向显式公共地址；从另一台 Desktop 成功兑换。
2. 接入两台 Desktop，各自域名、隧道与网络代理端独立，撤销一台不影响另一台。
3. 真实发布版 nfagent 完成入网、隧道下发和重连；阻断 UDP 后实际建立 TCP/443 L2 回退。
4. 公网 TLS 证书、DNS、Desktop Host/Origin 与手机认证通过；手机完成至少一次 HTTP 请求和 WebSocket 业务连接。
5. 邀请到期、相同尝试重试、不同尝试重复兑换、运行时应用失败、Desktop/Relay 重启和两端解除都有准确状态和恢复动作；结果未知和入网凭据到期的 pending 尝试可用原邀请与尝试标识取消，重复取消成功，其他尝试不能撤销它。

仓库内的本地测试、前端构建和模板静态校验不构成上述真实公网或手机验收证据。
