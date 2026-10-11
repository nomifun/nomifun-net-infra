# NomiRelay 接入文档

面向外部团队与自托管管理员，描述当前实现的部署、API、协议和运维行为。实现入口与证据边界随行为一起维护；遇到代码与文档不一致时，请以当前实现核实并修正文档。

| 要做的事 | 阅读入口 |
|---|---|
| 先跑通通用中继 | [1. 五分钟上手](01-quickstart.md) |
| 决定部署形态与开放端口 | [2. 部署与端口](02-deployment.md) |
| 用程序驱动管理员 API | [3. API 与服务间集成](03-api.md) |
| 安装网络代理端与管理生命周期 | [4. agent 生命周期](04-agent.md) |
| 选择隧道组合 | [5. 能力矩阵](05-capabilities.md) |
| 理解后端收到的网关请求 | [6. 网关契约](06-gateway.md) |
| 生产运维 | [7. 运维](07-operations.md) |
| 实现其他网络代理端 | [8. 线协议](08-wire-protocol.md) |
| 核对实现限制 | [9. 已知缺口](09-known-gaps.md) |
| 连接 Desktop 并让手机跨网访问 | [10. Desktop 接入与手机访问](10-desktop-connect.md) |

控制台默认是本机 HTTP。远程管理使用 SSH 隧道，或显式配置有 TLS 的反代与 Cookie 加固。Desktop 生产接入模板保留本机管理端，仅公开 HTTPS 邀请兑换与单连接控制路径。

通用管理员 API 仍使用管理员会话，没有角色或通用只读 API key。Desktop 专用接入使用一次性邀请及单连接控制 bearer；Mobile 使用 Desktop 设备邀请。三个凭据的权限和使用入口不同，不能互换。

所有业务隧道仍需要网络代理端承载。配置预检通过和中继传输就绪分别表示配置与承载状态，真实公网 TLS、Desktop 认证和手机 HTTP/WebSocket 访问需要额外验收。

MIT，见 [LICENSE](../../LICENSE)。
