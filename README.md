# NomiFun Net Infra

NomiFun Net Infra（NomiRelay）是自托管的跨网络传输基础设施，负责把 Desktop 或其他 HTTP/WebSocket/TCP/UDP 服务安全地暴露给受信任的客户端和设备。本仓库只维护 Go 服务、协议、部署和运维技术内容。

## 产品使用文档

安装、跨网络接入、Mobile 配置和用户排障统一维护在 [NomiFun Portal](https://www.nomifun.com/zh/docs/guides/net-infra/)。

## 技术文档

- 集成入口：[`docs/integration/`](docs/integration/)
- API 与线协议：[`docs/integration/03-api.md`](docs/integration/03-api.md)、[`docs/integration/08-wire-protocol.md`](docs/integration/08-wire-protocol.md)
- 部署与端口：[`docs/integration/02-deployment.md`](docs/integration/02-deployment.md)
- Desktop 接入与手机访问：[`docs/integration/10-desktop-connect.md`](docs/integration/10-desktop-connect.md)，包含独立的 [`docker-compose.desktop-https.yml`](docker-compose.desktop-https.yml) 生产部署模板
- 运维与安全：[`docs/integration/07-operations.md`](docs/integration/07-operations.md)、[`docs/research/12-security-ops.md`](docs/research/12-security-ops.md)
- 开发验证：以 `Makefile`、`AGENTS.md` 和当前 Go 源码为准

旧的 handover、superpower 设计稿和重复研究草稿已移除；实现考古请使用 Git 历史。
