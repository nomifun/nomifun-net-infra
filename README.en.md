# NomiFun Net Infra

NomiFun Net Infra (NomiRelay) is self-hosted cross-network transport infrastructure for exposing Desktop or other HTTP/WebSocket/TCP/UDP services to trusted clients and devices. This repository maintains Go implementation, protocols, deployment, and operations documentation.

## Product documentation

Installation, cross-network setup, Mobile configuration, screenshots, and user troubleshooting are maintained centrally in the [NomiFun Portal Net Infra guide](https://www.nomifun.com/docs/guides/net-infra/).

## Technical documentation

- Integration index: [`docs/integration/`](docs/integration/)
- API and wire protocol: [`docs/integration/03-api.md`](docs/integration/03-api.md), [`docs/integration/08-wire-protocol.md`](docs/integration/08-wire-protocol.md)
- Deployment and ports: [`docs/integration/02-deployment.md`](docs/integration/02-deployment.md)
- Operations and security: [`docs/integration/07-operations.md`](docs/integration/07-operations.md), [`docs/research/12-security-ops.md`](docs/research/12-security-ops.md)
- Development checks: follow `Makefile`, `AGENTS.md`, and current Go source

Old handovers, superpower drafts, and redundant research notes have been removed; use Git history for archaeology.
