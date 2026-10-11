# scripts/

本目录收集发布、安装与手动验证脚本。运行前请先读 `AGENTS.md` 的验证约定。

## 发布与安装

| 脚本 | 用途 | 入口 |
|---|---|---|
| `sign-release.sh` | 对 `dist/SHA256SUMS` 做 Ed25519 detached 签名，**只在离线签名机上跑** | `make sign`（需 `NFR_SIGN_KEY`） |
| `verify-release.sh` | 校验一份发布产物：先验签名，再核对每个文件的 SHA256 | `make verify` |
| `install.sh` | 一键安装 `nfrelay` / `nfagent`：下载二进制**之前**先验签，任一步失败即中止且不留半成品 | 见 `docs/integration/02-deployment.md` |

发布签名密钥是占位公钥、私钥不入库；真实发布前先 `make keygen`，见
[`release/README.md`](../release/README.md) 与 `docs/integration/07-operations.md`。

## 手动验证（不进 `make check`，太慢/要抢端口）

| 脚本 | 用途 |
|---|---|
| `browser-smoke.py` | Firefox/WebDriver 对控制台做真实渲染冒烟：首屏、向导、隧道详情、设置页等八个环节 |
| `check-unreachable-exports.py` | 找出「实现了但生产代码从不调用」的导出标识符——防「功能写完忘了接线」 |
| `verify/*.py` | 起真实 `nfrelay` + `nfagent` 打真实流量的断言复核脚本，见 [`verify/README.md`](verify/README.md) |

跑 `verify/` 下的脚本前**先清残留的 nfrelay/nfagent 进程**，否则会连到一台陈旧中继，
症状与真实原因毫无关系。细节见 `verify/README.md`。
