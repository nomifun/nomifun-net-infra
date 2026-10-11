# AGENTS.md

本仓库（`nomifun-net-infra` / NomiRelay）的开发约定。动手前先读完。

## 高效验证

- 根据改动范围选择能覆盖风险的最小检查，不要求每次提交都运行完整 `make check`。
- 纯文档改动检查差异、链接与格式即可；Go、前端、协议和发布改动分别运行对应的
  定向检查。跨模块、发布前或无法用定向检查建立信心时，再运行 `make check`。
- 命令慢、平台语义不同或本机缺少工具时，如实记录未运行项和原因；与改动无关的
  全仓失败不再阻断提交。
- 本地脚本或其他自动化可以按实际维护价值选用；普通改动不需要审计
  `.github/workflows/` 是否为空。**但 GitHub Actions 本身是绝对禁止的**——
  `.github/workflows/` 下不允许存在任何 workflow YAML（见 CLAUDE.md 的强制条款）。

## Git 工作流

- 使用贡献者当前配置的 Git 身份，不要求专用署名钩子。
- 保留无关改动，提交前检查暂存范围；未经明确授权不强推、不改写共享历史、不提交密钥。

## 提交信息

Conventional Commit 风格，中文：`<type>(<scope>): <描述>`。
type 取 `feat|fix|docs|refactor|perf|test|build|chore|style`。

描述要说清**为什么**或那个洞见，而不只是重述改了什么。

## 代码约定

- 优先沿用既有模式，而不是引入新抽象。
- 注释只在解释非显而易见的意图、不变量或集成约束时才写。
- 行为变更时同步更新文档；过期文档算 bug。
- 不引入违反本地优先承诺的遥测、云依赖或后台数据传输。

## Go

- 目标 Go 1.26。标准库优先：不引入 `chi`/`gin`/`echo`/`gorilla/mux`。
- **`nfagent` 不得 import `internal/store`**（`modernc.org/sqlite` 无 MIPS 移植，
  MIPS 路由器只构建 agent）。`make check` 会用 `go list -deps` 断言这条。
- 日志只用 `log/slog`。
- 配置结构体走 `Complete()` / `Validate()` / `Clone()` 三段式，严格分离。
- 校验用 `errors.Join` 返回**所有**失败，以便控制台一次高亮全部坏字段。
- 敏感比较一律走 `crypto/subtle`。
- `crypto/tls` 的 `CurvePreferences` 保持 nil（手动设置会静默关掉后量子曲线）。

## 验证建议

跑覆盖本次改动的最小集合，并在 PR/报告里记录实际命令：

- `make check`（fmt + vet + lint + test）——跨模块改动或发布前的完整检查。
- `make e2e`——涉及数据面或协议改动时。
- `make web-check`——涉及前端改动时。

纯文档改动无需编译。命令未运行时写明原因即可。

## 文档

- 规范文档放 `docs/integration/`，研究档案放 `docs/research/`（旧的
  `docs/superpowers/`、`docs/plans/` 已随文档精简移除）。
- 对可能漂移的事实，链接到实现源码（`file:line`）。
- 有 spec 的行为发生变更时，同步改 spec。
