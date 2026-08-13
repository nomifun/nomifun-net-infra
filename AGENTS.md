# AGENTS.md

本仓库（`nomifun-net-infra` / NomiRelay）的强制约定。动手前先读完。

## GitHub Actions 绝对禁止

这是不可协商的、仓库范围的规则，适用于每个分支、worktree、贡献者、编码 agent 与自动化工具。

- 绝不创建、恢复、生成、暂存、提交、合并或重命名任何 GitHub Actions workflow 进 `.github/workflows/`。
- 该目录下不允许存在任何 `.yml`/`.yaml`。禁用的、仅手动触发的、定时的、可复用的、仅发布用的、
  临时的 workflow **一律禁止，无例外**。
- 构建、测试、打包、发布自动化必须使用本地脚本与文档化的手工命令。
- **门禁只有一个入口：提交前本地跑 `make check`。**
- 完成任何变更前，确认 `.github/workflows/` 下不存在 workflow YAML。若任务与本规则冲突，停下并报告冲突。

## Git 署名必须指向人类

- 每个 commit 必须归属于负责的人类开发者。
- 绝不把 AI 模型、AI 产品、厂商、bot 或 agent 身份写进 Git author 或 committer 的 name/email。
  禁止的身份包括但不限于 Claude、Codex、GPT、ChatGPT、Gemini、Copilot、OpenAI、Anthropic。
- 绝不添加 AI 署名 trailer 或等效归属，包括 `Co-authored-by`、`Generated-by`、`Assisted-by` 等。
- 责任人无法确定时，author 与 committer 均用 `RiKa0-0 <redacted@example.invalid>`。
- 不使用 `--no-verify` 绕过仓库钩子，不修改全局 Git 配置。

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

## 验证阶梯

跑覆盖本次改动的最小集合，并在 PR/报告里记录实际命令：

- `make check`（fmt + vet + lint + test）——提交前必过。
- `make e2e`——涉及数据面或协议改动时。
- `make web-check`——涉及前端改动时。

**命令慢或本机不可用时，不要伪造。**写明「未运行」并给出原因。

## 文档

- 规格与计划放 `docs/superpowers/specs/`、`docs/plans/`；研究档案放 `docs/research/`。
- 对可能漂移的事实，链接到实现源码（`file:line`）。
- 有 spec 的行为发生变更时，同步改 spec。
