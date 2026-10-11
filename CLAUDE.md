# CLAUDE.md

动手改本仓库任何东西之前，先读并遵守 [`AGENTS.md`](AGENTS.md)。

其中两条是强制的：

1. **GitHub Actions 绝对禁止。** `.github/workflows/` 下不允许存在任何 workflow YAML，
   无论是否禁用。门禁只有一个入口：提交前本地跑 `make check`。

2. **Git 署名必须指向人类。** Claude 以及任何其他 AI 模型可以协助工作，
   但**绝不能**出现在 Git 的 author、committer、co-author 或致谢贡献者中。
   不要添加 `Co-authored-by`、`Generated-by`、`Assisted-by` 等 AI 署名 trailer。
   责任人无法确定时用 `RiKa0-0 <redacted@example.invalid>`。

`docs/integration/` 是当前的规范性文档集：字段名、常量、状态名以它为准，不得偏离。
调研证据在 `docs/research/`（现存 dossier 10–12；更早的设计规格
`docs/superpowers/` 与 dossier 01–09、13–16 已随文档精简移除，
原稿可用 `git show 22463af~1:docs/superpowers/specs/2026-08-07-nomirelay-design.md`
等 Git 历史路径找回）。代码注释里的「规格 §N」引的就是那份旧规格。
