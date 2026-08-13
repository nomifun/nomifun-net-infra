# NomiRelay — 本地构建门禁
#
# 本仓刻意没有 GitHub workflow（见 AGENTS.md）。门禁只有一个入口：
#   make check      提交前必过（fmt + vet + lint + test）
#
# 常用：
#   make build      构建两个二进制到 ./bin
#   make e2e        端到端测试（需要 loopback 端口）
#   make dist       全平台交叉编译 + SHA256SUMS
#   make help       列出全部目标

SHELL := /bin/bash
.DEFAULT_GOAL := help

MODULE  := github.com/nomifun/nomifun-net-infra
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

BIN_DIR  := bin
DIST_DIR := dist
WEB_DIR  := web

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT)

GOFLAGS_COMMON := -trimpath -ldflags '$(LDFLAGS)'

# web/dist 缺失时自动加 noweb tag，保证新克隆里 go build ./... 不中断。
# （这是 frp 的做法，值得照抄：web/frps/embed.go + Makefile:4）
ifeq ($(wildcard $(WEB_DIR)/dist/index.html),)
BUILD_TAGS := noweb
else
BUILD_TAGS :=
endif
ifneq ($(BUILD_TAGS),)
TAGFLAG := -tags $(BUILD_TAGS)
else
TAGFLAG :=
endif

CGO_ENABLED := 0
export CGO_ENABLED

# -race 需要 cgo，而发布产物必须 CGO_ENABLED=0 才能静态交叉编译。
# 这两个要求互斥，所以测试目标单独打开 cgo：竞态检测比「测试也走纯静态」重要得多。
# 若本机没有 C 工具链，用 make test RACE= 退化为无竞态检测（并会打印提示）。
RACE ?= -race
TEST_CGO := 1

## help: 列出所有目标
.PHONY: help
help:
	@echo "NomiRelay 构建目标："
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | column -t -s ':'
	@echo
	@echo "当前：VERSION=$(VERSION) COMMIT=$(COMMIT) TAGS=$(if $(BUILD_TAGS),$(BUILD_TAGS),<无>)"

## check: 提交前必过的门禁（fmt + vet + lint + test + 前端 + noweb 分支）
#
# # 为什么前端也必须在这里
#
# 控制台是产品的主要交互面，而在这一行之前它**完全不在唯一的强制门禁里**：
# 一个带 TypeScript 类型错误、locale 键缺失、或硬编码中文的控制台
# 可以静默通过 make check 与 make dist 进入发布产物 —— 因为 `make ui`
# 只跑 vite build，而 esbuild 只剥类型、不校验类型。
#
# 代价是 check 慢几十秒，且要求装了 bun。装不了 bun 的环境见 web-check 里的降级。
#
# # 为什么要单独跑一次 noweb
#
# TAGFLAG 由「web/dist/index.html 存不存在」决定（见文件开头）。开发机上
# dist 一直在，所以 noweb 那半边代码**永远不被编译、也永远不被测**——
# 而它恰好是 cmd/nfrelay 里 consoleHandler 的另一个 return 分支，
# 以及 web.Embedded() 为 false 时的全部行为。MIPS/裸后端部署走的正是它。
.PHONY: check
check: fmt-check vet lint test test-noweb web-check deps-check reach-check
	@echo "✓ check 通过"

## test-noweb: 只跑 noweb 那半边（默认构建永远覆盖不到）
#
# 输出只在**失败时**打出来。此前是 `>/dev/null && echo ✓`：
# 成功时安静（对的），但失败时**也**安静 —— 一次真实的偶发失败只留下
# 「make: *** [test-noweb] 错误 1」，而排查它需要的那几行 FAIL 已经被丢掉了。
# 我在这上面浪费过一次机会：那次失败之后十几轮都没能复现，
# 而唯一能解释它的输出本来就在管道里。
.PHONY: test-noweb
test-noweb:
	@out=$$(go test -tags noweb -count=1 ./cmd/nfrelay/ ./web/ 2>&1) \
		&& echo "✓ go test（noweb 分支）" \
		|| { printf '%s\n' "$$out"; exit 1; }

## fmt: 格式化 Go 代码
.PHONY: fmt
fmt:
	@gofmt -w -s $$(find . -name '*.go' -not -path './web/node_modules/*' 2>/dev/null) 2>/dev/null || true

## fmt-check: 断言代码已格式化
.PHONY: fmt-check
fmt-check:
	@files=$$(gofmt -l -s $$(find . -name '*.go' -not -path './web/node_modules/*' 2>/dev/null) 2>/dev/null); \
	if [ -n "$$files" ]; then echo "以下文件未格式化，请跑 make fmt："; echo "$$files"; exit 1; fi
	@echo "✓ gofmt"

## vet: go vet
.PHONY: vet
vet:
	@go vet $(TAGFLAG) ./... && echo "✓ go vet"

## lint: staticcheck（缺失则跳过并提示）
.PHONY: lint
lint:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck $(TAGFLAG) ./... && echo "✓ staticcheck"; \
	else \
		echo "⚠ staticcheck 未安装，已跳过。安装：go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

## test: 单元测试（默认开 -race，需要 C 工具链）
.PHONY: test
test:
	@if [ -n "$(RACE)" ] && ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then \
		echo "⚠ 未找到 C 编译器，无法用 -race。降级为无竞态检测（跑 make test RACE= 可消除本提示）"; \
		go test $(TAGFLAG) -count=1 ./... && echo "✓ go test（无竞态检测）"; \
	else \
		CGO_ENABLED=$(TEST_CGO) go test $(TAGFLAG) $(RACE) -count=1 ./... && echo "✓ go test"; \
	fi

## deps-check: 断言 nfagent 不依赖 store（modernc.org/sqlite 无 MIPS 移植）
.PHONY: deps-check
deps-check:
	@if [ -d ./cmd/nfagent ]; then \
		deps=$$(go list $(TAGFLAG) -deps ./cmd/nfagent) || { \
			echo "✗ go list 失败，依赖断言无法执行 —— 不能当作通过"; exit 1; }; \
		if printf '%s\n' "$$deps" | grep -q '$(MODULE)/internal/store'; then \
			echo "✗ nfagent 依赖了 internal/store —— 这会让 MIPS 构建失败（sqlite 无 MIPS 移植）"; exit 1; \
		fi; \
		if printf '%s\n' "$$deps" | grep -q 'caddyserver/certmagic'; then \
			echo "✗ nfagent 依赖了 certmagic —— 它会拖进 zap 与 miekg/dns，MIPS 路由器上不该背这些"; exit 1; \
		fi; \
		if printf '%s\n' "$$deps" | grep -q 'pion/turn'; then \
			echo "✗ nfagent 依赖了 pion/turn —— TURN 只在中继侧"; exit 1; \
		fi; \
		echo "✓ nfagent 未依赖 store / certmagic / turn"; \
	fi

## reach-check: 断言没有「实现了但生产代码从不调用」的导出
##
## 本仓库两次踩到同一个坑：包实现完整、测试齐全，而生产路径上零调用点
## （internal/udpflow 与 internal/gateway 都是）。测试全绿证明不了它被接上了。
.PHONY: reach-check
reach-check:
	@if command -v python3 >/dev/null 2>&1; then \
		python3 scripts/check-unreachable-exports.py || exit 1; \
	else \
		echo "⚠ 没有 python3，跳过可达性检查"; \
	fi

## build: 构建两个二进制到 ./bin
.PHONY: build
build: $(BIN_DIR)
	@go build $(TAGFLAG) $(GOFLAGS_COMMON) -o $(BIN_DIR)/nfrelay ./cmd/nfrelay
	@go build $(GOFLAGS_COMMON) -o $(BIN_DIR)/nfagent ./cmd/nfagent
	@echo "✓ 构建完成：$(BIN_DIR)/nfrelay $(BIN_DIR)/nfagent"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

## e2e: 端到端测试（真实 relay + agent + 后端服务跑在 loopback）
.PHONY: e2e
e2e:
	@CGO_ENABLED=$(TEST_CGO) go test -tags 'e2e $(BUILD_TAGS)' $(RACE) -count=1 -timeout 5m ./test/e2e/... \
		&& echo "✓ e2e"

## ui: 构建控制台前端到 web/dist
.PHONY: ui
ui:
	@cd $(WEB_DIR) && bun install --frozen-lockfile && bun run build
	@echo "✓ 前端构建完成"

## web-check: 前端类型检查与 lint
.PHONY: web-check
web-check:
	@if ! command -v bun >/dev/null 2>&1; then \
		echo "⚠ 未找到 bun，跳过前端门禁（tsc / locale 对齐 / 词汇锁 / 禁硬编码中文 / oxlint）。"; \
		echo "  这一跳过是**有代价的**：带类型错误或缺 locale 键的控制台会静默进产物。"; \
		echo "  提交前请在装了 bun 的机器上跑一次 make web-check。"; \
	else \
		cd $(WEB_DIR) && bun run check; \
	fi

## fuzz: 跑协议解析器的 fuzz（默认各 30s）
.PHONY: fuzz
fuzz:
	@go test $(TAGFLAG) -run '^$$' -fuzz 'FuzzFrame' -fuzztime $${FUZZTIME:-30s} ./internal/proto/
	@go test $(TAGFLAG) -run '^$$' -fuzz 'FuzzParseFrame' -fuzztime $${FUZZTIME:-30s} ./internal/udpflow/
	@echo "✓ fuzz"

## clean: 清理构建产物
.PHONY: clean
clean:
	@rm -rf $(BIN_DIR) $(DIST_DIR) $(WEB_DIR)/dist
	@echo "✓ 已清理"

# ── 交叉编译矩阵 ────────────────────────────────────────────────────────────
# 两个二进制的目标平台不同：modernc.org/sqlite 没有 MIPS 移植，
# 所以 MIPS 路由器只能构建 nfagent。这正是我们出两个二进制而不是一个带子命令的原因。

RELAY_PLATFORMS := \
	linux/amd64 linux/arm64 linux/arm linux/386 linux/riscv64 linux/loong64 \
	windows/amd64 windows/arm64 \
	darwin/amd64 darwin/arm64 \
	freebsd/amd64

AGENT_PLATFORMS := $(RELAY_PLATFORMS) \
	linux/mips linux/mipsle linux/mips64le

## dist: 全平台交叉编译并生成 SHA256SUMS
#
# # 为什么不能写成 `dist: clean`
#
# BUILD_TAGS 是在 Makefile **解析时**按 web/dist/index.html 是否存在算出来的，
# 而 clean 会把 web/dist 删掉。于是同一条命令有两种坏结局：
#
#   * 树上原本有 web/dist → 解析时 TAGFLAG 为空（embed 生效）→ clean 删掉它
#     → go build 因为 `//go:embed all:dist` 找不到目录而失败。
#   * 树上原本没有 web/dist → 解析时 TAGFLAG = -tags noweb → 构建**成功**，
#     产出的发布二进制里**一个前端文件都没有**，而且没有任何警告。
#
# 第二种更危险：它会安安静静地发出一批没有控制台的中继。
#
# 所以顺序在 recipe 里显式串起来（`$(MAKE)` 子调用会重新解析 Makefile，
# 于是 ui 跑完之后 TAGFLAG 才被算成空），并且**断言 embed 真的生效** ——
# 把「静默发出没有界面的产物」变成一次构建失败。
.PHONY: dist
dist:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ui
	@test -f $(WEB_DIR)/dist/index.html || { \
		echo "✗ web/dist/index.html 不存在 —— 发布产物会不带控制台。中止。"; \
		exit 1; \
	}
	@$(MAKE) --no-print-directory dist-build

.PHONY: dist-build
dist-build:
	@test -z "$(BUILD_TAGS)" || { \
		echo "✗ 发布构建带上了 -tags $(BUILD_TAGS) —— 那会让控制台不被内嵌。中止。"; \
		exit 1; \
	}
	@mkdir -p $(DIST_DIR)
	@set -e; for p in $(RELAY_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "  nfrelay $$os/$$arch"; \
		env GOOS=$$os GOARCH=$$arch \
			$$(case "$$arch" in arm) echo GOARM=7;; esac) \
			go build $(GOFLAGS_COMMON) \
			-o $(DIST_DIR)/nfrelay-$$os-$$arch$$ext ./cmd/nfrelay; \
	done
	@set -e; for p in $(AGENT_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "  nfagent $$os/$$arch"; \
		env GOOS=$$os GOARCH=$$arch \
			$$(case "$$arch" in mips|mipsle) echo GOMIPS=softfloat;; arm) echo GOARM=7;; esac) \
			go build $(GOFLAGS_COMMON) \
			-o $(DIST_DIR)/nfagent-$$os-$$arch$$ext ./cmd/nfagent; \
	done
	@cd $(DIST_DIR) && sha256sum * > SHA256SUMS
	@echo "✓ dist 完成，产物在 $(DIST_DIR)/（含 SHA256SUMS）"
	@echo "  注意：SHA256SUMS 只防损坏，不防篡改 —— 它是在这台构建机上生成的。"
	@echo "  下一步：把 $(DIST_DIR)/ 拷到**离线签名机**，在那里跑"
	@echo "         NFR_SIGN_KEY=<私钥> make sign"
	@echo "  校验方（用户）跑：make verify   或   sh scripts/verify-release.sh <目录>"

## sign: 对 dist/SHA256SUMS 做离线签名（需 NFR_SIGN_KEY，只在签名机上跑）
.PHONY: sign
sign:
	@sh scripts/sign-release.sh $(DIST_DIR)

## verify: 校验一份发布产物（先验签名，再核校验和）
.PHONY: verify
verify:
	@sh scripts/verify-release.sh $(DIST_DIR)

## keygen: 生成一对发布签名密钥（**在离线机上跑**）
.PHONY: keygen
keygen:
	@test -n "$(OUT)" || { echo "用法：make keygen OUT=/path/to/keyname"; exit 1; }
	@test ! -f "$(OUT).pem" || { echo "✗ $(OUT).pem 已存在，不覆盖"; exit 1; }
	@openssl genpkey -algorithm ed25519 -out "$(OUT).pem"
	@chmod 600 "$(OUT).pem"
	@openssl pkey -in "$(OUT).pem" -pubout -out "$(OUT).pub"
	@echo "✓ 私钥 $(OUT).pem（600，**绝不要**拷到构建机或提交进仓库）"
	@echo "✓ 公钥 $(OUT).pub —— 把它提交到 release/nomirelay-release.pub"

## tidy: go mod tidy
.PHONY: tidy
tidy:
	@go mod tidy && echo "✓ go mod tidy"
