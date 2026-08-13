package store

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestEventKindsMatchTheFrontendEnum 是一条**跨语言契约测试**。
//
// # 为什么需要它
//
// 事件种类在两处各写了一遍：这里的 Kind* 常量，与 web/src/api/types.ts 的
// EVENT_KINDS。而 TypeScript 那边 RelayEvent.kind 的类型是
// `EventKind | string` —— 宽容到什么都能过，于是漂了也不会报错。
//
// 它确实漂过：后端加了 agent.kicked / tunnel.stream_denied /
// turn.credential_issued 三种，前端一条都没跟上。后果是事件流里出现界面
// 不认识的种类（映射不到文案、映射不到图标），而**没有任何一层会报错**。
//
// # 为什么是 Go 测试而不是前端脚本
//
// 真相源在 Go 这边（常量是后端写的），所以门禁也该在这边 ——
// 放到前端就变成「前端得知道后端加了什么」，那是反的。
// 而且 make check 一定会跑它，bun run check 只在改前端时跑。
func TestEventKindsMatchTheFrontendEnum(t *testing.T) {
	// ── 后端：从本包的源码里抽 Kind* 常量的值 ──────────────────────────
	//
	// 从**源码**抽而不是手写一份列表：手写的那份自己就会漂，
	// 于是这条测试变成「我抄的两份一致吗」，而不是「代码与前端一致吗」。
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("读 metrics.go 失败：%v", err)
	}
	kindRe := regexp.MustCompile(`(?m)^\s*Kind\w+\s*=\s*"([^"]+)"`)
	var backend []string
	for _, m := range kindRe.FindAllStringSubmatch(string(src), -1) {
		backend = append(backend, m[1])
	}
	if len(backend) < 10 {
		t.Fatalf("只抽到 %d 个 Kind 常量，正则大概坏了：%v", len(backend), backend)
	}

	// ── 前端：从 types.ts 里抽 EVENT_KINDS 的字面量 ────────────────────
	tsPath := filepath.Join("..", "..", "web", "src", "api", "types.ts")
	ts, err := os.ReadFile(tsPath)
	if err != nil {
		t.Fatalf("读 %s 失败：%v", tsPath, err)
	}
	block := regexp.MustCompile(`(?s)export const EVENT_KINDS = \[(.*?)\] as const;`).
		FindStringSubmatch(string(ts))
	if block == nil {
		t.Fatal("在 types.ts 里找不到 EVENT_KINDS —— 它被改名了？" +
			"那这条契约测试就失效了，必须一起改")
	}
	var frontend []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(block[1], -1) {
		frontend = append(frontend, m[1])
	}

	// ── 逐项比对 ─────────────────────────────────────────────────────
	slices.Sort(backend)
	slices.Sort(frontend)

	var missing, extra []string
	for _, k := range backend {
		if !slices.Contains(frontend, k) {
			missing = append(missing, k)
		}
	}
	for _, k := range frontend {
		if !slices.Contains(backend, k) {
			extra = append(extra, k)
		}
	}

	if len(missing) > 0 {
		t.Errorf("后端有、前端 EVENT_KINDS 里没有：%s\n"+
			"把它们加进 web/src/api/types.ts —— 界面认不出的事件种类会静默落到默认分支，"+
			"而 TypeScript 看不出来（kind 的类型是 EventKind | string）",
			strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("前端 EVENT_KINDS 里有、后端却不存在：%s\n"+
			"要么后端漏了这个常量，要么前端写了一个永远不会出现的种类",
			strings.Join(extra, ", "))
	}
}
