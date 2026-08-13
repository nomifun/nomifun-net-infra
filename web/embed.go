//go:build !noweb

// Package web 内嵌控制台前端资源。
//
// # 为什么有 noweb 构建标签
//
// 新克隆的仓库里 web/dist 不存在，若 embed 无条件生效，`go build ./...` 会
// 直接失败 —— 一个必须先装 bun、跑完前端构建才能编译后端的仓库，
// 对只想改 Go 代码的人是很差的体验。
//
// Makefile 在 web/dist/index.html 缺失时自动加 -tags noweb，
// 此时由 embed_stub.go 提供同名符号。这是 frp 的做法
// （web/frps/embed.go + embed_stub.go + Makefile:4），值得照抄。
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS 返回内嵌的前端资源，根目录为 dist 的内容。
func FS() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}

// Embedded 报告本次构建是否内嵌了前端。
func Embedded() bool { return true }
