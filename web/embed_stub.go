//go:build noweb

package web

import (
	"errors"
	"io/fs"
)

// ErrNoAssets 表示本次构建未内嵌前端资源。
var ErrNoAssets = errors.New("web: 本构建未内嵌控制台前端（noweb）")

// FS 在 noweb 构建下返回错误，让调用方能给出一句人类可读的说明，
// 而不是提供一个空文件系统导致用户看到白屏还以为控制台坏了。
func FS() (fs.FS, error) { return nil, ErrNoAssets }

// Embedded 报告本次构建是否内嵌了前端。
func Embedded() bool { return false }
