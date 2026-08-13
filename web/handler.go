package web

import (
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// AssetHandler 提供 SPA 资源，带三件 http.FileServerFS 不做的事。
//
//  1. **SPA 回退**：GET/HEAD 且路径不存在时返回 index.html，让前端路由接手。
//     只对 GET/HEAD 回退 —— 对 POST 回退会把「路由写错」伪装成 200。
//  2. **缓存分层**：带内容哈希的资源 `immutable, max-age=31536000`，
//     index.html `no-cache`。反过来做（index 长缓存）会让用户在升级后
//     永远看到旧 SPA，这是最难排查的一类「已经修好了但还是不对」。
//  3. **预压缩协商**：vite 构建时已经产出 .br / .gz（见 vite.config.ts 的
//     precompress 插件），这里按 Accept-Encoding 挑一个直接发。
//     刻意**不**按请求 gzip：frp 就是那么做的，等于把已压缩资源再压一遍烧 CPU。
func AssetHandler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "只支持 GET/HEAD", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "." {
			name = "index.html"
		}

		info, err := fs.Stat(fsys, name)
		if err != nil || info.IsDir() {
			// 未命中就是前端路由（/tunnels/foo 这类深链接）。
			name = "index.html"
			if info, err = fs.Stat(fsys, name); err != nil {
				http.NotFound(w, r)
				return
			}
		}

		h := w.Header()
		// 哈希文件名的资源可以永久缓存；index.html 必须每次校验。
		if strings.HasPrefix(name, "assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		if ctype := mime.TypeByExtension(path.Ext(name)); ctype != "" {
			h.Set("Content-Type", ctype)
		}

		// 协商预压缩变体。Vary 必须设，否则中间缓存会把 br 的响应
		// 喂给不支持 br 的客户端。
		h.Add("Vary", "Accept-Encoding")
		serveName := name
		accept := r.Header.Get("Accept-Encoding")
		for _, cand := range []struct{ enc, ext string }{{"br", ".br"}, {"gzip", ".gz"}} {
			if !strings.Contains(accept, cand.enc) {
				continue
			}
			if _, err := fs.Stat(fsys, name+cand.ext); err != nil {
				continue
			}
			serveName = name + cand.ext
			h.Set("Content-Encoding", cand.enc)
			break
		}

		f, err := fsys.Open(serveName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		// 有 Content-Encoding 时不能用 http.ServeContent：它会按解压后的
		// 尺寸算 Range 与 Content-Length，与实际发出的字节不一致。
		if h.Get("Content-Encoding") != "" {
			if r.Method == http.MethodHead {
				return
			}
			_, _ = io.Copy(w, f)
			return
		}
		if rs, ok := f.(io.ReadSeeker); ok {
			http.ServeContent(w, r, name, info.ModTime(), rs)
			return
		}
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(w, f)
	})
}
