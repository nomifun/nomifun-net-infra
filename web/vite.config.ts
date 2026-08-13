import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { brotliCompressSync, constants as zlibConstants, gzipSync } from 'node:zlib';
import { join } from 'node:path';

import react from '@vitejs/plugin-react';
import UnoCSS from 'unocss/vite';
import { defineConfig, type Plugin } from 'vite';

/**
 * API 契约版本。改动 src/api/types.ts 的线协议形状时必须 +1。
 *
 * 它会被写进 dist/ui-api-contract-version.txt 与 nomifun-build.json，
 * 让一个被缓存的旧 SPA 打到新中继时能显示「请刷新」而不是一串神秘 400。
 */
const API_CONTRACT_VERSION = 1;

/** 控制台后端地址。dev 时 /api 与 SSE 都代理到这里。 */
const RELAY_ORIGIN = process.env['NFR_CONSOLE_ORIGIN'] ?? 'http://127.0.0.1:9443';

/**
 * 构建清单插件：产出 nomifun-build.json + ui-api-contract-version.txt。
 *
 * 这是从 nomifun-tauri 抄过来的：没有它，前端资源与后端契约的漂移
 * 只能表现为运行时怪异行为；有了它，中继可以在 index.html 之外读到一个
 * 明确的版本号并据此提示刷新。
 */
function buildManifest(): Plugin {
  return {
    name: 'nomirelay-build-manifest',
    apply: 'build',
    closeBundle() {
      const outDir = 'dist';
      const info = {
        name: 'nomirelay-console',
        api_contract_version: API_CONTRACT_VERSION,
        built_at: new Date().toISOString(),
      };
      writeFileSync(join(outDir, 'nomifun-build.json'), `${JSON.stringify(info, null, 2)}\n`);
      writeFileSync(join(outDir, 'ui-api-contract-version.txt'), `${API_CONTRACT_VERSION}\n`);
    },
  };
}

/**
 * 预压缩插件：为可压缩资源生成 .br 与 .gz。
 *
 * 刻意不在 Go 侧按请求 gzip：frp 就是那么做的，结果是把已经压缩过的
 * 资源再压一遍（纯 CPU 浪费）。预压缩 + 按 Accept-Encoding 协商是正确形状，
 * 而且交叉编译时每个目标平台的字节完全相同。
 */
function precompress(): Plugin {
  const compressible = /\.(js|css|html|svg|json|txt|map)$/;
  return {
    name: 'nomirelay-precompress',
    apply: 'build',
    enforce: 'post',
    closeBundle() {
      const walk = (dir: string): string[] =>
        readdirSync(dir).flatMap((entry) => {
          const full = join(dir, entry);
          return statSync(full).isDirectory() ? walk(full) : [full];
        });

      let count = 0;
      for (const file of walk('dist')) {
        if (!compressible.test(file)) continue;
        const raw = readFileSync(file);
        // 小文件压完往往更大，压它没有意义。
        if (raw.byteLength < 1024) continue;
        writeFileSync(`${file}.gz`, gzipSync(raw, { level: 9 }));
        writeFileSync(
          `${file}.br`,
          brotliCompressSync(raw, {
            params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 11 },
          }),
        );
        count += 1;
      }
      const hash = createHash('sha256').update(String(count)).digest('hex').slice(0, 8);
      this.info(`预压缩 ${count} 个资源（${hash}）`);
    },
  };
}

export default defineConfig(({ command }) => ({
  // 必须是绝对 base：SPA 有 /tunnels/:slug 这样的深链接，相对 base 会让
  // 资源 URL 相对深路径解析（/tunnels/assets/...）而全部 404。
  base: '/',
  plugins: [react(), UnoCSS(), buildManifest(), precompress()],
  resolve: {
    alias: { '@': new URL('./src', import.meta.url).pathname },
  },
  define: {
    __API_CONTRACT_VERSION__: String(API_CONTRACT_VERSION),
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    target: 'es2022',
    // 控制台是内网工具，sourcemap 对排障的价值高于体积代价。
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: {
          // Arco 一个包就占大头，单独切出来让它长期命中缓存。
          arco: ['@arco-design/web-react'],
          charts: ['uplot'],
        },
      },
    },
  },
  ...(command === 'serve'
    ? {
        server: {
          port: 5173,
          strictPort: true,
          proxy: {
            '/api': {
              target: RELAY_ORIGIN,
              // changeOrigin 必须是 false：控制台的会话 Cookie 是
              // host-only（__Host- 前缀甚至禁止 Domain 属性），改写 Host
              // 会让 Cookie 落在错误的 host 上，登录态直接消失。
              changeOrigin: false,
              // 这里刻意**没有** timeout / proxyTimeout：
              // /api/events 是一条长活 SSE 流，任何超时都会在传输中途把它切断，
              // 表现为图表每 N 秒空一次而没有任何报错。
              ws: false,
            },
          },
        },
      }
    : {}),
}));
