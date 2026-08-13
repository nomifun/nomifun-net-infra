import { defineConfig, presetMini, presetWind3, transformerDirectives, transformerVariantGroup } from 'unocss';
import { presetExtra } from 'unocss-preset-extra';

/**
 * Arco CSS 变量 ↔ UnoCSS token 桥。
 *
 * 设计前提：**Arco 的 CSS 变量就是设计 token**，UnoCSS 只负责布局与间距。
 * 这样暗色模式只需要翻 body[arco-theme=dark] 一个属性，所有颜色自动重新解析；
 * 若改用 Tailwind 的 dark: 变体，就得永远手写每一对明暗值。
 *
 * ⚠️ 从 nomifun-tauri 继承下来的两个坑（ui/src/renderer/styles/MIGRATION.md）：
 *
 * 1. 键名就是类名的后半段，没有 `bg` 这一层：`bg-1` 对，`bg-bg-1` 会去查一个
 *    名叫「bg-1」的颜色，查不到就产出 0 条 CSS（元素完全透明，且不报错）。
 * 2. 数字键会**劫持带方向的边框类**：`border-b-2` 不是「下边框 2px」，
 *    而是 `border-bottom-color: var(--color-bg-2)`（方向先被解析掉，
 *    再拿 `2` 来查颜色）。宽度必须写 `border-b-2px`。
 */
const textColors = {
  // Arco 官方文字色阶：1 最强，4 最弱（禁用）。
  1: 'var(--color-text-1)',
  2: 'var(--color-text-2)',
  3: 'var(--color-text-3)',
  4: 'var(--color-text-4)',
};

const semanticColors = {
  primary: 'rgb(var(--primary-6))',
  success: 'rgb(var(--success-6))',
  warning: 'rgb(var(--warning-6))',
  danger: 'rgb(var(--danger-6))',
  link: 'rgb(var(--link-6))',
};

const backgroundColors = {
  base: 'var(--color-bg-1)',
  1: 'var(--color-bg-1)',
  2: 'var(--color-bg-2)',
  3: 'var(--color-bg-3)',
  4: 'var(--color-bg-4)',
  5: 'var(--color-bg-5)',
  white: 'var(--color-bg-white)',
  hover: 'var(--color-fill-2)',
  active: 'var(--color-fill-3)',
};

const borderColors = {
  'line-1': 'var(--color-border-1)',
  'line-2': 'var(--color-border-2)',
  'line-3': 'var(--color-border-3)',
  'line-4': 'var(--color-border-4)',
};

export default defineConfig({
  presets: [presetMini(), presetExtra(), presetWind3()],
  transformers: [transformerVariantGroup(), transformerDirectives({ enforce: 'pre' })],
  content: {
    pipeline: {
      // 用正则而不是 glob：glob 是相对 Vite root 解析的，一旦 root 变了就静默失效。
      include: [/\.[jt]sx?($|\?)/, /\.css($|\?)/],
      exclude: [/[\\/]node_modules[\\/]/, /\.html($|\?)/],
    },
  },
  theme: {
    colors: {
      ...semanticColors,
      ...backgroundColors,
      ...borderColors,
      // text-1..4 走下面的自定义规则，不放进 colors，避免与 border-t-1 之类冲突。
    },
    fontFamily: {
      mono: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
    },
  },
  rules: [
    // Arco 文字色阶。放在 rules 里而不是 theme.colors，是为了避开上面第 2 条方向坑。
    [/^text-([1-4])$/, ([, d]: string[]) => ({ color: textColors[Number(d) as 1 | 2 | 3 | 4] })],
    [/^bg-fill-([1-4])$/, ([, d]: string[]) => ({ 'background-color': `var(--color-fill-${d})` })],
  ],
  shortcuts: {
    // 一行答完「我从哪进，落到哪」的端点单元格用到的排版。
    'endpoint-row': 'flex items-center gap-1 font-mono text-13px leading-tight',
    'tile-card': 'rounded-4px border border-line-2 bg-2 px-16px py-12px',
    'muted-note': 'text-3 text-12px leading-relaxed',
  },
});
