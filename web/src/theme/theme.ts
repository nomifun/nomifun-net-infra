/**
 * 明暗主题。
 *
 * Arco 的整套 token 挂在 body[arco-theme=dark] 上，所以切换主题只需要翻一个属性，
 * 不需要为每个组件手写明暗两份样式。首帧前的恢复在 public/theme-boot.js 里
 * （必须是外部脚本：控制台 CSP 没放开 inline script）。
 *
 * uPlot 例外：它需要**字面颜色**而不是 CSS 变量，所以主题变化时图表必须
 * 重新从 getComputedStyle 读一遍描边色 —— 这就是这里要暴露订阅的原因。
 */

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'nfr_theme';

const listeners = new Set<() => void>();

function read(): Theme {
  const attr = document.documentElement.getAttribute('data-theme');
  return attr === 'dark' ? 'dark' : 'light';
}

let current: Theme = read();

export function getTheme(): Theme {
  return current;
}

export function applyTheme(next: Theme): void {
  current = next;
  document.documentElement.setAttribute('data-theme', next);
  document.documentElement.style.colorScheme = next;
  // 空字符串而不是移除属性：Arco 只检查属性值，空值就是浅色。
  document.body.setAttribute('arco-theme', next === 'dark' ? 'dark' : '');
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    /* 忽略 */
  }
  for (const fn of listeners) fn();
}

export function toggleTheme(): void {
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

export function subscribeTheme(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * 读一个 CSS 变量的计算值。给 uPlot 用。
 *
 * 变量在 :root 上，所以从 documentElement 读；拿不到时返回兜底色，
 * 否则 uPlot 会画出透明线条而且不报错。
 */
export function cssVar(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v === '' ? fallback : v;
}

/** Arco 的语义色是 `--primary-6: 22,93,255` 这种裸 RGB 三元组，要包一层。 */
export function rgbVar(name: string, fallback: string): string {
  const v = cssVar(name, '');
  return v === '' ? fallback : `rgb(${v})`;
}
