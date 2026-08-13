/**
 * locale key 对齐门禁。
 *
 * zh-CN 是**源语言**，en-US 是派生译文。这个脚本断言两边键集合逐一对应：
 * 少一条译文是构建失败，而不是界面上一个 [missing key]。
 * 顺带查两件事：
 *   - 插值占位符（{{x}}）在两个语言里必须一致，否则翻译会静默丢参数；
 *   - 不允许空字符串值（除了显式白名单，例如英文里不需要的量词单位）。
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../src/locales/', import.meta.url).pathname;
const SOURCE = 'zh-CN';
const TARGETS = ['en-US'];

/** 允许为空的键（语言差异导致的合法空值）。 */
const ALLOW_EMPTY = new Set(['common:unit.count']);

function flatten(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix === '' ? k : `${prefix}.${k}`;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out.set(key, v);
  }
  return out;
}

function load(lang) {
  const dir = join(ROOT, lang);
  const out = new Map();
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    const ns = file.replace(/\.json$/, '');
    const json = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    for (const [k, v] of flatten(json, '', new Map())) out.set(`${ns}:${k}`, v);
  }
  return out;
}

function placeholders(value) {
  return new Set([...String(value).matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).toSorted());
}

const problems = [];
const source = load(SOURCE);

/**
 * 界面**不渲染 Markdown**，locale 值里的 `**强调**` 会被原样显示成星号。
 *
 * 这条是真浏览器冒烟抓出来的：设置页上写着「应用后会被**删除**」，
 * 而屏幕上就是那六个字符加四个星号。写文档时的肌肉记忆很容易带进来，
 * 而 tsc / oxlint / locale 对齐原本一个都看不见 —— 只有把页面渲染出来
 * 用眼睛看才发现。要强调就用 <strong> 或颜色，别在文案里放标记。
 */
function markdownEmphasis(value) {
  return /\*\*|(?:^|\s)_[^\s_][^_]*_(?:\s|$)|`[^`]+`/.test(String(value));
}

for (const [key, value] of source) {
  if (typeof value !== 'string') problems.push(`${SOURCE} ${key}: 值不是字符串`);
  else if (value.trim() === '' && !ALLOW_EMPTY.has(key)) problems.push(`${SOURCE} ${key}: 空值`);
}

for (const lang of [SOURCE, ...TARGETS]) {
  for (const [key, value] of load(lang)) {
    if (typeof value === 'string' && markdownEmphasis(value)) {
      problems.push(
        `${lang} ${key}: 文案里有 Markdown 标记（界面不渲染它，会显示成字面的 ** / _ / \`）`,
      );
    }
  }
}

for (const lang of TARGETS) {
  const target = load(lang);
  for (const key of source.keys()) {
    if (!target.has(key)) {
      problems.push(`${lang} 缺键：${key}`);
      continue;
    }
    const a = placeholders(source.get(key));
    const b = placeholders(target.get(key));
    if ([...a].join(',') !== [...b].join(',')) {
      problems.push(`${lang} ${key}: 插值占位符不一致（${[...a]} vs ${[...b]}）`);
    }
    if (String(target.get(key)).trim() === '' && !ALLOW_EMPTY.has(key)) {
      problems.push(`${lang} ${key}: 空值`);
    }
  }
  for (const key of target.keys()) {
    if (!source.has(key)) problems.push(`${lang} 多出键（源语言没有）：${key}`);
  }
}

if (problems.length > 0) {
  console.error('✗ locale 对齐失败：');
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`✓ locale 对齐（${source.size} 条键 × ${TARGETS.length + 1} 语言）`);
