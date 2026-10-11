/**
 * 禁止 JSX 里出现硬编码中文。
 *
 * 「所有面向用户的字符串都过 i18next」这条纪律靠人盯是守不住的，
 * 所以机械化：扫 src/**\/*.tsx（以及 .ts），剥掉注释与字符串里的
 * i18n key，剩下的 CJK 字符一律报错。
 *
 * 注释里的中文是**鼓励**的（本仓库的注释就是中文），所以必须先剥注释。
 *
 * # 豁免
 *
 * 极少数字符串**必须**用目标语言的原文硬编码 —— 典型是语言切换器的标签：
 * 一个显示「English」的按钮不能翻译成中文，一个显示「中文」的按钮也不能
 * 翻译成英文，否则用户在看不懂的界面里找不到切换入口。
 *
 * 这类行用 `// i18n-exempt: 理由` 显式豁免，写在**该行行尾或紧邻的上一行**
 * （上一行更符合本仓库中文注释常常独占一行的写法）。**必须写理由** ——
 * 一个无需解释的豁免机制迟早会被当成绕过检查的后门。
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const CJK = /[一-鿿㐀-䶿＀-￯　-〿]/;

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
  );
}

/** 剥掉 // 与 /* *\/ 注释。够用：本项目不在字符串里放注释标记。 */
function stripComments(src) {
  let out = '';
  let i = 0;
  let inLine = false;
  let inBlock = false;
  let quote = '';
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (inLine) {
      if (c === '\n') {
        inLine = false;
        out += c;
      }
      i += 1;
      continue;
    }
    if (inBlock) {
      if (c === '*' && n === '/') {
        inBlock = false;
        i += 2;
        continue;
      }
      if (c === '\n') out += c;
      i += 1;
      continue;
    }
    if (quote !== '') {
      out += c;
      if (c === '\\') {
        out += n ?? '';
        i += 2;
        continue;
      }
      if (c === quote) quote = '';
      i += 1;
      continue;
    }
    if (c === '/' && n === '/') {
      inLine = true;
      i += 2;
      continue;
    }
    if (c === '/' && n === '*') {
      inBlock = true;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      out += c;
      i += 1;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

const problems = [];
let exempted = 0;
const files = walk(SRC).filter((f) => /\.tsx?$/.test(f) && !f.includes('/locales/'));

/** 豁免标记必须带理由：`// i18n-exempt: 语言切换器标签需用目标语言原文` */
const EXEMPT = /\/\/\s*i18n-exempt:\s*\S/;

for (const file of files) {
  const raw = readFileSync(file, 'utf8').split('\n');
  const stripped = stripComments(readFileSync(file, 'utf8'));
  stripped.split('\n').forEach((line, idx) => {
    if (!CJK.test(line)) return;
    // 豁免看**原始行**（注释已被剥掉，所以标记只能从原文里找）：
    // 支持行尾标记，也支持紧邻上一行的独立注释行 —— 后者是本仓库
    // 中文注释的常见写法，只认行尾会让豁免机制在实践中形同虚设。
    if (EXEMPT.test(raw[idx] ?? '') || EXEMPT.test(raw[idx - 1] ?? '')) {
      exempted += 1;
      return;
    }
    problems.push(`${file}:${idx + 1}: 硬编码中文 → 改走 i18next：${line.trim().slice(0, 80)}`);
  });
}

if (problems.length > 0) {
  console.error('✗ 发现硬编码中文（面向用户的字符串必须走 locale 文件）：');
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(
  `✓ 无硬编码中文（扫了 ${files.length} 个文件` +
    (exempted > 0 ? `，${exempted} 处显式豁免` : '') +
    '）',
);
