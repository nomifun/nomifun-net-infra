/**
 * 词汇锁 + 禁语门禁。
 *
 * 两件事：
 *
 * 1. **禁语**。硬性规则：绝不把随机高位端口当作安全措施展示 ——
 *    约 16 位熵，Shodan 级可枚举。所以「端口即密钥」及其任何等价说法
 *    不允许出现在 locale 文件里。这条是安全承诺，不是文案偏好。
 *
 * 2. **词汇锁**。同一个概念在整个产品里只有一个词：locale 文案、Go 日志、
 *    文档必须一致，否则用户会以为「代理端」和「客户端」是两个东西。
 *    每个概念给出规范词与禁用同义词。
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const LOCALES = new URL('../src/locales/', import.meta.url).pathname;

/** 禁语：出现即失败。 */
const FORBIDDEN = [
  // 「端口即密钥」及等价表述。
  '端口即密钥',
  '端口就是密钥',
  '端口当密钥',
  '端口作为密钥',
  '随机端口即安全',
  '随机高位端口足够安全',
  'port as a secret',
  'port is the secret',
  'port as the key',
  'security by obscurity',
  'security through obscurity',
  // 「跳过证书校验」也不该作为卖点出现（本工具不提供该选项）。
  'InsecureSkipVerify',
  '跳过证书校验',
];

/**
 * 词汇表：概念 → { canonical, banned }。
 * canonical 至少要出现一次（否则说明该概念在界面上根本没被命名）；
 * banned 一次都不许出现。
 */
const GLOSSARY = [
  { concept: 'Tunnel', canonical: '隧道', banned: ['代理条目', '转发条目'] },
  { concept: 'Agent', canonical: '代理端', banned: ['探针', '代理服务器', '节点端'] },
  { concept: 'Relay', canonical: '中继', banned: ['转发服务器', '中转服务器'] },
  { concept: 'Session', canonical: '会话', banned: ['连接会话'] },
  // 直通是规范词。「透传」在设计文档里出现过，但界面上只能有一个说法。
  { concept: 'passthrough', canonical: '直通', banned: ['透传'] },
  { concept: 'gateway', canonical: '网关', banned: ['代理网关'] },
  { concept: 'exposure', canonical: '暴露', banned: ['曝露'] },
  { concept: 'allow-list', canonical: '允许列表', banned: ['白名单'] },
  { concept: 'enrol token', canonical: '入网令牌', banned: ['注册令牌', '加入令牌'] },
  { concept: 'carrier rung', canonical: '承载梯级', banned: ['传输层级'] },
  { concept: 'datagram', canonical: '数据报', banned: ['数据包报文'] },
  { concept: 'loss', canonical: '丢包', banned: ['掉包'] },
];

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
  );
}

const files = walk(LOCALES).filter((f) => f.endsWith('.json'));
const problems = [];
const corpus = new Map();

for (const file of files) {
  const text = readFileSync(file, 'utf8');
  corpus.set(file, text);
  for (const bad of FORBIDDEN) {
    if (text.includes(bad)) problems.push(`${file}: 出现禁语「${bad}」`);
  }
  for (const g of GLOSSARY) {
    for (const bad of g.banned) {
      if (text.includes(bad)) {
        problems.push(`${file}: ${g.concept} 用了禁用同义词「${bad}」，规范词是「${g.canonical}」`);
      }
    }
  }
}

// canonical 覆盖检查只针对 zh-CN（英文侧没有对应的中文词）。
const zh = [...corpus.entries()]
  .filter(([f]) => f.includes('zh-CN'))
  .map(([, t]) => t)
  .join('\n');
for (const g of GLOSSARY) {
  if (!zh.includes(g.canonical)) {
    problems.push(`zh-CN 未出现规范词「${g.canonical}」（${g.concept}）—— 该概念在界面上没有名字`);
  }
}

if (problems.length > 0) {
  console.error('✗ 词汇锁失败：');
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`✓ 词汇锁（${FORBIDDEN.length} 条禁语 + ${GLOSSARY.length} 组词汇）`);
