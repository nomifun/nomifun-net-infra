/**
 * i18n。**zh-CN 是源语言**，en-US 是派生译文。
 *
 * 两条纪律：
 * 1. 任何面向用户的字符串都必须有 zh-CN 源值，JSX 里不写字面中文
 *    （scripts/check-no-hardcoded-cjk.mjs 会守住这一条）。
 * 2. zh-CN 的键集合就是类型：漏一条 en-US 翻译是 typecheck 失败，
 *    不是运行时才发现的 [missing key]（见 i18next.d.ts + scripts/check-locales.mjs）。
 */

import i18next from 'i18next';
import { initReactI18next } from 'react-i18next';

import zhAgents from '../locales/zh-CN/agents.json';
import zhAuth from '../locales/zh-CN/auth.json';
import zhCommon from '../locales/zh-CN/common.json';
import zhDiagnostics from '../locales/zh-CN/diagnostics.json';
import zhDesktop from '../locales/zh-CN/desktop.json';
import zhErrors from '../locales/zh-CN/errors.json';
import zhMedia from '../locales/zh-CN/media.json';
import zhOverview from '../locales/zh-CN/overview.json';
import zhSettings from '../locales/zh-CN/settings.json';
import zhSetup from '../locales/zh-CN/setup.json';
import zhTunnelDetail from '../locales/zh-CN/tunnelDetail.json';
import zhTunnels from '../locales/zh-CN/tunnels.json';

import enAgents from '../locales/en-US/agents.json';
import enAuth from '../locales/en-US/auth.json';
import enCommon from '../locales/en-US/common.json';
import enDiagnostics from '../locales/en-US/diagnostics.json';
import enDesktop from '../locales/en-US/desktop.json';
import enErrors from '../locales/en-US/errors.json';
import enMedia from '../locales/en-US/media.json';
import enOverview from '../locales/en-US/overview.json';
import enSettings from '../locales/en-US/settings.json';
import enSetup from '../locales/en-US/setup.json';
import enTunnelDetail from '../locales/en-US/tunnelDetail.json';
import enTunnels from '../locales/en-US/tunnels.json';

export const defaultNS = 'common';

export const resources = {
  'zh-CN': {
    common: zhCommon,
    overview: zhOverview,
    tunnels: zhTunnels,
    tunnelDetail: zhTunnelDetail,
    agents: zhAgents,
    setup: zhSetup,
    diagnostics: zhDiagnostics,
    desktop: zhDesktop,
    settings: zhSettings,
    media: zhMedia,
    errors: zhErrors,
    auth: zhAuth,
  },
  'en-US': {
    common: enCommon,
    overview: enOverview,
    tunnels: enTunnels,
    tunnelDetail: enTunnelDetail,
    agents: enAgents,
    setup: enSetup,
    diagnostics: enDiagnostics,
    desktop: enDesktop,
    settings: enSettings,
    media: enMedia,
    errors: enErrors,
    auth: enAuth,
  },
} as const;

export type Lang = keyof typeof resources;

const STORAGE_KEY = 'nfr_lang';

export function storedLang(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'zh-CN' || v === 'en-US') return v;
  } catch {
    /* localStorage 被禁用 */
  }

  // 无存储偏好时**无条件默认 zh-CN**，不按浏览器 locale 猜。
  //
  // 规格要求「zh-CN 优先，en-US 派生」。第一版写的是
  // `navigator.language.startsWith('zh') ? 'zh-CN' : 'en-US'`，
  // 结果任何非中文 locale 的浏览器上界面全是英文 —— 而中文用户用
  // 英文 locale 的浏览器极其常见（多数开发者都是）。
  // 这是浏览器冒烟测试抓出来的：无头 Firefox 报 en-US，界面就变英文了。
  //
  // 第二版改成「全是英文偏好才用 en-US」，仍然会让上述那位中文用户看到英文。
  // 所以最终结论是：默认就是源语言 zh-CN，英文用户在界面右上角
  // （首启页也有）切一次，选择存进 localStorage 后不再询问。
  return 'zh-CN';
}

export function setLang(lang: Lang): void {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    /* 忽略 */
  }
  void i18next.changeLanguage(lang);
}

void i18next.use(initReactI18next).init({
  resources,
  lng: storedLang(),
  // 源语言即兜底语言：zh-CN 永远不会 missing。
  fallbackLng: 'zh-CN',
  defaultNS,
  ns: Object.keys(resources['zh-CN']),
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18next;
