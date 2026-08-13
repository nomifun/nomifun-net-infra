import type { defaultNS, resources } from './index';

/**
 * 把 zh-CN 的键集合注册成 i18next 的类型。
 *
 * 这是 dossier 11 里「最高价值」的那一条：漏一条翻译变成 **typecheck 失败**，
 * 而不是等到界面上出现一个 [missing key]。维护者先写中文，所以这里
 * 用 zh-CN 当类型源比反过来更有用。
 */
declare module 'i18next' {
  interface CustomTypeOptions {
    defaultNS: typeof defaultNS;
    resources: (typeof resources)['zh-CN'];
    returnNull: false;
  }
}
