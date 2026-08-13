/*
 * 首帧前恢复主题。两个属性都要设：
 *   html[data-theme]  —— 我们自己的样式与 UnoCSS 变体读它
 *   body[arco-theme]  —— Arco 全部 token 靠它重新解析（一个属性换掉整套颜色）
 * 顺序上 body 还不存在，所以用 documentElement 记下来，DOMContentLoaded 前
 * 由 main.tsx 再补一次 body 属性；但这里能先把 html 属性与背景色定死，
 * 已经足够消除闪白。
 */
(function () {
  try {
    var stored = localStorage.getItem('nfr_theme');
    var theme =
      stored === 'dark' || stored === 'light'
        ? stored
        : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.colorScheme = theme;
    document.addEventListener('DOMContentLoaded', function () {
      document.body.setAttribute('arco-theme', theme === 'dark' ? 'dark' : '');
    });
    if (document.body) {
      document.body.setAttribute('arco-theme', theme === 'dark' ? 'dark' : '');
    }
  } catch (e) {
    /* localStorage 被禁用时静默退回浅色 */
  }
})();
