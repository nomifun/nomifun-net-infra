import { ConfigProvider } from '@arco-design/web-react';
import { setCreateRoot } from '@arco-design/web-react/es/_util/react-dom';
import enUS from '@arco-design/web-react/es/locale/en-US';
import zhCN from '@arco-design/web-react/es/locale/zh-CN';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { useTranslation } from 'react-i18next';
import { BrowserRouter } from 'react-router-dom';
import { SWRConfig } from 'swr';

import App from './App';
import { swrConfig } from './api/hooks';
import './i18n';
import { applyTheme, getTheme } from './theme/theme';

import 'virtual:uno.css';
import '@arco-design/web-react/dist/css/arco.css';
import 'uplot/dist/uPlot.min.css';
import './styles/global.css';

/**
 * Arco 的 locale 跟着 i18next 走。
 *
 * 选 Arco 的第二条理由正是这个：zh-CN 是它的**源语言**，
 * `Pagination` 原生读作「共 N 条」，DatePicker 不是英文优先的手工翻译。
 */
function Root(): React.JSX.Element {
  const { i18n } = useTranslation();
  const locale = i18n.language === 'en-US' ? enUS : zhCN;
  return (
    <ConfigProvider locale={locale}>
      <SWRConfig value={swrConfig}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </SWRConfig>
    </ConfigProvider>
  );
}

/**
 * 把 createRoot 交给 Arco，**否则它所有命令式 API 静默失效**。
 *
 * Arco 的 Message / Notification / Modal.confirm 不在 React 树里，它们各自
 * 造一个容器 div 再单独渲染。渲染走 `_util/react-dom` 的兼容层，而那一层是
 * `createRoot = ReactDOM.createRoot` —— React 19 的 `react-dom` **不再导出**
 * 这个函数（它搬去了 `react-dom/client`），于是兼容层退回 `ReactDOM.render`，
 * 而那个函数在 React 19 里已经被删掉。
 *
 * 结果是**彻底静默**：容器 div 照样被 append 到 body 上，里面永远是空的。
 * 没有报错、没有警告、tsc 与 oxlint 都看不见 —— 表现是「点了按钮什么都没发生」。
 * 本仓有 32 处 Message.* 调用，在这一行之前**一个都没显示过**。
 * Arco 为此专门导出了 setCreateRoot（源码注释写着「react 19 的 index.js
 * 不会再导出 createRoot，必须从 react-dom/client 导入」）。
 *
 * 必须在任何组件渲染之前调用。回归判据在 scripts/browser-smoke.py ——
 * 这件事只有在真浏览器里点一下才看得见。
 */
setCreateRoot(createRoot);

// theme-boot.js 已经在首帧前把 html 属性设好了；这里补一次 body 属性，
// 覆盖「脚本被拦掉」或「body 尚未存在」这两种边界情况。
applyTheme(getTheme());

const container = document.getElementById('root');
if (!container) throw new Error('#root not found');

createRoot(container).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
