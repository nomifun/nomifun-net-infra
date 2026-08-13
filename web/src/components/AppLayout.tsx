import { Alert, Button, Tooltip } from '@arco-design/web-react';
import { useEffect, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { NavLink, useNavigate } from 'react-router-dom';

import { useStreamHealth } from '@/api/hooks';
import { setLang, type Lang } from '@/i18n';
import { getTheme, subscribeTheme, toggleTheme } from '@/theme/theme';

interface Props {
  username?: string;
  onLogout: () => void;
  children: React.ReactNode;
}

const NAV = [
  { to: '/', key: 'overview' },
  { to: '/tunnels', key: 'tunnels' },
  { to: '/agents', key: 'agents' },
  { to: '/media', key: 'media' },
  { to: '/diagnostics', key: 'diagnostics' },
  { to: '/settings', key: 'settings' },
] as const;

/** 流健康点。中继采样而非排队，丢帧数是**它保护数据面的证据**，不是错误。 */
function StreamDot(): React.JSX.Element {
  const { t } = useTranslation('common');
  const health = useStreamHealth();

  const color =
    health.phase === 'open'
      ? health.droppedFrames > 0
        ? 'rgb(var(--warning-6))'
        : 'rgb(var(--success-6))'
      : health.phase === 'closed'
        ? 'rgb(var(--danger-6))'
        : 'var(--color-text-4)';

  const phaseLabel = t(`stream.${health.phase}` as 'stream.open');
  const tip =
    health.droppedFrames > 0
      ? `${t('stream.dropped', { count: health.droppedFrames })} — ${t('stream.droppedTip')}`
      : phaseLabel;

  return (
    <Tooltip content={tip}>
      <span className="inline-flex items-center gap-5px text-12px text-3">
        <span
          className="inline-block h-8px w-8px rounded-full"
          style={{ background: color }}
          aria-hidden="true"
        />
        {t('stream.label')} {phaseLabel}
      </span>
    </Tooltip>
  );
}

/**
 * 契约版本不一致的横幅。
 *
 * # 为什么必须真的显示出来
 *
 * contractMismatch 原本被算出来（stream.ts 的 onHello 里比对
 * api_contract_version）然后**丢掉** —— 没有任何一处渲染它。
 * 于是中继升级之后、浏览器还挂着旧前端的那段时间里，用户看到的是
 * 一个「看起来正常但数字不对」的界面：新字段读不到、枚举值认不出，
 * 而所有校验都通过（后端宽容、前端类型也宽容）。
 *
 * 这正是最难自查的一类故障 —— 用户不会想到「我该刷新一下」。
 * 所以它必须是一条挡在内容之上的、说清该做什么的提示。
 */
function ContractBanner(): React.JSX.Element | null {
  const { t } = useTranslation('common');
  const health = useStreamHealth();
  if (!health.contractMismatch) return null;
  return (
    <Alert
      type="warning"
      className="mx-20px mt-12px"
      content={t('stream.contractMismatch')}
      action={
        <Button size="small" onClick={() => window.location.reload()}>
          {t('action.reload')}
        </Button>
      }
    />
  );
}

/**
 * 全局外壳：顶部导航 + 主题 / 语言 / 流健康。
 *
 * 快捷键 `/` 搜索、`c` 新建（dossier 11「Premium details」）。绑定在这里而不是
 * 各页面各绑一次，是为了保证行为一致 —— 而且在输入框里必须不触发，
 * 否则用户打字时会莫名跳页。
 */
export default function AppLayout({ username, onLogout, children }: Props): React.JSX.Element {
  const { t, i18n } = useTranslation('common');
  const navigate = useNavigate();
  // 主题按钮的文字必须跟着主题走，所以订阅而不是直接读一次。
  const theme = useSyncExternalStore(subscribeTheme, getTheme);

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      const el = e.target as HTMLElement | null;
      const typing =
        el instanceof HTMLInputElement ||
        el instanceof HTMLTextAreaElement ||
        el?.isContentEditable === true;
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === '/') {
        const search = document.querySelector<HTMLInputElement>('[data-nfr-search] input');
        if (search) {
          e.preventDefault();
          search.focus();
        }
      } else if (e.key === 'c') {
        e.preventDefault();
        void navigate('/tunnels/new');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate]);

  const nextLang: Lang = i18n.language === 'en-US' ? 'zh-CN' : 'en-US';

  return (
    <div className="min-h-100vh flex flex-col">
      <header className="flex items-center gap-16px border-b border-line-2 bg-2 px-20px py-10px">
        <div className="flex items-baseline gap-8px">
          <span className="text-16px font-semibold">{t('app.name')}</span>
          <span className="text-12px text-3">{t('app.subtitle')}</span>
        </div>
        <nav className="flex flex-1 items-center gap-4px">
          {NAV.map((item) => (
            <NavLink
              key={item.key}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `rounded-3px px-10px py-4px text-14px ${
                  isActive ? 'bg-fill-2 text-1 font-medium' : 'text-2'
                }`
              }
            >
              {t(`nav.${item.key}` as 'nav.overview')}
            </NavLink>
          ))}
        </nav>
        <StreamDot />
        <Tooltip content={t('theme.toggle')}>
          <Button size="mini" type="text" onClick={() => toggleTheme()}>
            {theme === 'dark' ? t('theme.dark') : t('theme.light')}
          </Button>
        </Tooltip>
        <Tooltip content={t('lang.toggle')}>
          <Button size="mini" type="text" onClick={() => setLang(nextLang)}>
            {i18n.language === 'en-US' ? t('lang.enShort') : t('lang.zhShort')}
          </Button>
        </Tooltip>
        {username ? (
          <Button size="mini" type="text" onClick={onLogout}>
            {t('action.logout')}
          </Button>
        ) : null}
      </header>
      <ContractBanner />
      <main className="flex-1 px-20px py-16px">{children}</main>
    </div>
  );
}
