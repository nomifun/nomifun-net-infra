import { Button, Result, Skeleton } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom';

import { ApiError, api } from './api/client';
import { useIdentity, useSetupState } from './api/hooks';
import AppLayout from './components/AppLayout';
import Agents from './pages/Agents';
import Diagnostics from './pages/Diagnostics';
import DesktopConnect from './pages/DesktopConnect';
import Login from './pages/Login';
import MediaRelay from './pages/MediaRelay';
import Overview from './pages/Overview';
import RotatePassword from './pages/RotatePassword';
import Settings from './pages/Settings';
import Setup from './pages/Setup';
import TunnelDetail from './pages/TunnelDetail';
import TunnelWizard from './pages/TunnelWizard';
import Tunnels from './pages/Tunnels';

/**
 * 路由与门禁。
 *
 * 顺序即语义，且刻意与 spec §8.2 对齐：
 *   未配置 → /setup（任何路径都落到这里）
 *   未登录 → /login
 *   首登未改密 → 强制改密，别的什么都不给做
 * frp 的反面教材是「凭据双空即放行一切」，所以这里没有任何一条分支
 * 能在未认证状态下渲染控制台内容。
 */
export default function App(): React.JSX.Element {
  const { t } = useTranslation(['common', 'errors']);
  const setup = useSetupState();
  const identity = useIdentity();
  const navigate = useNavigate();

  const reload = (): void => {
    void setup.mutate();
    void identity.mutate();
  };

  if (setup.isLoading) {
    return (
      <div className="p-24px">
        <Skeleton animation text={{ rows: 6 }} />
      </div>
    );
  }

  // /api/setup 是不需要鉴权的，所以它失败就意味着中继根本连不上。
  if (setup.error) {
    return (
      <Result
        status="error"
        title={t('errors:network')}
        extra={
          <Button type="primary" onClick={reload}>
            {t('common:action.retry')}
          </Button>
        }
      />
    );
  }

  if (setup.data?.needs_setup === true) {
    return (
      <Routes>
        <Route path="/setup" element={<Setup onDone={reload} />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    );
  }

  if (identity.isLoading) {
    return (
      <div className="p-24px">
        <Skeleton animation text={{ rows: 4 }} />
      </div>
    );
  }

  const unauth =
    identity.error instanceof ApiError ? identity.error.isUnauthenticated : identity.error !== undefined;
  if (unauth || !identity.data) {
    return <Login onLoggedIn={reload} />;
  }

  if (identity.data.must_rotate === true) {
    return <RotatePassword onDone={reload} />;
  }

  const logout = (): void => {
    void api.logout().finally(() => {
      reload();
      void navigate('/');
    });
  };

  return (
    <AppLayout username={identity.data.username} onLogout={logout}>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/tunnels" element={<Tunnels />} />
        <Route path="/tunnels/new" element={<TunnelWizard />} />
        <Route path="/tunnels/:slug" element={<TunnelDetail />} />
        <Route path="/tunnels/:slug/edit" element={<TunnelWizard />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/desktop-connect" element={<DesktopConnect />} />
        <Route path="/media" element={<MediaRelay />} />
        <Route path="/diagnostics" element={<Diagnostics />} />
        <Route path="/settings" element={<Settings />} />
        {/* 首启完成后再访问 /setup 没有意义，直接回概览。 */}
        <Route path="/setup" element={<Navigate to="/" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}
