import { Button, Card, Input, Message } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, api } from '@/api/client';

interface Props {
  onLoggedIn: () => void;
}

export default function Login({ onLoggedIn }: Props): React.JSX.Element {
  const { t } = useTranslation(['auth', 'common', 'errors']);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = (): void => {
    if (username === '' || password === '') {
      Message.warning(t('auth:login.empty'));
      return;
    }
    setBusy(true);
    void api
      .login(username, password)
      .then(() => onLoggedIn())
      .catch((err: unknown) => {
        Message.error(
          err instanceof ApiError && err.status === 401 ? t('auth:login.failed') : t('errors:generic'),
        );
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="min-h-100vh flex items-center justify-center">
      <Card className="w-360px" title={t('auth:login.title')}>
        <div className="flex flex-col gap-12px">
          <Input
            value={username}
            onChange={setUsername}
            placeholder={t('auth:login.username')}
            onPressEnter={submit}
          />
          <Input.Password
            value={password}
            onChange={setPassword}
            placeholder={t('auth:login.password')}
            onPressEnter={submit}
          />
          <Button type="primary" loading={busy} onClick={submit}>
            {t('auth:login.submit')}
          </Button>
        </div>
      </Card>
    </div>
  );
}
