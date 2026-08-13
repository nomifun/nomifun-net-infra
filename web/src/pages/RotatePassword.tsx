import { Button, Card, Input, Message } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { api } from '@/api/client';

interface Props {
  onDone: () => void;
}

/**
 * 首次登录强制改密。
 *
 * 这一屏不能跳过：初始密码是自动生成并落盘的，它同时存在于文件系统里，
 * 不轮换就等于把一份长期凭据留在磁盘上。
 */
export default function RotatePassword({ onDone }: Props): React.JSX.Element {
  const { t } = useTranslation(['auth', 'settings', 'errors']);
  const [current, setCurrent] = useState('');
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = (): void => {
    if (pw.length < 12) {
      Message.warning(t('auth:rotate.tooShort'));
      return;
    }
    if (pw !== again) {
      Message.warning(t('auth:rotate.mismatch'));
      return;
    }
    setBusy(true);
    // 改密必须验旧密码：否则一个被盗的会话 Cookie 就能永久锁定账号。
    void api
      .changePassword(current, pw)
      .then(() => onDone())
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  return (
    <div className="min-h-100vh flex items-center justify-center">
      <Card className="w-380px" title={t('auth:rotate.title')}>
        <div className="flex flex-col gap-12px">
          <div className="muted-note">{t('settings:password.mustRotate')}</div>
          <Input.Password
            value={current}
            onChange={setCurrent}
            placeholder={t('auth:rotate.current')}
          />
          <Input.Password value={pw} onChange={setPw} placeholder={t('auth:rotate.new')} />
          <Input.Password
            value={again}
            onChange={setAgain}
            placeholder={t('auth:rotate.repeat')}
            onPressEnter={submit}
          />
          <Button type="primary" loading={busy} onClick={submit}>
            {t('auth:rotate.submit')}
          </Button>
        </div>
      </Card>
    </div>
  );
}
