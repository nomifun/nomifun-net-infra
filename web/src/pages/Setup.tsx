import { Button, Card, Input, Message, Steps } from '@arco-design/web-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { setLang, storedLang, type Lang } from '@/i18n';

import { api } from '@/api/client';
import { useSnapshot, useStreamHealth } from '@/api/hooks';
import CopyBlock from '@/components/CopyBlock';
import { InstallPanel } from '@/pages/Agents';
import type { EnrolToken } from '@/api/types';
import { TEMPLATES } from '@/utils/templates';

interface Props {
  onDone: () => void;
}

/**
 * 生成 24 字符密码。
 *
 * 用 crypto.getRandomValues 而不是 Math.random；字符集去掉了形近字符
 * （0/O、1/l/I），因为这个密码会被人**抄一遍**。
 */
function generatePassword(): string {
  const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+';
  const bytes = new Uint32Array(24);
  crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length] ?? 'x';
  return out;
}

/**
 * 首启向导。目标：零到一条可用隧道，两分钟内。
 *
 * 与 frp 的对照（spec §8.2）：frp 的 `webServer.port = 7500` 一行就能得到一个
 * 监听 0.0.0.0 的**无鉴权**控制台，README 还教 admin/admin。这里第一步就是
 * 创建管理员，且密码只显示一次、拒绝空值。
 */
export default function Setup({ onDone }: Props): React.JSX.Element {
  const { t } = useTranslation(['setup', 'agents', 'tunnels', 'common', 'errors']);
  const { data: snapshot } = useSnapshot();
  useStreamHealth();

  const [step, setStep] = useState(0);
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');

  // 下一个可切换的语言。zh-CN 是源语言与默认值，所以按钮通常显示 English。
  const current: Lang = storedLang();
  const nextLang: Lang = current === 'zh-CN' ? 'en-US' : 'zh-CN';
  // i18n-exempt: 语言切换器标签必须用目标语言原文，否则用户在看不懂的界面里找不到入口
  const nextLangLabel = nextLang === 'en-US' ? 'English' : '中文';
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState<EnrolToken | null>(null);
  const [withAgent, setWithAgent] = useState<boolean | null>(null);

  const onlineAgent = useMemo(
    () => (snapshot?.agents ?? []).find((a) => a.online && !a.revoked),
    [snapshot],
  );

  // 页面**在事件流上等**：agent 一上线就自己往下走，不需要用户点刷新。
  useEffect(() => {
    if (step === 2 && withAgent === true && onlineAgent) setStep(3);
  }, [step, withAgent, onlineAgent]);

  const createAdmin = (): void => {
    if (username === '' || password === '') {
      Message.warning(t('setup:admin.empty'));
      return;
    }
    setBusy(true);
    void api
      .setup(username, password)
      .then(() => setStep(1))
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  const issueToken = (): void => {
    setBusy(true);
    setWithAgent(true);
    void api
      .issueEnrolToken('setup')
      .then((tk) => {
        setToken(tk);
        setStep(2);
      })
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  return (
    <div className="mx-auto max-w-760px flex flex-col gap-16px py-32px">
      {/* 首启页必须有语言切换器：默认语言是 zh-CN，
          没有切换入口的话英文用户会被困在看不懂的界面里。
          正常界面的切换器在 AppLayout 里，但首启不走那个布局。 */}
      <div className="flex justify-end">
        <Button size="mini" type="text" onClick={() => setLang(nextLang)}>
          {nextLangLabel}
        </Button>
      </div>
      <div>
        <div className="text-20px font-semibold">{t('setup:title')}</div>
        <div className="muted-note">{t('setup:subtitle')}</div>
      </div>

      <Steps current={step + 1} size="small">
        <Steps.Step title={t('setup:step.admin')} />
        <Steps.Step title={t('setup:step.address')} />
        <Steps.Step title={t('setup:step.attach')} />
        <Steps.Step title={t('setup:step.done')} />
      </Steps>

      {step === 0 ? (
        <Card size="small" bordered>
          <div className="flex flex-col gap-12px">
            <label className="flex flex-col gap-4px">
              <span className="text-13px">{t('setup:admin.username')}</span>
              <Input
                value={username}
                onChange={setUsername}
                placeholder={t('setup:admin.usernamePlaceholder')}
              />
            </label>
            <label className="flex flex-col gap-4px">
              <span className="text-13px">{t('setup:admin.password')}</span>
              {/* 用 Input.Password 而不是 Input：默认遮蔽、带可见性切换。
                  浏览器冒烟测试发现这里原本是普通 Input，
                  密码会明文显示在屏幕上。 */}
              <Input.Password value={password} onChange={setPassword} />
            </label>
            <div className="flex items-center gap-8px">
              <Button size="small" onClick={() => setPassword(generatePassword())}>
                {t('setup:admin.generate')}
              </Button>
              <span className="muted-note">{t('setup:admin.rejectWeak')}</span>
            </div>
            {password === '' ? null : (
              <CopyBlock text={password} label={t('setup:admin.password')} note={t('setup:admin.showOnce')} />
            )}
            <Button type="primary" loading={busy} onClick={createAdmin}>
              {t('setup:admin.submit')}
            </Button>
          </div>
        </Card>
      ) : null}

      {step === 1 ? (
        <Card size="small" bordered>
          <div className="flex flex-col gap-12px">
            {/*
              中继目前不上报 STUN 自测到的公网地址（没有对应端点），
              所以这里显示浏览器实际访问到的 host，并如实说明它可能不是外网地址。
              绝不编一个地址出来让用户去「确认」。
            */}
            <div className="nfr-mono text-14px">
              {t('setup:address.detected', { addr: window.location.host })}
            </div>
            <div className="muted-note">{t('setup:address.unknown')}</div>
            <div className="muted-note">{t('setup:address.stunNote')}</div>
            <Button type="primary" onClick={() => setStep(2)}>
              {t('setup:address.confirm')}
            </Button>
          </div>
        </Card>
      ) : null}

      {step === 2 ? (
        <div className="flex flex-col gap-12px">
          <div className="text-15px font-medium">{t('setup:attach.title')}</div>
          <div className="flex flex-col gap-12px sm:flex-row">
            <Card size="small" bordered className="flex-1">
              <div className="font-medium">{t('setup:attach.withAgent.title')}</div>
              <div className="muted-note mt-4px">{t('setup:attach.withAgent.detail')}</div>
              <Button className="mt-10px" type="primary" loading={busy} onClick={issueToken}>
                {t('setup:attach.withAgent.action')}
              </Button>
            </Card>
            <Card size="small" bordered className="flex-1">
              <div className="font-medium">{t('setup:attach.withoutAgent.title')}</div>
              <div className="muted-note mt-4px">{t('setup:attach.withoutAgent.detail')}</div>
              <Button
                className="mt-10px"
                onClick={() => {
                  setWithAgent(false);
                  setStep(3);
                }}
              >
                {t('setup:attach.withoutAgent.action')}
              </Button>
            </Card>
          </div>
          {token ? (
            <Card size="small" bordered>
              <InstallPanel token={token} />
              <div className="mt-10px flex items-center gap-8px">
                <span className="inline-block h-8px w-8px animate-pulse rounded-full bg-primary" />
                <span className="text-13px">{t('setup:waiting.title')}</span>
              </div>
              <div className="muted-note">{t('setup:waiting.hint')}</div>
            </Card>
          ) : null}
        </div>
      ) : null}

      {step === 3 ? (
        <Card size="small" bordered>
          <div className="flex flex-col gap-12px">
            {onlineAgent ? (
              <div className="text-14px">
                {t('setup:waiting.connected', {
                  host: onlineAgent.hostname || onlineAgent.id,
                  os: onlineAgent.os,
                  arch: onlineAgent.arch,
                })}
              </div>
            ) : null}
            <div className="text-15px font-medium">{t('setup:template.title')}</div>
            <div className="grid grid-cols-1 gap-12px sm:grid-cols-2">
              {TEMPLATES.map((tpl) => (
                <Card
                  key={tpl.id}
                  size="small"
                  hoverable
                  onClick={() => {
                    onDone();
                    window.location.assign(`/tunnels/new?template=${tpl.id}`);
                  }}
                >
                  <div className="font-medium">{t(`tunnels:template.${tpl.id}.name` as const)}</div>
                  <div className="muted-note">{t(`tunnels:template.${tpl.id}.detail` as const)}</div>
                </Card>
              ))}
            </div>
            <Button type="text" onClick={onDone}>
              {t('setup:template.skip')}
            </Button>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
