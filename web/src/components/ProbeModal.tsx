import { Button, Checkbox, Modal } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, api } from '@/api/client';
import type { ProbeResult, TunnelDraft } from '@/api/types';
import CopyBlock from './CopyBlock';

interface Props {
  visible: boolean;
  /** 后端路由用隧道 ID；slug 只用于标题展示。 */
  id: string;
  slug: string;
  /** 向导里还没有落库的隧道也要能测，所以允许直接传草稿。 */
  draft?: TunnelDraft;
  onClose: () => void;
}

const HOPS = [
  'listener_bound',
  'agent_reachable',
  'carrier_rtt',
  'target_dialable',
  'first_byte',
] as const;

/**
 * 逐跳探测。
 *
 * 关键不是「通/不通」，而是**指名哪一跳失败**：入口监听器绑上了吗、
 * 代理端可达吗、承载 RTT 多少、目标拨得通吗、首字节（或 101 升级）回来了吗。
 * 「从外网测」是必须的第二个按钮 —— loopback 会骗你。
 */
export default function ProbeModal({ visible, id, slug, draft, onClose }: Props): React.JSX.Element {
  const { t } = useTranslation(['tunnels', 'common', 'errors']);
  const [fromInternet, setFromInternet] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ProbeResult | null>(null);
  const [failure, setFailure] = useState<'none' | 'network' | 'notImplemented'>('none');

  const run = (): void => {
    setBusy(true);
    setFailure('none');
    void api
      .probeTunnel(id, fromInternet)
      .then((r) => setResult(r))
      .catch((err: unknown) => {
        // 404 在这里是「中继还没实现这个端点」，不是「隧道不存在」——
        // 报成网络故障会把人引到完全错误的方向。
        setFailure(err instanceof ApiError && err.isMissingEndpoint ? 'notImplemented' : 'network');
      })
      .finally(() => setBusy(false));
  };

  const stepFor = (hop: string): { ok: boolean; ms?: number; detail?: string } | undefined =>
    result?.steps.find((s) => s.hop === hop);

  /**
   * 「没测」与「测了，通」必须看得出区别。
   *
   * 后端原本给 UDP 隧道的 target_dialable 报 ok=true，于是整条探测恒显示
   * 「全链路通」并在那一跳画绿勾 —— 用户会在真正的故障点上白找半天。
   * 现在后端如实把它放进 unverified，这里渲染成中性的「—」加上原因。
   */
  const unverifiedFor = (hop: string): string | undefined =>
    result?.unverified?.find((u) => u.hop === hop)?.why;

  return (
    <Modal
      visible={visible}
      title={`${t('tunnels:wizard.probe.title')} · ${slug}`}
      onCancel={onClose}
      footer={
        <div className="flex items-center justify-between">
          <Checkbox checked={fromInternet} onChange={setFromInternet}>
            <span className="text-13px">{t('tunnels:wizard.probe.fromInternet')}</span>
          </Checkbox>
          <div className="flex gap-8px">
            <Button onClick={onClose}>{t('common:action.close')}</Button>
            <Button type="primary" loading={busy} onClick={run}>
              {t('tunnels:wizard.probe.run')}
            </Button>
          </div>
        </div>
      }
    >
      <div className="flex flex-col gap-8px">
        <div className="muted-note">{t('tunnels:wizard.probe.fromInternetHint')}</div>
        {draft ? <div className="muted-note nfr-mono">{draft.backend.addr ?? draft.backend.path}</div> : null}
        <ol className="m-0 flex list-none flex-col gap-6px p-0">
          {HOPS.map((hop) => {
            const step = stepFor(hop);
            const why = unverifiedFor(hop);
            const mark = step === undefined ? (why === undefined ? '·' : '—') : step.ok ? '✓' : '✗';
            const color =
              step === undefined
                ? 'var(--color-text-4)'
                : step.ok
                  ? 'rgb(var(--success-6))'
                  : 'rgb(var(--danger-6))';
            return (
              <li key={hop} className="flex items-center gap-8px">
                <span style={{ color }} aria-hidden="true">
                  {mark}
                </span>
                <span className="flex-1">{t(`tunnels:wizard.probe.hop.${hop}` as const)}</span>
                {step?.ms === undefined ? null : (
                  <span className="nfr-mono text-3">
                    {step.ms} {t('common:unit.ms')}
                  </span>
                )}
                {step?.detail ? <span className="text-12px text-3">{step.detail}</span> : null}
                {why === undefined ? null : <span className="text-12px text-4">{why}</span>}
              </li>
            );
          })}
        </ol>
        {failure === 'none' ? null : (
          <div className="muted-note">
            {failure === 'notImplemented' ? t('errors:notImplemented') : t('errors:network')}
          </div>
        )}
        {result?.example_cmd ? (
          <CopyBlock text={result.example_cmd} label={t('tunnels:wizard.probe.example')} />
        ) : null}
        {result ? (
          <div className="text-13px">
            {result.ok
              ? result.unverified?.length
                ? // 「已测的都通过」≠「端到端可用」。不说清楚的话，
                  // 一条 UDP 隧道会显示「全链路通」而它的本地目标根本没起。
                  t('tunnels:wizard.probe.okPartial', { count: result.unverified.length })
                : t('tunnels:wizard.probe.ok')
              : t('tunnels:wizard.probe.failedAt', {
                  hop: t(
                    `tunnels:wizard.probe.hop.${
                      result.steps.find((s) => !s.ok)?.hop ?? 'listener_bound'
                    }` as const,
                  ),
                })}
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
