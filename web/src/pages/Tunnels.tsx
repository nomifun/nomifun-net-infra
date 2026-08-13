import { Button, Card, Input, Message, Select, Space, Table, Tag } from '@arco-design/web-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { api } from '@/api/client';
import { keys } from '@/api/keys';
import { useApiMutate, useSnapshot, useStreamHealth, useTunnels } from '@/api/hooks';
import { stream } from '@/api/stream';
import type { Tunnel, TunnelStatus } from '@/api/types';
import EmptyAction from '@/components/EmptyAction';
import EndpointCell from '@/components/EndpointCell';
import ExposureBadge from '@/components/ExposureBadge';
import ProbeModal from '@/components/ProbeModal';
import Sparkline from '@/components/Sparkline';
import StateBadge from '@/components/StateBadge';
import TypeToConfirm from '@/components/TypeToConfirm';
import { exposureLevel, publicEndpoint, targetAddr } from '@/utils/endpoint';
import { formatBytes, formatLoss, formatRTT } from '@/utils/format';
import { TEMPLATES, draftFromTunnel } from '@/utils/templates';

/**
 * 隧道列表 —— 产品重心。
 *
 * 相对 frp 的三处结构性差异：
 * 1. **有写路径**。frps 控制台只有一个写操作（DELETE 离线代理），
 *    根因是配置归客户端所有；这里中继是权威，所以整套 CRUD 都在。
 * 2. **一行答完「我从哪进，落到哪」**（EndpointCell）。
 * 3. 筛选状态在 URL 里，可分享、可刷新。
 */
export default function Tunnels(): React.JSX.Element {
  const { t } = useTranslation(['tunnels', 'common']);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  useStreamHealth();

  const { data: tunnels, isLoading } = useTunnels();
  const { data: snapshot } = useSnapshot();
  const apiMutate = useApiMutate();

  const [probing, setProbing] = useState<Tunnel | null>(null);
  const [deleting, setDeleting] = useState<Tunnel | null>(null);
  const [busy, setBusy] = useState(false);

  // 中继自测到的公网地址目前没有 API（首启向导里也只能显示「未知」），
  // 所以退回浏览器看到的 host —— 它至少是「用户现在确实能访问到的地址」。
  const relayHost = window.location.hostname;

  const q = params.get('q') ?? '';
  const fKind = params.get('kind') ?? '';
  const fState = params.get('state') ?? '';
  const fMode = params.get('mode') ?? '';

  const setParam = (key: string, value: string): void => {
    const next = new URLSearchParams(params);
    if (value === '') next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  const statusByID = useMemo(() => {
    const m = new Map<string, TunnelStatus>();
    for (const s of snapshot?.tunnels ?? []) m.set(s.id, s);
    return m;
  }, [snapshot]);

  const agentName = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of snapshot?.agents ?? []) m.set(a.id, a.hostname || a.id);
    return m;
  }, [snapshot]);

  const rows = useMemo(() => {
    const all = tunnels ?? [];
    const needle = q.trim().toLowerCase();
    return all.filter((tn) => {
      if (fKind !== '' && tn.kind !== fKind) return false;
      if (fMode !== '' && tn.tls !== fMode) return false;
      if (fState !== '' && (statusByID.get(tn.id)?.state ?? tn.state) !== fState) return false;
      if (needle === '') return true;
      return (
        tn.slug.toLowerCase().includes(needle) ||
        publicEndpoint(tn, relayHost).toLowerCase().includes(needle) ||
        targetAddr(tn).toLowerCase().includes(needle)
      );
    });
  }, [tunnels, q, fKind, fMode, fState, statusByID, relayHost]);

  const toggleEnabled = (tn: Tunnel): void => {
    const next = !(tn.enabled ?? true);
    setBusy(true);
    // 没有专门的 :enable 端点，就是一次普通更新 —— 少一个端点少一处漂移。
    void apiMutate(
      () => api.updateTunnel(tn.id, { ...draftFromTunnel(tn), enabled: next }),
      [keys.tunnels, keys.snapshot],
    )
      .then(() =>
        Message.success(
          next ? t('tunnels:toast.enabled', { slug: tn.slug }) : t('tunnels:toast.disabled', { slug: tn.slug }),
        ),
      )
      .catch(() => Message.error(t('common:action.retry')))
      .finally(() => setBusy(false));
  };

  const doDelete = (): void => {
    const target = deleting;
    if (!target) return;
    setBusy(true);
    void apiMutate(() => api.deleteTunnel(target.id), [keys.tunnels, keys.snapshot])
      .then(() => {
        Message.success(t('tunnels:toast.deleted', { slug: target.slug }));
        setDeleting(null);
      })
      .catch(() => Message.error(t('common:action.retry')))
      .finally(() => setBusy(false));
  };

  if (!isLoading && (tunnels?.length ?? 0) === 0) {
    return (
      <EmptyAction
        title={t('tunnels:empty.title')}
        actionLabel={t('tunnels:empty.pickTemplate')}
        onAction={() => void navigate('/tunnels/new')}
      >
        <div className="grid grid-cols-1 gap-12px sm:grid-cols-2">
          {TEMPLATES.map((tpl) => (
            <Card
              key={tpl.id}
              size="small"
              hoverable
              onClick={() => void navigate(`/tunnels/new?template=${tpl.id}`)}
            >
              <div className="font-medium">{t(`tunnels:template.${tpl.id}.name` as const)}</div>
              <div className="muted-note">{t(`tunnels:template.${tpl.id}.detail` as const)}</div>
            </Card>
          ))}
        </div>
      </EmptyAction>
    );
  }

  return (
    <div className="flex flex-col gap-12px">
      <div className="flex flex-wrap items-center gap-8px">
        <span className="text-16px font-semibold">
          {t('tunnels:count', { count: tunnels?.length ?? 0 })}
        </span>
        <div className="flex-1" />
        <span data-nfr-search>
          <Input
            allowClear
            className="w-260px"
            value={q}
            onChange={(v: string) => setParam('q', v)}
            placeholder={`${t('tunnels:searchPlaceholder')} — ${t('common:shortcut.search')}`}
          />
        </span>
        <Select
          className="w-140px"
          {...(fKind === '' ? {} : { value: fKind })}
          placeholder={t('tunnels:filter.kind')}
          allowClear
          onChange={(v: string | undefined) => setParam('kind', v ?? '')}
          options={[
            { label: t('common:kind.service'), value: 'service' },
            { label: t('common:kind.reverse'), value: 'reverse' },
          ]}
        />
        <Select
          className="w-120px"
          {...(fState === '' ? {} : { value: fState })}
          placeholder={t('tunnels:filter.state')}
          allowClear
          onChange={(v: string | undefined) => setParam('state', v ?? '')}
          options={[
            { label: t('common:state.active'), value: 'active' },
            { label: t('common:state.degraded'), value: 'degraded' },
            { label: t('common:state.stopped'), value: 'stopped' },
            { label: t('common:state.error'), value: 'error' },
          ]}
        />
        <Select
          className="w-110px"
          {...(fMode === '' ? {} : { value: fMode })}
          placeholder={t('tunnels:filter.mode')}
          allowClear
          onChange={(v: string | undefined) => setParam('mode', v ?? '')}
          options={[
            { label: t('common:mode.passthrough'), value: 'passthrough' },
            { label: t('common:mode.gateway'), value: 'gateway' },
          ]}
        />
        <Button type="primary" onClick={() => void navigate('/tunnels/new')}>
          {t('tunnels:wizard.title')}
        </Button>
      </div>

      <Table
        size="small"
        rowKey="id"
        loading={isLoading}
        data={rows}
        pagination={rows.length > 20 ? { pageSize: 20, sizeCanChange: true } : false}
        columns={[
          {
            title: t('tunnels:column.state'),
            dataIndex: 'state',
            width: 110,
            render: (_: unknown, tn: Tunnel) => {
              const st = statusByID.get(tn.id);
              return (
                <StateBadge
                  state={st?.state ?? tn.state}
                  {...(st?.reason ?? tn.state_reason
                    ? { reason: st?.reason ?? tn.state_reason ?? '' }
                    : {})}
                />
              );
            },
          },
          {
            title: t('tunnels:column.endpoint'),
            dataIndex: 'slug',
            render: (_: unknown, tn: Tunnel) => (
              <EndpointCell
                tunnel={tn}
                relayHost={relayHost}
                {...(tn.agent_id ? { agentName: agentName.get(tn.agent_id) ?? tn.agent_id } : {})}
              />
            ),
          },
          {
            title: t('tunnels:column.mode'),
            dataIndex: 'tls',
            width: 80,
            render: (_: unknown, tn: Tunnel) => (
              <Tag size="small">
                {tn.tls === 'gateway' ? t('common:mode.gateway') : t('common:mode.passthrough')}
              </Tag>
            ),
          },
          {
            title: t('tunnels:column.exposure'),
            dataIndex: 'exposure',
            width: 120,
            render: (_: unknown, tn: Tunnel) => <ExposureBadge level={exposureLevel(tn, false)} />,
          },
          {
            title: t('tunnels:column.sessions'),
            dataIndex: 'sessions',
            width: 70,
            render: (_: unknown, tn: Tunnel) => statusByID.get(tn.id)?.sessions ?? 0,
          },
          {
            title: t('tunnels:column.rtt'),
            dataIndex: 'rtt',
            width: 160,
            render: (_: unknown, tn: Tunnel) => {
              const ring = stream.ring(tn.id);
              const m = stream.metric(tn.id);
              return (
                <div className="flex items-center gap-6px">
                  <Sparkline
                    values={ring.values('rtt_p95_ms')}
                    title={t('tunnels:row.rttSparkline')}
                    colorVar={tn.l4 === 'udp' ? '--warning-6' : '--primary-6'}
                  />
                  <div className="flex flex-col leading-tight">
                    <span className="nfr-mono">
                      {formatRTT(m?.rtt_p50_us ?? 0)} {t('common:unit.ms')}
                    </span>
                    <span className="text-11px text-3">
                      {tn.l4 === 'udp'
                        ? t('tunnels:row.lossPps', {
                            // 「没测到」必须显示成「—」而不是 0%。
                            //
                            // 丢包率全仓**没有任何测量点**（store 从不写
                            // loss_ppm），所以 `?? 0` 会在每一行上断言
                            // 「测过，丢包为零」——那是一句凭空造出来的好消息。
                            // 详情页早就显示「—」了，这一列漂了。
                            loss:
                              m?.loss_ppm === undefined
                                ? '—'
                                : `${formatLoss(m.loss_ppm)}%`,
                            pps: m?.pkts_in ?? 0,
                          })
                        : t('tunnels:row.p95', { value: `${formatRTT(m?.rtt_p95_us ?? 0)}ms` })}
                    </span>
                  </div>
                </div>
              );
            },
          },
          {
            title: t('tunnels:column.traffic'),
            dataIndex: 'bytes',
            width: 120,
            render: (_: unknown, tn: Tunnel) => {
              const st = statusByID.get(tn.id);
              return (
                <span className="nfr-mono text-13px">
                  {formatBytes(st?.bytes_in ?? 0)} / {formatBytes(st?.bytes_out ?? 0)}
                </span>
              );
            },
          },
          {
            title: t('tunnels:column.actions'),
            dataIndex: 'actions',
            width: 260,
            render: (_: unknown, tn: Tunnel) => (
              <Space size={4}>
                <Button size="mini" type="text" disabled={busy} onClick={() => toggleEnabled(tn)}>
                  {(tn.enabled ?? true) ? t('common:action.disable') : t('common:action.enable')}
                </Button>
                <Button size="mini" type="text" onClick={() => void navigate(`/tunnels/${tn.slug}/edit`)}>
                  {t('common:action.edit')}
                </Button>
                <Button
                  size="mini"
                  type="text"
                  onClick={() => void navigate(`/tunnels/new?from=${tn.slug}`)}
                >
                  {t('common:action.duplicate')}
                </Button>
                <Button size="mini" type="text" onClick={() => setProbing(tn)}>
                  {t('common:action.test')}
                </Button>
                <Button size="mini" type="text" status="danger" onClick={() => setDeleting(tn)}>
                  {t('common:action.delete')}
                </Button>
              </Space>
            ),
          },
        ]}
      />

      {probing === null ? null : (
        <ProbeModal visible id={probing.id} slug={probing.slug} onClose={() => setProbing(null)} />
      )}
      {deleting === null ? null : (
        <TypeToConfirm
          visible
          slug={deleting.slug}
          title={t('tunnels:delete.title', { slug: deleting.slug })}
          warning={t('tunnels:delete.warn')}
          okLoading={busy}
          onOk={doDelete}
          onCancel={() => setDeleting(null)}
        />
      )}
    </div>
  );
}
