import { Alert, Button, Card, Descriptions, Message, Modal, Radio, Space, Table, Tabs, Tag } from '@arco-design/web-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';

import { ApiError, api } from '@/api/client';
import { keys } from '@/api/keys';
import { useApiMutate, useSamples, useSnapshot, useStreamHealth, useTunnelBySlug } from '@/api/hooks';
import { MetricRing, RING_CAPACITY, stream, type LiveSession } from '@/api/stream';
import type { Sample, Tunnel, TunnelStatus } from '@/api/types';
import CopyBlock from '@/components/CopyBlock';
import LearnedSourcesPanel from '@/components/LearnedSourcesPanel';
import LiveChart, { type LiveSeries } from '@/components/LiveChart';
import ProbeModal from '@/components/ProbeModal';
import ProvenanceTag from '@/components/ProvenanceTag';
import StatTile from '@/components/StatTile';
import StateBadge from '@/components/StateBadge';
import { publicEndpoint, targetAddr } from '@/utils/endpoint';
import { draftFromTunnel } from '@/utils/templates';
import { formatBytes, formatCount, formatDateTime, formatLoss, formatRTT } from '@/utils/format';

/**
 * 「没有这个指标」与「这个指标是 0」必须区分开。
 *
 * 中继当前的 metric 帧不带 RTT / 分级丢弃（见 stream.ts 的 richMetrics），
 * 那时候画一个 0 就是在断言「一个包都没丢」。这里统一显示「—」。
 */
function known(v: number | undefined): string {
  return v === undefined ? '—' : formatCount(v);
}

/**
 * 非零即标红的计数。
 *
 * 用给「发包代理端不符」与「分片范围重叠」这两格：它们与旁边的容量数字
 * **不是一类**。其他分项非零意味着调参数（加容量、提配额、放宽限速），
 * 这两格非零意味着有人在构造帧 —— 处置是吊销凭据、查审计。
 * 摆成同样的黑色数字等于把安全事件藏进容量指标里。
 *
 * 零的时候保持普通样式：一整排红字会让真正非零的那一格失去意义。
 */
function alarmCount(v: number): React.JSX.Element {
  const text = formatCount(v);
  if (v === 0) return <span>{text}</span>;
  return (
    <span style={{ color: 'rgb(var(--danger-6))', fontWeight: 600 }}>
      {text}
      <span className="ml-4px text-12px">⚠</span>
    </span>
  );
}

const RTT_SERIES: LiveSeries[] = [
  { key: 'rtt_p50_ms', label: 'p50', colorVar: '--primary-6', fallback: '#165dff' },
  { key: 'rtt_p95_ms', label: 'p95', colorVar: '--warning-6', fallback: '#ff7d00' },
  { key: 'rtt_p99_ms', label: 'p99', colorVar: '--danger-6', fallback: '#f53f3f' },
];

const RATE_SERIES: LiveSeries[] = [
  { key: 'rate_in_mbps', label: 'in', colorVar: '--success-6', fallback: '#00b42a' },
  { key: 'rate_out_mbps', label: 'out', colorVar: '--link-6', fallback: '#3491fa' },
];

type Range = '1h' | '24h' | '7d' | '30d';

const RANGE_SECONDS: Record<Range, number> = {
  '1h': 3600,
  '24h': 86_400,
  '7d': 7 * 86_400,
  '30d': 30 * 86_400,
};

export default function TunnelDetail(): React.JSX.Element {
  const { slug } = useParams<{ slug: string }>();
  const { t } = useTranslation(['tunnelDetail', 'tunnels', 'common', 'errors']);
  const navigate = useNavigate();
  useStreamHealth();

  const { tunnel, error, isLoading } = useTunnelBySlug(slug);
  const { data: snapshot } = useSnapshot();
  const apiMutate = useApiMutate();
  // 后端路由用 ID，地址栏用 slug；两者的桥就在这一行。
  const tunnelID = tunnel?.id;

  const [tab, setTab] = useState('live');
  const [probing, setProbing] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [range, setRange] = useState<Range>('24h');

  const now = Math.floor(Date.now() / 1000);
  // 只有历史页签才拉样本：这是唯一一处真正昂贵的读。
  const { data: history } = useSamples(
    tab === 'history' ? tunnelID : undefined,
    now - RANGE_SECONDS[range],
  );

  if (error) {
    return <Alert type="error" content={t('errors:generic')} />;
  }
  if (isLoading) {
    return <Card loading size="small" />;
  }
  if (!tunnel) {
    // 「还在加载」与「加载完了但没有这条隧道」必须分开。
    //
    // 合在一起的后果是一个**永久转圈**的页面：地址栏里的 slug 不存在
    //（书签过的 URL、隧道被改名或删掉、手打错一个字母）时，
    // 列表已经拿回来了、里面就是没有它，而页面还在转 ——
    // 用户完全无从判断是网络慢还是这条隧道不在了。
    // 这是浏览器冒烟测试抓出来的：详情页只渲染了 53 个字符。
    return (
      <Alert
        type="warning"
        content={t('tunnelDetail:notFound', { slug: slug ?? '' })}
        action={
          <Button size="small" onClick={() => void navigate('/tunnels')}>
            {t('tunnelDetail:backToList')}
          </Button>
        }
      />
    );
  }

  const status = snapshot?.tunnels.find((s) => s.id === tunnel.id);
  const ring = stream.ring(tunnel.id);
  const relayHost = window.location.hostname;

  const switchToGateway = (): void => {
    void apiMutate(
      () =>
        api.updateTunnel(tunnel.id, {
          ...draftFromTunnel(tunnel),
          tls: 'gateway',
          // 网关模式下若要按 Host 路由就必须是 http 路由器；tls-sni 在网关下非法。
          ...(tunnel.router ? { router: { ...tunnel.router, kind: 'http' as const } } : {}),
        }),
      [keys.tunnels, keys.snapshot],
    )
      .then(() => {
        setSwitching(false);
        Message.success(t('tunnels:toast.updated', { slug: tunnel.slug }));
      })
      .catch(() => Message.error(t('errors:generic')));
  };

  return (
    <div className="flex flex-col gap-12px">
      <div className="flex flex-wrap items-center gap-12px">
        <Button size="small" type="text" onClick={() => void navigate('/tunnels')}>
          {t('tunnelDetail:back')}
        </Button>
        <span className="text-16px font-semibold">{tunnel.slug}</span>
        <StateBadge
          state={status?.state ?? tunnel.state}
          {...(status?.reason ?? tunnel.state_reason
            ? { reason: status?.reason ?? tunnel.state_reason ?? '' }
            : {})}
        />
        <span className="text-13px text-3">
          {t('tunnelDetail:summary', {
            tls: tunnel.tls === 'gateway' ? t('common:mode.gateway') : t('common:mode.passthrough'),
            l4: t(`common:l4.${tunnel.l4}` as 'common:l4.tcp'),
            kind: tunnel.kind,
          })}
        </span>
        <div className="flex-1" />
        <Space size={4}>
          <Button size="small" onClick={() => setProbing(true)}>
            {t('common:action.test')}
          </Button>
          <Button size="small" onClick={() => void navigate(`/tunnels/${tunnel.slug}/edit`)}>
            {t('common:action.edit')}
          </Button>
        </Space>
      </div>

      <div className="endpoint-row text-2">
        <span className="nfr-mono">{publicEndpoint(tunnel, relayHost)}</span>
        <span aria-hidden="true">→</span>
        <span className="nfr-mono">{targetAddr(tunnel)}</span>
      </div>

      <Tabs activeTab={tab} onChange={setTab}>
        <Tabs.TabPane key="live" title={t('tunnelDetail:tab.live')}>
          <LiveTab
            tunnel={tunnel}
            ring={ring}
            {...(status ? { status } : {})}
            onSwitch={() => setSwitching(true)}
          />
        </Tabs.TabPane>
        <Tabs.TabPane key="config" title={t('tunnelDetail:tab.config')}>
          <ConfigTab tunnel={tunnel} />
        </Tabs.TabPane>
        <Tabs.TabPane key="history" title={t('tunnelDetail:tab.history')}>
          <HistoryTab range={range} onRange={setRange} samples={history?.samples ?? []} />
        </Tabs.TabPane>
      </Tabs>

      {probing ? (
        <ProbeModal visible id={tunnel.id} slug={tunnel.slug} onClose={() => setProbing(false)} />
      ) : null}

      {/* 模式切换必须走 diff 预览 + 确认，绝不静默切换。 */}
      <Modal
        visible={switching}
        title={t('tunnelDetail:live.switchDialog.title')}
        okText={t('tunnelDetail:live.switchDialog.confirm')}
        cancelText={t('common:action.cancel')}
        onOk={switchToGateway}
        onCancel={() => setSwitching(false)}
      >
        <div className="flex flex-col gap-8px">
          <div>{t('tunnelDetail:live.switchDialog.intro')}</div>
          <ul className="m-0 pl-18px text-2">
            <li>{t('tunnelDetail:live.switchDialog.item1')}</li>
            <li>{t('tunnelDetail:live.switchDialog.item2')}</li>
            <li>{t('tunnelDetail:live.switchDialog.item3')}</li>
            <li>{t('tunnelDetail:live.switchDialog.item4')}</li>
          </ul>
          <CopyBlock text={`tls: passthrough  →  tls: gateway`} label="diff" />
        </div>
      </Modal>
    </div>
  );
}

/** 实时页签 —— frp 完全没有的那一屏。 */
function LiveTab({
  tunnel,
  ring,
  status,
  onSwitch,
}: {
  tunnel: Tunnel;
  ring: MetricRing;
  status?: TunnelStatus | undefined;
  onSwitch: () => void;
}): React.JSX.Element {
  const { t } = useTranslation(['tunnelDetail', 'common']);
  const m = stream.metric(tunnel.id);
  // 数据报 MTU 走快照，metric 帧那个字段留作回落 —— 见下方那一格的说明。
  const mtu = status?.dgram_mtu ?? m?.dgram_mtu;
  const sessions = stream.sessionsFor(tunnel.id);

  // 快照里的承载 RTT 优先：它由控制流 Ping/Pong 测得，一定有值；
  // 富 metric 帧的值作为备选（中继当前不发富帧）。
  const rttP50 = status?.rtt_p50_us ?? m?.rtt_p50_us ?? 0;
  const rttP95 = status?.rtt_p95_us ?? m?.rtt_p95_us ?? 0;
  const rttP99 = status?.rtt_p99_us ?? m?.rtt_p99_us ?? 0;

  return (
    <div className="flex flex-col gap-12px">
      <div className="flex flex-wrap gap-12px">
        {/*
          承载 RTT。优先用**快照**里的值（控制流 Ping/Pong 测的，一定有），
          富 metric 帧的值作为备选 —— 中继当前不发富帧，所以之前这里恒为 0，
          而「0.00 / 0.00 / 0.00 ms」会被读成「延迟极低」。
          一个观测都还没有时显示「—」。
        */}
        <StatTile
          label={t('tunnelDetail:live.stat.rtt')}
          value={
            rttP50 === 0
              ? '—'
              : `${formatRTT(rttP50)} / ${formatRTT(rttP95)} / ${formatRTT(rttP99)}`
          }
          suffix={rttP50 === 0 ? undefined : t('common:unit.ms')}
          hint={t('tunnelDetail:live.stat.rttTip')}
        />
        <StatTile
          label={t('tunnelDetail:live.stat.loss')}
          value={m?.loss_ppm === undefined ? '—' : formatLoss(m.loss_ppm)}
          suffix={m?.loss_ppm === undefined ? undefined : t('common:unit.percent')}
        />
        <StatTile
          label={t('tunnelDetail:live.stat.throughput')}
          value={`${ring.last('rate_in_mbps').toFixed(2)} / ${ring.last('rate_out_mbps').toFixed(2)}`}
          suffix={t('common:unit.mbps')}
        />
        {tunnel.l4 === 'udp' ? (
          <StatTile
            label={t('tunnelDetail:live.stat.mtu')}
            // 优先读快照里的值（中继真的会发它），metric 帧那个留作回落。
            //
            // 此前只读 m?.dgram_mtu，而中继**从不发**那种 rich metric 帧
            // （见本文件开头的说明），于是这一格恒为「—」——
            // 而这个值其实早就被承载层学到并在影响分片决策了。
            value={mtu ? String(mtu) : '—'}
            suffix={
              mtu
                ? mtu >= 1300
                  ? t('tunnelDetail:live.mtuNegotiated')
                  : t('tunnelDetail:live.mtuLearning')
                : undefined
            }
            hint={t('tunnelDetail:live.mtuTip')}
          />
        ) : null}
        <StatTile
          label={t('tunnelDetail:live.stat.sessions')}
          value={String(status?.sessions ?? m?.sessions ?? 0)}
        />
      </div>

      <Card size="small" bordered title={t('tunnelDetail:live.chartTitle')}>
        <LiveChart
          ring={ring}
          series={RTT_SERIES}
          yLabel={t('common:unit.ms')}
          emptyHint={t('common:stream.noDataYet')}
          windowSeconds={RING_CAPACITY}
        />
        <LiveChart
          ring={ring}
          series={RATE_SERIES}
          yLabel={t('common:unit.mbps')}
          height={120}
          emptyHint={t('common:stream.noDataYet')}
          windowSeconds={RING_CAPACITY}
        />
      </Card>

      {tunnel.l4 === 'udp' ? (
        <div className="grid grid-cols-1 gap-12px lg:grid-cols-3">
          {/* 分级丢弃：三个站点对应数据面的三处丢弃点。 */}
          <Card size="small" bordered title={t('tunnelDetail:live.udpDrops.title')}>
            <Descriptions
              size="small"
              column={1}
              colon=""
              data={[
                {
                  label: t('tunnelDetail:live.udpDrops.queueHead'),
                  value: known(m?.drop_queue_head),
                },
                {
                  label: t('tunnelDetail:live.udpDrops.inflight'),
                  value: known(m?.drop_inflight_cap),
                },
                {
                  label: t('tunnelDetail:live.udpDrops.kernel'),
                  value: known(m?.drop_kernel),
                },
              ]}
            />
            <div className="muted-note mt-8px">{t('tunnelDetail:live.udpDrops.hint')}</div>
          </Card>
          <Card size="small" bordered title={t('tunnelDetail:live.reorder.title')}>
            <Descriptions
              size="small"
              column={1}
              colon=""
              data={[
                { label: t('tunnelDetail:live.reorder.count'), value: known(m?.reorder_count) },
                {
                  label: t('tunnelDetail:live.reorder.maxDepth'),
                  value: known(m?.reorder_max_depth),
                },
                {
                  label: t('tunnelDetail:live.reorder.jitter'),
                  value:
                    m?.jitter_us === undefined
                      ? '—'
                      : `${formatRTT(m.jitter_us)} ${t('common:unit.ms')}`,
                },
              ]}
            />
          </Card>
          <Card size="small" bordered title={t('tunnelDetail:live.frag.title')}>
            <Descriptions
              size="small"
              column={1}
              colon=""
              data={[
                {
                  label: t('tunnelDetail:live.frag.rate'),
                  value:
                    m?.frag_rate_ppm === undefined
                      ? '—'
                      : `${formatLoss(m.frag_rate_ppm)} ${t('common:unit.percent')}`,
                },
                {
                  label: t('tunnelDetail:live.frag.timeouts'),
                  value: known(m?.reassembly_timeouts),
                },
              ]}
            />
          </Card>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-12px lg:grid-cols-2">
        <Card size="small" bordered title={t('tunnelDetail:live.sessions.title', { count: sessions.length })}>
          <Table
            size="mini"
            rowKey="peer"
            pagination={false}
            data={sessions}
            noDataElement={<div className="muted-note py-12px">{t('tunnelDetail:live.sessions.empty')}</div>}
            columns={[
              {
                title: t('tunnelDetail:live.sessions.peer'),
                dataIndex: 'peer',
                render: (_: unknown, s: LiveSession) => <span className="nfr-mono">{s.peer}</span>,
              },
              {
                title: t('tunnelDetail:live.sessions.path'),
                dataIndex: 'path',
                width: 90,
                render: (_: unknown, s: LiveSession) => (
                  <Tag size="small">
                    {s.path === 'direct'
                      ? t('tunnelDetail:live.sessions.direct')
                      : s.path === 'relayed'
                        ? t('tunnelDetail:live.sessions.relayed')
                        : t('tunnelDetail:live.sessions.unknown')}
                  </Tag>
                ),
              },
              {
                title: t('tunnelDetail:live.sessions.since'),
                dataIndex: 'since',
                width: 110,
                render: (_: unknown, s: LiveSession) => (
                  <span className="nfr-mono text-3">
                    {new Date(s.since).toLocaleTimeString(undefined, { hour12: false })}
                  </span>
                ),
              },
            ]}
          />
          <div className="muted-note mt-6px">{t('tunnelDetail:live.sessions.sinceOpen')}</div>
        </Card>

        <Card size="small" bordered title={t('tunnelDetail:live.denied.title')}>
          <Descriptions
            size="small"
            column={1}
            colon=""
            data={[
              {
                label: t('tunnelDetail:live.denied.cidr'),
                value: formatCount(status?.denied_cidr ?? 0),
              },
              {
                label: t('tunnelDetail:live.denied.noSession'),
                value: formatCount(status?.no_session ?? 0),
              },
              {
                label: t('tunnelDetail:live.denied.openFailed'),
                value: formatCount(status?.open_failed ?? 0),
              },
              {
                label: t('tunnelDetail:live.denied.rateLimited'),
                value: formatCount(status?.rate_limited ?? 0),
              },
              // UDP 独有的三道闸。只在 UDP 隧道上显示 ——
              // 在 TCP 隧道上摆三个恒为 0 的数字，会让人以为「测过，是零」。
              ...(tunnel.l4 === 'udp'
                ? [
                    {
                      label: t('tunnelDetail:live.denied.tableFull'),
                      value: formatCount(status?.dropped_table_full ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.perIPQuota'),
                      value: formatCount(status?.dropped_per_ip_quota ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.unknownFlow'),
                      value: formatCount(status?.dropped_unknown_flow ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.reassembly'),
                      value: formatCount(status?.dropped_reassembly ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.rateLimitedBytes'),
                      value: formatCount(status?.rate_limited_bytes ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.evicted'),
                      value: formatCount(status?.flows_evicted ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.denied.carrier'),
                      value: formatCount(status?.dropped_carrier ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.fragments'),
                      value: `${formatCount(status?.fragments ?? 0)} / ${formatCount(
                        status?.reassembled ?? 0,
                      )}`,
                    },
                    {
                      // 重叠分片与旁边的容量数字也不是一类：正常发送方
                      // 按固定步长切片不会重叠，非零意味着有人在构造分片。
                      label: t('tunnelDetail:live.denied.overlapping'),
                      value: alarmCount(status?.reasm_overlapping ?? 0),
                    },
                    {
                      // 这一格与旁边几格不是一类：其他项非零意味着调参数，
                      // 它非零意味着**有个 agent 在往别人的隧道里注包**。
                      // 所以非零时标红，而不是当成又一个容量数字。
                      label: t('tunnelDetail:live.denied.wrongAgent'),
                      value: alarmCount(status?.dropped_wrong_agent ?? 0),
                    },
                    {
                      label: t('tunnelDetail:live.packets'),
                      value: `${formatCount(status?.packets_in ?? 0)} / ${formatCount(
                        status?.packets_out ?? 0,
                      )}`,
                    },
                  ]
                : []),
            ]}
          />
        </Card>
      </div>

      {/* 直通模式：**渲染字面说明**，而不是留一片空白让用户以为坏了。 */}
      {tunnel.tls === 'passthrough' ? (
        <Alert
          type="info"
          title={t('tunnelDetail:live.passthrough.notice')}
          content={
            <div className="flex flex-col gap-8px">
              <div>{t('tunnelDetail:live.passthrough.clientIP')}</div>
              <Space>
                <Button size="mini" type="primary" onClick={onSwitch}>
                  {t('tunnelDetail:live.passthrough.switch')}
                </Button>
              </Space>
            </div>
          }
        />
      ) : (
        <Card size="small" bordered title={t('tunnelDetail:live.http.title')}>
          <Descriptions
            size="small"
            column={3}
            colon=""
            data={[
              { label: t('tunnelDetail:live.http.status2xx'), value: formatCount(m?.http?.status_2xx ?? 0) },
              { label: t('tunnelDetail:live.http.status4xx'), value: formatCount(m?.http?.status_4xx ?? 0) },
              { label: t('tunnelDetail:live.http.status5xx'), value: formatCount(m?.http?.status_5xx ?? 0) },
              {
                label: t('tunnelDetail:live.http.p95'),
                value: `${formatRTT(m?.http?.req_p95_us ?? 0)} ${t('common:unit.ms')}`,
              },
              { label: t('tunnelDetail:live.http.topPath'), value: m?.http?.top_path ?? '—' },
            ]}
          />
        </Card>
      )}
    </div>
  );
}

/** 配置页签：生效值 + 来源。文件管理的行不可编辑，并把原因放在 tooltip 里。 */
interface ConfigRow {
  field: string;
  value: string;
  /** 显式设过（→ 控制台）还是取了默认值。 */
  set: boolean;
}

function ConfigTab({ tunnel }: { tunnel: Tunnel }): React.JSX.Element {
  const { t } = useTranslation(['tunnelDetail', 'tunnels', 'common', 'errors']);
  const [preview, setPreview] = useState<{ agent_yaml: string; relay_yaml: string } | null>(null);

  const rows: ConfigRow[] = [
    { field: t('tunnelDetail:config.field.slug'), value: tunnel.slug, set: true },
    { field: t('tunnelDetail:config.field.kind'), value: tunnel.kind, set: true },
    { field: t('tunnelDetail:config.field.tls'), value: tunnel.tls, set: true },
    { field: t('tunnelDetail:config.field.exposure'), value: tunnel.exposure, set: true },
    { field: t('tunnelDetail:config.field.l4'), value: tunnel.l4, set: true },
    {
      field: t('tunnelDetail:config.field.agent'),
      value: tunnel.agent_id ?? t('tunnelDetail:config.unset'),
      set: tunnel.agent_id !== undefined,
    },
    {
      field: t('tunnelDetail:config.field.listenPort'),
      value: tunnel.listen_port ? String(tunnel.listen_port) : t('tunnelDetail:config.unset'),
      set: Boolean(tunnel.listen_port),
    },
    { field: t('tunnelDetail:config.field.backend'), value: targetAddr(tunnel), set: true },
    {
      field: t('tunnelDetail:config.field.router'),
      value: tunnel.router
        ? `${tunnel.router.kind} ${(tunnel.router.domains ?? []).join(', ')}`
        : t('tunnelDetail:config.unset'),
      set: tunnel.router !== undefined,
    },
    {
      field: t('tunnelDetail:config.field.allowCidrs'),
      value: (tunnel.policy?.allow_cidrs ?? []).join(', ') || t('tunnelDetail:config.unset'),
      set: (tunnel.policy?.allow_cidrs?.length ?? 0) > 0,
    },
    {
      field: t('tunnelDetail:config.field.maxConns'),
      value: tunnel.policy?.max_conns
        ? String(tunnel.policy.max_conns)
        : t('tunnelDetail:config.unlimited'),
      set: Boolean(tunnel.policy?.max_conns),
    },
    {
      field: t('tunnelDetail:config.field.maxConnsPerIP'),
      value: tunnel.policy?.max_conns_per_ip
        ? String(tunnel.policy.max_conns_per_ip)
        : t('tunnelDetail:config.sameAsMaxConns'),
      set: Boolean(tunnel.policy?.max_conns_per_ip),
    },
    {
      field: t('tunnelDetail:config.field.bytesPerSecond'),
      value: tunnel.policy?.bytes_per_second
        ? formatBytes(tunnel.policy.bytes_per_second)
        : t('tunnelDetail:config.unlimited'),
      set: Boolean(tunnel.policy?.bytes_per_second),
    },
    {
      field: t('tunnelDetail:config.field.packetsPerSecond'),
      value: tunnel.policy?.packets_per_second
        ? String(tunnel.policy.packets_per_second)
        : t('tunnelDetail:config.unlimited'),
      set: Boolean(tunnel.policy?.packets_per_second),
    },
  ];

  const loadPreview = (): void => {
    void api
      .previewConfig(draftFromTunnel(tunnel))
      .then((p) => setPreview(p))
      .catch((err: unknown) => {
        setPreview(null);
        Message.warning(
          err instanceof ApiError && err.isMissingEndpoint
            ? t('errors:notImplemented')
            : t('errors:generic'),
        );
      });
  };

  return (
    <div className="flex flex-col gap-12px">
      <Table
        size="small"
        rowKey="field"
        pagination={false}
        data={rows}
        columns={[
          { title: t('tunnelDetail:config.column.field'), dataIndex: 'field', width: 200 },
          {
            title: t('tunnelDetail:config.column.value'),
            dataIndex: 'value',
            render: (_: unknown, row: ConfigRow) => <span className="nfr-mono">{row.value}</span>,
          },
          {
            title: t('tunnelDetail:config.column.provenance'),
            dataIndex: 'provenance',
            width: 140,
            // 隧道对象目前没有逐字段来源（只有 Settings 有），所以这里只能
            // 区分「显式设过」与「取默认值」。别假装知道得更多。
            render: (_: unknown, row: ConfigRow) => (
              <ProvenanceTag provenance={row.set ? 'console' : 'default'} />
            ),
          },
        ]}
      />
      {/* 学习模式挂在「配置」而不是「实时」：它写的是 allow_cidrs，
          是一个配置动作。放在实时页签里会让人以为它只是个观测视图。 */}
      <LearnedSourcesPanel tunnel={tunnel} />
      <Card
        size="small"
        bordered
        title={t('tunnels:wizard.preview.title')}
        extra={
          <Button size="mini" onClick={loadPreview}>
            {t('common:action.refresh')}
          </Button>
        }
      >
        {preview === null ? (
          <div className="muted-note">{t('tunnels:wizard.preview.hint')}</div>
        ) : (
          <div className="flex flex-col gap-8px">
            <CopyBlock text={preview.agent_yaml} label={t('tunnels:wizard.preview.agent')} />
            <CopyBlock text={preview.relay_yaml} label={t('tunnels:wizard.preview.relay')} />
          </div>
        )}
      </Card>
    </div>
  );
}

/** 历史页签：SQLite rollup 出来的样本。留存策略写在页脚，避免用户猜。 */
function HistoryTab({
  range,
  onRange,
  samples,
}: {
  range: Range;
  onRange: (r: Range) => void;
  samples: Sample[];
}): React.JSX.Element {
  const { t } = useTranslation(['tunnelDetail', 'common']);

  // 直接把历史样本喂进同一个环形缓冲实现 —— 图表组件因此完全复用。
  // 容量 900，超出时取最近的 900 个点（更早的数据靠调大粒度来看）。
  const ring = useMemo(() => {
    const r = new MetricRing();
    for (const s of samples.slice(-900)) {
      const secs = Math.max(1, s.samples);
      r.push(s.bucket, {
        rtt_p50_ms: s.rtt_sum_us / secs / 1000,
        rtt_p95_ms: s.rtt_max_us / 1000,
        rtt_p99_ms: 0,
        loss_pct: s.loss_ppm / 10_000,
        rate_in_mbps: (s.bytes_in * 8) / 1e6 / 60,
        rate_out_mbps: (s.bytes_out * 8) / 1e6 / 60,
        pps_in: s.pkts_in,
        pps_out: s.pkts_out,
      });
    }
    return r;
  }, [samples]);

  return (
    <div className="flex flex-col gap-12px">
      <Radio.Group
        type="button"
        size="small"
        value={range}
        onChange={(v: Range) => onRange(v)}
        options={(['1h', '24h', '7d', '30d'] as const).map((r) => ({
          label: t(`tunnelDetail:history.range.${r}` as const),
          value: r,
        }))}
      />
      {samples.length === 0 ? (
        <div className="muted-note py-24px text-center">{t('tunnelDetail:history.empty')}</div>
      ) : (
        <>
          <Card size="small" bordered title={t('tunnelDetail:history.traffic')}>
            <LiveChart
              ring={ring}
              series={RATE_SERIES}
              yLabel={t('common:unit.mbps')}
              emptyHint={t('common:stream.noDataYet')}
            />
          </Card>
          <Card size="small" bordered title={t('tunnelDetail:history.rtt')}>
            <LiveChart
              ring={ring}
              series={[
                { key: 'rtt_p50_ms', label: 'avg', colorVar: '--primary-6', fallback: '#165dff' },
                { key: 'rtt_p95_ms', label: 'max', colorVar: '--danger-6', fallback: '#f53f3f' },
              ]}
              yLabel={t('common:unit.ms')}
              emptyHint={t('common:stream.noDataYet')}
            />
          </Card>
          <Table
            size="mini"
            rowKey="bucket"
            data={samples.slice(-100).toReversed()}
            pagination={false}
            columns={[
              {
                title: t('tunnelDetail:history.range.1h'),
                dataIndex: 'bucket',
                width: 180,
                render: (_: unknown, s: Sample) => (
                  <span className="nfr-mono text-3">
                    {formatDateTime(new Date(s.bucket * 1000).toISOString())}
                  </span>
                ),
              },
              {
                title: t('tunnelDetail:history.traffic'),
                dataIndex: 'bytes_in',
                render: (_: unknown, s: Sample) => (
                  <span className="nfr-mono">
                    {formatBytes(s.bytes_in)} / {formatBytes(s.bytes_out)}
                  </span>
                ),
              },
              {
                title: t('tunnelDetail:history.conns'),
                dataIndex: 'conns_ok',
                render: (_: unknown, s: Sample) => `${s.conns_ok} / ${s.conns_err}`,
              },
              {
                title: t('tunnelDetail:live.stat.loss'),
                dataIndex: 'loss_ppm',
                // 恒为「—」。丢包率全仓**没有任何测量点**（store.Sample.LossPPM
                // 只被写进/读出 SQLite，从没被赋过非零值），所以这一列渲染
                // `formatLoss(0)%` 就是在每一行上断言「测过，丢包为零」。
                // 实时那一格早就显示「—」了，这一列漂了 —— 同一个数字在同一页
                // 上有两种读法，而其中一种是编的。
                render: () => '—',
              },
            ]}
          />
        </>
      )}
      <div className="muted-note">{t('tunnelDetail:history.retention')}</div>
    </div>
  );
}
