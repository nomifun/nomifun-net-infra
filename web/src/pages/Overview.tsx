import { Button, Card, Table, Tag } from '@arco-design/web-react';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import { useRecentEvents, useSnapshot, useStreamHealth } from '@/api/hooks';
import { RING_CAPACITY, stream } from '@/api/stream';
import type { RelayEvent } from '@/api/types';
import EmptyAction from '@/components/EmptyAction';
import LiveChart, { type LiveSeries } from '@/components/LiveChart';
import StatTile from '@/components/StatTile';
import { eventKindKey, formatBytes, formatClock, formatLoss, formatRTT } from '@/utils/format';

/** 两条 RTT 线。p99 在概览上是噪声，留给详情页。 */
const RTT_SERIES: LiveSeries[] = [
  { key: 'rtt_p50_ms', label: 'p50', colorVar: '--primary-6', fallback: '#165dff' },
  { key: 'rtt_p95_ms', label: 'p95', colorVar: '--warning-6', fallback: '#ff7d00' },
];

const RATE_SERIES: LiveSeries[] = [
  { key: 'rate_in_mbps', label: 'in', colorVar: '--success-6', fallback: '#00b42a' },
  { key: 'rate_out_mbps', label: 'out', colorVar: '--link-6', fallback: '#3491fa' },
];

export default function Overview(): React.JSX.Element {
  const { t } = useTranslation(['overview', 'common', 'errors']);
  const navigate = useNavigate();
  // useStreamHealth 同时起两个作用：开流（引用计数）与 1Hz 触发磁贴重渲染。
  const health = useStreamHealth();
  const { data: snapshot } = useSnapshot();
  const { data: eventsData } = useRecentEvents(20);

  const totals = snapshot?.totals;
  const ring = stream.totalsRing();

  const directRatio = useMemo(() => {
    const tunnels = snapshot?.tunnels ?? [];
    let direct = 0;
    let all = 0;
    for (const ts of tunnels) {
      const m = stream.metric(ts.id);
      if (!m) continue;
      direct += m.direct_sessions;
      all += m.direct_sessions + m.relayed_sessions;
    }
    return all === 0 ? null : Math.round((direct / all) * 100);
  }, [snapshot]);

  if (snapshot && snapshot.tunnels.length === 0) {
    return (
      <EmptyAction
        title={t('overview:empty.title')}
        actionLabel={t('overview:empty.action')}
        onAction={() => void navigate('/tunnels/new')}
      />
    );
  }

  const events: RelayEvent[] = eventsData?.events ?? [];

  return (
    <div className="flex flex-col gap-16px">
      <div className="flex flex-wrap gap-12px">
        <StatTile
          label={t('overview:tile.tunnels')}
          value={`${totals?.tunnels_up ?? 0} / ${totals?.tunnels_down ?? 0}`}
        />
        <StatTile label={t('overview:tile.agents')} value={String(totals?.agents_online ?? 0)} />
        <StatTile label={t('overview:tile.sessions')} value={String(totals?.sessions ?? 0)} />
        <StatTile
          label={t('overview:tile.throughput')}
          value={`${ring.last('rate_in_mbps').toFixed(1)} / ${ring.last('rate_out_mbps').toFixed(1)}`}
          suffix={t('common:unit.mbps')}
        />
        {/*
          承载 RTT 现在**有真值**（控制流 Ping/Pong）。门用 hasRTT 而不是
          richMetrics：后者问的是「中继发的是完整 metric 帧吗」，
          而 RTT 即使在只有快照的情况下也有值 —— 用 richMetrics 当门会让
          一个有数据的指标显示成「—」。
          丢包率仍然没有测量点，所以它继续用 richMetrics 并显示「—」：
          0 会被读成「测过，是零」。
        */}
        <StatTile
          label={t('overview:tile.rtt')}
          value={
            health.hasRTT
              ? `${formatRTT(ring.last('rtt_p50_ms') * 1000)} / ${formatRTT(ring.last('rtt_p95_ms') * 1000)}`
              : '—'
          }
          suffix={health.hasRTT ? t('common:unit.ms') : undefined}
          hint={t('overview:tileTip.rtt')}
        />
        <StatTile
          label={t('overview:tile.loss')}
          value={health.richMetrics ? formatLoss(ring.last('loss_pct') * 10_000) : '—'}
          suffix={health.richMetrics ? t('common:unit.percent') : undefined}
          hint={t('overview:tileTip.loss')}
        />
        <StatTile
          label={t('overview:tile.directRatio')}
          value={directRatio === null ? '—' : `${directRatio}`}
          suffix={directRatio === null ? undefined : t('common:unit.percent')}
          hint={t('overview:tileTip.directRatio')}
        />
      </div>

      <div className="grid grid-cols-1 gap-12px lg:grid-cols-2">
        <Card size="small" title={`${t('overview:chart.rttP50')} / ${t('overview:chart.rttP95')}`} bordered>
          <div className="muted-note mb-4px">{t('overview:chart.title')}</div>
          <LiveChart
            ring={ring}
            series={RTT_SERIES}
            yLabel={t('overview:chart.axisMs')}
            emptyHint={t('common:stream.noDataYet')}
            windowSeconds={RING_CAPACITY}
          />
        </Card>
        <Card size="small" title={t('overview:tile.throughput')} bordered>
          <div className="muted-note mb-4px">{t('overview:chart.title')}</div>
          <LiveChart
            ring={ring}
            series={RATE_SERIES}
            yLabel={t('overview:chart.axisMbps')}
            emptyHint={t('common:stream.noDataYet')}
            windowSeconds={RING_CAPACITY}
          />
        </Card>
      </div>

      <Card size="small" title={t('overview:events.title')} bordered>
        <Table
          size="small"
          borderCell={false}
          pagination={false}
          rowKey="id"
          data={events}
          noDataElement={
            <div className="py-20px text-center">
              {/* 用文字按钮而不是 <a onClick>：没有 href 的 <a> 既拿不到键盘焦点
                * 也没有正确的 role，读屏软件会把它读成普通文本。 */}
              <Button type="text" size="small" onClick={() => void navigate('/diagnostics')}>
                {t('overview:events.empty')}
              </Button>
            </div>
          }
          columns={[
            {
              title: t('overview:events.column.at'),
              dataIndex: 'at',
              width: 96,
              render: (_: unknown, row: RelayEvent) => (
                <span className="nfr-mono text-3">{formatClock(row.at)}</span>
              ),
            },
            {
              title: t('overview:events.column.kind'),
              dataIndex: 'kind',
              width: 180,
              render: (_: unknown, row: RelayEvent) => (
                <Tag
                  size="small"
                  {...(row.level === 'error'
                    ? { color: 'red' }
                    : row.level === 'warn'
                      ? { color: 'orange' }
                      : {})}
                >
                  {t(`errors:eventKind.${eventKindKey(row.kind)}` as 'errors:eventKind.agent_online', {
                    defaultValue: row.kind,
                  })}
                </Tag>
              ),
            },
            {
              title: t('overview:events.column.detail'),
              dataIndex: 'message',
              render: (_: unknown, row: RelayEvent) => (
                <span>
                  {row.subject ? <span className="nfr-mono text-3">{row.subject} </span> : null}
                  {row.message}
                </span>
              ),
            },
          ]}
        />
        <div className="muted-note mt-8px">
          {t('overview:totalBytes')}: {formatBytes(totals?.bytes_in ?? 0)} /{' '}
          {formatBytes(totals?.bytes_out ?? 0)}
        </div>
      </Card>
    </div>
  );
}
