import { Button, Card, Select, Space, Table, Tabs, Tag } from '@arco-design/web-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { api } from '@/api/client';
import { useRecentEvents, useStreamHealth } from '@/api/hooks';
import { stream } from '@/api/stream';
import type { ProbeResult, RelayEvent } from '@/api/types';
import { eventKindKey, formatClock, formatDateTime } from '@/utils/format';

/** 诊断：实时日志尾随、事件时间线、支持包。frp 三样全无（dossier 07 §8 item 5）。 */
export default function Diagnostics(): React.JSX.Element {
  const { t } = useTranslation(['diagnostics', 'common', 'errors']);
  useStreamHealth();
  const { data: eventsData } = useRecentEvents(200);

  const [tab, setTab] = useState('log');
  const [paused, setPaused] = useState(false);
  const [level, setLevel] = useState('');
  const [frozen, setFrozen] = useState<ReturnType<typeof stream.logs>>([]);
  const [selftest, setSelftest] = useState<ProbeResult | null>(null);
  const [busy, setBusy] = useState(false);

  const live = stream.logs();
  const lines = paused ? frozen : live;
  const shown = useMemo(
    () => (level === '' ? lines : lines.filter((l) => l.level === level)),
    [lines, level],
  );

  const events: RelayEvent[] = eventsData?.events ?? [];

  return (
    <Tabs activeTab={tab} onChange={setTab}>
      <Tabs.TabPane key="log" title={t('diagnostics:tab.log')}>
        <div className="flex flex-col gap-8px">
          <Space>
            <Button
              size="small"
              onClick={() => {
                // 暂停就是冻结当前快照：继续接收但不再滚动，否则「暂停」会丢日志。
                setFrozen(live);
                setPaused((p) => !p);
              }}
            >
              {paused ? t('diagnostics:log.resume') : t('diagnostics:log.pause')}
            </Button>
            <Select
              className="w-120px"
              placeholder={t('diagnostics:log.level')}
              allowClear
              {...(level === '' ? {} : { value: level })}
              onChange={(v: string | undefined) => setLevel(v ?? '')}
              options={(['debug', 'info', 'warn', 'error'] as const).map((l) => ({
                label: t(`errors:level.${l}` as const),
                value: l,
              }))}
            />
            <span className="muted-note">{t('diagnostics:log.rateLimited')}</span>
          </Space>
          <div
            className="nfr-cmd max-h-60vh overflow-auto rounded-4px border border-line-2 bg-2 p-10px"
            style={{ minHeight: 240 }}
          >
            {shown.length === 0 ? (
              <span className="text-3">{t('diagnostics:log.empty')}</span>
            ) : (
              shown.map((l) => (
                <div key={l.seq} className="flex gap-8px">
                  <span className="text-3">{formatClock(l.at)}</span>
                  <span
                    style={{
                      color:
                        l.level === 'error'
                          ? 'rgb(var(--danger-6))'
                          : l.level === 'warn'
                            ? 'rgb(var(--warning-6))'
                            : 'var(--color-text-3)',
                    }}
                  >
                    {l.level}
                  </span>
                  <span className="flex-1">{l.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </Tabs.TabPane>

      <Tabs.TabPane key="events" title={t('diagnostics:tab.events')}>
        <Table
          size="small"
          rowKey="id"
          data={events}
          pagination={events.length > 50 ? { pageSize: 50 } : false}
          noDataElement={<div className="muted-note py-20px">{t('diagnostics:events.empty')}</div>}
          columns={[
            {
              title: t('diagnostics:events.column.at'),
              dataIndex: 'at',
              width: 170,
              render: (_: unknown, e: RelayEvent) => (
                <span className="nfr-mono text-3">{formatDateTime(e.at)}</span>
              ),
            },
            {
              title: t('diagnostics:events.column.level'),
              dataIndex: 'level',
              width: 80,
              render: (_: unknown, e: RelayEvent) => (
                <Tag
                  size="small"
                  {...(e.level === 'error'
                    ? { color: 'red' }
                    : e.level === 'warn'
                      ? { color: 'orange' }
                      : {})}
                >
                  {t(`errors:level.${e.level}` as 'errors:level.info')}
                </Tag>
              ),
            },
            {
              title: t('diagnostics:events.column.kind'),
              dataIndex: 'kind',
              width: 160,
              render: (_: unknown, e: RelayEvent) =>
                t(`errors:eventKind.${eventKindKey(e.kind)}` as 'errors:eventKind.agent_online', {
                  defaultValue: e.kind,
                }),
            },
            {
              title: t('diagnostics:events.column.subject'),
              dataIndex: 'subject',
              width: 160,
              render: (_: unknown, e: RelayEvent) => (
                <span className="nfr-mono text-3">{e.subject ?? ''}</span>
              ),
            },
            { title: t('diagnostics:events.column.message'), dataIndex: 'message' },
            {
              title: t('diagnostics:events.column.actor'),
              dataIndex: 'actor',
              width: 120,
              render: (_: unknown, e: RelayEvent) => e.actor ?? '',
            },
          ]}
        />
      </Tabs.TabPane>

      <Tabs.TabPane key="tools" title={t('diagnostics:tab.tools')}>
        <div className="flex flex-col gap-12px">
          <Card size="small" bordered title={t('diagnostics:selftest.title')}>
            <Space direction="vertical" size={8}>
              <Button
                size="small"
                type="primary"
                loading={busy}
                onClick={() => {
                  setBusy(true);
                  void api
                    .selfTest()
                    .then(setSelftest)
                    .catch(() => setSelftest(null))
                    .finally(() => setBusy(false));
                }}
              >
                {busy ? t('diagnostics:selftest.running') : t('diagnostics:selftest.run')}
              </Button>
              {selftest === null
                ? null
                : selftest.steps.map((s) => (
                    <div key={s.hop} className="flex items-center gap-8px text-13px">
                      <span
                        style={{
                          color: s.ok ? 'rgb(var(--success-6))' : 'rgb(var(--danger-6))',
                        }}
                        aria-hidden="true"
                      >
                        {s.ok ? '✓' : '✗'}
                      </span>
                      <span className="nfr-mono">{s.hop}</span>
                      <span className="text-3">{s.detail ?? ''}</span>
                    </div>
                  ))}
            </Space>
          </Card>
          <Card size="small" bordered title={t('diagnostics:bundle.title')}>
            <Space direction="vertical" size={8}>
              <Button size="small" href={api.supportBundleURL()} download>
                {t('diagnostics:bundle.download')}
              </Button>
              <span className="muted-note">{t('diagnostics:bundle.note')}</span>
            </Space>
          </Card>
        </div>
      </Tabs.TabPane>
    </Tabs>
  );
}
