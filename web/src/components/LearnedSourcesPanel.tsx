import { Alert, Button, Card, Checkbox, Message, Modal, Space, Table, Tag } from '@arco-design/web-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, api } from '@/api/client';
import { keys } from '@/api/keys';
import { useApiMutate, useLearnedSources } from '@/api/hooks';
import type { LearnedSource, Tunnel } from '@/api/types';
import { formatCount, formatDateTime } from '@/utils/format';

/**
 * 学习模式面板：把中继实际观测到的来源固定成允许列表。
 *
 * # 为什么是勾选而不是一个「一键收窄」按钮
 *
 * 学习窗口里（allow_cidrs 为空 = 放行一切）扫描器与真客户端的地址**混在
 * 一起**，中继分不开。一个全选按钮等于让人一键把撞门的人请进允许列表，
 * 而那正好是这个功能想解决的问题的反面。
 *
 * 所以界面的职责是把判据摆出来（命中次数、首见/最近），把判断交回给人。
 * 默认一个都不勾 —— 默认全勾会让「点两下就完事」变成最省力的路径。
 *
 * # 三条必须显式说出来的事
 *
 *  1. **观测只在内存里，重启即清空。** 一份只攒了五分钟的列表看起来与攒了
 *     一周的一模一样，所以观测起点必须显示。
 *  2. **列表可能被截断。** 到过上限就意味着有真客户端不在列表里，
 *     照它收窄会把那些人锁在门外 —— 那时整块换成警告，而不是推荐。
 *  3. **当前是否已有允许列表。** 「并入」与「从零收窄」的风险完全不同：
 *     后者是把一条全开的隧道关成只认这几个前缀。
 */
export default function LearnedSourcesPanel({ tunnel }: { tunnel: Tunnel }): React.JSX.Element | null {
  const { t } = useTranslation(['tunnelDetail', 'common', 'errors']);
  const mutateApi = useApiMutate();
  const { data, error } = useLearnedSources(tunnel.id);
  const [checked, setChecked] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  const sources = useMemo(() => data?.sources ?? [], [data]);
  const alreadyNarrowed = (tunnel.policy?.allow_cidrs?.length ?? 0) > 0;

  // 501：这台中继压根不观测。如实说，不要显示一个空列表 ——
  // 空列表会被读成「没人连过」，而两者的下一步动作不同。
  if (error instanceof ApiError && error.status === 501) {
    return (
      <Card size="small" bordered title={t('tunnelDetail:learn.title')}>
        <div className="muted-note">{t('tunnelDetail:learn.unsupported')}</div>
      </Card>
    );
  }
  if (error) return null;

  async function apply(): Promise<void> {
    if (checked.length === 0) {
      Message.warning(t('tunnelDetail:learn.nothingSelected'));
      return;
    }
    Modal.confirm({
      title: t('tunnelDetail:learn.confirmTitle'),
      content: (
        <div>
          <div className="mb-8px">
            {t('tunnelDetail:learn.confirmBody', { count: checked.length })}
          </div>
          {/* 把要写下去的前缀逐条列出来。
              「确认吗」而不给内容，等于让人凭记忆确认一个不可逆的动作。 */}
          <div className="nfr-mono text-12px">
            {checked.map((c) => (
              <div key={c}>{c}</div>
            ))}
          </div>
        </div>
      ),
      okButtonProps: { status: 'warning' },
      onOk: async () => {
        setBusy(true);
        try {
          const res = await mutateApi(
            () => api.applyLearnedSources(tunnel.id, checked),
            [keys.tunnels, keys.snapshot, keys.learned(tunnel.id)],
          );
          if ((res.added ?? 0) === 0) {
            Message.info(t('tunnelDetail:learn.nothingNew'));
          } else {
            Message.success(t('tunnelDetail:learn.applied', { count: res.added }));
          }
          setChecked([]);
        } catch (e) {
          Message.error(e instanceof ApiError ? e.message : String(e));
        } finally {
          setBusy(false);
        }
      },
    });
  }

  async function decline(): Promise<void> {
    setBusy(true);
    try {
      await mutateApi(() => api.declineLearnedSources(tunnel.id), [keys.learned(tunnel.id)]);
      Message.info(t('tunnelDetail:learn.declined'));
    } catch (e) {
      Message.error(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      size="small"
      bordered
      title={t('tunnelDetail:learn.title')}
      extra={
        data?.observed_from && !data.observed_from.startsWith('0001-') ? (
          <span className="muted-note">
            {t('tunnelDetail:learn.since', { at: formatDateTime(data.observed_from) })}
          </span>
        ) : null
      }
    >
      <div className="muted-note mb-8px">{t('tunnelDetail:learn.intro')}</div>

      {/* 截断优先级最高：它让整份列表不可信，所以摆在最前面且用警告色。 */}
      {data?.truncated ? (
        <Alert type="warning" className="mb-8px" content={t('tunnelDetail:learn.truncated')} />
      ) : null}

      <Alert
        type={alreadyNarrowed ? 'info' : 'warning'}
        className="mb-8px"
        content={t(alreadyNarrowed ? 'tunnelDetail:learn.already' : 'tunnelDetail:learn.open')}
      />

      <Table
        size="mini"
        rowKey="cidr"
        pagination={false}
        data={sources}
        noDataElement={<div className="muted-note py-12px">{t('tunnelDetail:learn.empty')}</div>}
        columns={[
          {
            title: '',
            width: 40,
            render: (_: unknown, s: LearnedSource) => (
              <Checkbox
                checked={checked.includes(s.cidr)}
                onChange={(on) =>
                  setChecked((prev) =>
                    on ? [...prev, s.cidr] : prev.filter((c) => c !== s.cidr),
                  )
                }
              />
            ),
          },
          {
            title: t('tunnelDetail:learn.cidr'),
            dataIndex: 'cidr',
            render: (_: unknown, s: LearnedSource) => <span className="nfr-mono">{s.cidr}</span>,
          },
          {
            title: t('tunnelDetail:learn.hits'),
            dataIndex: 'hits',
            width: 80,
            render: (_: unknown, s: LearnedSource) => (
              // 只出现过一次的地址不着色：它是「扫描器还是客户端」这个判断里
              // 最强的一个信号，值得在视觉上先被排除掉。
              //
              // 两个分支各写一次 Tag 而不是把 color 传 undefined：
              // exactOptionalPropertyTypes 下 `color={x ? 'a' : undefined}`
              // 不是合法的「不传这个属性」——它真的会传一个 undefined 进去。
              s.hits > 1 ? (
                <Tag size="small" color="arcoblue">
                  {formatCount(s.hits)}
                </Tag>
              ) : (
                <Tag size="small">{formatCount(s.hits)}</Tag>
              )
            ),
          },
          {
            title: t('tunnelDetail:learn.lastSeen'),
            dataIndex: 'last_seen',
            width: 150,
            render: (_: unknown, s: LearnedSource) => (
              <span className="nfr-mono text-3">{formatDateTime(s.last_seen)}</span>
            ),
          },
        ]}
      />

      {sources.length > 0 ? (
        <>
          <div className="muted-note mt-6px">{t('tunnelDetail:learn.hint')}</div>
          <div className="muted-note">{t('tunnelDetail:learn.volatile')}</div>
          <Space className="mt-8px">
            <Button type="primary" size="small" loading={busy} onClick={apply}>
              {checked.length > 0
                ? t('tunnelDetail:learn.applyN', { count: checked.length })
                : t('tunnelDetail:learn.apply')}
            </Button>
            {/* 「保持开放」只在还没收窄、且还没拒绝过时才有意义。 */}
            {!alreadyNarrowed && !data?.declined ? (
              <Button size="small" disabled={busy} onClick={decline}>
                {t('tunnelDetail:learn.decline')}
              </Button>
            ) : null}
            {data?.declined ? (
              <span className="muted-note">{t('tunnelDetail:learn.declined')}</span>
            ) : null}
          </Space>
        </>
      ) : null}
    </Card>
  );
}
