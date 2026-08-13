import { Button, Card, Input, Message, Modal, Table, Tag, Tooltip } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { api, ApiError } from '@/api/client';
import { useSettings, useTunnels } from '@/api/hooks';
import type { ConfigApplyResult, ConfigDiff, SettingItem, Tunnel } from '@/api/types';
import EmptyAction from '@/components/EmptyAction';
import ProvenanceTag from '@/components/ProvenanceTag';

/**
 * 设置：生效配置 + **来源**，加一个先校验后应用的编辑器。
 *
 * 修的是 frp 的 `PUT /api/config` 会把未校验的字节直接落盘（下次启动直接砖），
 * UI 还只是个裸 textarea。这里写入必须先过 `:validate` 再 `:apply`。
 *
 * # 为什么「删除」那一栏要单独做成一段警告 + 一次确认
 *
 * 这是一份**声明式**文档：不在清单里的隧道会被删掉。而用户的直觉往往是
 * 「我加一条」，于是他粘进去一条隧道就按应用 —— 那会删掉其余全部。
 * 只显示条数不够（「删除 3」看起来像一个统计而不是一次操作），
 * 所以要逐条列 slug，并且在真的要删东西时挡一次。
 */
/**
 * 把一条隧道压成模板里的一项。
 *
 * 空值**整项省掉**而不是写成 "" / 0：后端认这些键，但一份满是
 * `"agent_id": ""` 的模板会让用户以为那些字段是必填的，
 * 而其中几个填了空值就过不了校验。
 *
 * 也**不含** id / short_id / state：前两个由中继分配，第三个是运行时观测
 * —— 把它们放进一份会被手改的文档里只会引出「我改了它为什么没用」。
 */
function templateEntry(x: Tunnel): Record<string, unknown> {
  const out: Record<string, unknown> = {
    slug: x.slug,
    kind: x.kind,
    tls: x.tls,
    exposure: x.exposure,
    l4: x.l4,
    backend: x.backend,
  };
  if (x.agent_id) out.agent_id = x.agent_id;
  if (x.listen_port) out.listen_port = x.listen_port;
  if (x.router) out.router = x.router;
  if (x.policy) out.policy = x.policy;
  if (x.enabled !== undefined) out.enabled = x.enabled;
  return out;
}

/**
 * 从一次失败响应里取出后端给的 diff（逐条校验错误在里面）。
 *
 * 判据是 `create` 是不是数组：一个普通的 APIError 信封里没有这个键，
 * 而只看 status 会把 404「端点不存在」也当成一份 diff 去渲染。
 */
function diffFromError(e: unknown): ConfigDiff | null {
  if (!(e instanceof ApiError)) return null;
  const body = e.body as Partial<ConfigDiff> | undefined;
  if (!body || !Array.isArray(body.create)) return null;
  return body as ConfigDiff;
}

export default function Settings(): React.JSX.Element {
  const { t } = useTranslation(['settings', 'common', 'errors']);
  const { data: groups, error, mutate } = useSettings();
  const { data: tunnels, mutate: mutateTunnels } = useTunnels();
  const [doc, setDoc] = useState('');
  const [diff, setDiff] = useState<ConfigDiff | null>(null);
  const [busy, setBusy] = useState(false);

  if (error || (groups?.length ?? 0) === 0) {
    return (
      <EmptyAction
        title={t('settings:empty.title')}
        actionLabel={t('settings:empty.action')}
        onAction={() => void mutate()}
      />
    );
  }

  /** 校验通过 = 拿到了一份 ok 的 diff。「应用」在此之前一直是禁用的。 */
  const validated = diff?.ok === true;

  /**
   * 从当前配置生成一份模板。
   *
   * 这是编辑一份声明式文档唯一安全的起点：手写会漏掉现存隧道，
   * 而漏掉就等于删掉。
   */
  const fillTemplate = (): void => {
    setDoc(JSON.stringify({ version: 1, tunnels: (tunnels ?? []).map(templateEntry) }, null, 2));
    setDiff(null);
  };

  const validate = (): void => {
    setBusy(true);
    void api
      .validateConfig(doc)
      .then((res) => {
        setDiff(res);
        Message.success(t('settings:editor.ok'));
      })
      .catch((e: unknown) => {
        // 校验失败时后端回的是同一个 diff 结构（含逐条错误），
        // 所以失败也要把它渲染出来 —— 只弹一句「校验失败」等于让用户去猜。
        setDiff(diffFromError(e));
        Message.error(t('settings:editor.failed'));
      })
      .finally(() => setBusy(false));
  };

  const doApply = (): void => {
    setBusy(true);
    void api
      .applyConfig(doc)
      .then((res: ConfigApplyResult) => {
        void mutate();
        void mutateTunnels();
        setDiff(null);
        setDoc('');
        Message.success(
          t('settings:editor.applied', {
            create: res.create.length,
            update: res.update.length,
            delete: res.delete.length,
          }),
        );
      })
      .catch((e: unknown) => {
        // 失败也要刷新：partial_apply 与 apply_failed 都已经改了库，
        // 不刷的话界面上是改动之前的样子，而用户正要照着它决定下一步。
        void mutate();
        void mutateTunnels();
        // 三种失败要说三句不同的话。混成一句「失败」会让用户在
        // 「什么都没写」与「写了一半」之间无从判断，而那两种的下一步完全不同。
        if (e instanceof ApiError && e.code === 'partial_apply') {
          const applied = (e.body as { applied?: number } | undefined)?.applied ?? 0;
          Message.error(t('settings:editor.partial', { applied }));
        } else if (e instanceof ApiError && e.code === 'apply_failed') {
          Message.error(`${t('settings:editor.savedNotRunning')} ${e.message}`);
        } else {
          setDiff(diffFromError(e));
          Message.error(t('settings:editor.failed'));
        }
      })
      .finally(() => setBusy(false));
  };

  /**
   * 要删东西时挡一次。
   *
   * 用 Modal 而不是 Popconfirm：确认文案里要**逐条列出** slug，
   * 而一个气泡放不下几行。用户需要看到名字才可能发现自己漏了一条。
   */
  const apply = (): void => {
    const doomed = diff?.delete ?? [];
    if (doomed.length === 0) {
      doApply();
      return;
    }
    Modal.confirm({
      title: t('settings:editor.confirmTitle', { count: doomed.length }),
      // 分隔符也走 locale：中文用「、」而英文用「, 」，
      // 写死一个会让另一种语言读起来像乱码。
      content: t('settings:editor.confirmBody', {
        slugs: doomed.join(t('common:listSeparator')),
      }),
      okButtonProps: { status: 'danger' },
      onOk: doApply,
    });
  };

  return (
    <div className="flex flex-col gap-16px">
      {(groups ?? []).map((g) => (
        <Card
          key={g.group}
          size="small"
          bordered
          title={t(`settings:group.${g.group}` as 'settings:group.other', { defaultValue: g.group })}
        >
          <Table
            size="small"
            rowKey="key"
            pagination={false}
            data={g.items}
            columns={[
              {
                title: t('settings:column.key'),
                dataIndex: 'key',
                width: 260,
                render: (_: unknown, it: SettingItem) => <span className="nfr-mono">{it.key}</span>,
              },
              {
                title: t('settings:column.value'),
                dataIndex: 'value',
                render: (_: unknown, it: SettingItem) => (
                  <span className="nfr-mono">{it.value}</span>
                ),
              },
              {
                title: t('settings:column.provenance'),
                dataIndex: 'provenance',
                width: 240,
                render: (_: unknown, it: SettingItem) => (
                  <ProvenanceTag
                    provenance={it.provenance}
                    {...(it.source_ref ? { sourceRef: it.source_ref } : {})}
                  />
                ),
              },
              {
                title: t('settings:column.actions'),
                dataIndex: 'actions',
                width: 180,
                // 文件管理的行**禁用编辑并给原因**，不是隐藏。
                render: (_: unknown, it: SettingItem) =>
                  it.editable ? (
                    <Button size="mini" type="text">
                      {t('common:action.edit')}
                    </Button>
                  ) : (
                    <Tooltip
                      content={t('common:provenance.fileManagedTip', {
                        ref: it.source_ref ?? '',
                      })}
                    >
                      <Button size="mini" type="text" disabled>
                        {t('common:provenance.copyToConsole')}
                      </Button>
                    </Tooltip>
                  ),
              },
            ]}
          />
        </Card>
      ))}

      <Card size="small" bordered title={t('settings:editor.title')}>
        <div className="flex flex-col gap-8px">
          <span className="muted-note">{t('settings:editor.docNote')}</span>
          <Input.TextArea
            value={doc}
            onChange={(v: string) => {
              setDoc(v);
              // 文档一改，上一次的 diff 就不再描述这份文档了。留着它意味着
              // 「应用」对着一份用户已经改过的文档还是启用的。
              setDiff(null);
            }}
            autoSize={{ minRows: 6, maxRows: 20 }}
            style={{ fontFamily: 'ui-monospace, Menlo, Consolas, monospace', fontSize: 12 }}
          />
          <div className="flex items-center gap-8px">
            <Button size="small" onClick={fillTemplate} disabled={busy}>
              {t('settings:editor.template')}
            </Button>
            <Button size="small" loading={busy} onClick={validate} disabled={doc.trim() === ''}>
              {t('settings:editor.validate')}
            </Button>
            <Button
              size="small"
              type="primary"
              status={(diff?.delete.length ?? 0) > 0 ? 'danger' : 'default'}
              disabled={!validated}
              loading={busy}
              onClick={apply}
            >
              {t('settings:editor.apply')}
            </Button>
            <span className="muted-note">{t('settings:editor.note')}</span>
          </div>

          {diff ? <ConfigDiffView diff={diff} /> : null}
        </div>
      </Card>
    </div>
  );
}

/**
 * 干跑结果。
 *
 * 三栏都**逐条列 slug** 而不是只给条数：「删除 3」看起来像一个统计，
 * 而它其实是一次不可逆的操作。用户要看到名字才可能发现自己漏了一条。
 */
function ConfigDiffView({ diff }: { diff: ConfigDiff }): React.JSX.Element {
  const { t } = useTranslation(['settings', 'common']);
  const rows: Array<{ key: string; color: string; slugs: string[] }> = [
    { key: 'create', color: 'green', slugs: diff.create },
    { key: 'update', color: 'arcoblue', slugs: diff.update },
    { key: 'delete', color: 'red', slugs: diff.delete },
  ];
  const quiet =
    diff.ok && diff.create.length === 0 && diff.update.length === 0 && diff.delete.length === 0;

  return (
    <div className="flex flex-col gap-6px mt-8px">
      <strong>{t('settings:editor.diffTitle')}</strong>

      {diff.errors?.length
        ? diff.errors.map((e) => (
            <div key={`${e.index}-${e.slug ?? ''}`} className="text-#f53f3f">
              {t('settings:editor.errorAt', { index: e.index + 1 })}
              {e.slug ? ` (${e.slug})` : ''}:{' '}
              {e.detail ?? (e.fields ?? []).map((f) => f.message).join('; ')}
            </div>
          ))
        : null}

      {rows.map((r) =>
        r.slugs.length === 0 ? null : (
          <div key={r.key} className="flex items-baseline gap-6px flex-wrap">
            <Tag color={r.color} size="small">
              {t(`settings:editor.${r.key}` as 'settings:editor.create')} {r.slugs.length}
            </Tag>
            <span className="nfr-mono">{r.slugs.join(t('common:listSeparator'))}</span>
          </div>
        ),
      )}

      {diff.unchanged > 0 ? (
        <span className="muted-note">
          {t('settings:editor.unchanged')} {diff.unchanged}
        </span>
      ) : null}

      {diff.delete.length > 0 ? (
        <div className="text-#f53f3f">
          {t('settings:editor.deleteWarning', { count: diff.delete.length })}
        </div>
      ) : null}

      {quiet ? <span className="muted-note">{t('settings:editor.nothingToDo')}</span> : null}
    </div>
  );
}
