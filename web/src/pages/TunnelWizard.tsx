import {
  Button,
  Card,
  Checkbox,
  Input,
  InputNumber,
  InputTag,
  Message,
  Radio,
  Select,
  Steps,
  Tooltip,
} from '@arco-design/web-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';

import { ApiError, api, type FieldError } from '@/api/client';
import { useAgents, useTunnelBySlug } from '@/api/hooks';
import { keys } from '@/api/keys';
import { shapeErrors } from '@/api/schema';
import type { TLSMode, TunnelDraft } from '@/api/types';
import CopyBlock from '@/components/CopyBlock';
import ModeChooser from '@/components/ModeChooser';
import ProbeModal from '@/components/ProbeModal';
import { exposureSummary } from '@/utils/endpoint';
import { TEMPLATES, draftFromTunnel, emptyDraft } from '@/utils/templates';
import { useApiMutate } from '@/api/hooks';

const STEPS = ['target', 'protocol', 'mode', 'exposure', 'test'] as const;

/**
 * 表单补丁类型。
 *
 * exactOptionalPropertyTypes 下 `Partial<T>` 不接受显式 undefined，而清空
 * router / policy 恰恰要传 undefined（那是「这条隧道没有分流规则」的表达），
 * 所以这里显式把 undefined 并进去。
 */
type DraftPatch = { [K in keyof TunnelDraft]?: TunnelDraft[K] | undefined };

/**
 * 新建 / 编辑隧道向导。
 *
 * 三条硬约束（dossier 11 §PART B + spec §8.3）：
 * 1. 模式是**两张并排单选卡**，不是下拉框（ModeChooser）。
 * 2. 网关独有字段在直通下**置灰并给原因**，不隐藏 —— 用户要学到代价。
 * 3. 暴露面摘要从真实配置算出；`0.0.0.0/0` 且既无允许列表又无鉴权时
 *    要求**逐字输入名称**确认。绝不把随机高位端口当作安全措施。
 */
export default function TunnelWizard(): React.JSX.Element {
  const { t } = useTranslation(['tunnels', 'common', 'errors']);
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { slug: editSlug } = useParams<{ slug: string }>();

  const templateID = params.get('template');
  const duplicateOf = params.get('from');
  const template = TEMPLATES.find((x) => x.id === templateID);

  const { tunnel: existing } = useTunnelBySlug(editSlug ?? duplicateOf ?? undefined);
  const { data: agents } = useAgents();
  const apiMutate = useApiMutate();

  const [step, setStep] = useState(0);
  const [draft, setDraft] = useState<TunnelDraft>(() => template?.draft ?? emptyDraft());
  const [useAgent, setUseAgent] = useState(true);
  const [confirmText, setConfirmText] = useState('');
  const [serverErrors, setServerErrors] = useState<FieldError[]>([]);
  const [busy, setBusy] = useState(false);
  const [probing, setProbing] = useState(false);
  const [preview, setPreview] = useState<{ agent_yaml: string; relay_yaml: string } | null>(null);

  // 编辑 / 复制：等隧道读回来再灌进表单。
  useEffect(() => {
    if (!existing) return;
    setDraft({
      ...draftFromTunnel(existing),
      // 复制时不能同名：slug 是唯一键，同名会被后端 409。
      ...(editSlug === undefined ? { slug: `${existing.slug}-copy` } : {}),
    });
    setUseAgent(Boolean(existing.agent_id));
  }, [existing, editSlug]);

  const patch = (p: DraftPatch): void =>
    setDraft((d) => {
      const next: Record<string, unknown> = { ...d, ...p };
      // 显式传 undefined 的语义是「删掉这个字段」，不是「把它设成 undefined」——
      // exactOptionalPropertyTypes 下这两件事是不同的类型，也是不同的线协议。
      for (const [k, v] of Object.entries(p)) if (v === undefined) delete next[k];
      return next as unknown as TunnelDraft;
    });

  const shapeBad = shapeErrors(draft.slug, draft.backend.addr ?? '');
  const serverFor = (path: string): string | undefined =>
    serverErrors.find((e) => e.path === path)?.message;

  const summary = useMemo(
    () =>
      exposureSummary({
        id: '',
        tenant_id: 'default',
        state: 'draft',
        ...draft,
      }),
    [draft],
  );

  const isOpenExposure =
    draft.exposure === 'port' && (draft.policy?.allow_cidrs?.length ?? 0) === 0 && !summary.hasAuth;
  const needsTypedConfirm = isOpenExposure && confirmText !== draft.slug;

  const passthroughDisabled =
    (template?.requiresHostRewrite ?? false) || (draft.router?.host_rewrite ?? '') !== ''
      ? t('tunnels:wizard.mode.disabledHostRewrite')
      : undefined;

  // 直通选不了 http 分流（读不到明文），所以 router.kind 跟着模式走。
  const setMode = (tls: TLSMode): void => {
    if (draft.exposure === 'shared') {
      patch({
        tls,
        router: {
          ...(draft.router ?? { kind: 'http' }),
          kind: tls === 'gateway' ? 'http' : 'tls-sni',
          // tls-sni 无法按路径分流、无法改写 Host —— 那都要求解密。
          ...(tls === 'gateway' ? {} : { locations: [], host_rewrite: '' }),
        },
      });
    } else {
      patch({ tls });
    }
  };

  const submit = (): void => {
    setBusy(true);
    setServerErrors([]);
    // 提交前先跑一次服务端 dry-run —— 这修掉的正是 frp store API 的缺陷：
    // 控制台接受一个中继稍后才拒绝的端口，表现为隧道进 error 相而不是写入时 400。
    // 先 dry-run 再写：校验失败是 400 + fields，由 catch 分支高亮所有坏字段。
    void api
      .validateTunnel(draft)
      .then(() =>
        apiMutate(
          () =>
            existing !== undefined && editSlug !== undefined
              ? api.updateTunnel(existing.id, draft)
              : api.createTunnel(draft),
          [keys.tunnels, keys.snapshot],
        ).then((saved) => {
          Message.success(
            editSlug === undefined
              ? t('tunnels:toast.created', { slug: saved.slug })
              : t('tunnels:toast.updated', { slug: saved.slug }),
          );
          void navigate(`/tunnels/${saved.slug}`);
        }),
      )
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.fields.length > 0) {
          setServerErrors(err.fields);
          Message.error(t('tunnels:wizard.validateFailed'));
        } else {
          Message.error(t('errors:generic'));
        }
      })
      .finally(() => setBusy(false));
  };

  const loadPreview = (): void => {
    void api
      .previewConfig(draft)
      .then(setPreview)
      .catch((err: unknown) => {
        setPreview(null);
        Message.warning(
          err instanceof ApiError && err.isMissingEndpoint
            ? t('errors:notImplemented')
            : t('errors:generic'),
        );
      });
  };

  const agentOptions = (agents ?? [])
    .filter((a) => !a.revoked)
    .map((a) => ({
      label: `${a.hostname || a.id} · ${a.os}/${a.arch}${a.online ? '' : ' ·'}`,
      value: a.id,
    }));

  return (
    <div className="mx-auto max-w-900px flex flex-col gap-16px">
      <div className="text-16px font-semibold">
        {editSlug === undefined
          ? t('tunnels:wizard.title')
          : t('tunnels:wizard.editTitle', { slug: editSlug })}
      </div>

      <Steps current={step + 1} size="small" onChange={(c: number) => setStep(c - 1)}>
        {STEPS.map((s) => (
          <Steps.Step key={s} title={t(`tunnels:wizard.step.${s}` as const)} />
        ))}
      </Steps>

      <Card size="small" bordered>
        {step === 0 ? (
          <div className="flex flex-col gap-14px">
            <label className="flex flex-col gap-4px">
              <span className="text-13px">{t('tunnels:wizard.target.slug')}</span>
              <Input
                value={draft.slug}
                onChange={(v: string) => patch({ slug: v })}
                {...(shapeBad.has('slug') && draft.slug !== ''
                  ? { status: 'error' as const }
                  : {})}
              />
              <span className="muted-note">
                {serverFor('slug') ?? t('tunnels:wizard.target.slugHint')}
              </span>
            </label>

            <div className="flex flex-col gap-6px">
              <span className="text-13px">{t('tunnels:wizard.target.source')}</span>
              <Radio.Group
                value={useAgent ? 'agent' : 'relay'}
                onChange={(v: string) => {
                  const on = v === 'agent';
                  setUseAgent(on);
                  // 中继直拨那条路径不经过 agent，所以 kind 也随之改变。
                  patch(on ? { kind: 'service' } : { kind: 'reverse', agent_id: '' });
                }}
                options={[
                  { label: t('tunnels:wizard.target.withAgent'), value: 'agent' },
                  // 「中继直接拨号」**禁用而不隐藏**。
                  //
                  // 这条路径在数据面不存在：三个入口（裸端口 TCP、网关、UDP）
                  // 全都调 SessionFor(t.AgentID)，返回 false 就放弃，没有任何
                  // 回落。而这个选项此前是可选的，选中后 patch 出
                  // { kind: 'reverse', agent_id: '' } —— 用户于是拿到一条
                  // 永远停在「等待代理端上线」的隧道（对一个明确选了「不要
                  // agent」的人，那是一句永远不会奏效的下一步），或者在恰好
                  // 一个 agent 在线时被静默绑到那个 agent 上，行为与所选相反。
                  //
                  // 禁用而不是删掉，是本仓既有的口径（见 SettingItem.Editable
                  // 的注释）：隐藏会让用户以为这一项不存在，然后去别处找。
                  // 禁用 + 说明理由，他才知道这是「还没做」而不是「我找错了」。
                  {
                    label: t('tunnels:wizard.target.withoutAgent'),
                    value: 'relay',
                    disabled: true,
                  },
                ]}
              />
              <span className="muted-note">
                {useAgent
                  ? t('tunnels:wizard.target.withAgentHint')
                  : t('tunnels:wizard.target.withoutAgentHint')}
              </span>
            </div>

            {useAgent ? (
              <label className="flex flex-col gap-4px">
                <span className="text-13px">{t('tunnels:wizard.target.agent')}</span>
                <Select
                  placeholder={
                    agentOptions.length === 0
                      ? t('tunnels:wizard.target.noAgents')
                      : t('tunnels:wizard.target.agentPlaceholder')
                  }
                  {...(draft.agent_id ? { value: draft.agent_id } : {})}
                  options={agentOptions}
                  onChange={(v: string) => patch({ agent_id: v })}
                />
                {serverFor('agent_id') ? (
                  <span className="text-12px" style={{ color: 'rgb(var(--danger-6))' }}>
                    {serverFor('agent_id')}
                  </span>
                ) : null}
              </label>
            ) : null}

            <label className="flex flex-col gap-4px">
              <span className="text-13px">{t('tunnels:wizard.target.addr')}</span>
              <Input
                value={draft.backend.addr ?? ''}
                placeholder={t('tunnels:wizard.target.addrPlaceholder')}
                onChange={(v: string) => patch({ backend: { kind: 'addr', addr: v } })}
                {...(shapeBad.has('addr') && (draft.backend.addr ?? '') !== ''
                  ? { status: 'error' as const }
                  : {})}
              />
              <span className="muted-note">
                {serverFor('backend.addr') ?? t('tunnels:wizard.target.addrHint')}
              </span>
            </label>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="flex flex-col gap-14px">
            <div className="flex flex-col gap-6px">
              <span className="text-13px">{t('tunnels:wizard.protocol.l4')}</span>
              <Radio.Group
                type="button"
                value={draft.l4}
                onChange={(v: 'tcp' | 'udp') =>
                  patch(v === 'udp' ? { l4: v, exposure: 'port', router: undefined } : { l4: v })
                }
                options={[
                  { label: t('common:l4.tcp'), value: 'tcp' },
                  { label: t('common:l4.udp'), value: 'udp' },
                ]}
              />
              {draft.l4 === 'udp' ? (
                <span className="muted-note">{t('tunnels:wizard.protocol.udpHint')}</span>
              ) : null}
            </div>

            <div className="flex flex-col gap-6px">
              <span className="text-13px">{t('tunnels:wizard.protocol.exposure')}</span>
              <Radio.Group
                value={draft.exposure}
                onChange={(v: 'port' | 'shared') =>
                  patch(
                    v === 'shared'
                      ? {
                          exposure: v,
                          router: { kind: draft.tls === 'gateway' ? 'http' : 'tls-sni', domains: [] },
                        }
                      : { exposure: v, router: undefined },
                  )
                }
              >
                <Radio value="port">{t('tunnels:wizard.protocol.exposurePort')}</Radio>
                <Tooltip
                  content={t('tunnels:wizard.protocol.sharedUdpDisabled')}
                  disabled={draft.l4 !== 'udp'}
                >
                  <Radio value="shared" disabled={draft.l4 === 'udp'}>
                    {t('tunnels:wizard.protocol.exposureShared')}
                  </Radio>
                </Tooltip>
              </Radio.Group>
            </div>

            {draft.exposure === 'port' ? (
              <label className="flex flex-col gap-4px">
                <span className="text-13px">{t('tunnels:wizard.protocol.listenPort')}</span>
                <InputNumber
                  min={0}
                  max={65_535}
                  className="w-200px"
                  {...(draft.listen_port ? { value: draft.listen_port } : {})}
                  onChange={(v: number | undefined) => patch({ listen_port: v ?? 0 })}
                />
                <span className="muted-note">
                  {serverFor('listen_port') ?? t('tunnels:wizard.protocol.listenPortHint')}
                </span>
              </label>
            ) : (
              <>
                <label className="flex flex-col gap-4px">
                  <span className="text-13px">{t('tunnels:wizard.protocol.domains')}</span>
                  <InputTag
                    placeholder={t('tunnels:wizard.protocol.domainsPlaceholder')}
                    value={draft.router?.domains ?? []}
                    onChange={(v: string[]) =>
                      patch({ router: { ...(draft.router ?? { kind: 'http' }), domains: v } })
                    }
                  />
                  <span className="muted-note">{t('tunnels:wizard.protocol.routerAuto')}</span>
                </label>

                {/* 网关独有：置灰 + 原因，不隐藏。 */}
                <Tooltip
                  content={t('tunnels:wizard.gatewayOnly.reason')}
                  disabled={draft.tls === 'gateway'}
                >
                  <label className="flex flex-col gap-4px">
                    <span className="text-13px">{t('tunnels:wizard.protocol.locations')}</span>
                    <InputTag
                      disabled={draft.tls !== 'gateway'}
                      placeholder={t('tunnels:wizard.protocol.locationsPlaceholder')}
                      value={draft.router?.locations ?? []}
                      onChange={(v: string[]) =>
                        patch({ router: { ...(draft.router ?? { kind: 'http' }), locations: v } })
                      }
                    />
                    <span className="muted-note">
                      {draft.tls === 'gateway' ? '' : t('tunnels:wizard.gatewayOnly.reason')}
                    </span>
                  </label>
                </Tooltip>

                <Tooltip
                  content={t('tunnels:wizard.gatewayOnly.reason')}
                  disabled={draft.tls === 'gateway'}
                >
                  <label className="flex flex-col gap-4px">
                    <span className="text-13px">{t('tunnels:wizard.protocol.hostRewrite')}</span>
                    <Input
                      disabled={draft.tls !== 'gateway'}
                      value={draft.router?.host_rewrite ?? ''}
                      onChange={(v: string) =>
                        patch({ router: { ...(draft.router ?? { kind: 'http' }), host_rewrite: v } })
                      }
                    />
                    <span className="muted-note">
                      {t('tunnels:wizard.protocol.hostRewriteHint')}
                    </span>
                  </label>
                </Tooltip>
              </>
            )}
          </div>
        ) : null}

        {step === 2 ? (
          <ModeChooser
            value={draft.tls}
            onChange={setMode}
            passthroughDisabledReason={passthroughDisabled}
          />
        ) : null}

        {step === 3 ? (
          <div className="flex flex-col gap-14px">
            <div className="text-15px font-medium">{t('tunnels:wizard.exposureStep.title')}</div>
            <div className="tile-card">
              <div className="nfr-mono text-13px">
                {t('tunnels:wizard.exposureStep.summary', {
                  addr: summary.addr,
                  source:
                    summary.sourceCount === 0
                      ? t('tunnels:wizard.exposureStep.sourceAny')
                      : t('tunnels:wizard.exposureStep.sourceList', { count: summary.sourceCount }),
                  auth: summary.hasAuth
                    ? t('tunnels:wizard.exposureStep.authSome')
                    : t('tunnels:wizard.exposureStep.authNone'),
                })}
              </div>
              <div className="muted-note mt-6px">{t('tunnels:wizard.exposureStep.note')}</div>
            </div>

            <label className="flex flex-col gap-4px">
              <span className="text-13px">{t('tunnels:wizard.exposureStep.allowList')}</span>
              <InputTag
                placeholder={t('tunnels:wizard.exposureStep.allowListPlaceholder')}
                value={draft.policy?.allow_cidrs ?? []}
                onChange={(v: string[]) => patch({ policy: { ...draft.policy, allow_cidrs: v } })}
              />
            </label>

            <div className="flex flex-wrap gap-12px">
              <label className="flex flex-col gap-4px">
                <span className="text-13px">{t('tunnels:wizard.exposureStep.maxConns')}</span>
                <InputNumber
                  min={0}
                  className="w-160px"
                  {...(draft.policy?.max_conns ? { value: draft.policy.max_conns } : {})}
                  onChange={(v: number | undefined) =>
                    patch({ policy: { ...draft.policy, max_conns: v ?? 0 } })
                  }
                />
              </label>
              <label className="flex flex-col gap-4px">
                {/*
                  每源 IP 上限。只有全局上限时，一个源 IP 就能占满它并把别人
                  挤出去 —— 「最多 N 路」保护的是中继不被压垮，不是保护其他用户。
                */}
                <span className="text-13px">{t('tunnels:wizard.exposureStep.maxConnsPerIP')}</span>
                <InputNumber
                  min={0}
                  className="w-160px"
                  {...(draft.policy?.max_conns_per_ip
                    ? { value: draft.policy.max_conns_per_ip }
                    : {})}
                  onChange={(v: number | undefined) =>
                    patch({ policy: { ...draft.policy, max_conns_per_ip: v ?? 0 } })
                  }
                />
              </label>
              <label className="flex flex-col gap-4px">
                <span className="text-13px">{t('tunnels:wizard.exposureStep.bytesPerSecond')}</span>
                <InputNumber
                  min={0}
                  className="w-180px"
                  {...(draft.policy?.bytes_per_second ? { value: draft.policy.bytes_per_second } : {})}
                  onChange={(v: number | undefined) =>
                    patch({ policy: { ...draft.policy, bytes_per_second: v ?? 0 } })
                  }
                />
              </label>
              <label className="flex flex-col gap-4px">
                <span className="text-13px">{t('tunnels:wizard.exposureStep.packetsPerSecond')}</span>
                <InputNumber
                  min={0}
                  className="w-180px"
                  {...(draft.policy?.packets_per_second
                    ? { value: draft.policy.packets_per_second }
                    : {})}
                  onChange={(v: number | undefined) =>
                    patch({ policy: { ...draft.policy, packets_per_second: v ?? 0 } })
                  }
                />
                <span className="muted-note w-180px">{t('tunnels:wizard.exposureStep.ppsHint')}</span>
              </label>
            </div>

            {isOpenExposure ? (
              <div className="flex flex-col gap-6px">
                <div className="text-13px" style={{ color: 'rgb(var(--warning-6))' }}>
                  {t('tunnels:wizard.exposureStep.confirmOpen')}
                </div>
                <Input
                  className="w-260px"
                  value={confirmText}
                  onChange={setConfirmText}
                  placeholder={t('common:typeToConfirm.label', { slug: draft.slug })}
                />
              </div>
            ) : null}
          </div>
        ) : null}

        {step === 4 ? (
          <div className="flex flex-col gap-14px">
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
            {serverErrors.length > 0 ? (
              <ul className="m-0 pl-18px text-13px" style={{ color: 'rgb(var(--danger-6))' }}>
                {serverErrors.map((e) => (
                  <li key={`${e.path}:${e.message}`}>
                    <span className="nfr-mono">{e.path}</span> {e.message}
                  </li>
                ))}
              </ul>
            ) : null}
            <Checkbox checked disabled>
              <span className="muted-note">{t('tunnels:wizard.probe.fromInternetHint')}</span>
            </Checkbox>
          </div>
        ) : null}
      </Card>

      <div className="flex items-center justify-end gap-8px">
        {step > 0 ? <Button onClick={() => setStep(step - 1)}>{t('common:action.back')}</Button> : null}
        {step < STEPS.length - 1 ? (
          <Button type="primary" onClick={() => setStep(step + 1)}>
            {t('common:action.next')}
          </Button>
        ) : (
          <>
            {editSlug === undefined ? null : (
              <Button onClick={() => setProbing(true)}>{t('common:action.test')}</Button>
            )}
            <Tooltip
              content={t('tunnels:wizard.exposureStep.confirmOpen')}
              disabled={!needsTypedConfirm}
            >
              <Button type="primary" loading={busy} disabled={needsTypedConfirm} onClick={submit}>
                {editSlug === undefined
                  ? t('tunnels:wizard.submit')
                  : t('tunnels:wizard.submitEdit')}
              </Button>
            </Tooltip>
          </>
        )}
      </div>

      {probing && existing !== undefined ? (
        <ProbeModal
          visible
          id={existing.id}
          slug={existing.slug}
          draft={draft}
          onClose={() => setProbing(false)}
        />
      ) : null}
    </div>
  );
}
