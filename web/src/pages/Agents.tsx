import {
  Alert,
  Button,
  Input,
  InputNumber,
  Message,
  Modal,
  Space,
  Table,
  Tag,
  Tooltip,
} from '@arco-design/web-react';
import { QRCodeSVG } from 'qrcode.react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, api } from '@/api/client';
import { useAgents, useStreamHealth } from '@/api/hooks';
import { keys } from '@/api/keys';
import { useApiMutate } from '@/api/hooks';
import type { AgentStatus, DesktopPairingInvite, EnrolToken } from '@/api/types';
import CopyBlock from '@/components/CopyBlock';
import EmptyAction from '@/components/EmptyAction';
import TypeToConfirm from '@/components/TypeToConfirm';
import { relativeTime } from '@/utils/format';
import { externallyReachable } from '@/utils/reachable';

const DEFAULT_DESKTOP_LISTEN_PORT = 25808;
const DEFAULT_PAIRING_TTL_SECONDS = 600;

export function encodeDesktopPairingString(
  invite: DesktopPairingInvite,
  origin: string,
): string {
  const payload = JSON.stringify({
    bootstrap_url: `${origin}/api/bootstrap/desktop`,
    invite: invite.token,
    expires_at: invite.expires_at,
  });
  const bytes = new TextEncoder().encode(payload);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `nomifun-relay-pair:v1:${encoded}`;
}

function formatPairingExpiry(expiresAt: string): string {
  const date = new Date(expiresAt);
  return Number.isNaN(date.getTime()) ? expiresAt : date.toLocaleString();
}

function PairingInvitePanel(): React.JSX.Element {
  const { t } = useTranslation(['agents', 'common']);
  const [visible, setVisible] = useState(false);
  const [ttlSeconds, setTtlSeconds] = useState(DEFAULT_PAIRING_TTL_SECONDS);
  const [listenPort, setListenPort] = useState(DEFAULT_DESKTOP_LISTEN_PORT);
  const [note, setNote] = useState('');
  const [invite, setInvite] = useState<DesktopPairingInvite | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const create = (): void => {
    setBusy(true);
    setError('');
    void api
      .createDesktopPairingInvite(ttlSeconds, listenPort, note)
      .then(setInvite)
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('pairing.error'));
      })
      .finally(() => setBusy(false));
  };

  const pairingString =
    invite === null ? null : encodeDesktopPairingString(invite, window.location.origin);

  return (
    <>
      <Button type="secondary" onClick={() => setVisible(true)}>
        {t('pairing.action')}
      </Button>
      <Modal
        visible={visible}
        title={t('pairing.title')}
        confirmLoading={busy}
        okText={t('pairing.create')}
        cancelText={t('common:action.cancel')}
        onOk={create}
        onCancel={() => {
          if (!busy) setVisible(false);
        }}
      >
        <div className="flex flex-col gap-12px">
          {error ? <Alert type="error" content={error} /> : null}
          <label className="flex flex-col gap-4px">
            <span className="text-13px">{t('pairing.ttl')}</span>
            <InputNumber
              min={1}
              max={86_400}
              value={ttlSeconds}
              onChange={(value) => setTtlSeconds(value ?? DEFAULT_PAIRING_TTL_SECONDS)}
            />
          </label>
          <label className="flex flex-col gap-4px">
            <span className="text-13px">{t('pairing.listenPort')}</span>
            <InputNumber
              min={1}
              max={65_535}
              value={listenPort}
              onChange={(value) => setListenPort(value ?? DEFAULT_DESKTOP_LISTEN_PORT)}
            />
          </label>
          <label className="flex flex-col gap-4px">
            <span className="text-13px">{t('pairing.note')}</span>
            <Input value={note} onChange={setNote} maxLength={200} />
          </label>
          {invite && pairingString ? (
            <div className="flex flex-col gap-10px">
              <div className="muted-note">
                {t('pairing.expires', { time: formatPairingExpiry(invite.expires_at) })}
              </div>
              <CopyBlock text={pairingString} label={t('pairing.string')} />
              <div className="flex flex-col items-start gap-4px">
                <span className="text-12px text-3">{t('pairing.qr')}</span>
                <div className="bg-white p-8px">
                  <QRCodeSVG value={pairingString} size={192} />
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </Modal>
    </>
  );
}

/** 入网命令面板。空态直接把它内联出来（空态 = 一个主操作）。 */
export function InstallPanel({ token }: { token: EnrolToken }): React.JSX.Element {
  const { t } = useTranslation('agents');
  const minutes = Math.max(
    1,
    Math.round((Date.parse(token.expires_at) - Date.now()) / 60_000),
  );
  const qrHost = (() => {
    if (token.qr_url === undefined) return null;
    try {
      return externallyReachable(new URL(token.qr_url).hostname) ? token.qr_url : null;
    } catch {
      return null;
    }
  })();

  return (
    <div className="flex flex-col gap-10px">
      <div className="text-13px font-medium">{t('install.title')}</div>
      <CopyBlock text={token.install_cmd} label={t('install.oneliner')} />
      {token.raw_cmd ? <CopyBlock text={token.raw_cmd} label={t('install.raw')} /> : null}
      {token.print_only_cmd ? (
        <CopyBlock
          text={token.print_only_cmd}
          label={t('install.printOnly')}
          note={t('install.printOnlyHint')}
        />
      ) : null}
      <div className="muted-note">{t('install.expires', { minutes })}</div>
      <div className="muted-note">{t('install.checksum')}</div>
      {qrHost === null ? (
        <div className="muted-note">{t('install.qrUnavailable')}</div>
      ) : (
        <div className="flex flex-col items-start gap-4px">
          <span className="text-12px text-3">{t('install.qr')}</span>
          <div className="bg-white p-8px">
            <QRCodeSVG value={qrHost} size={128} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function Agents(): React.JSX.Element {
  const { t } = useTranslation(['agents', 'common', 'errors']);
  useStreamHealth();
  const { data: agents, isLoading } = useAgents();
  const apiMutate = useApiMutate();

  const [token, setToken] = useState<EnrolToken | null>(null);
  const [showInstall, setShowInstall] = useState(false);
  const [revoking, setRevoking] = useState<AgentStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const issue = (note: string): void => {
    setBusy(true);
    void api
      .issueEnrolToken(note)
      .then((tk) => {
        setToken(tk);
        setShowInstall(true);
      })
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  /**
   * 轮换入网令牌 = 重新签发一枚。
   *
   * 令牌是一次性、只入网一个代理端的，所以「轮换」在语义上就是发一枚新的，
   * 而不是原地改一个长期密钥 —— 后者本身就是 frp 那种「抓一对凭据永久可用」的形状。
   */
  const rotate = (id: string): void => {
    setBusy(true);
    void api
      .issueEnrolToken(`rotate:${id}`)
      .then((tk: EnrolToken) => {
        setToken(tk);
        setShowInstall(true);
      })
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  const kick = (id: string): void => {
    void apiMutate(() => api.kickAgent(id), [keys.agents, keys.snapshot]).catch((err: unknown) => {
      Message.error(
        err instanceof ApiError && err.isMissingEndpoint
          ? t('errors:notImplemented')
          : t('errors:generic'),
      );
    });
  };

  const revoke = (): void => {
    const target = revoking;
    if (!target) return;
    setBusy(true);
    void apiMutate(() => api.revokeAgent(target.id), [keys.agents, keys.snapshot])
      .then(() => setRevoking(null))
      .catch(() => Message.error(t('errors:generic')))
      .finally(() => setBusy(false));
  };

  if (!isLoading && (agents?.length ?? 0) === 0) {
    return (
      <>
        <EmptyAction
          title={t('agents:empty.title')}
          actionLabel={t('agents:empty.action')}
          onAction={() => issue('bootstrap')}
        >
          {token ? <InstallPanel token={token} /> : null}
        </EmptyAction>
        <div className="flex justify-center">
          <PairingInvitePanel />
        </div>
      </>
    );
  }

  return (
    <div className="flex flex-col gap-12px">
      <div className="flex items-center gap-12px">
        <span className="text-16px font-semibold">
          {t('agents:count', { count: agents?.length ?? 0 })}
        </span>
        <div className="flex-1" />
        <Button type="primary" loading={busy} onClick={() => issue('console')}>
          {t('agents:empty.action')}
        </Button>
        <PairingInvitePanel />
      </div>

      <Table
        size="small"
        rowKey="id"
        loading={isLoading}
        data={agents ?? []}
        pagination={false}
        columns={[
          {
            title: t('agents:column.id'),
            dataIndex: 'id',
            render: (_: unknown, a: AgentStatus) => (
              <div className="flex flex-col leading-tight">
                <span className="font-medium">{a.hostname || a.id}</span>
                <span className="nfr-mono text-3 text-11px">{a.id}</span>
              </div>
            ),
          },
          {
            title: t('agents:online'),
            dataIndex: 'online',
            width: 100,
            render: (_: unknown, a: AgentStatus) =>
              a.revoked ? (
                <Tag size="small" color="red">
                  {t('agents:revoked')}
                </Tag>
              ) : (
                <Tag size="small" {...(a.online ? { color: 'green' } : {})}>
                  {a.online ? t('agents:online') : t('agents:offline')}
                </Tag>
              ),
          },
          { title: t('agents:column.version'), dataIndex: 'version', width: 110 },
          {
            title: t('agents:column.platform'),
            dataIndex: 'os',
            width: 130,
            render: (_: unknown, a: AgentStatus) => (
              <span className="nfr-mono">
                {a.os}/{a.arch}
              </span>
            ),
          },
          {
            title: t('agents:column.rung'),
            dataIndex: 'rung',
            width: 140,
            render: (_: unknown, a: AgentStatus) => (
              <Tooltip content={a.supports_datagram ? t('agents:datagram') : t('agents:noDatagram')}>
                <span className="nfr-mono">
                  {a.rung ?? t('agents:rungUnknown')}
                  {a.supports_datagram ? ' ·' : ''}
                </span>
              </Tooltip>
            ),
          },
          {
            // agent **自报**的 UDP 丢弃分项。
            //
            // 中继看不见这些：拨本地目标失败、被本地策略否决、回向发送队列满、
            // 回向超限、回向重组失败。它们正是「下行统计都对，就是收不到回包」
            // 的原因，而在这条上报之前**没有任何数字**能告诉运维为什么。
            //
            // 没收到过上报时显示「—」而不是 0 —— 0 会被读成「测过，是零」。
            title: t('agents:column.reported'),
            dataIndex: 'reported',
            width: 200,
            render: (_: unknown, a: AgentStatus) => {
              const r = a.reported;
              if (!r) return <span className="text-4">—</span>;
              const u = r.udp;
              const bad =
                u.dial_failed + u.denied + u.write_failed + u.send_queue_full + u.reasm_timed_out;
              const alarm = u.reasm_overlapping + u.reasm_too_many_frag;
              // 上报卡住了要看得出来 —— 否则一份十分钟前的数会被当成现在的。
              const ageSec = Math.max(0, Math.floor(Date.now() / 1000) - r.at_unix);
              const stale = ageSec > 30;
              return (
                <Tooltip
                  content={t('agents:reportedTip', {
                    dial: u.dial_failed,
                    denied: u.denied,
                    write: u.write_failed,
                    queue: u.send_queue_full,
                    timeout: u.reasm_timed_out,
                    age: ageSec,
                  })}
                >
                  <span className="nfr-mono text-13px">
                    <span style={stale ? { color: 'rgb(var(--warning-6))' } : undefined}>
                      {bad}
                    </span>
                    {alarm > 0 ? (
                      <span style={{ color: 'rgb(var(--danger-6))', fontWeight: 600 }}>
                        {' '}
                        ⚠{alarm}
                      </span>
                    ) : null}
                    {stale ? <span className="ml-4px text-12px">⏱</span> : null}
                  </span>
                </Tooltip>
              );
            },
          },
          {
            title: t('agents:column.lastSeen'),
            dataIndex: 'last_seen_at',
            width: 120,
            render: (_: unknown, a: AgentStatus) => {
              const rel = relativeTime(a.last_seen_at);
              return (
                <span className="text-3">
                  {rel === null
                    ? t('common:time.never')
                    : t(`common:time.${rel.key}` as 'common:time.justNow', { count: rel.count })}
                </span>
              );
            },
          },
          {
            title: t('agents:column.actions'),
            dataIndex: 'actions',
            width: 250,
            render: (_: unknown, a: AgentStatus) => (
              <Space size={4}>
                <Button size="mini" type="text" disabled={busy} onClick={() => rotate(a.id)}>
                  {t('agents:action.rotate')}
                </Button>
                <Button size="mini" type="text" disabled={!a.online} onClick={() => kick(a.id)}>
                  {t('agents:action.kick')}
                </Button>
                <Button
                  size="mini"
                  type="text"
                  status="danger"
                  disabled={a.revoked}
                  onClick={() => setRevoking(a)}
                >
                  {t('agents:action.revoke')}
                </Button>
              </Space>
            ),
          },
        ]}
      />

      <Modal
        visible={showInstall}
        title={t('agents:install.title')}
        footer={null}
        onCancel={() => setShowInstall(false)}
      >
        {token ? <InstallPanel token={token} /> : null}
      </Modal>

      {revoking === null ? null : (
        <TypeToConfirm
          visible
          slug={revoking.id}
          title={t('agents:revoke.title', { id: revoking.id })}
          warning={t('agents:revoke.warn')}
          okLoading={busy}
          onOk={revoke}
          onCancel={() => setRevoking(null)}
        />
      )}
    </div>
  );
}
