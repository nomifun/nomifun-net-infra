import { Alert, Button, Card, Input, InputNumber, Message, Modal, Table, Tag } from '@arco-design/web-react';
import { QRCodeSVG } from 'qrcode.react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, api } from '@/api/client';
import { useApiMutate, useDesktopConnections, useDesktopPreflight } from '@/api/hooks';
import { keys } from '@/api/keys';
import type { DesktopConnection, DesktopPairingInvite } from '@/api/types';
import CopyBlock from '@/components/CopyBlock';
import { encodeDesktopPairingString } from '@/utils/desktopPairing';

const DEFAULT_TTL = 600;

export default function DesktopConnect(): React.JSX.Element {
  const { t } = useTranslation(['desktop', 'common', 'errors']);
  const preflight = useDesktopPreflight();
  const connections = useDesktopConnections();
  const apiMutate = useApiMutate();
  const [note, setNote] = useState('');
  const [businessURL, setBusinessURL] = useState('');
  const [ttlSeconds, setTTLSeconds] = useState(DEFAULT_TTL);
  const [invite, setInvite] = useState<DesktopPairingInvite | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState<DesktopConnection | null>(null);

  useEffect(() => {
    setBusinessURL((value) => value || preflight.data?.default_business_url || '');
  }, [preflight.data?.default_business_url]);

  const create = (): void => {
    setError('');
    setBusy(true);
    setInvite(null);
    void apiMutate(
      () => api.createDesktopPairingInviteV2(ttlSeconds, note.trim(), businessURL.trim()),
      [keys.desktopConnections],
    )
      .then((out) => {
        if (out.protocol_version !== 2 || !out.bootstrap_url) {
          throw new Error(t('desktop:errors.contract'));
        }
        setInvite(out);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : t('errors:generic')))
      .finally(() => setBusy(false));
  };

  const revoke = (): void => {
    if (!revoking) return;
    const target = revoking;
    setBusy(true);
    void apiMutate(() => api.revokeDesktopConnection(target.invite_id), [
      keys.desktopConnections, keys.tunnels, keys.agents, keys.snapshot,
    ])
      .then(() => {
        setRevoking(null);
        if (invite?.id === target.invite_id) setInvite(null);
        Message.success(t('desktop:revoke.done'));
      })
      .catch((err: unknown) => Message.error(err instanceof Error ? err.message : t('errors:generic')))
      .finally(() => setBusy(false));
  };

  const pairingString = invite ? encodeDesktopPairingString(invite) : '';
  const loadError = preflight.error ?? connections.error;

  return (
    <div className="flex flex-col gap-16px">
      <div>
        <h1 className="mb-8px text-20px font-semibold">{t('desktop:title')}</h1>
        <p className="m-0 text-2">{t('desktop:description')}</p>
      </div>
      {loadError ? (
        <Alert type="error" content={
          loadError instanceof ApiError && loadError.isMissingEndpoint
            ? t('desktop:errors.upgrade') : loadError.message
        } action={<Button onClick={() => {
          void preflight.mutate(); void connections.mutate();
        }}>{t('common:action.retry')}</Button>} />
      ) : null}
      <Card title={t('desktop:preflight.title')} loading={preflight.isLoading}>
        <div className="flex flex-col gap-12px">
          <Alert type={preflight.data?.ready ? 'info' : 'warning'}
            content={preflight.data?.ready ? t('desktop:preflight.ready') : t('desktop:preflight.blocked')} />
          <div className="muted-note">{t('desktop:preflight.addresses')}</div>
          {preflight.data?.bootstrap_url ? <CopyBlock text={preflight.data.bootstrap_url}
            label={t('desktop:preflight.bootstrap')} /> : null}
          <div className="flex flex-col gap-8px">
            {(preflight.data?.checks ?? []).map((check) => (
              <div key={check.code} className="flex items-start gap-8px">
                <Tag color={check.ok ? 'green' : 'orange'}>{check.ok ? t('desktop:preflight.ok') : t('desktop:preflight.fix')}</Tag>
                <span className="text-2">{t(`desktop:check.${check.code}` as 'desktop:check.bootstrap_url', { defaultValue: check.message })}</span>
              </div>
            ))}
          </div>
          <div><Button size="small" loading={preflight.isValidating}
            onClick={() => void preflight.mutate()}>{t('desktop:preflight.retry')}</Button></div>
        </div>
      </Card>
      <Card title={t('desktop:invite.title')}>
        <div className="flex flex-col gap-12px max-w-760px">
          {error ? <Alert type="error" content={error} /> : null}
          <label className="flex flex-col gap-4px">
            <span>{t('desktop:invite.name')}</span>
            <Input value={note} onChange={setNote} maxLength={200}
              placeholder={t('desktop:invite.namePlaceholder')} disabled={busy} />
          </label>
          <label className="flex flex-col gap-4px">
            <span>{t('desktop:invite.businessURL')}</span>
            <Input value={businessURL} onChange={setBusinessURL}
              placeholder="https://desktop.example.com" disabled={busy} />
            <span className="muted-note">{t('desktop:invite.businessHint')}</span>
          </label>
          <details>
            <summary className="cursor-pointer text-2">{t('desktop:invite.advanced')}</summary>
            <label className="mt-8px flex flex-col gap-4px max-w-260px">
              <span>{t('desktop:invite.ttl')}</span>
              <InputNumber min={60} max={86_400} value={ttlSeconds}
                onChange={(value) => setTTLSeconds(value ?? DEFAULT_TTL)} disabled={busy} />
            </label>
          </details>
          <div><Button type="primary" loading={busy}
            disabled={preflight.data?.ready !== true || !!preflight.error || !note.trim()}
            onClick={create}>{t('desktop:invite.create')}</Button></div>
          {invite ? (
            <div className="flex flex-col gap-12px">
              <Alert type="info" content={t('desktop:invite.next')} />
              <CopyBlock text={pairingString} label={t('desktop:invite.string')}
                note={t('desktop:invite.expires', { time: new Date(invite.expires_at).toLocaleString() })} />
              <div>
                <p className="muted-note">{t('desktop:invite.qrHint')}</p>
                <div className="inline-block bg-white p-8px"><QRCodeSVG value={pairingString} size={192} /></div>
              </div>
              <Button type="text" onClick={() => setInvite(null)}>{t('desktop:invite.hide')}</Button>
            </div>
          ) : null}
        </div>
      </Card>
      <Card title={t('desktop:connections.title')}>
        <p className="muted-note">{t('desktop:connections.evidence')}</p>
        <Table rowKey="invite_id" data={connections.data ?? []} loading={connections.isLoading}
          pagination={false} noDataElement={t('desktop:connections.empty')}
          columns={[
            { title: t('desktop:invite.name'), dataIndex: 'note',
              render: (_: unknown, row: DesktopConnection) => row.note || row.invite_id },
            { title: t('desktop:invite.businessURL'), dataIndex: 'business_url',
              render: (_: unknown, row: DesktopConnection) => <span className="nfr-mono">{row.business_url || '—'}</span> },
            { title: t('desktop:connections.state'), dataIndex: 'state',
              render: (_: unknown, row: DesktopConnection) => <div className="flex flex-col gap-4px">
                <span>{t(`desktop:state.${row.state}` as 'desktop:state.waiting', { defaultValue: row.state })}</span>
                {row.reason ? <span className="muted-note">{row.reason}</span> : null}
              </div> },
            { title: t('common:action.delete'), dataIndex: 'actions', width: 140,
              render: (_: unknown, row: DesktopConnection) => <Button size="small" type="text"
                status="danger" disabled={row.revoked || busy}
                onClick={() => setRevoking(row)}>{t('desktop:revoke.action')}</Button> },
          ]} />
      </Card>
      <Modal visible={revoking !== null} title={t('desktop:revoke.title')}
        okText={t('desktop:revoke.action')} confirmLoading={busy} onOk={revoke}
        onCancel={() => { if (!busy) setRevoking(null); }}>
        {t('desktop:revoke.warning', { name: revoking?.note || revoking?.invite_id || '' })}
      </Modal>
    </div>
  );
}
