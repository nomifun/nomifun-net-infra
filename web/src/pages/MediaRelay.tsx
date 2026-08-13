import { Button, Message, Space, Table } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import { api } from '@/api/client';
import { useTurnAllocations } from '@/api/hooks';
import type { IceConfig, TurnAllocation } from '@/api/types';
import CopyBlock from '@/components/CopyBlock';
import EmptyAction from '@/components/EmptyAction';
import { formatBytes, formatDateTime, formatDuration } from '@/utils/format';

/**
 * 媒体中继（TURN 分配）。
 *
 * TURN 分配**故意不是 Tunnel**：它不由控制台创建，硬塞进隧道模型会破坏
 * 「Tunnel 是期望状态」这个定义。所以它有自己一屏。
 */
export default function MediaRelay(): React.JSX.Element {
  const { t } = useTranslation(['media', 'common']);
  const navigate = useNavigate();
  const { data: allocations, isLoading, error } = useTurnAllocations();
  const [ice, setIce] = useState<IceConfig | null>(null);
  const [minting, setMinting] = useState(false);

  // 签发一对临时凭据并把 iceServers 原样交出去。
  //
  // 没有这个按钮的话，TURN 对浏览器就是不可用的：后端能签，
  // 而唯一的取用方式是 curl —— 那不叫产品化。
  const onMint = async () => {
    setMinting(true);
    try {
      setIce(await api.mintTurnCredential('console'));
    } catch (e) {
      Message.error(e instanceof Error ? e.message : String(e));
    } finally {
      setMinting(false);
    }
  };

  const mintButton = (
    <Button type="primary" size="small" loading={minting} onClick={() => void onMint()}>
      {t('media:mint.action')}
    </Button>
  );

  // 凭据是**短期**的（默认 10 分钟），所以显示时必须带上到期时刻 ——
  // 用户看到一段 JSON 却不知道它什么时候失效，就会在失效后以为功能坏了。
  const iceBlock = ice ? (
    <CopyBlock
      label={t('media:mint.label')}
      text={JSON.stringify({ iceServers: ice.iceServers }, null, 2)}
      note={t('media:mint.note', {
        ttl: formatDuration(ice.ttl_seconds),
        at: formatDateTime(ice.expires_at),
      })}
    />
  ) : null;

  // TURN 未启用与「启用了但还没人用」是**两件不同的事**，界面必须分开说。
  //
  // 混成同一个空状态会让用户照着「新建 UDP 媒体隧道」做完，然后永远
  // 等不到分配 —— 因为 TURN 压根没开。后端给的那句话是可行动的
  //（少了哪个配置项），咽掉它就等于把一个五秒能解决的问题变成一小时。
  if (error?.code === 'turn_disabled') {
    return (
      <EmptyAction
        title={t('media:disabled.title')}
        actionLabel={t('media:disabled.action')}
        onAction={() => void navigate('/settings')}
      >
        <div className="muted-note nfr-cmd">{error.message}</div>
      </EmptyAction>
    );
  }

  if (!isLoading && !error && (allocations?.length ?? 0) === 0) {
    return (
      <EmptyAction
        title={t('media:empty.title')}
        actionLabel={t('media:empty.action')}
        onAction={() => void navigate('/tunnels/new?template=udpMedia')}
      >
        {/* 空列表不等于「不能用」：TURN 在跑，只是还没人分配。
            所以签发凭据的入口在空态下也必须在。 */}
        <div className="flex flex-col items-center gap-12px">
          <Space>{mintButton}</Space>
          {iceBlock}
        </div>
      </EmptyAction>
    );
  }

  return (
    <div className="flex flex-col gap-12px">
      <Space>{mintButton}</Space>
      {iceBlock}
      <Table
        size="small"
        rowKey="id"
        loading={isLoading}
        pagination={false}
        data={allocations ?? []}
        columns={[
          { title: t('media:column.credential'), dataIndex: 'username' },
          {
            title: t('media:column.relayed'),
            dataIndex: 'relayed_addr',
            render: (_: unknown, a: TurnAllocation) => (
              <span className="nfr-mono">{a.relayed_addr}</span>
            ),
          },
          { title: t('media:column.peers'), dataIndex: 'peer_count', width: 90 },
          {
            title: t('media:column.bytes'),
            dataIndex: 'bytes_relayed',
            width: 120,
            render: (_: unknown, a: TurnAllocation) => formatBytes(a.bytes_relayed),
          },
          {
            title: t('media:column.ttl'),
            dataIndex: 'credential_ttl_s',
            width: 110,
            render: (_: unknown, a: TurnAllocation) => formatDuration(a.credential_ttl_s),
          },
          {
            title: t('media:column.created'),
            dataIndex: 'created_at',
            width: 170,
            render: (_: unknown, a: TurnAllocation) => (
              <span className="text-3">{formatDateTime(a.created_at)}</span>
            ),
          },
        ]}
      />
      <div className="muted-note">{t('media:note')}</div>
    </div>
  );
}
