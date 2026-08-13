import { Tag, Tooltip } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import type { Tunnel } from '@/api/types';
import { publicEndpoint, targetAddr } from '@/utils/endpoint';

interface Props {
  tunnel: Tunnel;
  relayHost: string;
  agentName?: string;
  /** 由配置文件管理的行：显示标记并在 tooltip 里给原因，而不是隐藏。 */
  fileManagedRef?: string;
}

/**
 * 表格里的端点单元格 —— **整个对象模型的验收点**。
 *
 * 一行必须答完「我从哪进，落到哪」：
 *   https://api.example.com → 代理端「home-desktop」127.0.0.1:8080
 */
export default function EndpointCell({
  tunnel,
  relayHost,
  agentName,
  fileManagedRef,
}: Props): React.JSX.Element {
  const { t } = useTranslation(['tunnels', 'common']);
  const entry = publicEndpoint(tunnel, relayHost);
  const target = targetAddr(tunnel);
  const via = tunnel.agent_id
    ? t('tunnels:row.agent', { name: agentName ?? tunnel.agent_id })
    : t('tunnels:row.relayDials');

  return (
    <div className="flex flex-col gap-2px">
      <div className="flex items-center gap-8px">
        <Link to={`/tunnels/${tunnel.slug}`} className="font-medium">
          {tunnel.slug}
        </Link>
        {fileManagedRef ? (
          <Tooltip content={t('common:provenance.fileManagedTip', { ref: fileManagedRef })}>
            <Tag size="small" bordered>
              {t('tunnels:row.fileManaged')}
            </Tag>
          </Tooltip>
        ) : null}
      </div>
      <div className="endpoint-row text-2">
        <span className="nfr-mono">{entry}</span>
        <span className="text-3" aria-hidden="true">
          →
        </span>
        <span className="text-3">{via}</span>
        <span className="nfr-mono">{target}</span>
      </div>
    </div>
  );
}
