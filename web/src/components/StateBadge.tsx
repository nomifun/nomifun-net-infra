import { Tooltip } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

import type { State } from '@/api/types';

interface Props {
  state: State | string;
  reason?: string;
}

/**
 * 健康徽章。**四种颜色最多**，降级与错误必须带原因。
 *
 * 「没有原因的红点」是 frp 那种 ProxyStatusResp.Err 只有一个当前字符串的后果：
 * 用户看到红色但不知道为什么。所以这里 degraded / error 一律挂 Tooltip，
 * 并在旁边渲染一个 ⓘ 提示有内容可看。
 */
export default function StateBadge({ state, reason }: Props): React.JSX.Element {
  const { t } = useTranslation('common');

  const color = ((): string => {
    switch (state) {
      case 'active':
        return 'rgb(var(--success-6))';
      case 'degraded':
        return 'rgb(var(--warning-6))';
      case 'error':
      case 'rejected_by_agent':
        return 'rgb(var(--danger-6))';
      default:
        return 'var(--color-text-4)';
    }
  })();

  const known: readonly string[] = [
    'active',
    'degraded',
    'stopped',
    'error',
    'draft',
    'pending',
    'rejected_by_agent',
  ];
  const label = known.includes(state) ? t(`state.${state}` as 'state.active') : t('state.unknown');

  const dot = (
    <span className="inline-flex items-center gap-6px whitespace-nowrap">
      <span
        className="inline-block h-7px w-7px rounded-full"
        style={{ background: color }}
        aria-hidden="true"
      />
      <span>{label}</span>
      {reason ? <span className="text-3">ⓘ</span> : null}
    </span>
  );

  return reason ? <Tooltip content={reason}>{dot}</Tooltip> : dot;
}
