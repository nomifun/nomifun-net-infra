import { Tooltip } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

import type { ExposureLevel } from '@/utils/endpoint';

interface Props {
  level: ExposureLevel;
}

/**
 * 暴露面徽章：● 受限 / ● 开放 / ● 开放·已接受。
 *
 * 反唠叨设计（dossier 11「The S2 bare-port risk, without nagging」）：
 * 一个安静、**可操作**、持续存在的指示器 —— 没有弹窗，没有重复 toast。
 * 操作员明确拒绝收紧之后翻成 informational 的 `accepted` 并**停止再问**。
 *
 * 硬性规则：绝不把随机高位端口当作安全措施展示（约 16 位熵，Shodan 级可枚举），
 * 所以这里没有、也永远不会有「端口足够随机所以安全」这种文案。
 */
export default function ExposureBadge({ level }: Props): React.JSX.Element {
  const { t } = useTranslation('common');

  const color =
    level === 'restricted'
      ? 'rgb(var(--success-6))'
      : level === 'open'
        ? 'rgb(var(--warning-6))'
        : 'var(--color-text-3)';

  const label =
    level === 'restricted'
      ? t('exposure.restricted')
      : level === 'open'
        ? t('exposure.open')
        : t('exposure.accepted');

  const tip =
    level === 'restricted'
      ? t('exposure.restrictedTip')
      : level === 'open'
        ? t('exposure.openTip')
        : t('exposure.acceptedTip');

  return (
    <Tooltip content={tip}>
      <span className="inline-flex items-center gap-5px whitespace-nowrap text-13px">
        <span
          className="inline-block h-7px w-7px rounded-full"
          style={{ background: color }}
          aria-hidden="true"
        />
        {label}
      </span>
    </Tooltip>
  );
}
