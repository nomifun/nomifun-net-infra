import { Tag, Tooltip } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

import type { Provenance } from '@/api/types';

interface Props {
  provenance: Provenance;
  sourceRef?: string;
}

/**
 * 来源徽章。每个字段都要显示生效值**与来源**。
 *
 * 文件管理的行是 edit-**disabled 并把原因放进 tooltip**，不是隐藏 ——
 * 隐藏会让用户以为控制台坏了，而 frp 的做法（提示你去手改 TOML）
 * 等于把问题丢回给用户（dossier 07 §8 item 7）。
 */
export default function ProvenanceTag({ provenance, sourceRef }: Props): React.JSX.Element {
  const { t } = useTranslation('common');

  const label = t(`provenance.${provenance}` as 'provenance.file');
  const tag = (
    // exactOptionalPropertyTypes 下不能把 undefined 显式传给可选 prop，
    // 所以用条件展开而不是三元 —— 全项目统一这个写法。
    <Tag size="small" bordered {...(provenance === 'file' ? { color: 'orange' } : {})}>
      {provenance === 'file' && sourceRef ? `${label} ${sourceRef}` : label}
    </Tag>
  );

  if (provenance !== 'file' || !sourceRef) return tag;
  return <Tooltip content={t('provenance.fileManagedTip', { ref: sourceRef })}>{tag}</Tooltip>;
}
