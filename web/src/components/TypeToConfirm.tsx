import { Input, Modal } from '@arco-design/web-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

interface Props {
  visible: boolean;
  title: string;
  /** 必须逐字输入的名称。 */
  slug: string;
  warning: string;
  okLoading?: boolean;
  onOk: () => void;
  onCancel: () => void;
}

/**
 * 破坏性操作的 type-to-confirm。
 *
 * 输入的是 slug 本身而不是「DELETE」这类通用词：通用词会被肌肉记忆秒过，
 * 而抄一遍名字强迫用户确认自己删的是哪一条。
 */
export default function TypeToConfirm({
  visible,
  title,
  slug,
  warning,
  okLoading,
  onOk,
  onCancel,
}: Props): React.JSX.Element {
  const { t } = useTranslation('common');
  const [typed, setTyped] = useState('');
  const matched = typed === slug;

  return (
    <Modal
      visible={visible}
      title={title}
      okText={t('action.confirm')}
      cancelText={t('action.cancel')}
      okButtonProps={{ status: 'danger', disabled: !matched }}
      confirmLoading={okLoading ?? false}
      onOk={() => {
        if (matched) onOk();
      }}
      onCancel={() => {
        setTyped('');
        onCancel();
      }}
      afterClose={() => setTyped('')}
    >
      <div className="flex flex-col gap-12px">
        <div className="text-2">{warning}</div>
        <Input
          value={typed}
          onChange={setTyped}
          placeholder={t('typeToConfirm.label', { slug })}
          {...(typed !== '' && !matched ? { status: 'error' as const } : {})}
        />
        {typed !== '' && !matched ? (
          <div className="text-12px" style={{ color: 'rgb(var(--danger-6))' }}>
            {t('typeToConfirm.mismatch')}
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
