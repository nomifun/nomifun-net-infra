import { Button, Message } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

import { copyText } from '@/utils/format';

interface Props {
  text: string;
  label?: string;
  /** 次要说明，例如「只打印不执行」的信任提示。 */
  note?: string;
}

/**
 * 可复制的命令块。
 *
 * 用 user-select: all 而不是只给一个复制按钮：`navigator.clipboard` 在
 * 非安全上下文（http 的局域网地址）里根本不存在，那时候按钮点了没反应
 * 才是最恶劣的失败模式 —— 所以一定要能手选。
 */
export default function CopyBlock({ text, label, note }: Props): React.JSX.Element {
  const { t } = useTranslation('common');

  const onCopy = (): void => {
    void copyText(text).then((ok) => {
      if (ok) Message.success(t('action.copied'));
      else Message.warning(t('action.copyFailed'));
    });
  };

  return (
    <div className="rounded-4px border border-line-2 bg-2">
      <div className="flex items-center justify-between gap-8px px-10px py-4px">
        <span className="text-12px text-3">{label ?? ''}</span>
        <Button size="mini" type="text" onClick={onCopy}>
          {t('action.copy')}
        </Button>
      </div>
      <div className="nfr-cmd px-10px pb-8px">{text}</div>
      {note ? <div className="muted-note px-10px pb-8px">{note}</div> : null}
    </div>
  );
}
