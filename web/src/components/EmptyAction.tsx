import { Button, Empty } from '@arco-design/web-react';

interface Props {
  title: string;
  actionLabel: string;
  onAction: () => void;
  /** 少数确实需要第二块内容的空态（例如模板卡片、安装命令）从这里塞。 */
  children?: React.ReactNode;
}

/**
 * 空态 = **一个主操作**，绝不是一段说明文字。
 *
 * 这是 dossier 11 的硬规定：隧道空态渲染四个模板卡片，代理端空态直接把
 * 安装一行内联出来。说明性散文一律不要 —— 用户在空态里要的是下一步，
 * 不是阅读材料。
 */
export default function EmptyAction({
  title,
  actionLabel,
  onAction,
  children,
}: Props): React.JSX.Element {
  return (
    <div className="flex flex-col items-center gap-16px py-40px">
      <Empty description={title} />
      <Button type="primary" onClick={onAction}>
        {actionLabel}
      </Button>
      {children ? <div className="w-full max-w-720px">{children}</div> : null}
    </div>
  );
}
