import { Tooltip } from '@arco-design/web-react';

interface Props {
  label: string;
  value: string;
  /**
   * 次要文字，例如单位或副指标。
   *
   * 显式写 `| undefined`：exactOptionalPropertyTypes 下 `suffix?: string` 不接受
   * 显式传入的 undefined，而调用方经常要 `cond ? x : undefined`。
   * **约定**：自家组件的可选 prop 都写 `?: T | undefined`；第三方（Arco）组件
   * 改不了，就在调用处用条件展开。
   */
  suffix?: string | undefined;
  hint?: string | undefined;
  /** 语义色变量名，只在需要强调时给。 */
  colorVar?: string | undefined;
}

/** 概览与详情页的指标磁贴。Arco 的 Statistic 太重（带动画），这里要的是密度。 */
export default function StatTile({ label, value, suffix, hint, colorVar }: Props): React.JSX.Element {
  const body = (
    <div className="tile-card min-w-0 flex-1">
      <div className="flex items-center gap-4px text-12px text-3">
        <span className="truncate">{label}</span>
        {hint ? <span aria-hidden="true">ⓘ</span> : null}
      </div>
      <div className="mt-4px flex items-baseline gap-4px">
        <span
          className="text-20px font-semibold leading-tight"
          style={colorVar === undefined ? undefined : { color: `rgb(var(${colorVar}))` }}
        >
          {value}
        </span>
        {suffix ? <span className="text-12px text-3">{suffix}</span> : null}
      </div>
    </div>
  );
  return hint ? <Tooltip content={hint}>{body}</Tooltip> : body;
}
