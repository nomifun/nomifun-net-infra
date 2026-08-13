import { useMemo } from 'react';

interface Props {
  /** 采样点，按时间升序。最多取最后 count 个。 */
  values: readonly number[];
  count?: number;
  width?: number;
  height?: number;
  /** 语义色变量名。 */
  colorVar?: string;
  title?: string;
}

/**
 * 30 点内联 SVG 折线。
 *
 * 推论自 dossier 11：**不要用图表说一个徽章就能说的事**。表格里的趋势不值得
 * 一个 uPlot 实例（每行一个 canvas，7 行就是 7 个 rAF 循环），
 * 一条 polyline 就够，而且随主题自动换色（stroke 用 currentColor 之外的变量）。
 */
export default function Sparkline({
  values,
  count = 30,
  width = 56,
  height = 16,
  colorVar = '--primary-6',
  title,
}: Props): React.JSX.Element {
  const points = useMemo(() => {
    const src = values.slice(Math.max(0, values.length - count));
    if (src.length < 2) return '';
    let min = Infinity;
    let max = -Infinity;
    for (const v of src) {
      if (v < min) min = v;
      if (v > max) max = v;
    }
    const span = max - min || 1;
    const stepX = width / (src.length - 1);
    return src
      .map((v, i) => {
        const x = i * stepX;
        const y = height - ((v - min) / span) * (height - 2) - 1;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }, [values, count, width, height]);

  if (points === '') {
    return (
      <svg className="nfr-spark" width={width} height={height} aria-hidden="true">
        <line
          x1="0"
          y1={height / 2}
          x2={width}
          y2={height / 2}
          stroke={`var(${colorVar})`}
          strokeOpacity="0.3"
          strokeWidth="1"
        />
      </svg>
    );
  }

  return (
    <svg className="nfr-spark" width={width} height={height} role="img" aria-label={title}>
      {title === undefined ? null : <title>{title}</title>}
      <polyline
        points={points}
        fill="none"
        stroke={`rgb(var(${colorVar}))`}
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  );
}
