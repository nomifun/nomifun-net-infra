import { useEffect, useRef, useState } from 'react';
import uPlot from 'uplot';

import { SERIES, type MetricRing, type SeriesKey } from '@/api/stream';
import { rgbVar, subscribeTheme } from '@/theme/theme';

export interface LiveSeries {
  key: SeriesKey;
  label: string;
  /** Arco 语义色变量名，例如 `--primary-6`。uPlot 需要字面颜色，见下文。 */
  colorVar: string;
  fallback: string;
}

interface Props {
  ring: MetricRing;
  series: LiveSeries[];
  height?: number;
  yLabel?: string;
  /** 还没有任何数据点时显示的文案。不给就只画一个空图。 */
  emptyHint?: string;
  /**
   * 实时窗口长度（秒）。**给了它就变成一个滚动窗口图。**
   *
   * # 为什么必须显式钉住
   *
   * 不钉的话点数很少时 uPlot 会自己挑一个默认时间域 —— 实测画出来是
   * 「Dec 2026 / Apr 2027 / … / Apr 2029」，而图标题写着「最近 15 分钟」。
   * 那不是空图，那是一个**看起来有三年数据**的图。
   * 这条是从截图里看出来的：类型检查、lint、locale 对齐都看不见它。
   *
   * # 为什么每帧都设一次，而不是只在构造时给一个 range
   *
   * 构造时给静态区间的话窗口会**冻在挂载那一刻**：15 分钟之后所有数据
   * 都堆在右边缘，再往后就滚出画面了。滚动窗口只能每帧重设。
   *
   * # 不给它的场合
   *
   * 历史页签的图有自己的时间范围（用户选的 1h/24h/7d/30d），
   * 那里要的是 uPlot 的自动定域 + 可拖拽缩放。所以这个属性**不设默认值**：
   * 「实时滚动」与「历史可缩放」是两种行为，不该由一个默认值偷偷决定。
   */
  windowSeconds?: number;
}

/** 最高重绘频率。事件速率再高也只画这么多次 —— 这是「1Hz 不掉帧」的另一半。 */
const MAX_HZ = 10;

/**
 * uPlot 包装。没有值得用的现成 React 包装，所以这里就是那 80 行。
 *
 * 三个要点：
 * 1. **数据不进 React**。环形缓冲由 SSE 直接写，这里按 rAF 节流读 revision，
 *    变了才 setData —— 组件本身从不因为新数据重渲染。
 * 2. ResizeObserver 而不是 window resize：图表常在可折叠面板里，
 *    容器变了而窗口没变的情况很常见。
 * 3. uPlot 需要**字面颜色**，CSS 变量它读不懂，所以主题切换时必须重建实例
 *    并重新 getComputedStyle 一遍。
 */
export default function LiveChart({
  ring,
  series,
  height = 180,
  yLabel,
  emptyHint,
  windowSeconds,
}: Props): React.JSX.Element {
  const hostRef = useRef<HTMLDivElement>(null);
  const [themeRev, setThemeRev] = useState(0);
  // 「一个数据点都还没有」必须与「有数据但都是 0」分开。
  //
  // uPlot 拿到空的 x 序列时会自己挑一个默认时间域 —— 实测画出来是
  // 「Dec 2026 / Apr 2027 / … / Apr 2029」，而图标题写着「最近 15 分钟」。
  // 那不是空图，那是一个**看起来有三年数据**的图。
  // 这条是从截图里看出来的：类型检查、lint、locale 对齐都看不见它。
  //
  // 只在**第一个**数据点到达时翻一次，所以整个生命周期里只多一次重渲染 ——
  // 「数据不进 React」那条原则仍然成立。
  const [hasData, setHasData] = useState(false);

  useEffect(() => subscribeTheme(() => setThemeRev((n) => n + 1)), []);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const stroke = series.map((s) => rgbVar(s.colorVar, s.fallback));
    const axisColor = rgbVar('--color-text-3', '#86909c');
    const gridColor = rgbVar('--color-border-2', '#e5e6eb');

    const u = new uPlot(
      {
        width: host.clientWidth || 600,
        height,
        // 图例默认跟随光标；实时图里我们要的是「当前值」，所以关掉 live。
        legend: { live: false },
        cursor: { drag: { x: true, y: false } },
        scales: { x: { time: true } },
        axes: [
          { stroke: axisColor, grid: { stroke: gridColor, width: 1 } },
          {
            stroke: axisColor,
            grid: { stroke: gridColor, width: 1 },
            ...(yLabel === undefined ? {} : { label: yLabel }),
          },
        ],
        series: [
          {},
          ...series.map((s, i) => ({
            label: s.label,
            stroke: stroke[i] ?? s.fallback,
            width: 1.5,
            points: { show: false },
          })),
        ],
      },
      [new Float64Array(0), ...series.map(() => new Float64Array(0))] as unknown as uPlot.AlignedData,
      host,
    );

    const ro = new ResizeObserver(() => {
      u.setSize({ width: host.clientWidth || 600, height });
    });
    ro.observe(host);

    // 滚动窗口：把 x 域推到「现在往前 windowSeconds」。
    //
    // 代价是实时图上的拖拽缩放会在下一帧被顶回去 —— 对一个「最近 N 分钟」
    // 的图那是对的行为；历史图不传这个属性，于是保留 uPlot 的自动定域与缩放。
    const scroll = (): void => {
      if (windowSeconds === undefined || windowSeconds <= 0) return;
      const nowSec = Date.now() / 1000;
      u.setScale('x', { min: nowSec - windowSeconds, max: nowSec });
    };
    // 构造之后立刻设一次，否则**第一帧**画的是 uPlot 自己挑的默认域
    // （那个域对空数据是几年宽的，见 windowSeconds 的说明）。
    scroll();

    let raf = 0;
    let lastRev = -1;
    let lastDraw = 0;
    const tick = (now: number): void => {
      raf = requestAnimationFrame(tick);
      // 节流只看时间，**不看 revision** —— 窗口要跟着时间滚，
      // 而没有新数据时 revision 不变。只在 revision 变了时才重设数据。
      if (now - lastDraw < 1000 / MAX_HZ) return;
      lastDraw = now;
      scroll();
      if (ring.revision === lastRev) return;
      lastRev = ring.revision;
      const all = ring.snapshot();
      const xs = all[0] ?? new Float64Array(0);
      if (xs.length > 0) setHasData(true);
      const picked = series.map((s) => all[1 + SERIES.indexOf(s.key)] ?? new Float64Array(0));
      u.setData([xs, ...picked] as unknown as uPlot.AlignedData);
    };
    raf = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      u.destroy();
    };
    // themeRev 在依赖里：主题一变就重建实例，重新读字面颜色。
  }, [ring, series, height, yLabel, windowSeconds, themeRev]);

  return (
    <div className="relative">
      <div ref={hostRef} className="nfr-chart" />
      {hasData || emptyHint === undefined ? null : (
        // 盖在图上而不是替换掉它：替换会卸载 uPlot 宿主，于是第一个数据点
        // 到达时要重建整个实例（而重建要重新 getComputedStyle 读颜色）。
        <div
          className="absolute inset-0 flex items-center justify-center text-13px text-3"
          style={{ background: 'rgb(var(--color-bg-2))' }}
        >
          {emptyHint}
        </div>
      )}
    </div>
  );
}
