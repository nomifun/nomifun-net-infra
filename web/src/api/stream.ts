/**
 * SSE 实时通道 + 定长环形缓冲。
 *
 * 三条设计约束，全部来自 dossier 11：
 *
 * 1. **一个 EventSource**，按 topic 多路复用。HTTP/1.1 浏览器每源约 6 连接，
 *    一个图表一个 EventSource 会把仪表盘拖死，所以这里是模块级单例。
 * 2. **指标写进定长 Float64Array 环**，绝不进 React state。900 样本 = 15 分钟 @1Hz。
 *    图表组件自己按 rAF 节流读环，事件速率再高也不会多渲染一次。
 * 3. **`state` / `session` 折进 swr 缓存**（`mutate(key, updater, {revalidate:false})`），
 *    这样列表页不需要轮询就是活的。
 */

import { mutate } from 'swr';

import type {
  HelloFrame,
  LogFrame,
  MetricFrame,
  RelayEvent,
  SessionFrame,
  Snapshot,
  StateFrame,
  TunnelMetric,
} from './types';
import { keys } from './keys';

/** 环形缓冲容量：900 = 15 分钟 @ 1Hz。 */
export const RING_CAPACITY = 900;

/** 每隧道跟踪的序列。顺序即 uPlot 的 series 顺序，改动要同步图表配置。 */
export const SERIES = [
  'rtt_p50_ms',
  'rtt_p95_ms',
  'rtt_p99_ms',
  'loss_pct',
  'rate_in_mbps',
  'rate_out_mbps',
  'pps_in',
  'pps_out',
] as const;

export type SeriesKey = (typeof SERIES)[number];

/**
 * 定长环。写入 O(1)，读出时物化到预分配的 scratch 数组里，
 * 稳定状态下**零分配** —— 这是「1Hz 不掉帧」的前提。
 */
export class MetricRing {
  private readonly xs = new Float64Array(RING_CAPACITY);
  private readonly ys: Float64Array[] = SERIES.map(() => new Float64Array(RING_CAPACITY));
  private readonly scratchX = new Float64Array(RING_CAPACITY);
  private readonly scratchY: Float64Array[] = SERIES.map(() => new Float64Array(RING_CAPACITY));
  private head = 0;
  private size = 0;
  /** 每次写入自增，图表用它判断「有没有新数据」而不必比较内容。 */
  revision = 0;

  push(tSeconds: number, values: Record<SeriesKey, number>): void {
    const i = this.head;
    this.xs[i] = tSeconds;
    for (let s = 0; s < SERIES.length; s += 1) {
      const key = SERIES[s] as SeriesKey;
      const arr = this.ys[s];
      if (arr) arr[i] = values[key];
    }
    this.head = (i + 1) % RING_CAPACITY;
    if (this.size < RING_CAPACITY) this.size += 1;
    this.revision += 1;
  }

  get length(): number {
    return this.size;
  }

  /** 最后一次写入的某个序列值，给磁贴用。 */
  last(key: SeriesKey): number {
    if (this.size === 0) return 0;
    const idx = (this.head - 1 + RING_CAPACITY) % RING_CAPACITY;
    const arr = this.ys[SERIES.indexOf(key)];
    return arr ? (arr[idx] ?? 0) : 0;
  }

  /** 单个序列按时间升序的普通数组，给 sparkline 用（30 点内联 SVG，不值得开 canvas）。 */
  values(key: SeriesKey): number[] {
    const arr = this.ys[SERIES.indexOf(key)];
    if (!arr || this.size === 0) return [];
    const out: number[] = Array.from({ length: this.size }, () => 0);
    const start = (this.head - this.size + RING_CAPACITY) % RING_CAPACITY;
    for (let k = 0; k < this.size; k += 1) {
      out[k] = arr[(start + k) % RING_CAPACITY] ?? 0;
    }
    return out;
  }

  /** 物化成 uPlot 的 AlignedData 形状：[xs, ...series]。 */
  snapshot(): Float64Array[] {
    const n = this.size;
    const start = (this.head - n + RING_CAPACITY) % RING_CAPACITY;
    for (let k = 0; k < n; k += 1) {
      const src = (start + k) % RING_CAPACITY;
      this.scratchX[k] = this.xs[src] ?? 0;
      for (let s = 0; s < SERIES.length; s += 1) {
        const from = this.ys[s];
        const to = this.scratchY[s];
        if (from && to) to[k] = from[src] ?? 0;
      }
    }
    return [
      this.scratchX.subarray(0, n),
      ...this.scratchY.map((a) => a.subarray(0, n)),
    ];
  }
}

export type StreamPhase = 'connecting' | 'open' | 'retrying' | 'closed';

export interface StreamHealth {
  phase: StreamPhase;
  /** 中继侧因为我们读得慢而丢掉的 metric 帧数。采样而非排队。 */
  droppedFrames: number;
  /** 最近一帧的本地接收时刻，用于「多久没数据了」。 */
  lastFrameAt: number;
  seq: number;
  /** 服务端契约版本与前端不一致时提示刷新。 */
  contractMismatch: boolean;
  /**
   * 是否收到过**完整**的 metric 帧（带 RTT 分位数、分级丢弃等）。
   *
   * 中继当前的 metric 帧其实就是一份 Snapshot（只有字节与会话数），
   * 所以在它补上遥测之前，界面必须把 RTT / 丢包 / 分级丢弃显示为「—」
   * 而不是 0 —— 0 会被读成「测过，是零」，那是撒谎。
   */
  richMetrics: boolean;
  /**
   * 是否已经有承载 RTT 观测。
   *
   * 与 richMetrics 分开：那一项问的是「中继发的是完整 metric 帧吗」，
   * 这一项问的是「RTT 这个具体指标有数了吗」——
   * 承载 RTT 现在由控制流 Ping/Pong 测，即使 metric 帧仍然只是快照它也有值。
   * 合成一个标志会让 RTT 在有数据的情况下仍然显示「—」。
   */
  hasRTT: boolean;
}

type Listener = () => void;

/** 一行日志。seq 由本地单调递增，给 React key 用（时间戳会撞）。 */
export interface LogLine extends LogFrame {
  seq: number;
}

/** 一条观测到的会话。Session 是观测状态，与 Tunnel（期望状态）是不同对象。 */
export interface LiveSession {
  peer: string;
  path: 'direct' | 'relayed' | 'unknown';
  since: number;
}

const LOG_CAPACITY = 500;

/** 每条隧道最多保留多少个会话行。会话可能上千，界面只需要头部若干。 */
const SESSIONS_PER_TUNNEL = 50;

class StreamStore {
  private es: EventSource | null = null;
  private readonly listeners = new Set<Listener>();
  private readonly rings = new Map<string, MetricRing>();
  private readonly totals = new MetricRing();
  private logLines: LogLine[] = [];
  private logSeq = 0;
  private latest = new Map<string, TunnelMetric>();
  private readonly sessions = new Map<string, LiveSession[]>();

  health: StreamHealth = {
    phase: 'closed',
    droppedFrames: 0,
    lastFrameAt: 0,
    seq: 0,
    contractMismatch: false,
    richMetrics: false,
    hasRTT: false,
  };

  /** 上一次快照的接收时刻与累计字节，用来把累计计数差分成瞬时速率。 */
  private lastSnapAt = 0;
  private prevTotalBytes: [number, number] = [0, 0];
  private readonly prevTunnelBytes = new Map<string, [number, number]>();

  /** 引用计数：最后一个订阅者离开时才断流。 */
  private refs = 0;

  subscribe = (fn: Listener): (() => void) => {
    this.listeners.add(fn);
    this.refs += 1;
    if (this.refs === 1) this.open();
    return () => {
      this.listeners.delete(fn);
      this.refs -= 1;
      if (this.refs === 0) this.close();
    };
  };

  getHealth = (): StreamHealth => this.health;

  ring(tunnelID: string): MetricRing {
    let r = this.rings.get(tunnelID);
    if (!r) {
      r = new MetricRing();
      this.rings.set(tunnelID, r);
    }
    return r;
  }

  totalsRing(): MetricRing {
    return this.totals;
  }

  metric(tunnelID: string): TunnelMetric | undefined {
    return this.latest.get(tunnelID);
  }

  logs(): LogLine[] {
    return this.logLines;
  }

  /**
   * 某条隧道当前观测到的会话。
   *
   * **只包含本页打开之后观测到的会话** —— Session 是观测状态，
   * 中继没有「历史会话」这个对象（那正是 frp 需要「清理离线」按钮的原因：
   * 它把配置与运行时混在一张表里）。界面上要如实说明这一点。
   */
  sessionsFor(tunnelID: string): LiveSession[] {
    return this.sessions.get(tunnelID) ?? [];
  }

  private open(): void {
    if (this.es) return;
    this.setHealth({ phase: 'connecting' });
    // EventSource 自带重连并携带 Last-Event-ID，不需要我们写重连代码。
    const es = new EventSource('/api/events', { withCredentials: true });
    this.es = es;

    es.addEventListener('open', () => this.setHealth({ phase: 'open' }));
    es.addEventListener('error', () => {
      // 浏览器会自己退避重连；这里只反映状态，绝不手动 close() 后重建，
      // 那会丢掉 Last-Event-ID 的续传语义。
      this.setHealth({ phase: es.readyState === EventSource.CLOSED ? 'closed' : 'retrying' });
    });

    es.addEventListener('hello', (ev) => this.onHello(parse<HelloFrame>(ev)));
    es.addEventListener('metric', (ev) => this.onMetric(parse<MetricFrame | Snapshot>(ev)));
    es.addEventListener('state', (ev) => this.onState(parse<StateFrame>(ev)));
    es.addEventListener('session', (ev) => this.onSession(parse<SessionFrame>(ev)));
    es.addEventListener('event', (ev) => this.onEvent(parse<RelayEvent>(ev)));
    es.addEventListener('log', (ev) => this.onLog(parse<LogFrame>(ev)));
  }

  private close(): void {
    this.es?.close();
    this.es = null;
    this.setHealth({ phase: 'closed' });
  }

  private onHello(f: HelloFrame | undefined): void {
    if (!f) return;
    // 中继未接上运行时时 hello 不带 snapshot；此时不要用 undefined 覆盖缓存。
    if (f.snapshot) void mutate(keys.snapshot, f.snapshot, { revalidate: false });
    this.setHealth({
      seq: f.seq,
      contractMismatch:
        f.api_contract_version !== undefined && f.api_contract_version !== __API_CONTRACT_VERSION__,
    });
  }

  /**
   * metric 帧。**两种形状都要吃**。
   *
   * 规格里的完整形状带 RTT 分位数、分级丢弃、MTU 等；而中继当前发的
   * 就是一份 Snapshot（cmd/nfrelay 的采样循环）。线上宽容是这里的正确姿态：
   * 认得的字段就用，认不得的一律不假装。
   */
  private onMetric(f: MetricFrame | Snapshot | undefined): void {
    if (!f) return;
    if (typeof (f as MetricFrame).t !== 'number') {
      this.onSnapshotMetric(f as Snapshot);
      return;
    }
    this.onRichMetric(f as MetricFrame);
  }

  /**
   * 从两次快照的**累计字节差**算瞬时速率。
   *
   * 吞吐由累计字节差分得出；**承载 RTT 现在有真值**（控制流 Ping/Pong，
   * 见 relay/rtt.go），丢包仍然留空（0 + richMetrics=false），
   * 界面据此显示「—」。
   */
  private onSnapshotMetric(s: Snapshot): void {
    const nowMs = Date.now();
    const dt = this.lastSnapAt === 0 ? 0 : (nowMs - this.lastSnapAt) / 1000;
    this.lastSnapAt = nowMs;
    const t = nowMs / 1000;

    const rate = (cur: number, prev: number): number => (dt > 0 ? Math.max(0, (cur - prev) / dt) : 0);

    // 承载 RTT 现在**真的有值**（控制流 Ping/Pong）。会话级的数 ——
    // 同一个 agent 名下所有隧道是同一条曲线，总览取任意一个有观测的即可。
    // 一个都没有时保持 0，界面据此显示「—」（0 会被读成「测过，是零」）。
    const anyRTT = (s.tunnels ?? []).find((x) => (x.rtt_p50_us ?? 0) > 0);
    if (anyRTT) this.setHealth({ hasRTT: true });

    const totals = s.totals;
    if (totals) {
      const [pin, pout] = this.prevTotalBytes;
      this.totals.push(t, {
        rtt_p50_ms: (anyRTT?.rtt_p50_us ?? 0) / 1000,
        rtt_p95_ms: (anyRTT?.rtt_p95_us ?? 0) / 1000,
        rtt_p99_ms: (anyRTT?.rtt_p99_us ?? 0) / 1000,
        loss_pct: 0,
        rate_in_mbps: (rate(totals.bytes_in, pin) * 8) / 1e6,
        rate_out_mbps: (rate(totals.bytes_out, pout) * 8) / 1e6,
        pps_in: 0,
        pps_out: 0,
      });
      this.prevTotalBytes = [totals.bytes_in, totals.bytes_out];
    }

    for (const ts of s.tunnels ?? []) {
      const [pin, pout] = this.prevTunnelBytes.get(ts.id) ?? [ts.bytes_in, ts.bytes_out];
      this.ring(ts.id).push(t, {
        rtt_p50_ms: (ts.rtt_p50_us ?? 0) / 1000,
        rtt_p95_ms: (ts.rtt_p95_us ?? 0) / 1000,
        rtt_p99_ms: (ts.rtt_p99_us ?? 0) / 1000,
        loss_pct: 0,
        rate_in_mbps: (rate(ts.bytes_in, pin) * 8) / 1e6,
        rate_out_mbps: (rate(ts.bytes_out, pout) * 8) / 1e6,
        pps_in: 0,
        pps_out: 0,
      });
      this.prevTunnelBytes.set(ts.id, [ts.bytes_in, ts.bytes_out]);
    }

    // 快照本身就是最新状态，直接折进缓存 —— 这就是磁贴 1Hz 变化的来源。
    void mutate(keys.snapshot, s, { revalidate: false });
    this.setHealth({ lastFrameAt: nowMs });
  }

  private onRichMetric(f: MetricFrame): void {
    const t = f.t / 1000;
    this.totals.push(t, {
      rtt_p50_ms: f.totals.rtt_p50_us / 1000,
      rtt_p95_ms: f.totals.rtt_p95_us / 1000,
      rtt_p99_ms: 0,
      loss_pct: f.totals.loss_ppm / 10_000,
      rate_in_mbps: (f.totals.rate_in * 8) / 1e6,
      rate_out_mbps: (f.totals.rate_out * 8) / 1e6,
      pps_in: 0,
      pps_out: 0,
    });
    for (const m of f.tunnels) {
      this.latest.set(m.tunnel_id, m);
      this.ring(m.tunnel_id).push(t, {
        rtt_p50_ms: m.rtt_p50_us / 1000,
        rtt_p95_ms: m.rtt_p95_us / 1000,
        rtt_p99_ms: m.rtt_p99_us / 1000,
        loss_pct: m.loss_ppm / 10_000,
        rate_in_mbps: (m.rate_in * 8) / 1e6,
        rate_out_mbps: (m.rate_out * 8) / 1e6,
        pps_in: m.pkts_in,
        pps_out: m.pkts_out,
      });
    }
    // 磁贴与流健康点要更新，但**图表不订阅这里** —— 它自己按 rAF 读环。
    this.setHealth({ droppedFrames: f.dropped_frames, lastFrameAt: Date.now(), richMetrics: true });
  }

  private onState(f: StateFrame | undefined): void {
    if (!f) return;
    const id = f.tunnel_id ?? f.tunnel;
    // 带了完整状态就本地折叠一次，界面立刻变；没带就只失效缓存重取。
    if (id !== undefined && f.state !== undefined) {
      const state = f.state;
      const reason = f.reason ?? '';
      void mutate(
        keys.snapshot,
        (prev: Snapshot | undefined) => {
          if (!prev) return prev;
          return {
            ...prev,
            tunnels: prev.tunnels.map((t) => (t.id === id ? { ...t, state, reason } : t)),
          };
        },
        { revalidate: false },
      );
    } else {
      void mutate(keys.snapshot);
    }
    // 隧道列表的 state 字段也要跟着走，否则表格与详情页会互相打脸。
    void mutate(keys.tunnels);
    // 每次状态变化后端都会写一条事件，所以事件流也该刷新 ——
    // 中继目前不单独推送 `event` 帧，这是让「近期事件」保持鲜活的唯一途径。
    void mutate(keys.recentEvents);
    if (f.agent !== undefined) void mutate(keys.agents);
  }

  private onSession(f: SessionFrame | undefined): void {
    if (!f) return;
    if (f.peer !== undefined) {
      const list = this.sessions.get(f.tunnel_id) ?? [];
      if (f.delta > 0) {
        // 显式标注类型：数组字面量会把 'direct' 这类字面量宽化成 string。
        const fresh: LiveSession = { peer: f.peer, path: f.path ?? 'unknown', since: Date.now() };
        this.sessions.set(f.tunnel_id, [fresh, ...list].slice(0, SESSIONS_PER_TUNNEL));
      } else {
        this.sessions.set(
          f.tunnel_id,
          list.filter((s) => s.peer !== f.peer),
        );
      }
    }
    void mutate(
      keys.snapshot,
      (prev: Snapshot | undefined) => {
        if (!prev) return prev;
        return {
          ...prev,
          totals: { ...prev.totals, sessions: Math.max(0, prev.totals.sessions + f.delta) },
          tunnels: prev.tunnels.map((t) =>
            t.id === f.tunnel_id ? { ...t, sessions: f.sessions } : t,
          ),
        };
      },
      { revalidate: false },
    );
    // 会话列表不在 swr 里，所以要显式通知订阅者。
    this.emit();
  }

  private onEvent(f: RelayEvent | undefined): void {
    if (!f) return;
    void mutate(
      keys.recentEvents,
      (prev: { events: RelayEvent[] } | undefined) =>
        prev ? { events: [f, ...prev.events].slice(0, 200) } : { events: [f] },
      { revalidate: false },
    );
  }

  private onLog(f: LogFrame | undefined): void {
    if (!f) return;
    this.logSeq += 1;
    this.logLines = [{ ...f, seq: this.logSeq }, ...this.logLines].slice(0, LOG_CAPACITY);
    this.emit();
  }

  private setHealth(patch: Partial<StreamHealth>): void {
    this.health = { ...this.health, ...patch };
    this.emit();
  }

  private emit(): void {
    for (const fn of this.listeners) fn();
  }
}

function parse<T>(ev: Event): T | undefined {
  const data = (ev as MessageEvent<string>).data;
  if (!data) return undefined;
  try {
    return JSON.parse(data) as T;
  } catch {
    return undefined;
  }
}

/** 模块级单例。见文件头第 1 条。 */
export const stream = new StreamStore();
