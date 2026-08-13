/** 展示层格式化。单位换算集中在这里，避免每个页面各写一遍除法。 */

/** 字节数 → 人类可读。基数 1024，标注沿用 KB/MB 的习惯写法。 */
export function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const unit = units[i] ?? 'B';
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${unit}`;
}

/** 字节/秒 → Mbps。网络人看的是比特率，不是字节率。 */
export function formatRate(bytesPerSecond: number): string {
  const mbps = (bytesPerSecond * 8) / 1e6;
  if (mbps >= 100) return mbps.toFixed(0);
  if (mbps >= 10) return mbps.toFixed(1);
  return mbps.toFixed(2);
}

/** 微秒 → 毫秒字符串。0 表示「还没有观测」，显示为短横。 */
export function formatRTT(us: number): string {
  if (!us) return '—';
  const ms = us / 1000;
  if (ms >= 100) return ms.toFixed(0);
  if (ms >= 10) return ms.toFixed(1);
  return ms.toFixed(2);
}

/** 百万分率 → 百分比字符串。 */
export function formatLoss(ppm: number): string {
  if (ppm <= 0) return '0';
  const pct = ppm / 10_000;
  return pct >= 1 ? pct.toFixed(1) : pct.toFixed(2);
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat().format(n);
}

/** 相对时间的分桶。返回 key + count，交给 i18next 组词。 */
export function relativeTime(iso: string | undefined): { key: string; count: number } | null {
  if (!iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 5) return { key: 'justNow', count: 0 };
  if (secs < 60) return { key: 'secondsAgo', count: secs };
  if (secs < 3600) return { key: 'minutesAgo', count: Math.round(secs / 60) };
  if (secs < 86_400) return { key: 'hoursAgo', count: Math.round(secs / 3600) };
  return { key: 'daysAgo', count: Math.round(secs / 86_400) };
}

/** 时间戳 → 本地 HH:MM:SS，日志与事件流用。 */
export function formatClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString(undefined, { hour12: false });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { hour12: false });
}

/** 事件种类 `tunnel.created` → locale key 片段 `tunnel_created`。 */
export function eventKindKey(kind: string): string {
  return kind.replace(/\./g, '_');
}

/** 秒 → `12m 30s`，凭据 TTL 用。 */
export function formatDuration(seconds: number): string {
  if (seconds <= 0) return '—';
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

/** 复制到剪贴板。返回是否成功，失败时调用方要提示手动选中。 */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
