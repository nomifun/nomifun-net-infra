/**
 * 二维码可达性过滤。
 *
 * 这是 nomifun-tauri 的 webuiQrLinks.ts 已经踩过的坑：把
 * `http://127.0.0.1:9443/...` 编成二维码给手机扫，手机扫到的是**它自己**的
 * loopback —— 一个naive 的二维码实现必然出这个 bug。所以宁可不显示二维码。
 */

/** 判断一个 host 是否可能被同一局域网里的另一台设备访问到。 */
export function externallyReachable(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (h === '' || h === 'localhost') return false;
  if (h === '0.0.0.0' || h === '::' || h === '::1') return false;

  // IPv4 字面量。
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    const c = Number(v4[3]);
    if ([a, b, c, Number(v4[4])].some((n) => Number.isNaN(n) || n > 255)) return false;
    if (a === 127) return false; // loopback
    if (a === 169 && b === 254) return false; // link-local
    if (a >= 224) return false; // 多播与保留段
    if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1
    if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
    return true;
  }

  // IPv6：只挡掉明显不可用的段，其余放行。
  if (h.includes(':')) {
    if (h.startsWith('fe80')) return false; // link-local
    if (h.startsWith('ff')) return false; // 多播
    return true;
  }

  // 域名：`.local` 靠 mDNS，跨设备经常解析不到，其余放行。
  return !h.endsWith('.local');
}
