/**
 * 公网端点与目标的推导。
 *
 * 这是整个模型要通过的那个测试：**一行答完「我从哪进，落到哪」**。
 * frp 的一行是 name/type/status，公网端点要用户自己从拼接的字符串里凑出来
 * （dossier 07 §8 item 9）。所以这段逻辑必须是唯一实现，任何地方都从这里取。
 */

import type { Exposure, Tunnel } from '@/api/types';

/** 公网入口的可读形式。 */
export function publicEndpoint(t: Tunnel, relayHost: string): string {
  const host = relayHost || 'relay';

  if (t.exposure === 'shared' && t.router) {
    const domain = t.router.domains?.[0] ?? host;
    const path = t.router.locations?.[0] ?? '';
    // 共享端口一定是 443：这正是网关模式换来的东西。
    return `https://${domain}${path}`;
  }
  if (t.exposure === 'private') {
    return `private://${t.slug}`;
  }

  const port = t.listen_port ? String(t.listen_port) : '?';
  if (t.l4 === 'udp') return `udp://${host}:${port}`;
  // 独占端口 + 网关终止 TLS 时按 https 展示；直通只搬字节，写 tcp 更诚实。
  return t.tls === 'gateway' ? `https://${host}:${port}` : `tcp://${host}:${port}`;
}

/** 目标的可读形式（不含「代理端」前缀，前缀由调用方本地化）。 */
export function targetAddr(t: Tunnel): string {
  if (t.backend.kind === 'unix') return t.backend.path ?? '';
  return t.backend.addr ?? '';
}

/** 暴露面三态。 */
export type ExposureLevel = 'restricted' | 'open' | 'accepted';

/**
 * 判定暴露等级。
 *
 * 与 Go 侧 Tunnel.IsBareExposure() 同一套判据：独占端口且没有任何来源限制。
 * `accepted` 是操作员明确拒绝过收紧之后的状态 —— 那之后不再提示（反唠叨规则）。
 */
export function exposureLevel(t: Tunnel, accepted: boolean): ExposureLevel {
  const bare = t.exposure === 'port' && (t.policy?.allow_cidrs?.length ?? 0) === 0;
  if (!bare) return 'restricted';
  return accepted ? 'accepted' : 'open';
}

/** 暴露面摘要的三段数据，创建向导与详情页共用。 */
export interface ExposureSummary {
  addr: string;
  sourceCount: number;
  hasAuth: boolean;
}

export function exposureSummary(t: Tunnel | undefined, bindHost = '0.0.0.0'): ExposureSummary {
  const port = t?.listen_port ? String(t.listen_port) : '?';
  const shared = t?.exposure === 'shared';
  return {
    addr: shared ? `${t?.router?.domains?.[0] ?? '*'}:443` : `${bindHost}:${port}`,
    sourceCount: t?.policy?.allow_cidrs?.length ?? 0,
    // v1 的应用层鉴权只有网关模式下的注入鉴权；直通模式下中继无从鉴权。
    hasAuth: t?.tls === 'gateway',
  };
}

/** 入口形态的排序权重，让列表里独占端口的隧道排在前面（它们风险更高）。 */
export function exposureWeight(e: Exposure): number {
  switch (e) {
    case 'port':
      return 0;
    case 'shared':
      return 1;
    case 'private':
      return 2;
    default:
      return 3;
  }
}
