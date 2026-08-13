import type { Tunnel, TunnelDraft } from '@/api/types';

/**
 * 模板。空态渲染成四张卡片（空态 = 一个主操作，不是说明文字），
 * 首启向导第 5 步也复用它们。
 */
export interface TunnelTemplate {
  id: 'httpApi' | 'udpMedia' | 'fixedPort' | 'tcpSsh';
  /**
   * 该模板是否必须改写 Host 头。
   *
   * 为 true 时**直通卡片必须置灰并给出原因**：接 nomifun-tauri 这类服务时，
   * 它的 host guard 挂在路由器之外，会 403 掉任何域名型 Host/Origin，
   * 而直通按定义读不到明文、改不了请求头 —— 让用户选完再撞一堵 403 的墙是不可接受的。
   */
  requiresHostRewrite: boolean;
  draft: TunnelDraft;
}

export const TEMPLATES: readonly TunnelTemplate[] = [
  {
    id: 'httpApi',
    requiresHostRewrite: true,
    draft: {
      slug: 'api',
      kind: 'service',
      tls: 'gateway',
      exposure: 'shared',
      l4: 'tcp',
      router: { kind: 'http', domains: [], locations: ['/'] },
      backend: { kind: 'addr', addr: '127.0.0.1:8080' },
    },
  },
  {
    id: 'udpMedia',
    requiresHostRewrite: false,
    draft: {
      slug: 'media',
      kind: 'service',
      tls: 'passthrough',
      exposure: 'port',
      l4: 'udp',
      backend: { kind: 'addr', addr: '127.0.0.1:5004' },
    },
  },
  {
    id: 'fixedPort',
    requiresHostRewrite: false,
    draft: {
      // 场景二：设备只能填 IP + 端口，所以是 reverse。
      slug: 'desktop',
      kind: 'reverse',
      tls: 'passthrough',
      exposure: 'port',
      l4: 'tcp',
      backend: { kind: 'addr', addr: '10.0.0.5:3389' },
    },
  },
  {
    id: 'tcpSsh',
    requiresHostRewrite: false,
    draft: {
      slug: 'ssh',
      kind: 'service',
      tls: 'passthrough',
      exposure: 'port',
      l4: 'tcp',
      backend: { kind: 'addr', addr: '127.0.0.1:22' },
      policy: { allow_cidrs: [] },
    },
  },
];

/** 空草稿：向导从零开始时的初值，与 Go 侧 Complete() 的默认值保持一致。 */
export function emptyDraft(): TunnelDraft {
  return {
    slug: '',
    kind: 'service',
    // 默认直通：它是最少假设、最少信任的那个选项（与 Go 侧一致）。
    tls: 'passthrough',
    exposure: 'port',
    l4: 'tcp',
    backend: { kind: 'addr', addr: '' },
  };
}

/**
 * 从已有隧道生成一份可提交的草稿。
 *
 * 必须逐字段挑，不能整个对象丢回去：写隧道的请求体走
 * `DisallowUnknownFields`，而 Tunnel 上的 id / tenant_id / state 这些
 * 运行时字段虽然存在，但 PUT 时由服务端接管（ID 取自 URL）。
 * 条件展开是 exactOptionalPropertyTypes 的要求。
 */
export function draftFromTunnel(t: Tunnel): TunnelDraft {
  return {
    slug: t.slug,
    kind: t.kind,
    tls: t.tls,
    exposure: t.exposure,
    l4: t.l4,
    ...(t.agent_id ? { agent_id: t.agent_id } : {}),
    ...(t.listen_port ? { listen_port: t.listen_port } : {}),
    ...(t.router ? { router: t.router } : {}),
    ...(t.policy ? { policy: t.policy } : {}),
    backend: t.backend,
    ...(t.enabled === undefined ? {} : { enabled: t.enabled }),
  };
}
