/**
 * swr 缓存 key。集中在一处，SSE 折叠（stream.ts）与页面读取必须用同一把 key，
 * 否则「推送来的增量」会写进一个没人读的缓存槽 —— 一类极难发现的 bug。
 *
 * key 就用后端真实路径，这样调试时在 Network 面板一眼能对上。
 */
export const keys = {
  setupState: '/api/setup',
  me: '/api/me',
  snapshot: '/api/snapshot',
  tunnels: '/api/tunnels',
  /** 参数是隧道 ID（后端路由用 ID），浏览器地址栏用 slug。 */
  samples: (id: string, from: number) => `/api/tunnels/${id}/samples?from=${from}`,
  learned: (id: string) => `/api/tunnels/${id}/learned-sources`,
  agents: '/api/agents',
  recentEvents: '/api/events/recent',
  settings: '/api/settings',
  turn: '/api/turn/allocations',
} as const;
