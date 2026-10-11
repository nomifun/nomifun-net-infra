/**
 * 手写的类型化 API 客户端。
 *
 * 为什么手写（dossier 11「OpenAPI: publish the spec, hand-write the client」）：
 * 约 25 个封闭端点不值得每操作的样板；生成物不与 swr key 组合；而且
 * **OpenAPI 对 SSE 没有一等模型**，那恰好是本控制台最重要的通道 ——
 * 生成器会覆盖除了要紧那部分以外的一切。
 *
 * # 与后端的对齐
 *
 * 路径与形状**逐一对照 internal/console/routes.go**，Go 是唯一真相源。
 * 两个容易踩的点：
 *
 *  1. 隧道的 URL 参数是 **ID**（`/api/tunnels/{id}`），而浏览器地址栏用 **slug**
 *     （spec §8.1：human slug 作为键、出现在 URL 里）。所以调用方负责
 *     slug→ID 的解析，见 hooks.ts 的 useTunnelBySlug。
 *  2. 写隧道的请求体走 `DisallowUnknownFields`：多一个字段就是 400。
 *     TunnelDraft 因此只能含 tunnel.Tunnel 真实存在的 json tag。
 *
 * # 尚未由中继实现的端点
 *
 * 下面标了「未实现」的方法在当前后端会得到 404。相关界面按规格保留，
 * 但会显示 errors:notImplemented 而不是假装成功 —— 静默省略比 404 更糟。
 */

import type {
  AgentStatus,
  ConfigApplyResult,
  ConfigDiff,
  DesktopPairingInvite,
  DesktopPreflight,
  DesktopConnection,
  EnrolToken,
  LearnedSources,
  ProbeResult,
  RelayEvent,
  Sample,
  SettingsGroup,
  Snapshot,
  TurnAllocation,
  Tunnel,
  TunnelDraft,
  IceConfig,
} from './types';

/** CSRF 头名。与 internal/console/server.go 的 CSRFHeaderName 一致。 */
export const CSRF_HEADER = 'X-NFR-CSRF';

/** CSRF Cookie 名。双提交模式，前端可读。 */
const CSRF_COOKIE = 'nfr_csrf';

/** 单字段校验错误，映射到表单高亮。 */
export interface FieldError {
  path: string;
  message: string;
}

/** 与后端 APIError 一一对应的错误。 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly fields: FieldError[];
  /**
   * 解析后的原始响应体。
   *
   * code / message / fields 三个字段覆盖不了所有失败：`config:validate`
   * 的失败响应本身就是一份 diff（含逐条错误与「将被删除」的清单），
   * 而那些信息是用户下一步操作的**唯一**依据。丢掉它就只能弹一句
   * 「校验失败」让用户去猜。
   *
   * 类型是 unknown 而不是 any：调用方必须自己收窄，
   * 否则一个改过形状的响应会在渲染时才炸。
   */
  readonly body: unknown;

  constructor(
    status: number,
    code: string,
    message: string,
    fields: FieldError[] = [],
    body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.fields = fields;
    this.body = body;
  }

  /** 会话失效（401）需要跳登录页，与普通业务错误区别对待。 */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  /** 404 在这里通常意味着「中继还没实现这个端点」，不是「对象不存在」。 */
  get isMissingEndpoint(): boolean {
    return this.status === 404 && this.code === 'http_404';
  }
}

function readCookie(name: string): string {
  for (const part of document.cookie.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

/**
 * 登录返回的 CSRF 令牌。
 *
 * 后端把 CSRF 令牌放在**响应体**里（不是 Cookie），所以这一份内存副本
 * 是主路径；同时仍然兼容双提交 Cookie（若将来后端也下发 Cookie）。
 */
let csrfToken = '';

export function rememberCSRF(token: string): void {
  csrfToken = token;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') {
    headers[CSRF_HEADER] = csrfToken || readCookie(CSRF_COOKIE);
  }

  const res = await fetch(path, {
    method,
    headers,
    // 同源 Cookie 会话；SSE 走同一条会话，所以不能用 Bearer 令牌。
    credentials: 'same-origin',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const parsed: unknown = text === '' ? undefined : safeJSON(text);

  if (!res.ok) {
    const envelope = (parsed ?? {}) as { code?: string; message?: string; fields?: FieldError[] };
    throw new ApiError(
      res.status,
      envelope.code ?? `http_${res.status}`,
      envelope.message ?? res.statusText,
      envelope.fields ?? [],
      parsed,
    );
  }
  return parsed as T;
}

function safeJSON(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

const get = <T>(path: string) => request<T>('GET', path);
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
const put = <T>(path: string, body?: unknown) => request<T>('PUT', path, body);
const del = <T>(path: string) => request<T>('DELETE', path);

/** GET /api/setup 的响应。 */
export interface SetupState {
  needs_setup: boolean;
}

/** 登录 / 首启 / GET /api/me 共用的响应（Go 侧 LoginResponse）。 */
export interface Identity {
  username: string;
  csrf_token: string;
  must_rotate?: boolean;
}

export const api = {
  /** 未鉴权：是否需要走首启引导。 */
  setupState: () => get<SetupState>('/api/setup'),

  /** 当前身份。未登录时 401。 */
  me: async (): Promise<Identity> => {
    const id = await get<Identity>('/api/me');
    rememberCSRF(id.csrf_token);
    return id;
  },

  login: async (username: string, password: string): Promise<Identity> => {
    const out = await post<Identity>('/api/login', { username, password });
    rememberCSRF(out.csrf_token);
    return out;
  },
  logout: () => post<{ ok: boolean }>('/api/logout'),

  /** 首启：创建管理员并直接拿到会话。空凭据与短密码由后端拒绝。 */
  setup: async (username: string, password: string): Promise<Identity> => {
    const out = await post<Identity>('/api/setup', { username, password });
    rememberCSRF(out.csrf_token);
    return out;
  },

  /** 改密必须验旧密码：一个被盗的会话 Cookie 不该能永久锁定账号。 */
  changePassword: (current: string, next: string) =>
    post<{ ok: boolean }>('/api/password', { current, new: next }),

  snapshot: () => get<Snapshot>('/api/snapshot'),

  /** 注意：后端返回的是裸数组，不是 { tunnels: [...] } 信封。 */
  listTunnels: () => get<Tunnel[]>('/api/tunnels'),
  getTunnel: (id: string) => get<Tunnel>(`/api/tunnels/${encodeURIComponent(id)}`),
  createTunnel: (draft: TunnelDraft) => post<Tunnel>('/api/tunnels', draft),
  updateTunnel: (id: string, draft: TunnelDraft) =>
    put<Tunnel>(`/api/tunnels/${encodeURIComponent(id)}`, draft),
  deleteTunnel: (id: string) => del<{ ok: boolean }>(`/api/tunnels/${encodeURIComponent(id)}`),

  /**
   * 提交前的 dry-run 校验。**这是权威校验**：控制台自己的 zod 只管形状，
   * 端口冲突、router=http 需要 gateway 这类跨字段规则只有中继知道。
   * 成功返回 {ok:true}；失败是 400 + fields，由 ApiError.fields 承载。
   */
  validateTunnel: (draft: TunnelDraft) => post<{ ok: boolean }>('/api/tunnels:validate', draft),

  /** 时序样本 + 从直方图算出的分位数（不是「p95 的均值」）。 */
  samples: (id: string, fromSec: number) =>
    get<{ samples: Sample[]; rtt: { p50_us: number; p95_us: number; p99_us: number } }>(
      `/api/tunnels/${encodeURIComponent(id)}/samples?from=${fromSec}`,
    ),

  listAgents: () => get<AgentStatus[]>('/api/agents'),
  revokeAgent: (id: string) => del<{ ok: boolean }>(`/api/agents/${encodeURIComponent(id)}`),

  /**
   * 签发入网令牌。
   *
   * 这同时就是「轮换入网令牌」：令牌是一次性、只入网一个代理端的，
   * 所以「轮换」在语义上就是重新签发一枚，而不是原地改一个长期密钥。
   */
  issueEnrolToken: (note: string, ttlSeconds?: number) =>
    post<EnrolToken>('/api/enrol-tokens', {
      note,
      ...(ttlSeconds === undefined ? {} : { ttl_seconds: ttlSeconds }),
    }),

  createDesktopPairingInvite: (ttlSeconds: number, listenPort: number, note: string) =>
    post<DesktopPairingInvite>('/api/pairing-invites', {
      ttl_seconds: ttlSeconds,
      listen_port: listenPort,
      note,
    }),

  desktopPreflight: () => get<DesktopPreflight>('/api/desktop/preflight'),
  createDesktopPairingInviteV2: (ttlSeconds: number, note: string, businessURL: string) =>
    post<DesktopPairingInvite>('/api/pairing-invites/v2', {
      ttl_seconds: ttlSeconds,
      note,
      business_url: businessURL,
    }),
  desktopConnections: () =>
    get<{ connections: DesktopConnection[] }>('/api/desktop-connections'),
  revokeDesktopConnection: (id: string) =>
    del<DesktopConnection>(`/api/desktop-connections/${encodeURIComponent(id)}`),

  /** 注意：查询参数是 `since`（不是 since_id），返回裸数组。 */
  recentEvents: (limit = 100, since = 0) =>
    get<RelayEvent[]>(`/api/events/recent?limit=${limit}&since=${since}`),

  // ── 下面这些端点的实现状态各不相同，逐条注明。 ──
  // 注释必须与后端**逐条对齐**：一条过时的「未实现」会让人不去用已有功能，
  // 而一条过时的「已实现」会让人以为功能坏了。

  /** 已实现：逐跳探测。只返回中继真能测的那几跳，缺失的跳渲染成中性点。 */
  probeTunnel: (id: string, fromInternet: boolean) =>
    post<ProbeResult>(`/api/tunnels/${encodeURIComponent(id)}:test`, {
      from_internet: fromInternet,
    }),
  /** 已实现：生成的配置预览（agent 配置 + relay.yaml 片段）。 */
  previewConfig: (draft: TunnelDraft) =>
    post<{ agent_yaml: string; relay_yaml: string }>('/api/tunnels:preview', draft),
  /** 已实现：学习模式观测到的来源前缀（内存态，重启即清空）。 */
  learnedSources: (id: string) =>
    get<LearnedSources>(`/api/tunnels/${encodeURIComponent(id)}/learned-sources`),
  /**
   * 已实现：把勾选的来源并入允许列表。
   *
   * cidrs 省略表示「全部」，但界面**不这么用** —— 学习窗口里扫描器与真
   * 客户端混在一起，全选等于让人一键把撞门的人请进来。所以总是传勾选项。
   *
   * 后端与既有 allow_cidrs 取并集（不覆盖），且空集合会被拒绝
   *（allow_cidrs 为空的语义是放行一切，写空不是收窄而是全开）。
   */
  applyLearnedSources: (id: string, cidrs: string[]) =>
    post<{ tunnel: Tunnel; added?: number; message?: string }>(
      `/api/tunnels/${encodeURIComponent(id)}:apply-learned`,
      { cidrs },
    ),
  /** 已实现：记下「不用再提示了」，不改任何配置。与观测数据同生命周期。 */
  declineLearnedSources: (id: string) =>
    post<{ ok: boolean }>(`/api/tunnels/${encodeURIComponent(id)}:decline-learned`),
  /** 已实现：把代理端踢下线（连接层操作，不是撤销凭据 —— 它会自动重连）。 */
  kickAgent: (id: string) => post<{ ok: boolean }>(`/api/agents/${encodeURIComponent(id)}:kick`),
  /** 已实现：生效配置 + 来源。v1 没有配置文件，所以来源只会是 env / default / console。 */
  settings: () => get<{ groups: SettingsGroup[] }>('/api/settings'),
  /**
   * 已实现：声明式整份配置的干跑。**一个字节都不写。**
   *
   * 返回的 diff 里 `delete` 一栏是重点：不在文档里的现存隧道会被删掉，
   * 而这是用户在按下「应用」之前唯一的刹车。
   */
  validateConfig: (doc: string) => post<ConfigDiff>('/api/config:validate', { doc }),
  /**
   * 已实现：把文档落成期望状态（新建 + 更新 + **删除**）。
   *
   * 校验是一道全量的门：一条不合法就整份拒绝、什么都不动。写入本身不是原子的
   *（store 没有跨隧道的事务口子），但文档描述的是终态，重跑同一份是安全的。
   */
  applyConfig: (doc: string) => post<ConfigApplyResult>('/api/config:apply', { doc }),
  /** 已实现：TURN 分配枚举（明细来自我们自己维护的表 —— pion 不提供枚举 API）。 */
  turnAllocations: () => get<{ allocations: TurnAllocation[] }>('/api/turn/allocations'),
  /**
   * 已实现：签发一对临时 TURN 凭据，返回可直接喂给 RTCPeerConnection 的 iceServers。
   *
   * 不返回裸凭据而是拼好的 iceServers：让调用方自己拼 turn:/turns: URL 是在请他犯错
   * —— RFC 7065 明确要求「不得用通用的分层 URI 解析器解析 turn: URI」。
   */
  mintTurnCredential: (userID: string, ttlSeconds?: number) =>
    post<IceConfig>('/api/turn/credentials', {
      user_id: userID,
      ttl_seconds: ttlSeconds ?? 0,
    }),
  /** 未实现：中继自检。 */
  selfTest: () => post<ProbeResult>('/api/diagnostics:selftest'),
  /** 未实现：支持包下载。 */
  supportBundleURL: () => '/api/diagnostics/support-bundle',
};
