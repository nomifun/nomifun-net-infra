/**
 * 线协议类型。**Go 是唯一真相源**，这里是它的镜像。
 *
 * 字段名逐一对应 Go 结构体的 json tag：
 *   - Tunnel / Router / Policy / Backend  → internal/tunnel/tunnel.go
 *   - Snapshot / AgentStatus / TunnelStatus / APIError / FieldError
 *                                         → internal/console/server.go
 *   - Event / Sample                      → internal/store/metrics.go
 *
 * 手写而不是生成，理由见 dossier 11「Sharing schema with Go」：生成器只能编码
 * 规则的弱一半（形状），却暗示它编码了全部；真正有意思的校验是跨字段、
 * 服务端作用域的，所以**权威校验是一次往返**（POST /api/tunnels:validate）。
 * 将来若接上 `make gen-api-types`，本文件应被生成物替换而不是共存。
 */

// ── 隧道对象模型（正交四轴）──────────────────────────────────────────────────

/** 方向轴。peer 是场景三预留位，v1 不可用。 */
export type Kind = 'service' | 'reverse' | 'peer';

/** 「中继能否看见明文」轴。 */
export type TLSMode = 'passthrough' | 'gateway';

/** 「外部如何抵达」轴。p2p 是 v2 预留位。 */
export type Exposure = 'port' | 'shared' | 'private' | 'p2p';

export type L4 = 'tcp' | 'udp';

export type RouterKind = 'http' | 'tls-sni';

export type BackendKind = 'addr' | 'unix' | 'handler';

export type State = 'draft' | 'pending' | 'active' | 'degraded' | 'stopped' | 'error' | 'rejected_by_agent';

export interface Backend {
  kind: BackendKind;
  addr?: string;
  path?: string;
}

export interface Router {
  kind: RouterKind;
  domains?: string[];
  locations?: string[];
  host_rewrite?: string;
  /**
   * 把这条隧道设为共享端口的**默认落点**：所有没有匹配到域名的请求都落到它。
   * 一个共享端口最多一条。
   *
   * 场景二的设备只填「中继 IP + 端口」，不发 SNI、Host 是 IP 字面量甚至缺失，
   * 没有任何域名可匹配。用「域名列表为空」暗示这个意图是错的 ——
   * 那让「忘了填域名」与「故意要接住全部」在配置里长得一模一样，
   * 而后者是一个把整个端口都暴露出去的决定。
   */
  catch_all?: boolean;
}

export interface Policy {
  /** netip.Prefix 序列化成 "203.0.113.0/24" 这样的字符串。空数组即「裸端口开放」。 */
  allow_cidrs?: string[];
  max_conns?: number;
  /**
   * **单个源 IP** 的并发上限，0 表示与 max_conns 相同。
   *
   * 只有全局上限时，一个源 IP 就能占满它并把别人挤出去 ——
   * 「最多 N 路」保护的是中继不被压垮，不是保护其他用户。
   * 会被收敛到 max_conns 之内（大于它的话永远不触发）。
   */
  max_conns_per_ip?: number;
  bytes_per_second?: number;
  packets_per_second?: number;
  /**
   * 实时媒体：超过承载数据报上限的包**丢弃**而不是分片。
   *
   * 分片放大丢包影响（任一片丢失整个数据报作废），而一帧迟到的音频
   * 等于丢了还白占带宽。默认 false（分片），因为默认要错向安全的一侧：
   * 一条本该丢弃的媒体流被分片只是多点延迟，而一条本该分片的批量流
   * 被丢弃是静默数据丢失。
   */
  realtime_datagram?: boolean;
}

export interface Tunnel {
  id: string;
  slug: string;
  tenant_id: string;
  kind: Kind;
  tls: TLSMode;
  exposure: Exposure;
  l4: L4;
  agent_id?: string;
  listen_port?: number;
  router?: Router;
  policy?: Policy;
  backend: Backend;
  state: State;
  state_reason?: string;
  /** *bool 的三态：undefined（未设置，视为启用）/ true / false。 */
  enabled?: boolean;
}

/** 新建 / 编辑隧道的请求体。服务端会自己 Complete() 补默认值。 */
export interface TunnelDraft {
  slug: string;
  kind: Kind;
  tls: TLSMode;
  exposure: Exposure;
  l4: L4;
  agent_id?: string;
  listen_port?: number;
  router?: Router;
  policy?: Policy;
  backend: Backend;
  enabled?: boolean;
}

// ── 运行时状态 ──────────────────────────────────────────────────────────────

export interface SnapshotTotals {
  tunnels_up: number;
  tunnels_down: number;
  agents_online: number;
  /** **当前活跃**会话数（曾经这里是累计值，于是没人用的隧道也显示一堆）。 */
  sessions: number;
  bytes_in: number;
  bytes_out: number;
}

export interface AgentStatus {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  online: boolean;
  revoked: boolean;
  /** 当前承载梯级（L0/QUIC…）。frp 回答不了「我现在走的是哪条通道」。 */
  rung?: string;
  supports_datagram: boolean;
  /**
   * 数据报发送队列的计量。**发送器是惰性创建的**，没建过时这个字段缺席 ——
   * 不是一整排 0，因为 0 会被读成「测过，是零」。
   */
  /**
   * 这个 agent **自己上报**的计数器（TypeMetrics，每 5 秒一次）。没收到过则缺席。
   *
   * 与上面 datagram 那组**不是**同一次测量：那是中继观测到的，
   * 这是 agent 自报的。中继看不见 agent 侧的拨号失败、策略否决、
   * 回向队列满、回向重组失败 —— 而那些正是「下行统计都对，
   * 就是收不到回包」的原因。
   */
  reported?: {
    /** 这份数据到达中继的 unix 秒。用来判断上报是不是卡住了。 */
    at_unix: number;
    uptime_seconds: number;
    udp: AgentUDPMetrics;
  };
  datagram?: {
    sent: number;
    bytes: number;
    /** 队列满：承载带宽不够，要加带宽或降码率。 */
    queue_full: number;
    /** 超限：路径 MTU 比我们以为的小，要等 PMTUD 学到新值。 */
    too_large: number;
    failed: number;
    fragmented: number;
  };
  connected_at?: string;
  last_seen_at?: string;
}

export interface TunnelStatus {
  id: string;
  slug: string;
  state: string;
  reason?: string;
  /** **当前活跃**会话数（曾经这里是累计值，于是没人用的隧道也显示一堆）。 */
  sessions: number;
  /** 累计会话数。前端对它差分得出「新会话/秒」。 */
  sessions_total: number;
  bytes_in: number;
  bytes_out: number;
  /** 分阶段拒绝计数。「拒了多少」没用，「在哪一道闸拒的」才告诉你该调什么。 */
  denied_cidr: number;
  no_session: number;
  open_failed: number;
  rate_limited: number;
  /**
   * 以下五项只对 UDP 隧道有意义（TCP 隧道恒为 0）。
   *
   * 包数与字节数都要：UDP 的病态流量是「大量小包」，只看字节数看不出来
   * —— 10 万 pps 的 64 字节包在字节图上是一条平线，在包数图上是一根尖峰。
   */
  packets_in: number;
  packets_out: number;
  /**
   * 承载**反应式学到**的数据报载荷上限（字节）。缺席 / 0 = 还没学到。
   *
   * 它是承载（每 agent 一条 QUIC 连接）的属性，所以同一个 agent 名下所有
   * UDP 隧道是同一个值 —— 与承载 RTT 同理。
   */
  dgram_mtu?: number;
  /** 对应「加容量」与「提每源上限」两个完全不同的运维动作，所以不合并。 */
  dropped_table_full: number;
  dropped_per_ip_quota: number;
  /** 回向路径上 FlowID 查不到的包（会话已过期）。 */
  dropped_unknown_flow: number;
  /** 分片重组失败（超时 / 并发数满 / 字节数满 / 分片重叠）。 */
  dropped_reassembly: number;
  /** 回向分片数与重组成功数。分片率高说明路径 MTU 偏小，而分片放大丢包影响。 */
  fragments: number;
  reassembled: number;
  /**
   * 分片范围重叠而被拒的分片数。**非零就该看一眼** ——
   * 正常发送方按固定步长切片不会重叠；重叠是 teardrop / rose 那类手法。
   */
  reasm_overlapping: number;
  /**
   * 承载 RTT 分位数（微秒）。**缺席或 0 表示还没测到，不是 0 毫秒。**
   *
   * 测的是承载（每 agent 一条 QUIC 连接）的控制流往返，所以同一个 agent
   * 名下所有隧道是**同一条曲线** —— 规格 §8.4 的「每隧道 RTT」是展示粒度，
   * 不是测量粒度。而且它含重传、队头阻塞与对端调度延迟，比链路 RTT 偏大。
   */
  rtt_p50_us?: number;
  rtt_p95_us?: number;
  rtt_p99_us?: number;
  /** 承载发送侧丢的包（队列满 / 超限 / 承载错误）。细分原因在 agent 那一行。 */
  dropped_carrier: number;
  /**
   * 被限速丢掉的量。
   *
   * UDP 上是被丢掉的数据报数；**TCP 上恒为 0** —— 那里限速表现为变慢而不是
   * 丢弃（字节流丢中间一段就是把连接搞坏）。界面要写清楚这一点，
   * 否则用户会以为限速没生效。
   */
  rate_limited_bytes: number;
  /**
   * 因会话表超出容量而被挤掉的流数。
   *
   * 与 dropped_table_full 不是一回事：那一格是「这个包被拒了」，
   * 这一格是「别人的流被挤掉了」——流表淘汰最旧而不是拒绝新流。
   */
  flows_evicted: number;
  /**
   * 「发包的 agent 不是这条隧道的 agent」。**非零就是安全事件** ——
   * 与其他丢弃分项不是一类：其他项调参数，这一项吊销凭据。
   */
  dropped_wrong_agent: number;
  bare_exposure: boolean;
}

export interface Snapshot {
  relay_version: string;
  started_at: string;
  agents: AgentStatus[];
  tunnels: TunnelStatus[];
  totals: SnapshotTotals;
}

// ── 事件与时序 ──────────────────────────────────────────────────────────────

export type EventLevel = 'info' | 'warn' | 'error';

/**
 * 事件种类。这些字符串是**稳定标识**，与 internal/store/metrics.go 的
 * Kind* 常量逐字对应；locale key 直接用它们，所以改一个就会掉一条翻译。
 */
/**
 * 事件种类的封闭枚举。**必须与 internal/store/metrics.go 的 Kind* 常量逐字一致。**
 *
 * 有一条 Go 契约测试（TestEventKindsMatchTheFrontendEnum）会解析本文件
 * 并逐项比对 —— 因为漂过：后端加了 agent.kicked / tunnel.stream_denied /
 * turn.credential_issued 三种，这里一条都没跟上，而 TypeScript 完全看不出来
 * （kind 的类型是 `EventKind | string`，宽容到什么都能过）。
 * 后果是事件流里出现界面不认识的种类，而没有任何一层会报错。
 */
export const EVENT_KINDS = [
  'agent.online',
  'agent.offline',
  'agent.enrolled',
  'agent.revoked',
  'agent.kicked',
  'agent.handshake_failed',
  'tunnel.created',
  'tunnel.updated',
  'tunnel.deleted',
  'tunnel.rejected',
  'tunnel.stream_denied',
  'turn.credential_issued',
  'console.support_bundle',
  'console.config_applied',
  'console.login',
  'console.login_failed',
  'console.login_throttled',
  'pairing_invite.created',
  'relay.started',
  'relay.draining',
] as const;

export type EventKind = (typeof EVENT_KINDS)[number];

/** agent 自报的 UDP 数据面计数（proto.AgentUDPMetrics）。 */
export interface AgentUDPMetrics {
  packets_to_local: number;
  bytes_to_local: number;
  packets_from_local: number;
  bytes_from_local: number;
  flows: number;
  malformed: number;
  unknown_tunnel: number;
  denied: number;
  dial_failed: number;
  table_full: number;
  rate_limited: number;
  write_failed: number;
  /** 「这条流正在拨号，本包丢掉」。持续上涨说明拨号慢，多半是 DNS。 */
  pending_dial: number;
  /** 「隧道的后端改了，在途流被拆掉」。 */
  backend_changed: number;
  /** 队列满要加带宽/降码率；超限要等 PMTUD —— 两个动作方向相反。 */
  send_queue_full: number;
  send_too_large: number;
  send_failed: number;
  send_fragments: number;
  send_mtu_probes: number;
  reasm_completed: number;
  reasm_fragments: number;
  reasm_timed_out: number;
  /** 与 reasm_too_many_frag 都是**安全信号**，不是链路质量信号。 */
  reasm_overlapping: number;
  reasm_too_many_frag: number;
}

export interface RelayEvent {
  id: number;
  at: string;
  level: EventLevel;
  kind: EventKind | string;
  subject?: string;
  message: string;
  actor?: string;
}

/** 一个 1 分钟粒度桶内的聚合指标（internal/store/metrics.go 的 Sample）。 */
export interface Sample {
  tunnel_id: string;
  /** 桶起始的 unix 秒。 */
  bucket: number;
  bytes_in: number;
  bytes_out: number;
  pkts_in: number;
  pkts_out: number;
  conns_ok: number;
  conns_err: number;
  /** 百万分率，整数以避免浮点漂移累积。 */
  loss_ppm: number;
  rtt_sum_us: number;
  rtt_max_us: number;
  samples: number;
}

// ── SSE ─────────────────────────────────────────────────────────────────────

/**
 * SSE 帧。一个端点按 topic 多路复用（GET /api/events）。
 *
 * 为什么不是一个图表一个 EventSource：HTTP/1.1 浏览器每源约 6 连接上限，
 * 那样会把仪表盘拖死。
 */
export type StreamFrame =
  | { type: 'hello'; data: HelloFrame }
  | { type: 'metric'; data: MetricFrame }
  | { type: 'state'; data: StateFrame }
  | { type: 'session'; data: SessionFrame }
  | { type: 'event'; data: RelayEvent }
  | { type: 'log'; data: LogFrame };

export interface HelloFrame {
  /**
   * 首帧快照。中继未接上运行时（snapshot source 为 nil）时**不下发**这个字段，
   * 所以它是可选的 —— 假设它一定存在会在冷启动时崩掉整个仪表盘。
   */
  snapshot?: Snapshot;
  /** 服务器时间（unix 毫秒），前端据此算自己的时钟偏移。 */
  server_time: number;
  /** 单调递增序号，重连后用它判断是否丢过帧。 */
  seq: number;
  /**
   * 服务端的 API 契约版本。
   *
   * 中继当前**不下发**这个字段（internal/console/sse.go 的 hello 只有
   * server_time / seq / snapshot），所以「请刷新」提示暂时不会触发。
   * 字段保留：前端侧的机制已经就位，后端补上即生效。
   */
  api_contract_version?: number;
}

/** 每隧道的实时指标。RTT 是从直方图算出的分位数，单位微秒。 */
export interface TunnelMetric {
  tunnel_id: string;
  /** **当前活跃**会话数（曾经这里是累计值，于是没人用的隧道也显示一堆）。 */
  sessions: number;
  /** 累计会话数。前端对它差分得出「新会话/秒」。 */
  sessions_total: number;
  bytes_in: number;
  bytes_out: number;
  /** 瞬时吞吐，字节/秒。 */
  rate_in: number;
  rate_out: number;
  pkts_in: number;
  pkts_out: number;
  rtt_p50_us: number;
  rtt_p95_us: number;
  rtt_p99_us: number;
  loss_ppm: number;
  /** UDP 分级丢弃：三个站点分别对应 dossier 04 §4.5 的三处丢弃点。 */
  drop_queue_head: number;
  drop_inflight_cap: number;
  drop_kernel: number;
  reorder_count: number;
  reorder_max_depth: number;
  jitter_us: number;
  frag_rate_ppm: number;
  reassembly_timeouts: number;
  /** 反应式学到的当前有效数据报 MTU（字节）。PMTUD 完成前它偏小。 */
  dgram_mtu: number;
  /** 直连 / 经中继的会话数，用于「直连比」。 */
  direct_sessions: number;
  relayed_sessions: number;
  /**
   * 七层指标。**只有网关模式才有**：直通模式下中继不解密，
   * 这里必须是 undefined 而不是 0 —— 0 会被读成「没有 5xx」，
   * 而真相是「我们看不见」。
   */
  http?: HTTPMetric;
}

export interface HTTPMetric {
  status_2xx: number;
  status_4xx: number;
  status_5xx: number;
  req_p95_us: number;
  top_path?: string;
}

export interface MetricFrame {
  /** 采样时刻，unix 毫秒。 */
  t: number;
  totals: SnapshotTotals & {
    rate_in: number;
    rate_out: number;
    rtt_p50_us: number;
    rtt_p95_us: number;
    loss_ppm: number;
  };
  tunnels: TunnelMetric[];
  /** 中继**采样而非排队**：慢客户端丢帧并累加这个计数器，界面显示为流健康点。 */
  dropped_frames: number;
}

/**
 * 状态变化帧。
 *
 * 形状故意宽容：中继**当前**只发 `{tunnel: <id>}` 或
 * `{agent: <id>, revoked: true}`（internal/console/routes.go 的 hub.publish），
 * 而完整形状还要带 state/reason。前端两种都能吃 —— 线上宽容、配置严格，
 * 这与后端 decodeTunnel 的 DisallowUnknownFields 是同一条原则的两面。
 */
export interface StateFrame {
  /** 当前实现：发生变化的隧道 ID。 */
  tunnel?: string;
  /** 当前实现：发生变化的代理端 ID。 */
  agent?: string;
  deleted?: boolean;
  revoked?: boolean;
  /** 完整形状（后端补上后即生效）。 */
  tunnel_id?: string;
  slug?: string;
  state?: State;
  reason?: string;
}

export interface SessionFrame {
  tunnel_id: string;
  /** +1 表示新会话，-1 表示结束。 */
  delta: number;
  /** **当前活跃**会话数（曾经这里是累计值，于是没人用的隧道也显示一堆）。 */
  sessions: number;
  /** 累计会话数。前端对它差分得出「新会话/秒」。 */
  sessions_total: number;
  peer?: string;
  /** 该会话是直连还是经中继转发。 */
  path?: 'direct' | 'relayed';
}

export interface LogFrame {
  at: string;
  level: EventLevel | 'debug';
  msg: string;
  source?: string;
}

// ── 其余端点的响应形状 ──────────────────────────────────────────────────────

export interface EnrolToken {
  token: string;
  /** 可直接复制执行的一行安装命令。 */
  install_cmd: string;
  /** 路由器用的静态二进制形式（wget + 直接跑）。 */
  raw_cmd?: string;
  /** curl | sh 的信任兜底：只打印不执行。 */
  print_only_cmd?: string;
  /** 给手机 / nomifun-tauri 扫的 URL。不可达地址已在服务端过滤。 */
  qr_url?: string;
  expires_at: string;
}

export interface DesktopPairingInvite {
  id: string;
  token: string;
  relay: string;
  pin: string;
  listen_port: number;
  expires_at: string;
  bootstrap_url: string;
  protocol_version?: 1 | 2;
  business_url?: string;
}

export interface DesktopPreflight {
  protocol_version: 2;
  bootstrap_url: string;
  default_business_url: string;
  ready: boolean;
  checks: { code: string; ok: boolean; message: string }[];
}

export interface DesktopConnection {
  invite_id: string;
  note: string;
  business_url: string;
  tunnel_id: string;
  agent_id: string;
  state: string;
  reason: string;
  revoked: boolean;
}

/** 逐跳探测结果。「不通」没用，「哪一跳不通」才有用。 */
export type ProbeHop =
  | 'listener_bound'
  | 'agent_reachable'
  | 'carrier_rtt'
  | 'target_dialable'
  | 'first_byte';

export interface ProbeStep {
  hop: ProbeHop;
  ok: boolean;
  /** 耗时毫秒。 */
  ms?: number;
  detail?: string;
}

/** 一个**没能测**的环节，以及为什么没测。 */
export interface UnverifiedHop {
  hop: ProbeHop;
  why: string;
}

export interface ProbeResult {
  /**
   * 已测的每一跳都通过。
   *
   * **不等于「端到端可用」** —— unverified 非空时还有没测到的环节，
   * 界面必须一并显示，否则 ok 会被读成「测过了，通」。
   */
  ok: boolean;
  /** 从外网视角复测的结果（loopback 会骗人）。 */
  from_internet: boolean;
  steps: ProbeStep[];
  /** 没能测的环节。为空表示每一跳都真的测过了。 */
  unverified?: UnverifiedHop[];
  /** 可复制的等价命令。 */
  example_cmd?: string;
}

/** 配置项的来源。每个字段都要显示生效值**与来源**。 */
export type Provenance = 'file' | 'console' | 'default' | 'env';

export interface SettingItem {
  key: string;
  value: string;
  provenance: Provenance;
  /** provenance==='file' 时的 `/etc/relay/relay.yaml:42`。 */
  source_ref?: string;
  /** 文件管理的行禁止编辑，并把原因放进 tooltip（不是隐藏）。 */
  editable: boolean;
}

export interface SettingsGroup {
  group: string;
  items: SettingItem[];
}

/**
 * 交给浏览器的 ICE 配置。
 *
 * 只有 urls / username / credential 三个成员 —— 现行 W3C WebRTC REC
 *（2025-03-13）已经**没有** credentialType 了，多发字段会让严格的实现报错。
 */
export interface IceServer {
  urls: string[];
  username?: string;
  credential?: string;
}

export interface IceConfig {
  iceServers: IceServer[];
  ttl_seconds: number;
  expires_at: string;
}

/** TURN 分配。故意**不是** Tunnel：它不由控制台创建。 */
export interface TurnAllocation {
  id: string;
  username: string;
  relayed_addr: string;
  peer_count: number;
  bytes_relayed: number;
  /** 凭据剩余有效期（秒）。 */
  credential_ttl_s: number;
  created_at: string;
}

/** 学习模式的观测结果：把实际来源 IP 一键固化成允许列表。 */
/** 一条被观测到的来源前缀。与 console.LearnedSource 对应。 */
export interface LearnedSource {
  cidr: string;
  /**
   * 观测到的次数。
   *
   * 这一列是运维**唯一**能用来区分「真客户端」与「扫了一次的人」的依据 ——
   * 学习窗口里（allow_cidrs 为空、放行一切）两者的地址是混在一起的，
   * 中继分不开。所以界面不做「一键全选」的默认动作，而是把次数与时间摆出来。
   */
  hits: number;
  first_seen: string;
  last_seen: string;
}

/** 一条隧道的学习模式观测结果。与 console.LearnedSources 对应。 */
export interface LearnedSources {
  tunnel_id: string;
  sources: LearnedSource[];
  /**
   * 学习窗口的起点。**是进程启动之后的某一刻** —— 观测只在内存里，
   * 重启即清空（这些是第三方地址，绝不落库）。界面必须显示它，
   * 否则一份只攒了五分钟的列表会被当成完整的。
   */
  observed_from: string;
  /**
   * 这份列表**曾经被上限截断**。
   *
   * 为真时界面换成警告而不是推荐：一份残缺的列表拿去收窄，
   * 会把没上榜的真实客户端全部锁死。
   */
  truncated: boolean;
  /** 操作员已明确拒绝过一次之后就不再提示。 */
  declined: boolean;
}

/**
 * 一条隧道的逐字段校验错误（console.FieldError）。
 *
 * 与 APIError.fields 是同一个形状 —— 声明式导入的失败要能用同一段代码渲染。
 */
export interface ConfigFieldError {
  path?: string;
  message: string;
}

/** 声明式导入里某一条隧道的问题（console.ConfigDocError）。 */
export interface ConfigDocError {
  /** 文档里的第几条（从 0 起）。一条连 slug 都没填的隧道只能靠序号指认。 */
  index: number;
  slug?: string;
  fields?: ConfigFieldError[];
  detail?: string;
}

/**
 * 一次 `config:validate` 的结果（console.ConfigDiff）。
 *
 * `delete` 是这里最重要的一栏：声明式导入会删掉不在文档里的隧道，
 * 而这是用户在按下「应用」之前唯一的刹车。渲染时**不能**只显示条数。
 */
export interface ConfigDiff {
  ok: boolean;
  create: string[];
  update: string[];
  delete: string[];
  unchanged: number;
  errors?: ConfigDocError[];
}

/**
 * 一次 `config:apply` 的回执（console.ConfigApplyResult）。
 *
 * 内嵌 ConfigDiff 的全部字段，所以成功与失败都能用同一段代码渲染。
 * 部分失败时 ok 为 false 而 applied 指明已经落盘了几条。
 */
export interface ConfigApplyResult extends ConfigDiff {
  applied: number;
  code?: string;
  message?: string;
}
