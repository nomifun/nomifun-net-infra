# Dossier 11 — Web Console: Stack Selection and Product Design

Sibling project verified on disk as nomifun-tauri v0.4.1 — now renamed and checked out at
`../nomifun-desktop`; all `ui/...` line numbers are from the v0.4.1 checkout and may drift on
newer versions. Builds on Dossier 07 §8 (frp's enumerated console failures); those are not repeated.

---

## PART A — Stack

**Default to parity with nomifun-desktop; parity wins on almost everything.** One human maintains both, and
the cost of divergence is not "learning a library" but losing the *reflexes* — which Arco prop does
server-side pagination, where the theme token lives, how a locale key gets typed. Parity is also copy-paste:
`ui/uno.config.ts` (the Arco-CSS-var ↔ UnoCSS token bridge, ~200 lines with footguns already documented),
`ui/index.html:2,29-51` (pre-paint `data-theme` + `arco-theme` pair, no FOUC — moved up from
`ui/src/renderer/index.html` after v0.4.1),
`ui/src/renderer/main.tsx:29,84` (`ConfigProvider locale={zhCN}`), and the i18n key-parity machinery all
transfer with zero design work. I deviate in exactly three places.

| Item | Decision | Sibling | Why |
|---|---|---|---|
| Framework | react/react-dom **19.2.8** pinned exact | `^19.1.0` | Same major; nothing to gain by differing. |
| Build | vite **7.3.6** | `^6.4.1` | **Deviate.** No Vite config is shared between repos (the sibling's carries a Tauri/icon-park transform we don't want), so parity buys nothing, while 8.2.1 is one day old and UnoCSS 66 / plugin-react peer ranges under it are unverified. 7.3.6 = the `previous` dist-tag. |
| TypeScript | **5.x line**, not 7.0.2 | `^5.8.3` | TS 7 is the native port; Arco's `.d.ts` surface under it is unverified, and Arco types working is the whole reason we chose Arco. |
| tsconfig | **Deviate: stricter.** Keep `strict`, `target: ES2023`, `moduleResolution: bundler`, `@/*` paths; add `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, and flip `noUnusedLocals/Parameters` to **true** (`ui/tsconfig.json` has them false). | | The sibling relaxed those to survive a large port. This is ~40 greenfield files; strictness is free now and never again — and we index metric ring buffers constantly. |
| UI system | **@arco-design/web-react 2.66.16** | `^2.66.1` | Below. |
| Styling | **unocss 66.7.5** + `unocss-preset-extra`, Arco CSS vars as tokens. **No Tailwind.** | same | Two atomic engines in one app is indefensible. Inherit the documented traps: numeric colour keys hijack directional border classes, so `border-b-2` sets bottom border *colour*, not width (`ui/src/renderer/styles/MIGRATION.md` item 6). |
| Data layer | **swr 2.5.0** | `^2.3.6` | Below. |
| Tables | Arco `Table` | same | Below. |
| Forms | Arco `Form` + **zod 4.4.3** for shape only | Arco Form | Below. |
| Charts | **uplot 1.6.32** live; echarts 6.1.0 lazy for reports; **never Recharts** | n/a | Below. |
| i18n | **i18next 26.3.6** + matching react-i18next | `^23`/`^14` | New version, every convention kept. |
| PM | **bun 1.3.14** | same | |

### Arco vs shadcn/Tailwind — not close

Four reasons, in weight order. **Table depth**: six CRUD grids plus a live-sessions grid; Arco `Table` ships
controlled server-side pagination, fixed/resizable columns, expandable rows, selection and a `virtualized`
prop, where shadcn hands you headless TanStack Table and you author the shell, pagination, empty state and
skeleton seven times. **zh-CN quality**: Arco is ByteDance-authored, so zh-CN is the *source* locale, not a
contributed translation — `Pagination` reads 「共 N 条」natively — whereas Radix kits ship English strings and
an English-first date picker, the single worst component to localise by hand. **Dark mode**: one attribute
flip (`body[arco-theme=dark]`) re-tokens everything; Tailwind's `dark:` variant means authoring every
light/dark pair yourself, forever. **How "designed" it looks**: Arco is a complete language — motion,
elevation, focus rings, plus `Descriptions`, `Statistic`, `Result`, `Empty`, the components an admin console
is 60% made of. A solo maintainer will not out-design ByteDance as a side quest.

### swr over TanStack Query — because the live path is SSE, not polling

TanStack Query's differentiators (invalidation graphs, infinite queries, optimistic rollback) mostly address
*polling* apps. Our reads split cleanly: small config lists via swr, one push stream for everything live. The
pattern that makes the app feel live is ~30 lines — the SSE handler folds deltas into the swr cache via
`mutate(key, updater, { revalidate: false })`. swr's real weakness is mutations; answer it with a ~40-line
`apiMutate()` helper, not a second caching model. Also skip @tanstack/react-table 9.0.1 (one day old).

### Sharing schema with Go — types yes, validators no

**Go is the single source of truth; generate TS *types*; make the server the validator.** The interesting
validation is imperative, not tag-shaped — Dossier 07 §1 shows frp needed 1444 lines of validators because
rules are cross-field and server-scoped (`allowPorts`, subdomain claims), and nothing codegens that. The bug
class that bites is not type drift but *semantic* drift: the console accepts a port the relay later rejects,
exactly frp's store-API defect (§3), surfacing as a tunnel in `error` phase instead of a 400. A generated zod
schema would encode only the weak half of the rules while implying it encoded all. So `make gen-api-types`
emits `web/src/api/types.gen.ts` from the Go canonical structs, **committed** so `bun dev` never needs a Go
toolchain; client-side zod is ergonomic only; and the authoritative check is a round trip —
`POST /api/tunnels:validate` as a dry-run bound to submit, returning `[{path, code, message_zh,
message_en}]` mapping onto Arco Form's `setFields`.

### OpenAPI: publish the spec, hand-write the client

`make openapi` emits a checked-in `openapi.json`; the client is ~150 hand-written lines. Generated clients
lose on three counts: ~25 closed endpoints don't justify per-operation ceremony; output doesn't compose with
swr keys; and **OpenAPI has no first-class model for server-sent events**, our most important channel — the
generator would cover everything except the part that matters. Keep the spec for third-party docs, a CLI
consumer, and a **drift gate**: `make api-diff` fails the local build when a handler's shape changes without
regeneration. Contract artifact, not codegen input; with no CI, every guard is a Makefile target anyway.

### Charts: uPlot, specifically because the data is high-frequency

Recharts is disqualified on architecture: SVG plus one React element per point means a 600-sample × 4-series
chart reconciles thousands of nodes per tick and drops frames at 1 Hz, never mind 4 Hz. ECharts is canvas and
fast but 1 MB+ — lazy-load for report views only. uPlot is ~50 KB canvas and its update path is literally
`u.setData(arrays)` on a prebuilt instance: no VDOM involvement. Pattern: fixed-size `Float64Array` rings per
metric sized to the window (900 samples = 15 min at 1 Hz); the SSE handler writes into the ring; one
rAF-throttled effect calls `setData` at most ~10 Hz **regardless of event rate**. Honest costs: no React
wrapper worth using (~80-line `<LiveChart>` with `useRef` + `ResizeObserver`), and uPlot needs literal
colours — re-read them from `getComputedStyle` on theme change. Its 2025-03-14 date is an asset: frozen and
finished. Corollary: **don't chart what a badge can say** — sparklines are a 30-point inline SVG polyline.

### i18n and the dev loop

zh-CN is the source locale and `fallbackLng`; en-US is derived. Copy the sibling's per-screen namespaced JSON
under `locales/{zh-CN,en-US}/` and, highest-value of all, its generated `i18n-keys.d.ts` +
`localeKeyParity.ts`, which turn a missing translation into a **typecheck failure** — worth more here than
there, because the maintainer writes zh first. Port the vocabulary-lock idea from `check:agent-vocabulary`: a
~12-noun glossary (Tunnel/隧道, Agent/代理端, passthrough/直通, gateway/网关, Session/会话) enforced by script
so the locales and the Go log strings never diverge. Wire the `check:*` scripts into `make web-check`.

Shipping in one binary: `//go:embed all:dist` served by `http.FileServerFS` (Go 1.26), SPA fallback on
`ENOENT` **only** for GET/HEAD on non-`/api` paths; hashed assets `immutable, max-age=31536000`,
`index.html` `no-cache`. Adopt frp's build-tag escape hatch verbatim (§6): `//go:build !noweb` +
`embed_stub.go`, Makefile auto-adding `noweb` when `web/dist` is absent — that keeps `go build ./...` working
in a fresh clone with no bun, and it is why assets are a non-issue for `CGO_ENABLED=0` ARM/MIPS
cross-compiles (identical bytes per target). Keep an `--assets-dir` override. **Do not** gzip per request
(frp re-gzips already-compressed assets); precompress and negotiate `.br`/`.gz`. Dev: `vite dev` on 5173 with
`server.proxy` for `/api` gated on `mode === 'webdev'` as `ui/vite.config.ts` does, plus two SSE-specific
requirements — `changeOrigin: false` (keeps the host-only session cookie mapped to 127.0.0.1) and **no proxy
`timeout`**, or the stream is severed mid-flight. Copy the build-manifest plugin (`nomifun-build.json` +
`ui-api-contract-version.txt`) so a stale cached SPA against a newer relay shows 「请刷新」 rather than mystery
400s. One sibling constraint does **not** apply: it abandoned SSE because `EventSource` cannot carry the
desktop's local-trust header (`ui/src/common/adapter/ipcBridge.ts:3578`); a cookie session has no such issue.

---

## PART B — Product / UX

### The object model — agree with Dossier 07's Tunnel, with three sharpenings

**Tunnel is the noun and the relay is authoritative.** Dossier 07 §9's reasoning is the crux: in frp the
*client* owns proxy config, which is exactly why the relay console can never offer a write path (§8 item 1).
Inverting ownership is what buys console-first CRUD. Three corrections:

1. **Split the word "mode".** Dossier 07 uses `mode ∈ {service, reverse}` for direction; the owner uses
   passthrough-vs-gateway for TLS handling. Orthogonal axes must not share a label. Canonical:
   `kind ∈ {service, reverse}` × `tls ∈ {passthrough, gateway}`. Free now, a migration later.
2. **Tunnel is desired state; Session is observed state; different objects.** frp conflates config and
   runtime in one table, which is why it needs a *Clear Offline* button. A Session's absence must never imply
   a Tunnel's deletion; dead Sessions age out on their own.
3. **Agent is a dependency of a Tunnel, not its container.** One canonical JSON shape for file, store, API
   and UI — the fix for frp's three-shapes-one-object defect. Human slug as key, visible in the URL.

The test the model must pass: **one table row answers "where do I go, and where does it land?"** —
`https://api.example.com → agent "home-desktop" 127.0.0.1:8080`. frp's row is `name/type/status` and the user
synthesizes the endpoint from a concatenated string. Consequence: **S1 and S2 are the same object with a
different `kind`** — we are not building two products. TURN allocations are deliberately *not* Tunnels; they
aren't console-created, so forcing them in would break the model. Own screen.

### Information architecture

| Nav | Purpose |
|---|---|
| **概览** | Live tile row: tunnels up/down, sessions, throughput, **p50/p95 RTT, loss%**, direct-vs-relayed ratio; plus a recent-events feed. SSE-fed. |
| **隧道** | The CRUD table, centre of gravity. Detail = three tabs 实时 / 配置 / 历史. |
| **代理端** | Per agent: version, OS/arch, NAT type + STUN result, direct-vs-relayed ratio, last-seen, rotate join token, kick. |
| **媒体中继** | TURN allocations, bytes relayed, credential TTL. pion/turn exposes no counters and no allocation enumeration (Dossier 15 B8), so this is fed by our counting `RelayAddressGenerator`. |
| **诊断** | Live log tail, NAT/STUN self-test, port-reachability check, audit log, support-bundle download. |
| **设置** | Listeners, TLS/ACME, auth, retention, backup. Every field shows effective value **and provenance**. |

### Passthrough vs gateway, surfaced honestly

At creation this is **two radio cards, never a dropdown**, each stating what you get and lose:

| | 直通 passthrough | 网关 gateway |
|---|---|---|
| TLS 私钥位置 | 你的服务器 | **中继** |
| 中继可见明文 | 否 | 是 |
| ACME 自动证书 | ✗ | ✓ |
| Host/路径路由，多隧道共用 443 | ✗（一端口一隧道） | ✓ |
| 注入鉴权 / 改写请求头 | ✗ | ✓ |
| 后端拿到真实客户端 IP | 仅 PROXY protocol | XFF + PROXY |
| 状态码 / 路径 / 每请求延迟指标 | ✗ | ✓ |
| S2 ESP32（裸 IP，无 SNI） | ✓ | ✓（明文 http/ws） |

The honesty mechanism: gateway-only fields in passthrough are **greyed out with a reason**, not hidden, so
the user learns the price. The 实时 tab renders a literal placeholder where HTTP metrics would be:
「直通模式下中继不解析应用层，故无状态码/路径指标。可用：连接数、字节、RTT。」 Per Dossier 15 B6 the backend's
client IP is genuinely `unknown` in passthrough — surface that, do not silently patch it. That placeholder
carries a **切换到网关模式** action opening a diff preview (cert issuance begins, private key moves to the
relay, these headers get injected) requiring confirmation. Never switch silently.

### The S2 bare-port risk, without nagging

One quiet, **actionable**, persistent indicator; no modals, no repeat toasts. **At creation only**, an 暴露面
summary computed from real config — `0.0.0.0:8443 · 来源 IP: 任意 · 应用层鉴权: 无` — with typed confirmation
required only for `0.0.0.0/0` on a listener that has neither allowlist nor secret (Dossier 12 A2 rule 1:
default empty = deny). **Ongoing**, a narrow 暴露 column with three states: ● 受限 / ● 开放 / ● 开放·已接受.
The anti-nag is that the warning must be **reducible in one click**: pair it with Learn mode (A2 item 3) —
「观察到 2 个来源 IP（203.0.113.9, 203.0.113.10），固定为允许列表」. If the operator declines, log name +
timestamp, flip the badge to informational, and **stop asking**. Hard rule: never present a random high port
as security — ~16 bits, Shodan-enumerable. No 「端口即密钥」 string may exist in the locale files.

### First run: zero → working tunnel in under 2 minutes

Any request to an unconfigured relay lands on `/setup`. (1) Create admin — generate a 24-char password, show
once, copy, refuse empty; never admin/admin, whose frp equivalent is an unauthenticated dashboard on
`0.0.0.0` (§7). (2) Relay self-detects its public address via STUN and shows it to confirm. (3) **Attach a
target**, two first-class paths side by side:

- *有代理端* (S1): a one-liner carrying a **15-minute, single-use, enrol-one-agent token** —
  `curl -fsSL https://relay/install.sh | sh -s -- --token nf_enrol_…` — plus the raw static-binary form for
  routers (`wget` + `./nomifun-relay agent --token …`, viable because CGO_ENABLED=0), plus `--print-only` as
  the trust affordance any `curl | sh` needs. **QR of the same token URL** for the phone/nomifun-desktop path:
  reuse `qrcode.react ^4.2.0` *and* the reachability filter in
  `ui/src/renderer/components/layout/Sider/webuiQrLinks.ts`, which already rejects
  127/0.0.0.0/169.254/multicast/TEST-NET hosts — precisely the bug a naive QR ships with.
- *无代理端* (S2): 「直接转发到一个地址」, the relay dials the target itself. The factory operator installs
  nothing, so this must not be buried.

(4) The screen **waits live** on SSE and flips to 「已连接 home-desktop (linux/arm64, NAT:
endpoint-independent)」. (5) Template picker — HTTP+WS API / UDP 媒体 (WebRTC+TURN) / 固定端口→远程桌面 /
TCP·SSH — prefilling the target. (6) **测试** probes end-to-end and hands over a copyable `curl`; the wizard
exits into the tunnel detail page, already live. Honest clock: steps 1–2 and 5 are ~20 s of typing, step 3
one paste, and the long pole is the agent download — pin the URL, publish a checksum.

### Real-time observability

**One SSE endpoint multiplexed by topic**: `GET /api/events` carrying `hello` (snapshot + server time +
monotonic seq), `metric` (1 Hz), `session` (start/end deltas), `state` (up/down), `log` (rate-limited), with
subscribe over a companion POST. Multiplexing is not over-engineering: HTTP/1.1 caps browsers near 6
connections per origin, so one `EventSource` per chart would deadlock the dashboard. `metric` writes into
uPlot rings; `session`/`state` fold into swr caches. SSE beats WebSocket here: one-way, proxy-friendly, free
reconnect via `Last-Event-ID`, no framing code, Go-side just `ResponseController.Flush()`. And the relay
**samples, never queues** — a slow client drops `metric` frames and bumps a counter shown as a stream-health
dot, the same drop-never-block law as the data plane (Dossier 04 §4.5).

What frp cannot show at all (its telemetry vocabulary is bytes and connection counts — §8 item 4):
**per tunnel**, p50/p95/p99 carrier RTT, loss %, throughput, active sessions, new sessions/s, errors/s.
**UDP for S1 media**: pps in/out, and **drops broken out by stage** — public-socket→flow-queue drop-head,
flow→carrier inflight-cap drop, carrier→local-socket kernel error (Dossier 04 §4.5's sites). "We dropped" is
useless; "we dropped at the carrier inflight cap" tells you what to raise. Plus **reorder count and max
reorder depth** from sequence gaps, **smoothed inter-arrival jitter**, **fragmentation rate and reassembly
timeouts**, and the **current effective datagram MTU** learned reactively from
`DatagramTooLargeError.MaxDatagramPayloadSize` — display it, because it starts near 1244 B before PMTUD
completes and nothing else will explain a size-dependent failure. **TURN**: allocations, bytes relayed, and
direct-vs-relayed ratio per agent, the number that predicts the bandwidth bill. Retention is SQLite rollups
(`modernc.org/sqlite` v1.56.0, `modernc.org/libc` pinned exactly): 1 s live in RAM, 10 s for 24 h, 1 min for
30 d — replacing frp's volatile in-RAM 7 days.

### Premium details

**测试** is a real probe with per-hop verdicts (listener bound → agent reachable → carrier RTT → target
dialable → first byte / 101 upgrade), naming the failing hop, with a 从外网测 variant so loopback can't fool
you. **Generated config preview**: a read-only pane showing the exact agent config *and* the exact
`relay.yaml` fragment, live-generated from the form, copyable — the GitOps bridge, where console teaches and
file commits; never round-trip file → console (§9). **Copyable examples** from real config (`curl -i`,
`websocat wss://…`, `nc -u`), and for S2 the two fields the operator types into the robot's web form as a
labelled pair — the actual deliverable. **Health badges**: four states max (运行中/降级/停止/错误), degraded
always carrying a reason (「代理端在线但 p95 RTT > 300 ms」); no bare red dot without a why. **Empty states**
are one primary action, never prose — Tunnels-empty renders the four templates as cards, Agents-empty the
install one-liner inline. **Dark mode** sets attributes pre-paint per `index.html:23,45-48`; uPlot re-reads
strokes on theme change. **Provenance badges** on every field and row — `文件 /etc/relay/relay.yaml:42`
(read-only, with 复制为控制台副本) / `控制台` / `默认值` / `环境变量` — with file-managed rows edit-**disabled
and the reason in the tooltip**, not hidden; Settings gets an effective-config view with a provenance column,
and writes go through `POST /api/config:validate` then `:apply`, so a broken document can never reach disk
(frp's `PUT /api/config` writes unvalidated bytes, §4). Audit entries name operator + diff; destructive
actions type-to-confirm the slug; filter state lives in the URL; `/` searches, `c` creates.

### Wireframes

**1. Tunnels — the object model made visible**

```
┌─ NomiFun 中继 ────────────────────── 概览 隧道 代理端 媒体中继 诊断 设置 ── 🌙 zh ─┐
│ 隧道 (7)          [搜索 /]  类型:全部▾ 状态:全部▾ 模式:全部▾      [+ 新建隧道 c]│
├───────────────────────────────────────────────────────────────────────────────┤
│ 状态  名称/公网端点 → 目标                    模式   暴露  会话  RTT      24h  │
│ ●运行 phone-api                              网关   ●受限  12  ▁▂▃▂▁ 34ms 2.1G│
│       https://api.nomi.dev  →  home-desk 127.0.0.1:8080    p95 71ms          │
│ ●运行 media-udp                              直通   ●受限  3   ▁▁▂▁▁ 18ms 8.7G│
│       udp://relay:41820     →  home-desk 127.0.0.1:5004   丢包 0.2% 480pps   │
│ ●降级 robot-hmi   ⓘ p95>300ms                直通   ●开放  1   ▃▅▇▅▃ 312ms 44M│
│       tcp://203.0.113.7:8443 →  desk-A 10.0.0.5:80    📄文件管理             │
│ ○停止 ssh-fallback                           直通   ●受限  0   ─      0      │
│       tcp://relay:2222      →  home-desk 127.0.0.1:22                        │
│                                        [启用][编辑][复制][测试][删除] ⋯每行  │
└───────────────────────────────────────────────────────────────────────────────┘
```

**2. Tunnel detail → 实时 (the frp-beating screen)**

```
┌ 隧道 / media-udp   ●运行中   直通 · UDP · kind=service   [测试] [编辑] [⋯] ─┐
│ ┌ 实时 ┬ 配置 ┬ 历史 ┐                            ⬤ 流健康 正常 (0 丢帧)   │
│ RTT p50/p95/p99      丢包 %              吞吐 in/out        当前 DGRAM MTU  │
│  34 / 71 / 128 ms     0.21 %             3.1 / 8.4 Mbps      1200 B (已协商) │
│ ┌──────────────────────────────────────────────── 15 分钟 · 1 Hz ─────────┐ │
│ │ 200ms┤                                    ╭╮        p95 ───            │ │
│ │ 100ms┤        ╭─╮      ╭╮        ╭───╮ ╭──╯╰─╮      p50 ───            │ │
│ │   0  ┼────────┴─┴──────┴┴────────┴───┴─┴─────┴──────────────────────────│ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ UDP 分级丢弃 (60s)          乱序            分片            会话 (3)         │
│  公网→队列(丢队头)  142     计数 37       分片率 0.0%    对端            pps │
│  队列→载体(inflight) 8      最大深度 3     重组超时 0     198.51.100.7:9 240 │
│  载体→本地(内核)     0                                    198.51.100.8:9 238 │
│ ┌ 直通模式：中继不解析应用层，无状态码/路径指标 ── [了解] [切换到网关模式] ┐│
└───────────────────────────────────────────────────────────────────────────────┘
```

**3. 新建隧道 — mode chooser + exposure, honest by construction**

```
┌ 新建隧道 ── ① 目标 ─ ② 协议 ─ ③【模式】─ ④ 暴露 ─ ⑤ 测试 ───────────────┐
│ 中继如何处理 TLS？                                                        │
│ ┌───────────────────────────────┐ ┌───────────────────────────────────┐  │
│ │ ○ 直通 passthrough            │ │ ● 网关 gateway         ← 推荐     │  │
│ │ 中继只搬运密文，不解密         │ │ 中继终止 TLS，按 Host/路径路由     │  │
│ │ ✓ 私钥留在你的服务器           │ │ ✓ ACME 自动证书                   │  │
│ │ ✓ 端到端加密，中继零信任        │ │ ✓ 多隧道共用 443                  │  │
│ │ ✗ 无 ACME，证书自理            │ │ ✓ 可注入鉴权 / XFF 真实 IP        │  │
│ │ ✗ 一个端口一条隧道             │ │ ✓ 状态码/路径/每请求延迟指标       │  │
│ │ ✗ 无 HTTP 层指标，后端拿不到    │ │ ✗ 私钥与明文经过中继              │  │
│ │   真实客户端 IP（仅 PROXY）     │ │   （ESP32 无 SNI 场景仍可用）      │  │
│ └───────────────────────────────┘ └───────────────────────────────────┘  │
│ ── 暴露面 ────────────────────────────────────────────────────────────── │
│ 0.0.0.0:8443 · 来源 IP: ●任意 · 应用层鉴权: 无      [添加来源允许列表]   │
│ ⓘ 机器人只填 IP+端口时，边界只能在网络层。上线后可用「学习模式」一键固定。│
│                                          [上一步]  [下一步：暴露设置]     │
└───────────────────────────────────────────────────────────────────────────┘
```
