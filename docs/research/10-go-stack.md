# 10 — The definitive Go stack dossier

Versions verified against the registry this run or in local `go1.26.5`. **unverified** = confirm at implementation
time; no invented numbers. Counterpoint is frp (dossiers 01/02/07/12); §16 carries every module+version+why. Two
binaries, split load-bearing (§15): **`nfrelay`** (store, console, gateway, TURN), **`nfagent`** (carrier + dialer,
no SQLite).

## 1. Go target and stdlib leverage

`go 1.26.0` — also a floor, since `prometheus/client_golang` supports only the two newest Go majors. Stdlib features
that delete dependencies:

- **`ServeMux` patterns** (`"POST /api/v1/tunnels/{id}"`, `{name...}`, `{$}`, `r.PathValue`) — why chi is
  unnecessary. **Caveat:** host patterns are *literal only*, no `*.example.com`, so gateway multi-tenant vhost
  routing needs a hand-written Host router (longest-suffix wildcard + path prefix, explicit precedence).
- **`ResponseController`** (`Flush`/`Hijack`/`EnableFullDuplex`/deadlines) — powers SSE; also what `ReverseProxy`
  uses for 101 upgrades. **`FileServerFS(fs.FS)`** — serves the console from `embed.FS`.
- **`http.Protocols`/`SetUnencryptedHTTP2`** — pin *gateway* listeners to HTTP1 (S2's ESP32 speaks plain HTTP/1.1);
  the console listener enables HTTP2, escaping the 6-per-origin SSE cap (§6).
- **`CrossOriginProtection`** (free CSRF), **`log/slog`** (only logger), **`crypto/rand.Text()`** (128-bit secrets),
  `hkdf`/`pbkdf2`/`hmac`/`subtle` in-tree, **`testing/synctest`** (fake clock). **`crypto/tls`** 1.26 defaults
  include `X25519MLKEM768` + `SecP256r1MLKEM768` — leave `CurvePreferences` nil, since setting it silently disables
  post-quantum.
- **`encoding/json/v2` is real but gated.** Verified: `$GOROOT/src/encoding/json/v2` exists under
  `//go:build goexperiment.jsonv2`; `GOEXPERIMENT=jsonv2 go run` round-trips. **Not for v1** — a whole-build flag
  that must match across a 15-target matrix and can still change. Use v1 behind a one-function codec seam.

## 2. Transport: QUIC-first, with a fallback ladder

**QUIC is primary** (`quic-go v0.61.0`): RFC 9221 datagrams (`SendDatagram`/`ReceiveDatagram`,
`quic.Config{EnableDatagrams:true}`, both peers opt in, check `ConnectionState().SupportsDatagrams.{Local,Remote}`)
let S1's A/V UDP skip retransmission and head-of-line blocking; native streams remove a muxer; migration survives a
phone changing networks. **No getter for max datagram size** — learn it from
`*quic.DatagramTooLargeError.MaxDatagramPayloadSize`, cache per connection, re-learn on error. Probe rungs in
parallel, race to first success, cache the winner per agent, **and show the current rung in the console** (frp
cannot):

| Rung | Carrier | Beats |
|---|---|---|
| L0 | QUIC/UDP, configured port, ALPN `nomifun-relay/1` | normal networks |
| L1 | QUIC/UDP:443 | only-443 egress filters |
| L2 | TLS/TCP:443 + smux | UDP fully blocked |
| L3 | WSS:443, HTTP/1.1 Upgrade, `/_nf/t/v1`, **binary frames**, + smux | ALPN-hostile middleboxes, MITM proxies |
| L4 | L3 via customer nginx/Caddy or the org's nomifun-bridge-server | CDN-fronted |

Binary frames on L3 are mandatory — frp's `pkg/util/net/websocket.go:34-39` documents middleboxes UTF-8-validating
text frames and killing the tunnel. **CDN-fronted is gateway-mode-only**: a CDN terminates TLS, so passthrough's
end-to-end property is gone; the console must refuse `passthrough` + CDN. **Maintenance signal:** frp forks yamux
(`go.mod:78`, `replace … => fatedier/yamux`); upstream has three tags ever, last Sep 2024.

## 3. Multiplexing

`smux v1.5.57`, **only** on L2–L4; QUIC has native streams. **Stay on the v1 import path** — `v2.0.x`
`+incompatible` tags are from 2019 and older than v1. Never `DefaultConfig()` unexamined: set
`KeepAliveInterval/Timeout`, `MaxReceiveBuffer`, `MaxStreamBuffer`. One `Carrier` interface hides both, extending
frp's cleanest idea (`client/connector.go:40-44`) to be bidirectional: `OpenStream`/`AcceptStream`,
`SendDatagram`/`ReceiveDatagram` (QUIC native; framed on a dedicated stream for smux), `Rung()`, `Close()`.

## 4. Control-plane framing and codec

One control stream per carrier. **Fixed 12-byte big-endian header:**

```
0:1 ver=1 | 1:1 flags (b0 response, b1..2 codec id, b6 end-of-seq, b7 critical)
2:2 type uint16 | 4:4 corrID uint32 (0 = unsolicited event) | 8:4 length uint32 (<=1<<20) | 12:N payload
```

**Forward compatibility is a REQUIREMENT.** Reader does `io.ReadFull(hdr[:12])`, rejects `length > maxFrameLen`
*before allocating*, and on unknown `type` does `io.CopyN(io.Discard, r, int64(length))` and **continues — never
closes the connection**. Unknown + `b7 critical` also replies `TypeUnsupported (0x000F)`, but still skips. That lets
a v1.3 relay talk to a v1.0 agent forever, and makes the parser an ideal fuzz target (§14).

**Codec: JSON (`encoding/json`).** Control plane is low-rate and the data plane never touches the codec, so
throughput is irrelevant; JSON is readable in `tcpdump`/`slog`/the console's raw-frame panel, tolerates unknown
*fields* by default (never `DisallowUnknownFields` on the wire — do use it on config), and needs no codegen, which
matters when a Makefile is the only build system. Rejected: protobuf (`protoc` for ~30 messages), CBOR (opaque,
canonical-encoding subtleties once signatures appear). `flags` b1–2 reserve a codec id so binary stays additive.

## 5. HTTP: stdlib only

**No chi/gin/echo.** ServeMux covers method+wildcard routing (chi's only draw); middleware is
`func(http.Handler) http.Handler`; gin/echo impose a proprietary context that poisons every signature; and **our
server is simultaneously console API and data-plane gateway**, needing raw `net.Conn` — what frameworks obscure.
**Reverse proxy: `httputil.ReverseProxy`**, verified in local go1.26.5 source to handle WebSocket/101 natively
(`reverseproxy.go:573-579` → `handleUpgradeResponse:820-890`, hijack via `ResponseController`) — no hand-rolled
Hijack path. Use `Rewrite` not `Director`; `FlushInterval = -1` for streaming; a per-tunnel `Transport` whose
`DialContext` dials *into the tunnel*; `ErrorHandler` → 502 + metric; inbound HTTP/1.1, never h2-only ALPN.
`go-proxyproto v0.15.0` preserves client IP behind foreign LBs (and adds the UDP PROXY support S1 needs); it changed
`DefaultPolicy` to REQUIRE, so set policy per listener and trust PROXY headers only from an allowlisted upstream.

## 6. WebSocket — and SSE for the console stream

`coder/websocket v1.8.15` for L3: `websocket.NetConn` yields a `net.Conn` feeding smux. `MessageBinary`, compression
off, raised `SetReadLimit`. **Reject `gorilla/websocket v1.5.3`** — no tag in ~2 years, and v1.5.3 was itself a
revert of v1.5.2 back to v1.5.0. **Console event stream: SSE, not WebSocket** — console→server is already REST, so
the socket would be one-way anyway; SSE survives proxies that mangle `Upgrade`, gives reconnect with `Last-Event-ID`
resume free, and reuses ordinary auth + `CrossOriginProtection` instead of WebSocket's Origin dance.
`text/event-stream`, `Flush()` per event, comment heartbeat every 15 s, **one stream per tab** multiplexing topics
via the `event:` field, over HTTP/2.

## 7. Persistence

`modernc.org/sqlite v1.56.0` (pure Go, SQLite 3.53.3). **Critical: pin `modernc.org/libc` to the exact version in
sqlite's own `go.mod`** (upstream issue #177). Avoid retracted v1.42.0, v1.34.3, v1.33.0, v1.29.4, v1.20.1,
v1.16.0–v1.17.2. Open `WAL` + `synchronous=NORMAL` + `busy_timeout=5000` + `foreign_keys=ON`; a write handle with
`SetMaxOpenConns(1)` plus a read pool eliminates `SQLITE_BUSY` as a bug class. **Migrations: `goose/v3 v3.27.3`** —
`.sql` via `embed.FS` + `goose.SetBaseFS`, `WithLocker`, `WithSlog`; avoid retracted v3.21.0 and never read the
in-code `VERSION` constant (still "v3.18.0"). Reviewable SQL beats atlas's DSL.

**Timeseries rollups — what frp lacks entirely.** Identical tables at 1 m / 5 m / 1 h, all `WITHOUT ROWID`:

```sql
tunnel_sample_1m(tunnel_id, bucket,        -- bucket = unix sec floored to interval
  bytes_in, bytes_out, pkts_in, pkts_out, conns_ok, conns_err,
  loss_ppm,                                -- integers avoid float drift
  rtt_sum_us, rtt_max_us,
  samples,                                 -- fold count; needed to re-average when rolling up
  PRIMARY KEY (tunnel_id, bucket))
tunnel_rtt_hist_1m(tunnel_id, bucket, le_us, count,  -- percentiles must not be averaged
  PRIMARY KEY (tunnel_id, bucket, le_us))
```

Rollup is one ticker goroutine: `INSERT … SELECT … GROUP BY bucket/300 … ON CONFLICT DO UPDATE`, then a range
delete. Retention 1 m→48 h, 5 m→30 d, 1 h→400 d. **Store the `le_us` histogram for RTT, not a p95 column** — the
console shows p95 and a p95-of-p95 is arithmetically wrong. 400 days hourly × 200 tunnels ≈ 1.7 M rows.

## 8. Configuration

**TOML** via `go-toml/v2 v2.4.3`, loaded by `koanf/v2 v2.3.6` (koanf's providers are separate modules, **versions
unverified**). **Layered provenance: defaults < file < store (SQLite) < env,** plus a parallel `map[string]source` of
which layer last set each key, shown in the console — frp can't answer "why is this value what it is", and every
support conversation starts there. **Env templating:** expand `${NF_X}` / `${NF_X:-default}` over file bytes *before*
parsing, restricted to an `NF_` allowlist, never logging expansions for keys matching
`*token*|*secret*|*password*|*key*`. Unknown-field strictness on: a config typo must error.

**Three stages, strictly separated.** `Complete()` — fill zeros, derive dependents; mutating, idempotent, no I/O, no
errors. `Validate() error` — pure, returns **all** failures via `errors.Join` so the console highlights every bad
field at once; struct tags via `validator/v10 v10.30.3` at the DTO boundary, hand-written cross-field logic for relay
semantics (port collisions, `passthrough` + ACME, CDN + passthrough). `Clone() *Config` — deep copy, so hot reload
builds a candidate, Completes, Validates, then swaps atomically.

## 9. TLS and ACME

**`certmagic v0.25.4`, not `x/crypto/acme/autocert`.** Gateway mode is multi-tenant and tunnels appear from the
console at runtime, so certs must issue for names unknown at boot; autocert's `HostPolicy` is a static allowlist you
must rebuild. certmagic has real on-demand TLS via `DecisionFunc func(ctx context.Context, name string) error`
(verified — the README is stale), shared storage, `TryLocker`/`FileStorage.TryLock` (v0.25.1) and `LockLeaseRenewer`
(v0.25.0) for multi-instance safety, DNS-01 wildcards, ZeroSSL fallback. Pre-v1: pin exactly.

**certmagic's rate limiter is a queuer, not a gate — ours is mandatory.** *(Corrected 2026-08-08 against
v0.25.4 source; the earlier claim "ships no rate limiter" was wrong.)* It does ship `ratelimiter.go`, but
`acmeclient.go` calls `rl.Wait(ctx)` rather than `Allow()`, and the bucket is keyed on CA directory + account.
So a flood of unregistered SNI names **queues inside the TLS handshake** instead of being rejected — the
handshake goroutines are held, not freed. It also has **no negative cache for failed issuance** (grep for
`failedIssuance` / `Backoff` finds nothing), so a domain the CA just refused is retried on the very next
handshake — and Let's Encrypt's failed-validation limit is easier to hit than its success limit.

`SubjectQualifiesForPublicCert` is **not** sufficient to reject IP literals either *(corrected 2026-08-08;
verified at `certificates.go:586`)*: it only calls `SubjectIsInternal`, which for an IP checks private/loopback
via `isInternalIP`. A **public** IP literal passes — and with an empty SNI certmagic substitutes the local
connection IP as the name (`handshake.go`: `getNameFromClientHello` → `localIPFromConn`), which on a relay with
a public address is exactly a public IP. So `SubjectIsIP` must be called explicitly.

The `DecisionFunc` must therefore reject SNI names absent from the tunnels table, cap new-name issuances per
window, and negative-cache failures; else a scanner spraying random Host headers burns the ACME quota. Passthrough never terminates TLS → no ACME, SNI routing only; the console must
state that trade-off at the point of choice. For IP-only S2 endpoints, self-sign ECDSA P-256 and publish the SPKI
SHA-256 pin. **Never `InsecureSkipVerify`** — frp's default is exactly that (`pkg/transport/tls.go:150-152`), making
its "default TLS" encryption without authentication.

## 10. Auth and crypto

**Opaque tokens — not JWT, not PASETO.** The relay is the only verifier and already has the DB open, so claims buy
nothing: revocation is a `DELETE` not a denylist, no `alg`-confusion bug class, 32 bytes not 700. Wire form
`nfr_1_<id>.<secret>`: index on `id`, verify `subtle.ConstantTimeCompare(sha256(secret), stored)`. Enrolment =
single-use `crypto/rand.Text()` token stored as SHA-256 + expiry + use-count, exchanged over TLS for a long-lived
agent credential. For offline verification prefer PASETO v4 over JWT — **library unverified**, and not v1.
Designed against frp's failures (`pkg/util/util/util.go:50-56`, `pkg/transport/tls.go:150-152`):

| frp | Ours |
|---|---|
| `hex(MD5(token ‖ timestamp))` | `HMAC-SHA256(agent_key, canonical(ver‖ts‖nonce‖alpn‖exporter))` |
| `Timestamp` sent but never checked → replayable forever | reject `\|ts − now\| > 60 s`, metric `outcome="stale"` |
| no nonce, no replay ledger | 16-byte nonce in a bounded LRU keyed `(agent_id, nonce)`, TTL = 2× window |
| no channel binding | mix `tls.ConnectionState.ExportKeyingMaterial` into the MAC — replay on another TLS session fails even inside the window |
| `InsecureSkipVerify = true` default | ACME, or an explicit SPKI pin surfaced in the console |

**Passwords: Argon2id** via `golang.org/x/crypto/argon2` (v0.54.0, verified present) — m=64 MiB, t=3, p=2, PHC string
so parameters are upgradable; bcrypt cost 12 by config where 64 MiB isn't available (MIPS). Compare only
fixed-length hashes. ≥v0.52.0 mandatory if we ever add SSH (GO-2026-5005…5033, incl. auth bypasses); **never import
`x/crypto/openpgp`** (GO-2026-5932). S2 hardening (optional, default ON when bound to `0.0.0.0`): a `netip.Prefix`
source allowlist evaluated before `Accept`, plus a per-port secret (`X-NF-Port-Secret`, or a first-bytes preamble).

## 11. Rate limiting and shaping

**Control plane / API / ACME:** `golang.org/x/time/rate v0.15.0` buckets keyed per agent, per endpoint class, and per
source aggregate — **/24 and /64, not bare IPs** — with the limiter map LRU-bounded so the keyspace isn't itself a
DoS. **Data plane: do not use `x/time/rate` for bytes** — `Wait` granularity is poor at 100 Mbit. Token-bucket
`io.Reader`/`io.Writer` pair (burst 256 KiB, monotonic refill) inside the copy loop, separate up/down, and **shape
datagram paths by packet rate *and* bytes** — 100 kpps of 64-byte packets is the realistic attack and a byte-only
limiter waves it through. Three tiers — per-tunnel, per-agent, global — effective (minimum) limit shown; frp has only
per-proxy, so one tenant can wedge the relay. TURN metering rides the counting `RelayAddressGenerator` wrapper from
dossier 15 (pion/turn exposes no counters).

## 12. Metrics

`prometheus/client_golang v1.24.1` + standard Go/process collectors. Do **not** touch its `api/…` subpackage —
upstream says breaking changes there won't trigger a major bump.

| Metric (type) | Labels |
|---|---|
| `nf_build_info` (gauge=1) / `nf_agent_connected` (gauge) | `version, commit, go_version` / `agent` |
| `nf_agent_handshakes_total` (counter) | `outcome=ok\|bad_mac\|stale\|replay\|unknown_agent\|revoked\|ratelimited` |
| `nf_carrier_sessions` (gauge) / `nf_carrier_rung_change_total` (counter) | `rung, agent` / `from, to, reason` |
| `nf_tunnel_bytes_total` / `nf_tunnel_packets_total` (counters) | `tunnel, mode=passthrough\|gateway, dir` |
| `nf_tunnel_conns_total` (counter) / `nf_tunnel_active_conns` (gauge) | `tunnel, outcome` / `tunnel` |
| `nf_tunnel_rtt_seconds` (hist 1 ms…2 s) / `nf_tunnel_loss_ratio` (gauge) | `tunnel` |
| `nf_datagram_dropped_total` (counter) | `reason=too_large\|no_route\|shaped\|peer_unsupported` |
| `nf_shaper_throttled_seconds_total` (counter) | `tunnel, dir` |
| `nf_turn_allocations` (gauge) / `nf_turn_relayed_bytes_total` (counter) | `realm` (+`dir`) |
| `nf_gateway_requests_total` (counter) / `_request_duration_seconds` (hist) | `tunnel, code` / `tunnel` |
| `nf_acme_issuances_total` / `nf_acme_decision_denied_total` (counters) | `outcome` / `reason` |

`nf_agent_handshakes_total{outcome}` *is* the security dashboard; `nf_datagram_dropped_total{reason="too_large"}`
makes the `DatagramTooLargeError` learning loop visible. **Never label by client IP, port, or Host header** —
`tunnel`/`agent` are DB-bounded. **OTel: no for v1** — dozens of modules in a MIPS-router binary, and its payoff
needs a collector these deployments won't run. Emit `slog` with a per-connection `trace_id` and keep an internal
`Tracer` interface so an exporter is additive in v2.

## 13. Service installation

`kardianos/service v1.3.0`. Low-velocity (v1.2.2 Oct 2022 → v1.3.0 Jul 2026, no Releases page, ~139 open issues) but
not archived, and still the de facto choice — hand-rolling systemd *plus* launchd *plus* Windows SCM with
`StartType`/`OnFailure*` recovery is ~600 lines of platform code we'd maintain worse. Wrap it behind our own
three-method `svc` interface, pin, be ready to vendor, implement its optional `Shutdowner` for tunnel drain.

## 14. Testing

Stdlib `testing` plus `testing/synctest` (fake clock), `httptest`, `fstest`, `net.Pipe()`, and a small in-memory
`net.PacketConn`; `-race` by default. **A fuzz target on the frame parser is mandatory** — the header plus the
unknown-type-skip rule is exactly the shape of bug fuzzing finds, and a corpus regression protects forward
compatibility forever. `google/go-cmp` for diffs (**version unverified**). **Do not copy frp's ginkgo/gomega e2e
stack** — two dependency trees and a DSL that obscures stack traces; its one real benefit (structured `BeforeEach`
fixtures) is reachable with `t.Cleanup` + table tests. Skip testify too. Instead a plain Go harness under `test/e2e`
behind `//go:build e2e`, booting a real relay + agent + echo server on loopback and driving S1 (HTTP + WS + UDP
through a tunnel) and S2 (bare port → gateway). `make e2e`, separate from `make test`.

## 15. Build and release without GitHub Actions

**Hand-rolled Makefile; no goreleaser** — its value is CI integration we don't have, and it'd be an unpinned extra
toolchain in the release path. Targets: `deps` · `ui` (`bun run build` → `web/dist`) · `build`
(`-trimpath -ldflags "-s -w -X main.version=…"`) · `test` (`-race`) · `e2e` · `lint` (`go vet` + `gofmt -l` +
staticcheck pinned via `tools.go`) · **`check` = fmt+vet+lint+test, the single gate** · `dist` · `snapshot` ·
`install`.

**Frontend embed:** `web/embed.go` with `//go:build !noweb` + `//go:embed all:dist` served via `http.FileServerFS`; a
stub under `//go:build noweb`; an `--assets-dir` runtime override; and the Makefile auto-appending `-tags noweb` when
`web/dist` is absent so `go build ./...` never breaks on a fresh clone. This is frp's arrangement
(`web/frps/embed.go:1-16`, `assets/assets.go:40-50`, `Makefile:4`) and the part of frp's build to copy verbatim.

**Matrix, `CGO_ENABLED=0` everywhere:** linux/{amd64, arm64, arm (GOARM=7 and 5), 386, riscv64, loong64, mips,
mipsle, mips64le}, windows/{amd64, arm64}, darwin/{amd64, arm64}, freebsd/amd64; `GOMIPS=softfloat` for mips.
**The constraint that shapes the binary layout:** modernc.org/sqlite's verified ports are linux
386/amd64/arm/arm64/loong64/ppc64le/riscv64/s390x + darwin + windows + freebsd/openbsd — **no MIPS**. MIPS router
targets can therefore only build `nfagent`, which has no store; that is precisely why we ship two binaries rather
than one with subcommands. `make check` must fail (via `go list -deps`) if agent code imports the store.

**Release integrity:** `make dist` emits `SHA256SUMS`; a *separate* `make sign` produces a detached signature with a
key that never lives on the build host. frp ships only a checksum generated in the same job that built the artifacts
(`.goreleaser.yml:3-7`) — corruption protection, not compromise protection. **Signing tool unverified.**

## 16. Consolidated dependency set

| Module | Version | Why |
|---|---|---|
| `github.com/quic-go/quic-go` | v0.61.0 | Primary carrier: RFC 9221 datagrams, native streams, migration; clears GO-2026-5676 |
| `github.com/xtaci/smux` | v1.5.57 | Muxer for the TCP/WSS rungs; maintained, unlike the yamux frp forked |
| `github.com/coder/websocket` | v1.8.15 | L3 carrier via `NetConn` into smux; mature API, no dep tree |
| `github.com/pires/go-proxyproto` | v0.15.0 | Client-IP behind foreign LBs, incl. UDP PROXY new in v0.15.0 |
| `github.com/pion/turn/v5` | v5.0.12 | Embedded TURN; BYO sockets are our metering hook; coturn-compatible auth |
| `github.com/pion/stun/v3` | v3.1.6 | STUN layer pairing with turn v5 / ice v4 |
| `github.com/pion/ice/v4` | v4.4.1 | Candidate gathering for the P2P path that bypasses the relay |
| `modernc.org/sqlite` | v1.56.0 | CGO-free store; pin `modernc.org/libc` exactly per its go.mod |
| `github.com/pressly/goose/v3` | v3.27.3 | Embedded `.sql` migrations with `WithLocker` |
| `github.com/knadh/koanf/v2` | v2.3.6 | Layered config with provenance; provider versions unverified |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | TOML parser behind koanf; operator-editable |
| `github.com/go-playground/validator/v10` | v10.30.3 | Struct-tag validation at the DTO boundary in `Validate()` |
| `github.com/caddyserver/certmagic` | v0.25.4 | Multi-tenant on-demand certs with a real `DecisionFunc` |
| `golang.org/x/crypto` | v0.54.0 | argon2id hashing; ≥v0.52.0 required by the SSH advisory cluster |
| `golang.org/x/time` | v0.15.0 | Token buckets for control-plane and ACME-decision limiting |
| `github.com/prometheus/client_golang` | v1.24.1 | Metrics; avoid the experimental `api/…` subpackage |
| `github.com/kardianos/service` | v1.3.0 | Cross-platform service install; low-velocity but the right trade |
| `github.com/spf13/cobra` | v1.10.2 | CLI for both binaries; low-churn (note v1.10.2's yaml import move) |
| `github.com/google/go-cmp` | unverified | Struct diffs in tests — confirm at implementation time |

Frontend: see dossier 11 (parity with nomifun-desktop, the former nomifun-tauri — React 19.2.8, Arco 2.66.16, unocss, swr 2.5.0, Vite 7.3.6,
TypeScript 5.x, i18next zh-CN primary, uPlot for RTT/loss panels, bun 1.3.14).
