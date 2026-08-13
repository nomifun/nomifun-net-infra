# 16 — `nfagent`: the client half of NomiRelay

Fills the gap named in 13 §1. Decisions 1–7 are inputs, not topics. `nfagent` imports **no store** (10 §15:
`modernc.org/sqlite` has no MIPS port; `make check` enforces via `go list -deps`). Vocabulary:
`tls ∈ {passthrough, gateway}` × `kind ∈ {service, reverse, peer}`.

## 1. Config file — `agent.toml`

First match wins; `--config` overrides absolutely. Linux/BSD `/etc/nomifun/agent.toml` then
`$XDG_CONFIG_HOME/nomifun/agent.toml`; macOS `/Library/Application Support/nomifun/agent.toml`; Windows
`%ProgramData%\nomifun\agent.toml`. Mode `0640`; the agent refuses to start if group- or world-writable.
`${NF_*}` templating per 10 §8. ⚠ = secret: never logged, never returned by the local API, `"***"` in
`nfagent config dump`.

```toml
[agent]
name         = ""    # default os.Hostname(), ≤63 chars DNS-label charset
machine_id   = ""    # empty ⇒ read/create state file (§2). Never MAC-derived.
capabilities = ["tunnel.service","tunnel.reverse","udp.datagram","proxyproto.v2"]  # login hello (§11)
tags         = {}    # map[string]string, ≤16 keys

[relay]
addresses    = []    # []string REQUIRED, ordered: "relay.example.com:7443" | "203.0.113.9:7443";
                     #   optional scheme pins a rung: "quic://" "tls://" "wss://"
spki_pins    = []    # []string base64 SHA-256 SPKI; empty ⇒ WebPKI. Never InsecureSkipVerify.
server_name  = ""    # SNI override for IP-literal addresses
enrol_token  = ""    # ⚠ single-use; consumed on first login, then blanked
alpn         = "nomifun-relay/1"
failover     = "ordered"        # ordered | sticky | roundrobin
failover_after_failures = 3     # exhausted rung ladders before advancing addr_index
failover_sticky_ttl = "30m"     # then re-prefer addresses[0]
connect_timeout = "10s" ; handshake_timeout = "10s"

[carrier]
rungs = ["l0","l1","l2","l3"]   # subset+order; constrained profiles pin ["l3"]
probe_timeout = "3s" ; probe_stagger = "250ms" ; reprobe_interval = "30m"
hysteresis_margin = 0.25 ; hysteresis_dwell = "10m"
keepalive_interval = "10s" ; keepalive_timeout = "30s"   # frp's default-off heartbeat (01 §5) deleted
smux_max_receive_buffer = 4194304 ; smux_max_stream_buffer = 262144

[policy]                        # §5, security-critical
default_action = "deny"         # deny | allow; "allow" requires allow_any_ack
allow_any_ack  = false
allow = [] ; deny = []          # []Rule; deny evaluated first
allow_loopback = true ; allow_private = true
resolve_timeout = "2s" ; max_targets_per_tunnel = 4
  [[policy.allow]]
  cidr = "192.168.1.0/24"       # or host = "desktop.lan" (matched post-resolution, never a bypass)
  ports = "80,443,3000-3999" ; proto = "tcp"   # tcp|udp|any
  kinds = ["service"]

[limits]
max_tunnels = 64 ; max_conns_total = 512 ; max_conns_per_tunnel = 128
dial_timeout = "10s" ; idle_timeout = "300s" ; copy_buffer = 32768   # 65536 for udp.datagram
udp_flow_max = 4096 ; udp_flow_per_source = 32 ; udp_flow_idle = "75s"
udp_new_flow_rate = 200         # flows/sec, burst 400

[local_api]
enabled = true ; listen = "127.0.0.1:7451"   # or "unix:/run/nfagent.sock"
token = ""                      # ⚠ empty ⇒ auto-generated into state dir

[update]
mode = "notify"                 # off | notify | auto
manifest_url = ""               # default: relay /api/v1/updates
pubkey = ""                     # base64 Ed25519; compiled-in default
window = "03:00-05:00"
[log]
level = "info" ; format = "text" ; file = ""   # text|json; empty ⇒ stderr/journal
```

**Three stages (10 §8).** `Complete()` — mutating, idempotent, no I/O, no errors: fills `agent.name`, appends
`:7443` to bare hosts, sorts `rungs`, seeds the immutable default-deny prefixes into the effective denylist,
derives `copy_buffer`. `Validate() error` — pure, all faults via `errors.Join`: addresses non-empty and
parseable, `hysteresis_margin ∈ [0,1]`, `default_action=="allow" ⇒ allow_any_ack`,
`udp_flow_per_source ≤ udp_flow_max`, no `policy.allow` rule overlapping a default-deny prefix (an error, not
a silent override), no `local_api.token` on a non-loopback listen. `Clone() *Config` — deep copy; SIGHUP
builds a candidate, Completes, Validates, then swaps one `atomic.Pointer[Config]`. A bad candidate is a logged
no-op, never a partial apply.

## 2. On-disk state — no SQLite

Linux `/var/lib/nfagent`; macOS `/Library/Application Support/nomifun/agent`; Windows
`%ProgramData%\nomifun\agent\state`. Dir `0700`. Every write is temp-file + `fsync` + `os.Rename` under a
`flock` on `state.lock`, so a power cut cannot truncate a credential.

| File | Mode | Content |
|---|---|---|
| `machine_id` | 0600 | one UUIDv4, written once |
| `credential.json` | 0600 | `{v,agent_id,secret,issued_at,expires_at,prev_secret,prev_valid_until,relay_fp}` |
| `credential.json.prev` | 0600 | previous generation, kept until the new one authenticates once |
| `tunnels.json` | 0600 | last desired set + `config_generation` + `fetched_at` (offline start) |
| `carrier.json` | 0644 | `{addr_index,rung,score_ms,chosen_at,fail_streak}` |
| `local_api.token` | 0600 | 32-byte `crypto/rand.Text()` |
| `update/` | 0700 | staged binary, `manifest.json`, `manifest.sig`, `rollback/` |

**Everything is plain, protected by mode.** A KEK beside the ciphertext on the same disk with the same ACL is
theatre, and it breaks headless boot on a MIPS router with no keyring. The real control is file mode plus
`ProtectSystem=strict` / `StateDirectory=` (12 §B1). Optional OS-keyring wrapping is a v1.1 additive change —
`credential.json` already carries `"v"`.

**Rotation.** Credentials are `nfr_1_<agent_id>.<secret>` (10 §10), `expires_at` default 90 d. At 75 % of
lifetime, or on an unsolicited `RotateCredential` frame, the agent sends `RotateRequest{agent_id}`, gets
`RotateResponse{secret,expires_at}`, writes the new file (old → `.prev`, `prev_valid_until = now+24h`), and
uses the new secret from the next login. The relay keeps both hashes valid until the new one is used once —
that is what makes rotation crash-safe. Rotation never drops the live carrier.

## 3. Lifecycle state machine

`booting → enrolling → registering → connected → {reconciling, degraded} → draining → stopped`, plus
terminals `revoked`, `incompatible`, and the recovery loop `backoff`.

- **`booting`** — load, `Complete`/`Validate`, open state dir, read-or-create `machine_id`.
- **First boot, no credential** → `enrolling`: POST `relay.enrol_token` over TLS to the first reachable
  address, receive the credential, blank the token, persist, → `registering`. No token *and* no credential →
  stay `enrolling`, reason `no_credential`, retry every 60 s **forever**. The process never exits.
- **`registering`** — hello `{protocol_version:1, agent_id, machine_id, name, version, os, arch,
  capabilities[], tunnel_generation, nonce, ts, mac}`, `mac = HMAC-SHA256(agent_key,
  canonical(ver‖ts‖nonce‖alpn‖tls-exporter))`.
- **Relay unreachable at boot** — 01 §8's `LoginFailExit=true` is **deleted**. Per address run the ladder
  (§4); on total failure → `backoff`: the first three attempts inside a 60 s window are fast at **200 ms**,
  then `min(1s·2^n, 60s)` ±20 % jitter — 0.2, 0.4, 0.6, 1, 2, 4, 8, 16, 32, 60, 60 … After
  `failover_after_failures = 3` exhausted ladders on one address, advance `addr_index` (mod len) and reset
  backoff to 1 s so the sibling gets a fast first try. No attempt cap ever: a factory robot's gateway must not
  brick the agent. In `backoff` no tunnel serves (there is no ingress without the relay) but the cached set is
  displayed, so `nfagent status` stays useful offline.
- **`reconciling`** on any `TunnelSet`/`TunnelDelta`; back to `connected` when applied.
- **`degraded`** — carrier alive but impaired: one missed keepalive, rung > 0, or
  `SupportsDatagrams.Remote == false` so UDP rides a reliable stream (14). Tunnels keep serving. Two
  consecutive keepalive timeouts (30 s) → `backoff`.
- **Revoked mid-session** — `Revoked{reason}` then close. Stop accepting, close existing streams
  **immediately** (revocation is not a drain), delete `credential.json` and `.prev`, → `revoked`; as a service
  stay up polling config every 300 s for a fresh `enrol_token`. Never auto-re-enrol.
- **"Agent too old"** — `LoginRejected{code:"protocol_too_old", min_supported_protocol, message}` →
  `incompatible`. Retry every **900 s** (not a hot loop against a wall), surface the message verbatim, and if
  `update.mode != "off"` run the self-update check at once. A newer-than-relay agent degrades to the
  negotiated capability intersection and never fails.
- **Network change** (tethering, DHCP, route change) — watcher + 2 s debounce. L0/L1 QUIC tries **path
  migration** first (the reason QUIC is rung 0); if keepalive is not restored in 5 s, or the carrier is L2/L3,
  force-close and re-probe the full ladder ignoring `carrier.json`.
- **Sleep/resume** — monotonic-vs-wall jump > 30 s: treat as network change **and** invalidate the cached
  rung; always re-login, since the relay has reaped the session.
- **SIGHUP** — reload config only, never re-login: validate-then-swap, recompute effective policy, re-run
  reconciliation. A tunnel that newly violates policy is torn down as `rejected_by_agent`. The carrier is left
  alone unless `[relay]`/`[carrier]` changed materially.
- **SIGTERM / `Shutdowner`** — → `draining`: send `Draining{deadline}`, stop accepting, let in-flight copies
  finish for `min(20s, all-closed)`, flush `tunnels.json`, clean CONNECTION_CLOSE, → `stopped`. Second SIGINT
  closes immediately.

## 4. Carrier selection

Ladder (10 §2): **L0** QUIC/UDP configured port, ALPN `nomifun-relay/1`; **L1** QUIC/UDP:443; **L2**
TLS/TCP:443+smux; **L3** WSS:443, HTTP/1.1 Upgrade `/_nf/t/v1`, **binary frames only** (01 §3 — middleboxes
UTF-8-validate text frames and kill the tunnel), +smux. L4 (customer nginx, or the org's
nomifun-bridge-server) is configuration of L3, not a code path.

Staggered race, not a storm: L0 at t=0, L1 +250 ms, L2 +500 ms, L3 +750 ms, each a 3 s dial+handshake budget,
whole-ladder deadline 5 s. The winner is the first rung to complete a **full authenticated login** — never
first TCP connect, because a captive portal answers SYN cheerfully. Losers are cancelled.
`score_ms = handshake_rtt + 150ms × rung_index` (an explicit low-rung preference) goes to `carrier.json`; next
boot tries the cached rung **first and alone**, falling back to the ladder after one 3 s failure.

**Anti-flap.** Re-probe every 30 m out of band, without disturbing the live carrier. A challenger wins only if
**all** hold: `score_challenger < score_incumbent × 0.75`; incumbent live ≥ 10 m; challenger won **two
consecutive** re-probes. A forced re-probe (carrier lost) bypasses hysteresis. Changes emit
`nf_carrier_rung_change_total{from,to,reason}`, `reason ∈ {probe,better,forced,netchange,resume,failover,
config}`, capped at **6 voluntary switches/hour**; past that the incumbent is pinned until restart and
`rung_pinned` is logged.

## 5. Local target policy

Authoritative on the agent (12 §A5, decision 7). Order, per **dial**, on the **resolved** address:

1. **Immutable default-deny**, not config-overridable: `169.254.0.0/16`, `::ffff:169.254.0.0/112`,
   `fe80::/10`, `100.100.100.200/32`, `100.100.100.0/24`, `fd00:ec2::254/128`, `192.0.0.192/32`, names
   `metadata.google.internal` / `*.internal.cloudapp.net` / `instance-data`, plus `0.0.0.0/8`, multicast,
   `::/128`, and `127.0.0.0/8` for tunnels not explicitly loopback-marked.
2. `policy.deny` → 3. `policy.allow` (CIDR ∧ ports ∧ proto ∧ kind) → 4. `default_action`.

`type Rule struct { CIDR netip.Prefix; Host string; Ports PortSet; Proto Proto; Kinds []TunnelKind }`,
matched on `netip.Addr`, zero allocation. A `Host` rule resolves at check time and *every* resolved address
must independently pass.

**Anti-rebinding is structural.** `func (p *Policy) DialContext(ctx, network, addr) (net.Conn, error)` is the
agent's **only** egress path. It resolves via `LookupNetIP`, checks each candidate `netip.Addr`, then dials the
checked `netip.AddrPort` **literal** — never the hostname. There is no resolve-then-dial gap for a 1 s-TTL
record, and the check repeats on every connection, unlike frp's `validateTCPProxyConfigForClient` (`return
nil`). Verdicts are **never cached**: a few prefix compares are cheaper than the lookup beside them. Denials
emit `nf_agent_dial_denied_total{tunnel,reason}`, `reason ∈ {default_deny,denylist,no_allow_rule,port,proto,
kind,resolve_failed,too_many_targets}`, plus one rate-limited log line with the address.

**A violating pushed tunnel is never partially applied.** Reconciliation runs a *static* pre-check
(literal-IP target, port, proto, kind) and reports `TunnelState{tunnel_id, state:"rejected_by_agent",
reason_code:"policy.no_allow_rule", detail:"tcp 10.0.0.5:22 matches no allow rule", generation}` — the reason
appears in the console beside the tunnel (decision 7). No listener, no retry; re-evaluated only on a new
generation or SIGHUP. A hostname target passes statically and may still fail at dial: that is
`state:"degraded"`, `reason_code:"policy.resolved_denied"`, because the tunnel is valid and the failure is
data-dependent.

## 6. Reconciliation loop

One goroutine owns the tunnel map, driven by a channel — no locks held over I/O.

```go
type tunnelRuntime struct {
    Spec    TunnelSpec  // desired, from the relay
    State   TunnelState // pending|starting|serving|degraded|rejected_by_agent|draining|stopped
    Reason  string
    Backend Backend     // Addr | Unix | Handler  (05 §8; Handler reserved, §11)
    conns   *connSet    // bounded by limits.max_conns_per_tunnel
    flows   *udpFlowTable
    cancel  context.CancelFunc
}
```

`Reconcile(desired []TunnelSpec, generation uint64)` diffs by `tunnel_id` then `spec_hash` (FNV-1a of
canonical JSON). **Add** → policy pre-check → `pending`→`starting`→`serving`. **Remove** → `draining` (20 s)
→ `stopped` → delete. **Changed**: limits/shaping only → mutate in place, zero disruption; `target`, `proto`
or `tls` → drain-then-recreate, because a live TLS session cannot survive `passthrough→gateway` (13 §10).
Idempotent, so it is safe on every generation, SIGHUP and reconnect. Unservable tunnels stay in the map as
`rejected_by_agent`/`degraded` rather than vanishing. Upstream: `TunnelStateReport{generation, states[]}`
debounced 250 ms on change, plus a full snapshot every 30 s and on every reconnect, so a relay restart
re-learns everything. `max_tunnels` overflow is `rejected_by_agent` / `limits.max_tunnels`, not an unbounded
map.

## 7. Data path inside the agent

**Streams.** The relay opens the stream (01 §6: the muxer is symmetric, so `ReqWorkConn`/`NewWorkConn`/
`StartWorkConn` and the entire workConn pool are deleted — 0 extra RTT). First bytes are
`StreamHeader{tunnel_id, flow_id, target_id, src_addr, dst_addr, flags}`. The agent finds the runtime, admits
against `max_conns_per_tunnel`, calls `Policy.DialContext`, optionally writes PROXY-v2 **on the local dial
only** (13 §10 — never in tunnel payload), then splices: two goroutines, `io.CopyBuffer` over a `sync.Pool` of
32 KiB buffers, `CloseWrite()` on the finished half so half-close survives; on Linux `local→stream` tries
`TCPConn.ReadFrom` (splice). Rolling 300 s idle deadline; each close reports `bytes_in/out`, `duration_ms`,
`outcome`.

**Handler backends (05 §6).** For backends the agent terminates itself (local TLS termination, static share,
later the S3 capabilities) the stream becomes a `net.Conn` fed to an in-memory listener:

```go
type connListener struct{ ch chan net.Conn; addr net.Addr; once sync.Once; done chan struct{} }
func (l *connListener) PutConn(c net.Conn) error  // non-blocking, cap 64, ErrBacklogFull
func (l *connListener) Accept() (net.Conn, error)
```

so a plain `http.Server{Handler: …}.Serve(l)` consumes tunnel traffic with no socket.

**UDP flow table** — fixes 14 §2 (frp's unbounded `map[string]*net.UDPConn` = fd-exhaustion DoS):

```go
type flowKey struct{ TunnelID uint32; TargetID uint16; Src netip.AddrPort } // comparable, alloc-free
type udpFlowTable struct {
    mu [16]sync.Mutex; shards [16]map[flowKey]*udpFlow
    lru *list.List; perSource map[netip.Prefix]int
    cap, perSourceCap int; newRate *rate.Limiter
}
```

Capacity **4096** with LRU eviction (closes the socket, counts `nf_agent_udp_flow_evicted_total`); per-source
quota **32** keyed on the **/32 or /64**, not the bare `AddrPort`, so port-randomised spraying cannot buy 4096
fds; creation limited to **200/s burst 400**; idle sweep every 10 s at 75 s; **16 shards** so `net.DialUDP`
never runs under a global lock (14 §3). Both directions are bounded queues with **explicit drop** (14 §1:
frp's downstream path blocks and turns live media into a queue) — depth 256/flow, drop-newest, counted as
`nf_datagram_dropped_total{reason="queue_full"}`. Datagram ceiling learned reactively from
`*quic.DatagramTooLargeError.MaxDatagramPayloadSize`, cached, re-learned on error; no hard-coded MTU. Never
compress the UDP path.

## 8. `kind=reverse` / 无代理端 — the agent is not involved

Two sub-shapes. **`reverse` + agent-terminated** (the real S2, whose target desktop is NAT'd) is an ordinary
tunnel: relay listens on a bare public port, opens a stream, the agent dials the desktop. All differences are
relay-side (source-IP allowlist, per-port secret, no L7 rewriting); the only agent-side effect is `Kinds` in
policy rules, so an operator can permit a target for `service` but not `reverse`.

**`reverse` + `target_reachable_from_relay` (13 §5): no agent exists in this path at all.** That makes it an
explicit **relay-side responsibility** — `nfrelay` needs its own outbound dialer with the same immutable
default-deny list, the same re-resolve-every-dial rule, and its own `nf_relay_dial_denied_total`, or 12 §A5's
SSRF defence loses its host and console compromise becomes a network pivot. `nfagent` must never be asked to
proxy such a tunnel, and the console must label the option "target reachable from the relay", not "no agent
needed".

## 9. Service install & self-update

`kardianos/service v1.3.0` behind our own three-method `svc` interface (10 §13). `nfagent install|uninstall|
start|stop|restart|status`; `service.Config{Name:"nfagent", Option: service.KeyValue{"Restart":"always",
"RestartSec":1,"LimitNOFILE":1048576,"StartType":"automatic","OnFailure":"restart",
"DelayedAutoStart":true}}` with a custom `SystemdScript` carrying 12 §B1 hardening (`NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `StateDirectory=nfagent`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, empty `AmbientCapabilities` — the agent binds nothing
privileged). Watch v1.3.0's template-engine change: nothing beyond `{{.Name}}`-style keys.

```go
func (p *program) Start(service.Service) error    { go p.a.Run(); return nil }
func (p *program) Stop(service.Service) error     { return p.a.Drain(20*time.Second) }
func (p *program) Shutdown(service.Service) error { return p.a.Drain(5*time.Second) } // Shutdowner
```

`Shutdowner` matters because OS shutdown grants less grace than `systemctl stop`; a 5 s drain still emits
`Draining` so the relay marks tunnels down deliberately instead of timing them out.

**Self-update — never "stop, uninstall, reinstall" (12 §B2), which drops the tunnel.** The service definition
is never touched: the unit points at a stable path and only the file behind it changes. Fetch `manifest.json`
+ `manifest.sig` (Ed25519, offline key per 13 §3, public half compiled in, overridable by `[update] pubkey`);
verify signature, then `min_relay_protocol`, `version > current` (no downgrade without `--allow-downgrade`),
platform tuple, `sha256`; download to `update/nfagent.new`; **re-verify the digest on the written file**;
`chmod 0755`; run `nfagent --self-test` on the new binary (parses config, prints version, exits 0) —
**verify-before-swap**; hardlink the current binary to `update/rollback/nfagent-<oldver>`; `os.Rename` into
place (same filesystem; on Windows rename-away-then-rename-in); request a restart inside `[update] window`.
The new binary must reach `connected` within **120 s** and pass one keepalive, else the
`update/pending-verify` marker triggers **rollback**: rename the saved binary back, restart, force
`mode=notify` in memory, report `update_failed{from,to,reason}`. Default `mode="notify"` only reports.

## 10. Observability — the agent does have a local API

Answering 07's open "one console or two?": **one *web* console (relay-side, per 11), plus a
machine-and-CLI-only local API on the agent — no SPA, no embedded assets in `nfagent`.** A second SPA would
double the API surface and the MIPS binary; but a relay-only console is useless in exactly the case that
matters most, so the agent must be self-explaining locally.

Loopback-only, bearer token, `Host` validated, no CORS: `GET /healthz` (unauthenticated), `/readyz` (200 only
in `connected`/`reconciling`), `/api/v1/status`, `/tunnels`, `/carrier` (rung, score, last probe table),
`/policy/effective` (the *resolved* ruleset, not the flags — 12's closing warning),
`POST /policy/test {proto,host,port}` → verdict + matching rule, `/events?follow=1` (SSE, 512-entry ring),
`POST /reload`, `/reprobe`, `/drain`, `GET /metrics` (the `nf_agent_*` subset of 10 §12).

`nfagent status` is a local-API client that falls back to reading the state dir, so it works daemon-down:

```
nfagent 1.0.3 (linux/mipsle)   state: backoff   uptime 4h12m
relay:   tls://203.0.113.9:443 [3/3] attempt 7, next retry 12s
         last error: dial tcp 203.0.113.9:443: i/o timeout (14:02:31Z)
         addresses: relay.nomifun.net:7443 (fail 3) · relay-b:7443 (fail 0) · 203.0.113.9:443 (current)
carrier: L2 tls+smux rtt 41ms chosen 14:01:58Z  probes: L0 timeout L1 timeout L2 41ms L3 88ms
cred:    agent_id A7QK… expires 63d, rotates 40d
tunnels: 4 desired (cache 14:01:12Z) · 0 serving · 1 rejected_by_agent
  home-http  tcp 127.0.0.1:8080  serving-when-connected
  robot-vnc  tcp 10.0.0.5:5900   rejected_by_agent: policy.no_allow_rule
policy:  default deny · 3 allow · 11 immutable deny prefixes
udp:     flows 0/4096 · evicted 0 · dropped 0
hint:    relay unreachable — the relay console cannot show this. Try `nfagent probe`.
```

`nfagent probe` runs the ladder once and prints per-rung failures verbatim (DNS, TLS verify, ALPN, L3 HTTP
status) — the highest-value field-support command, with no frp equivalent.

## 11. Scenario-3 seams (reserve now, no wire break later)

All three are additive because the reader skips unknown frame types and JSON tolerates unknown fields
(10 §4).

1. **`kind = peer`** is in the enum and the relay column from v1. `TunnelSpec` carries
   `PeerAgentID string` and `PeerRole string // initiator|responder`, empty in v1. The reconciler recognises
   `peer` and, absent `"tunnel.peer"` in `capabilities[]`, reports `rejected_by_agent` /
   `capability.unsupported` — correct today, and the switch that lights S3 up later.
2. **Handler backend.** `Backend` is an interface from v1 — `{Addr, Unix, Handler}` (05 §8) — wire form
   `{"backend":{"type":"addr","addr":"127.0.0.1:8080"}}`, a **tagged union**, never a flat 33-field union like
   frp's `msg.NewProxy`. S3's screenshot/PTY/input arrive as `handler:"cap.screen"|"cap.pty"|"cap.input"`
   served over §7's `connListener`, dialing nothing. No existing field changes.
3. **`capabilities[]` + scoped credentials.** The hello sends the array; `ServerHello{protocol_version,
   min_supported_protocol, capabilities[]}` replies and the agent uses the intersection. Reserved tokens now:
   `tunnel.service`, `tunnel.reverse`, `tunnel.peer`, `udp.datagram`, `proxyproto.v2`, `handler.tls_terminate`,
   `cap.screen`, `cap.pty`, `cap.input`, `update.self`. The credential record carries `Scopes []string`
   (10 §10's opaque token has none) so a peer tunnel or a PTY capability is grantable and revocable per agent
   without revoking the agent — the S3 blast-radius control.

## 12. ESP32 profile and IPv6 posture

**An ESP32 never runs `nfagent`** — no QUIC, no ALPN control, no client certs, and Go does not target it. It
is purely an **S2 client**: plain http/ws to a bare IPv4 literal, no SNI, no cert validation. The relay must
therefore offer it an HTTP/1.1-only listener (10 §1's `http.Protocols` pinning, also why console and gateway
cannot share a listener), no HTTPS redirect, no HSTS, `Connection: close` tolerated, a bare-IPv4 bind, and
**gateway** mode — there is no SNI to route on, and 13 §6(b) shows a tauri target 403s a non-IP-literal
`Host`, so `Host`/`Origin` must be rewritten. Hardening for this class is the optional source-IP allowlist
plus per-port secret (decision 3), never client software. `carrier.rungs = ["l3"]` exists for the other
constrained class — devices that *do* run `nfagent` behind ALPN-hostile middleboxes or a CDN; L3-over-CDN
forces gateway mode, since a CDN terminates TLS.

**IPv6, split by leg** — 15 §A6's `udp4`/`tcp4`-only advice is about TURN, not the agent, and CN carriers hand
out IPv6-only/464XLAT. (a) *Relay TURN listeners*: `udp4`/`tcp4` only in v1, because v5.0.10's
`StrictAddressFamily` gives a browser omitting `REQUESTED-ADDRESS-FAMILY` an IPv6 relay on a dual-stack
listener. (b) *Agent→relay*: **dual-stack mandatory** — addresses resolve to both families, Happy Eyeballs
(`net.Dialer{FallbackDelay: 300*time.Millisecond}`), preferring the family of the last successful login; an
IPv6-only agent behind 464XLAT must work with zero configuration. (c) *Agent→target*: dual-stack, and the
immutable denylist covers IPv6 and IPv4-mapped forms of every metadata address (`::ffff:169.254.169.254`,
`fd00:ec2::254`, `fe80::/10`) — a v4-only denylist is a bypass. (d) *S2 public listeners*: v4 literal by
default, since the configuring device often cannot express an IPv6 address; IPv6 opt-in per tunnel.
