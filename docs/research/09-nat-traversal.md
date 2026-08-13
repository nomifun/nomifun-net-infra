# 09 — NAT traversal: should the new Go relay do P2P at all?

Source trees read: `/mnt/hgfs/share/net-infra/frp` (Go) and `/mnt/hgfs/share/net-infra/EasyTier`
(Rust). All line numbers refer to those checkouts. Judged against **S1** (phone on the public
internet → HTTP/WS/UDP APIs on a home-NAT desktop, via a public relay; A/V calling ⇒ UDP latency
matters) and **S2** (factory robot configured with only "relay IP + port", zero client software,
reaching a designated remote desktop).

**Verdict up front: v1 is relay-only. P2P is deferred, not designed out.** The reasoning and the
exact seams to preserve are in §6–§7.

---

## 1. frp `pkg/nathole` — what it actually does

### 1.1 Discovery is STUN, and it is fragile

`Discover(stunServers, localAddr)` opens one UDP socket and queries each STUN server in sequence
(`pkg/nathole/discovery.go:29-46`). Per server it does a Binding request, then — if the response
carried `OTHER-ADDRESS` — a **second** Binding request to that other address on the *same socket*
(`discovery.go:120-144`). The pair of mapped addresses is the entire raw signal.

Three concrete fragilities:

- **Any single STUN failure aborts everything.** `Discover` returns on the first error
  (`discovery.go:39-42`), it does not skip and continue.
- **The default is one STUN server**: `natHoleStunServer` defaults to `stun.easyvoip.com:3478`
  (`pkg/config/v1/client.go:89`), and both call sites pass a one-element slice —
  `nathole.Prepare([]string{pxy.clientCfg.NatHoleSTUNServer}, opts)`
  (`client/proxy/xtcp.go:74`, `client/visitor/xtcp.go:269`).
- **`Prepare` hard-fails with fewer than 2 addresses** (`pkg/nathole/nathole.go:124-126`). With one
  STUN server, the second address only exists if that server returns `OTHER-ADDRESS`
  (`discovery.go:132-134`). A STUN server without a second IP (very common — most cloud STUN
  deployments are single-homed) makes frp's XTCP **entirely non-functional**, with the error
  "discover error: not enough addresses". Read timeout is a flat 3s (`discovery.go:26`).

### 1.2 Classification is coarse

`ClassifyNATFeature` compares the mapped addresses and emits only `EasyNAT`/`HardNAT` plus a
behaviour label (`pkg/nathole/classify.go:83-96`). `PortsDifference = portMax - portMin`, and
`RegularPortsChange` is true iff that difference is in `[1,5]` (`classify.go:97-102`). Local
interface IPs appearing in the mapped set flip `PublicNetwork` (`classify.go:61-63`).

Note what is *missing*: no direction of drift. frp knows "ports moved by ≤5" but not whether the NAT
increments or decrements. That single missing bit is why frp's symmetric strategy has to sweep a
symmetric window around the last-seen port instead of predicting forward (see §1.4).

### 1.3 The server-side bandit is the best idea in the package

`server/nathole` (the controller) is where frp is genuinely clever. `Analyzer` keeps
`map[analysisKey]*makeHoleRecords` (`pkg/nathole/analysis.go:265-272`). The key is
`md5(visitorPublicIP ‖ vNatType ‖ vBehavior ‖ vRegular ‖ clientPublicIP ‖ cNatType ‖ cBehavior ‖
cRegular)` (`pkg/nathole/controller.go:74-92`).

Given the NAT feature pair, it seeds a candidate list of (mode, index) strategies with initial
scores (`analysis.go:181-225`): 2×Easy → mode 0; one Hard with regular ports → mode 1 then 2 then 0;
one Hard irregular → mode 2 then 1 then 0; both Hard both regular → 3 then 4; both Hard one regular
→ 4 only; otherwise a low-confidence 0/1/3 mix (`analysis.go:214-219`).

Then the bandit: `recommand()` picks the max-scoring entry **and decrements it**
(`analysis.go:250-255`), so repeated failures rotate through strategies; `reportSuccess` adds +2
capped at 10 (`analysis.go:236-239`), driven by the client's `NatHoleReport{Sid, Success}` message
(`pkg/msg/msg.go:244-247`, dispatched at `server/control.go:806-809`, recorded at
`controller.go:271-284`). Stale keys are swept hourly (`controller.go:110-122`).

**This is a per-NAT-pair reinforcement learner living on the relay.** Steal the shape.

Two caveats. The key uses only the *first* public IP of the mapped set (`controller.go:76-78,
84-86`), so every subscriber behind one CGNAT egress shares a statistics bucket — that is arguably
desirable (they really do share a NAT) but it does mean one tenant's punch outcomes steer another's
strategy. And the analysis map is unbounded between hourly sweeps.

### 1.4 `MakeHole` — five modes, and the price of mode 2/4

`MakeHole` (`nathole.go:192-288`) implements the behaviour the server dictated. Sender role sleeps
`SendDelayMs`, then probes `AssistedAddrs ++ CandidateAddrs` (`nathole.go:201-207`). Receiver role
optionally opens `ListenRandomPorts` extra sockets (`nathole.go:214-223`) and races
`waitDetectMessage` across all of them, first winner wins, losers are closed
(`nathole.go:260-287`).

The probes themselves: `NatHoleSid{TransactionID, Sid, Response, Nonce}` (`msg.go:237-242`) with
`Nonce` being 0–19 zero bytes to vary packet length (`nathole.go:357`), **encrypted with the proxy's
secret key** (`pkg/nathole/utils.go:27-38`, `crypto.Encode`). Low-TTL probes are sent by fetching,
setting and restoring the socket TTL per packet via `golang.org/x/net/ipv4`
(`nathole.go:363-380`) — that is 3 extra syscalls per probe port.

The cost is where S1 dies. Mode 2 (`analysis.go:72-85`) is: sender sends to **1000 random ports**
after a 3000 ms delay while the receiver listens on **256 random ports**. `sendSidMessageToRandomPorts`
sleeps **15 ms per port** (`nathole.go:440`) ⇒ ~15 s of pure sending. `sendSidMessageToRangePorts`
sleeps 2 ms per port (`nathole.go:400`). The controller therefore budgets
`max(sendDelays) + 5000`, plus **another 30 000 ms** whenever either side listens on random ports
(`controller.go:323-326`). So a mode-2 or mode-4 attempt legitimately runs 35–40 s, and the
controller goroutine sleeps `ReadTimeoutMs + 30000` afterwards holding the session
(`controller.go:252`).

Also: 256 extra UDP sockets on a phone, and a 1000-port sweep that any enterprise IDS will read as
a port scan. Neither is acceptable for S1.

### 1.5 Confirmed: P2P failure does **not** fall back to relay without explicit config

This was the specific question, and the answer in `client/visitor/xtcp.go:158-183` is unambiguous:

```go
ctx := sv.ctx
if sv.cfg.FallbackTo != "" {                                     // :161
    timeoutCtx, cancel := context.WithTimeout(ctx,
        time.Duration(sv.cfg.FallbackTimeoutMs)*time.Millisecond) // :162
    defer cancel()
    ctx = timeoutCtx
}
tunnelConn, err := sv.openTunnel(ctx)
if err != nil {
    tunnelErr = err
    if sv.cfg.FallbackTo == "" {                                  // :172
        return                                                    // → deferred userConn.Close() :152
    }
    ... sv.helper.TransferConn(sv.cfg.FallbackTo, userConn)        // :177
}
```

- With no `fallbackTo`, the user connection is **closed** (`:143-154` defer, `:172-174`). frps does
  not relay XTCP traffic at all — there is no relay path to fall back *to*.
- `fallbackTimeoutMs` defaults to **1000 ms** (`pkg/config/v1/visitor.go:163`; legacy path
  `pkg/config/legacy/visitor.go:161-162`), while `openTunnel` itself allows up to 20 s
  (`xtcp.go:204`) and retries every 500 ms (`xtcp.go:225`). So when fallback *is* configured, the
  P2P path gets one second — and a cold punch (§1.4) takes 10–40 s. The first user connection
  essentially always falls back; P2P only helps from the *second* connection onward, and only
  because `getTunnelConn` failure kicks `startTunnelCh` asynchronously (`xtcp.go:240-243`).
- `keepTunnelOpen` defaults to **false** (`conf/frpc_full_example.toml:447`), so nothing warms the
  tunnel unless the operator opts in (and then it is rate-limited to `maxRetriesAnHour = 8`,
  `pkg/config/v1/visitor.go:161`, enforced by a `rate.Limiter` at `xtcp.go:74`).
- `fallbackTo` is **commented out in the shipped example** (`frpc_full_example.toml:451`) and its
  value must name a *different visitor* — an `stcp` visitor (`:425-433`). So "P2P with relay
  fallback" costs the user four config blocks: xtcp proxy + xtcp visitor + stcp proxy + stcp
  visitor, with two secret keys and a `bindPort = -1` trick.

That is a product failure, not a code failure.

### 1.6 Two more adversarial notes on frp's control plane

- **`PreCheck` is an enumeration oracle.** `HandleVisitor` with `PreCheck: true` returns distinct
  errors for "xtcp server for [%s] doesn't exist" (`controller.go:159`) versus "xtcp visitor user
  [%s] not allowed" (`controller.go:163`) — and this path performs **no `SignKey` check** (the
  `util.ConstantTimeEqString` check only happens on the non-precheck path, `controller.go:189`). Any
  authenticated frpc can map other tenants' xtcp proxy names and ACLs.
- **Amplification against the target client.** Handlers are `msg.AsyncHandler`, i.e. `go f(m)`
  (`pkg/msg/handler.go:102-106`, registered at `server/control.go:730`). Each `NatHoleVisitor`
  spawns a goroutine that pushes a sid onto the target's unbuffered `sidCh` (`controller.go:209`)
  and waits up to `NatHoleTimeout = 10` s (`controller.go:39, 215-220`). Every accepted sid forces
  the target client to run a full `Prepare` — STUN round-trips plus a UDP listen
  (`client/proxy/xtcp.go:74`). There is no rate limit on this path.
- **There is no end-to-end test.** `pkg/nathole/analysis_test.go` is 33 lines;
  `discovery_test.go` is 382; there is no test for `MakeHole` or for `Controller`. A hole-puncher is
  effectively untestable without a NAT lab, and frp's authors evidently agree.

---

## 2. EasyTier — richer typing, automatic fallback, better economics

### 2.1 NAT typing has the bit frp lacks

`StunNatTypeDetectResult::nat_type_udp` (`easytier-core/src/connectivity/stun/client.rs:454-500`)
requires responses from **≥2 distinct STUN servers** or returns `Unknown` (`:455-457`). Cone
detection is "all mapped addresses identical" (`is_cone`, `:445-452`). Then
`OpenInternet` / `NoPat` / `FullCone` / `Restricted` / `PortRestricted` are separated using
`ip_changed` / `port_changed` response flags and mapped-port-equals-source-port (`:459-472`).

For non-cone, the discriminator is the good part (`:473-496`): if there are multiple public IPs, or
≤1 usable response, or `max_port - min_port > 15` ⇒ hard `Symmetric`. Otherwise it fires an **extra
bind test from a second local socket** (`collector.rs:264-275`, `get_extra_bind_result`) and compares
that mapped port against the observed window: `+`, `<100` ⇒ `SymmetricEasyInc`; `-`, `<100` ⇒
`SymmetricEasyDec` (`client.rs:485-491`). That is the direction bit, and it is what makes prediction
possible instead of scanning.

Typing is cached and refreshed on a schedule: 10 s while `Unknown` (or symmetric without the extra
test), **600 s** once confident (`collector.rs:277-292`), with an explicit `redetect_notify`
override. TCP typing is a separate, simpler ladder (`client.rs:502-518`).

### 2.2 The policy engine

`UdpNatType::get_punch_hole_method` (`connectivity/hole_punch/udp/common.rs:81-137`) is a total
function over the NAT-type pair returning `None | ConeToCone | SymToCone | EasySymToEasySym`. Its
honest admissions matter: `cone × sym ⇒ None` (`:114-119`), `easySym × hardSym ⇒ None` (`:120-123`),
`hardSym × sym ⇒ None` (`:128-133`), and `open ⇒ None` because a direct dial already works
(`:110-112`). Ties are broken deterministically: for `EasySymToEasySym` only the lower peer id acts
as client (`:149`), avoiding both sides punching simultaneously.

`policy.rs` layers *intent* on top of capability: `should_try_p2p_with_peer` /
`should_background_p2p_with_peer` combine the peer's advertised `PeerFeatureFlag`
(`is_public_server`, `need_p2p`, `disable_p2p`) with local `disable_p2p` / `need_p2p` / `lazy_p2p`
(`policy.rs:36-64`). `lazy_p2p` means "don't punch unless the peer asked for it"; `collect_udp_punch_tasks`
then upgrades a lazy peer to eligible when `has_recent_traffic` is true
(`hole_punch/udp/task.rs:45-60`) and skips peers that already have a direct connection or are
blacklisted (`:63-65`). This is a *demand-driven* puncher.

### 2.3 Punch mechanics and their cost

- **Cone↔cone** (`udp/client.rs:53-158`): ask the peer for a listener via signalling
  (`select_punch_listener`, `prefer_port_mapping: true`, `:67-75`), bind one local socket, resolve
  its public address, send, then RPC the peer to send back 5 batches × 2 packets at 400 ms
  (`:106-123`). Poll every 200 ms, resend on miss, and stop 1 s after the remote task finishes
  (`:126-137`). Sub-second in the common case.
- **Sym→cone** (`client.rs:339-441`): first try a plain direct connect (`:362-371`) — free win when
  typing was wrong. If the local NAT is *easy* symmetric, do the **predictable** pass first: tell the
  peer to spray the 50 ports immediately above/below the observed base port
  (`base_port ± 1 .. ± max_port_num`, `client.rs:256-263`, executed at `udp/server.rs:162-199`).
  Only if that fails does it fall back to the birthday-paradox pass: **84 local sockets**
  (`UDP_ARRAY_SIZE_FOR_HARD_SYM`, `client.rs:38`) against a shuffled port vector, `max_k2` drawn from
  `600..800` and shrinking with round (`server.rs:225-228`, floor
  `MAX_K1_FOR_RANDOM_HARD_SYM = 180`, `:37`), 3 packets per port, **1 ms** per port
  (`server.rs:776-789`). 84 × ~700 / 65535 ≈ 0.9 expected collisions per round in well under a
  second of wire time — versus frp's 15 s for a comparable sweep.
- **Easy-sym ↔ easy-sym** (`client.rs:468-...`): 25 sockets (`:39`), each side aims at the other's
  mapped port ± `DST_PORT_OFFSET = 20` (`:40, 508-512`), 5 s mutual wait window (`:41`).
- **Port mapping** (`hole_punch/port_mapping.rs`): try IGD/UPnP, then NAT-PMP
  (`:197-232`), renew every 240 s (`:15`), and the lease's `Drop` sends the stop signal so the
  mapping is removed on teardown (`:133-139, 254-285`). Gated by `should_map_udp_listener`, which
  requires a UDP scheme and a private/link-local/unspecified host (`:287-301`) — no pointless SSDP
  chatter on a public VPS. It is an **optional cargo feature** (`easytier/Cargo.toml:399`,
  `igd-next` + `natpmp`).

### 2.4 Fallback is automatic because relay is the *baseline*

There is no "fallback" code path in EasyTier, and that is the design. The puncher is a background
`PeerTaskManager` polling every **5000 ms** (`udp/connector.rs:455-457`), per-method retry loops with
explicit backoff ladders — `[1000,1000,2000,4000,4000,8000,8000,16000]` for cone,
`+64000` for symmetric (`connector.rs:228, 258-259, 312-313`) — and a **3600 s blacklist** for peers
whose signalling says "don't bother" (`common.rs:3`, `connector.rs:45-79, 160-175`). On success the
only action is `transport_sink.add_client_transport(...)` (`connector.rs:198-211`): a *new edge* is
added to the peer graph. Nothing is torn down; nothing was waiting.

Selection then happens in routing, not in the connector. `peers/route/peer_ospf_route.rs` runs
Dijkstra over the peer graph with per-edge latency cost (`:341-346`) and adds
`AVOID_RELAY_COST = i32::MAX` (`:85`) to edges out of peers that refuse to relay (`:343`); the second
pass picks least-latency among least-hop paths (`gen_next_hop_map_with_least_cost`, `:426-449`).
A direct 1-hop edge naturally beats a 2-hop relay path. `latency_first` flips the policy
(`peers/peer_manager.rs:177, 2296`).

So the user-visible behaviour is: **traffic works immediately over the relay, and silently gets
faster when a punch lands.** Zero configuration, zero failed connections, no timeout tuning.

### 2.5 The 200 ms hedge — and a correction

`HedgeExt::hedge` lives at `easytier/src/gateway/hedge.rs:43-94` (not in `easytier-core`). It takes
an iterator of futures, starts one, and every `delay` starts one more; first `Ok` wins, all errors
are collected into an `ErrorCollection` (`:57-93`). Both call sites build **5** attempts and hedge at
**200 ms**: KCP `connect` (`gateway/kcp_proxy.rs:78-96`) and QUIC `endpoint.connect`
(`gateway/quic_proxy.rs:299-310`).

Be precise about what this is: it hedges **tunnel-setup attempts over an already-chosen path**
against tail latency and lost handshake packets. It is *not* a P2P-versus-relay race. Do not cite it
as evidence about fallback. It is, however, a cheap and excellent pattern worth copying verbatim for
any connect/handshake in the new tool (see §7).

### 2.6 Adversarial notes on EasyTier

- **Punch probes are unauthenticated.** `new_hole_punch_packet` writes `msg_type = HolePunch`,
  `conn_id = tid` (a 32-bit random) and 16 bytes of random padding
  (`easytier-core/src/packet/hole_punch.rs:23-35`); `hole_punch_packet_tid` validates only the type
  and length (`:37-46`). Socket-to-tid matching is therefore by 32-bit token alone
  (`udp/socket_array.rs:45-46`). Authentication happens later, at transport admission
  (`connector.rs:200-207`). frp is stricter here: its sid probes are encrypted under the proxy
  secret (`frp/pkg/nathole/utils.go:27-38`). **Adopt frp's posture, not EasyTier's.**
- **The symmetric puncher is a global critical section.** `sym_punch_lock` is held across the whole
  `do_hole_punching` call (`connector.rs:287, 340`), so with two symmetric peers the 84-socket
  sweeps serialize. Correct (they'd interfere) but it makes worst-case convergence linear in peer
  count.
- **84 sockets + 600–800 ports × 3 packets** is ~2100 datagrams per round from one host. On a
  metered LTE link (a phone in S1) that is real money and real battery.
- **`is_open()` short-circuits punching entirely** (`task.rs:38-40`, `common.rs:110-112`,
  `connector.rs:406-408`) — correct, but it means a host with a public IP never validates the path
  and relies on plain dialling succeeding.

---

## 3. Manual vs automatic fallback: which is better product behaviour?

**EasyTier's, decisively — but the framing matters.** EasyTier does not have "better fallback"; it
has **no fallback, because it never gambles on P2P in the first place**. Relay is the always-on
substrate; P2P is an opportunistic edge added to a graph that already routes.

frp's model inverts this: XTCP is a *distinct proxy type* with no relay path, so P2P failure is a
user-visible connection failure unless the operator has pre-built a parallel STCP proxy/visitor pair
and wired `fallbackTo` at it (§1.5). The 1000 ms default (`pkg/config/v1/visitor.go:163`) against a
10–40 s cold punch (§1.4) means the intended behaviour barely functions even when configured.

For our product the conclusion is architectural, not cosmetic:

> **Never expose "P2P" as a user-selectable transport. Expose a *service*, and let the engine choose
> the path.** The console shows which path is live (Relay / Direct / LAN) and the measured RTT; it
> never asks the user to pick, and never fails a request because a punch failed.

---

## 4. Decision: relay-only v1

**P2P/hole-punching is out of scope for v1.**

1. **S2 does not want it and cannot use it.** The robot is configured with "relay IP + port" and runs
   zero of our software. There is no agent on the robot to punch with, no signalling channel, no
   candidate exchange. Any P2P work is 0% applicable to S2.
2. **S1 benefits, but the benefit is bounded and the cost is not.** The relay path adds one hop.
   For a phone on LTE talking to a home desktop, both hops are typically 15–40 ms; a good relay
   placement recovers most of that. Meanwhile the puncher is where all the irreducible complexity
   lives: frp spends ~1 600 non-test lines and still fails outright when a STUN server lacks
   `OTHER-ADDRESS` (§1.1); EasyTier spends **10 157 lines** across
   `connectivity/{stun,hole_punch}` and *still* returns `None` for cone×sym, easySym×hardSym and
   sym×sym (`common.rs:114-133`).
3. **It is not unit-testable.** frp ships no test for `MakeHole` or `Controller` (§1.6). Validating a
   puncher needs a lab with several real NAT devices, or CGNAT emulation. That is a multi-week
   fixture project competing directly with the web console — which is the actual differentiator.
4. **A relay-only v1 is never *wrong*.** It is slower on one axis. A half-correct puncher is wrong:
   it produces intermittent, unreproducible, support-burning failures.
5. **Media latency has cheaper wins first.** Getting UDP/媒体 right over the relay — QUIC datagrams
   or a raw UDP session table, no head-of-line blocking behind TCP, correct pacing, relay placed
   near users — buys more than P2P and is required regardless of whether P2P ever ships.

**Ship in v1 anyway (cheap, high console value):** a STUN client that reports NAT type per agent.
It is ~200 lines with `pion/stun`, needs no puncher, and gives the console a "your network: Port
Restricted Cone / Symmetric (dec)" panel plus the data needed to decide later whether P2P is worth
building for the actual install base.

---

## 5. What v1 must not foreclose — the specific seams

### 5.1 `Path` abstraction above the transport

Nothing above this interface may know whether bytes go via relay or direct.

```go
type PathKind uint8
const (PathRelay PathKind = iota; PathDirect; PathLAN)

// One live carrier to one peer agent.
type Path interface {
    Kind() PathKind
    OpenStream(ctx context.Context) (net.Conn, error) // reliable substream (HTTP/WS/TCP)
    SendDatagram(b []byte) error                      // unreliable (media)
    RecvDatagram() ([]byte, error)
    RTT() time.Duration
    Close() error
}

// v1 registers exactly one. P2P later registers a second.
type PathDialer interface {
    Name() string                                       // "relay" | "direct-udp" | "lan"
    Dial(ctx context.Context, peer AgentID) (Path, error)
}

// Per-peer set with a selection policy. v1's implementation is trivially "the one path".
type PathSet interface {
    Add(Path)
    Best(class TrafficClass) Path // TrafficMedia prefers low RTT; TrafficBulk prefers throughput
    Snapshot() []PathStatus       // → console
}
```

The single most important consequence: **`SendDatagram` must exist in v1**, even if it is UDP-over-
relay. If media goes out over a TCP stream in v1, adding P2P later means rewriting the media plane.

### 5.2 Signalling must be extensible from day one

The control channel is the future candidate-exchange channel. Steal frp's correlated
request/response shape — `transporter.Do(ctx, msg, laneKey, expectedRespType)`
(`frp/pkg/nathole/nathole.go:164-189`) — but make the envelope versioned and unknown-field-tolerant
(protobuf or a JSON envelope with an explicit `type` + `v`), so a v1 relay silently ignores a
`nat_probe` message from a v2 agent.

Also ship **capability flags** in the agent's login message in v1, even if all bits are zero. Copy
EasyTier's `PeerFeatureFlag` idea (`policy.rs:36-49`: `is_public_server`, `need_p2p`, `disable_p2p`)
plus `supports_direct`. Without this, v2 agents cannot tell whether a peer can punch, and you are
forced into a probe-and-timeout dance.

### 5.3 Do not assume exclusive ownership of the data-plane UDP socket

A puncher needs to send from the *same* mapped port the relay session uses, or at minimum to
coordinate ports. Route all UDP binds through one factory from day one:

```go
type UDPBinder interface {
    Bind(ctx context.Context, opts BindOptions) (*net.UDPConn, error)
    // v2: hand the same conn to an ICE UDPMux / puncher without rebinding.
}
```

This is exactly what EasyTier does with `VirtualUdpSocketFactory` +
`UdpBindOptions::hole_punch_control()` (`udp/client.rs:78-86`), and it is why its puncher can reuse
listeners (`punch_listener.rs`, `MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS = 4`, `:5`) instead of
allocating fresh sockets per attempt.

### 5.4 Session identity must survive a path change

Sessions must be keyed by an application-level ID, not by `(srcIP, srcPort)`. Concretely: run QUIC
between agent and relay so connection migration is native, or carry an explicit session ID in the
datagram header plus a `PathMigrate` control message. If v1 keys sessions by 5-tuple anywhere, path
upgrade becomes "drop and reconnect", which is visible to the user.

### 5.5 Reserve the relay-side strategy learner

Even with no puncher, define the server-side table now: `(natTypePair) → strategy scores`, with the
client reporting outcomes. frp's `Analyzer` (`analysis.go:265-329`) and the
`NatHoleReport{Sid, Success}` message (`msg.go:244-247`) are the template. In v1 the only "strategy"
is `relay`, and the report just records success/RTT — which is useful telemetry on its own and means
v2 adds rows, not tables.

### 5.6 NAT-type provider interface

```go
type NATInfoProvider interface {
    Info(ctx context.Context) (NATInfo, error) // type, public IPs, port-drift direction, mapped addrs
    Redetect()
}
```

Model `NATInfo` on EasyTier's enum, **including `SymmetricEasyInc` / `SymmetricEasyDec`**
(`client.rs:485-491`), not frp's binary Easy/Hard (`classify.go:24-32`). The direction bit is what
makes prediction possible later, it is free to collect now, and retrofitting it means re-designing
the probe schedule. Refresh on EasyTier's schedule: 10 s while unknown, 600 s once confident
(`collector.rs:277-292`).

---

## 6. Go libraries in 2026 — verified status

| Library | Latest | Status | Verdict |
|---|---|---|---|
| `github.com/pion/stun/v3` | **v3.1.6** (2026-06-19) | active, pushed 2026-08-07, 851★ | **Use in v1.** RFC 5389/8489 messages + attributes. |
| `github.com/pion/ice/v4` | **v4.4.1** (2026-08-06) | active, pushed 2026-08-07, not archived, 598★ | **Use in v2** for cone-class P2P. |
| `github.com/pion/turn/v5` | **v5.0.12** (2026-07-01) | active, pushed 2026-08-04, 2 249★ | Optional: only if you want a standards TURN server alongside your own relay. |
| `github.com/huin/goupnp` | pushed 2025-04-27, 461★ | maintained-ish | IGD/UPnP port mapping. |
| `github.com/jackpal/go-nat-pmp` | pushed 2019-11-16, 138★ | **stale** | NAT-PMP; tiny protocol, vendor or reimplement. |
| `github.com/libp2p/go-nat` | pushed 2025-08-21, 22★ | thin wrapper | Wraps goupnp + go-nat-pmp behind one interface — convenient, low traffic. |

**Would `pion/ice` make a correct implementation cheap? Partly — and knowing exactly where it stops
is the point.**

What you get for free (`pkg.go.dev/github.com/pion/ice/v4`): `NewAgentWithOptions(opts ...AgentOption)`
(the `NewAgent`/`AgentConfig` pair is deprecated); `GatherCandidates()` with trickle via
`OnCandidate(func(Candidate))`; `AddRemoteCandidate` / `SetRemoteCredentials`;
`Dial(ctx, remoteUfrag, remotePwd) (*Conn, error)` on the controlling side and `Accept(...)` on the
controlled side, both returning a `*Conn` that implements `net.Conn`; plus
`StartDial`/`StartAccept`/`AwaitConnect` for non-blocking use. Options that matter to us:
`WithUDPMux` / `WithUDPMuxSrflx` / `WithTCPMux` (share **one** port with our data plane — this is
precisely seam §5.3), `WithNetworkTypes`, `WithCandidateTypes`, `WithPortRange`,
`WithInterfaceFilter`, `WithIPFilter`, `WithTURNTransportProtocols`, `WithContinualGatheringPolicy`.
It requires an out-of-band signalling channel to exchange ufrag/pwd and candidates — which our
control channel already is.

Where it stops: the candidate model is host / server-reflexive / peer-reflexive / relay
(`candidate_host.go`, `candidate_server_reflexive.go`, `candidate_peer_reflexive.go`,
`candidate_relay.go` in the repo root). **There is no port-prediction or birthday-paradox module.**
RFC 8445 ICE resolves hard-symmetric pairs by going to TURN, not by guessing ports. So:

- cone↔cone, LAN, and public-IP cases: **essentially free** with `pion/ice` + `pion/stun`.
- symmetric↔cone and easy-sym↔easy-sym: you must write EasyTier's logic yourself
  (`client.rs:339-441`, `:468-...`; `server.rs:143-247`). ICE can *carry* the extra guessed
  addresses as remote candidates, but it will not generate them or schedule the sweep.
- hard-sym↔hard-sym: TURN/relay only. Which is v1. Which is fine.

Estimated v2 cost with pion: ~600–900 lines for a cone-class ICE path behind the `PathDialer` seam;
~1 500–2 500 more lines plus a NAT lab for the symmetric strategies. The seams in §5 are what make
that an *addition* rather than a rewrite.

---

## 7. Patterns to lift regardless of the P2P decision

1. **The 200 ms hedge** (`easytier/src/gateway/hedge.rs:43-94`) — 5 racing connect attempts, first
   success wins, errors aggregated. Apply to *every* agent→relay dial and QUIC/TLS handshake in v1.
   In Go: `errgroup` plus a ticker, or a small generic helper over `func() (T, error)`.
2. **Backoff ladders with rollback** (`policy.rs:9-33`; used at `connector.rs:228, 258-259`).
   `rollback()` on a *transient* error (as opposed to a clean negative result) keeps the ladder from
   sprinting to 64 s because of one blip. Cheap, and the distinction is exactly right.
3. **Peer blacklist with TTL** (`connector.rs:45-79`, 3600 s) for "this peer told us not to bother".
4. **Refresh cadence tied to confidence** — 10 s unknown / 600 s confident
   (`collector.rs:277-292`).
5. **Lease-as-`Drop`** for external resources (`port_mapping.rs:133-139`). In Go: return a
   `func()`/`io.Closer` from every mapping/reservation call and never a bare success.
6. **Deterministic initiator election** — lower ID acts as client (`common.rs:149`). Applies to any
   symmetric protocol we add, P2P or not.
7. **frp's `Analyzer` bandit** (`analysis.go:181-256`) as the shape for any relay-side strategy
   learning, with the fix that the key should include a tenant/network scope, not just the public IP
   (`controller.go:74-92`).
8. **frp's encrypted probe payloads** (`utils.go:27-47`) — every out-of-band probe carries a MAC
   under the tunnel secret. Strictly better than EasyTier's bare 32-bit tid
   (`packet/hole_punch.rs:23-46`).
