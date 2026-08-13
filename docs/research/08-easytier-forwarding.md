# 08 — EasyTier: forwarding, relay and security mechanisms worth stealing

Source tree read: `/mnt/hgfs/share/net-infra/EasyTier` (Rust). All line numbers below refer to that
checkout. Judged against **S1** (phone on internet → HTTP/WS/UDP APIs on a home-NAT desktop, via a
public relay; A/V calling ⇒ UDP latency matters) and **S2** (factory robot configured with only
"relay IP + port", zero client software, reaching a designated remote desktop).

---

## 1. `gateway/port_forward.rs` — EasyTier's answer to S2, TCP **and** UDP

This file is small (453 lines) because all the hard work was pushed behind a `DataPlaneRuntime`
abstraction. Its job is: bind a *host* socket, and splice it into an *overlay* socket.

**Config shape** (`config/gateway.rs:16-20`): `PortForwardConfig { bind_addr, dst_addr, proto }`
where `proto` is the string `"tcp"`/`"udp"`. Validation is a string match up front over the whole
list before any binding happens (`port_forward.rs:158-166`), so a bad rule can't half-apply.

**TCP path** (`port_forward.rs:214-264`). `host.bind_tcp` on `bind_addr`, then a per-listener accept
loop with a `CancellationToken` in a `biased` select so shutdown wins over new connections
(`:234-244`). Per connection it calls `data_plane.connect_tcp(dst_addr, …)` with a 10s deadline and
— importantly — the **source address is passed into the connect options**
(`DataPlaneTcpConnectOptions::gateway(…, source_addr)`, `:247-251`), so the overlay side can attribute
the flow. Splicing is literally `tokio::io::copy_bidirectional` (`:444`). No custom buffering, no
half-close gymnastics.

Underneath, `connect_tcp` picks a route (`dataplane/mod.rs:758-808`): `LocalEndpoint | Smoltcp`
→ userspace smoltcp; `LocalHost` → loopback; `Kcp`; `Direct` → real kernel socket. The smoltcp path
(`dataplane/mod.rs:647-710`) is the interesting one: it *first reserves a real host TCP port*
(`bind_tcp` on `0.0.0.0:0`, `:654-671`), uses that port number as the smoltcp local port, registers
a `FlowKey{src,dst,kind:TCP_ENTRY}` lease (`:673-683`), then `smoltcp_net.tcp_connect`. The kernel
port reservation is a collision-avoidance trick: it makes the userspace stack's ephemeral ports
unable to clash with anything the OS hands out. The smoltcp interface is configured with
`max_transmission_unit = 1280`, `Medium::Ip`, 16 KiB TCP buffers, `set_any_ip(true)`
(`gateway/smoltcp/stack.rs:29-70`).

**UDP path** (`port_forward.rs:266-369`). One host UDP socket per rule. A single receive loop with
an 8192-byte stack buffer allocated *per packet* (`:291` — a `vec![0u8;8192]` per datagram, i.e. one
heap allocation per packet on the hot path; same again at `:334` on the response side). On each
datagram it builds `UdpClientKey { client_addr, forward }` (`:39-43`, `:303-306`) and looks it up in
`udp_clients: DashMap<UdpClientKey, Arc<UdpClientInfo>>` (`:93`).

**The UDP NAT session table** is that `DashMap` plus a sibling `udp_response_tasks: DashMap<key,
AbortOnDropHandle<()>>` (`:94`). On a miss: open a new outbound flow (`UdpFlowFactory::open`,
`:420-437` — host socket if the destination is a local virtual IP, otherwise
`data_plane_udp_bind(0, 10s)`), insert an entry with `last_active: AtomicCell<Instant>` (`:321-325`),
and **spawn a dedicated response task** that loops `flow.recv_from` → `inbound.send_to(client_addr)`
(`:330-357`). Every inbound datagram refreshes `last_active` (`:361`). Aging/GC is a 30-second ticker
that retains entries younger than 600s, then drops orphaned response tasks and `shrink_to_fit`s both
maps (`:371-386`). Because the handle is an `AbortOnDropHandle`, evicting the map entry *is* the task
cancellation — no separate teardown path. Reload does a set-diff on `cancel_tokens` with a
wildcard-destination special case, then cascades the retain through `udp_clients` and
`udp_response_tasks` (`:175-197`).

Note there are **two** independent UDP NAT tables in this codebase. The port-forward one above is
socket-level. The L3 proxy has a second, packet-level one in `gateway/proxy/udp_proxy_engine.rs`:
`UdpNatKey{src_socket,dst_socket}` (`:25-37`), `UdpNatEntry` with `last_active_time`, `stopped`,
`denied` and a UUID id (`:54-114`), `entry_ttl = 180s` (`:153`), `remove_expired_entries` sweeping
every 15s (`udp_proxy_service.rs:92-98`) plus a 1s IP-fragment reaper (`:101-108`). The `denied` flag
is decided **once at entry creation** (`udp_proxy_engine.rs:268`, via
`runtime.should_deny_udp_proxy`) and then short-circuits every later packet (`:284-291`) — an ACL
decision cached in the conntrack entry, which is fast but means a policy change doesn't take effect
until the entry ages out.

**Verdict for S2:** the shape is right and directly reusable. Adopt the structure, drop the
smoltcp/L3 machinery — we have no TUN and no virtual IPs, so `copy_bidirectional` over two real
sockets plus a UDP session map is the whole feature.

**Adversarial notes.** (a) Per-packet 8 KiB heap allocation on both UDP directions
(`:291`, `:334`) — for A/V relaying at 50 pps × N sessions this is pure GC pressure; a Go port must
use a `sync.Pool` or fixed per-goroutine buffers. (b) 8192 silently truncates jumbo datagrams; there
is no "truncated" signal. (c) 600s UDP idle timeout (`:379`) is very long — a public relay holding a
goroutine + socket + map entry for 10 minutes after a phone walks away is a cheap DoS surface. (d) No
per-rule cap on the number of UDP sessions, and no per-client cap: `udp_clients` grows unbounded
between 30s sweeps. (e) `MAX_PENDING/backpressure` is absent — `send_to` errors are logged and
dropped (`:362-364`). (f) The smoltcp listener hardcodes port 8899 with a 10s accept timeout
(`smoltcp/stack.rs:83-85, 108, 112`), which is fine for its narrow use but is not a general listener.

## 2. MTU: why `udp_response_ipv4_mtu = 1280`

`ProxyRuntimeConfig::udp_response_ipv4_mtu: usize` defaults to `1280` (`config/gateway.rs:57, 78`,
asserted at `:136`, hardcoded again when building instance config at `instance/config.rs:201`). It is
consumed only on the **UDP response** path: `udp_proxy_service.rs:181` feeds it to
`UdpProxyEngine::handle_socket_response`, which computes

```
payload_mtu = ipv4_mtu - IPV4_HEADER_LEN;  payload_mtu = max(payload_mtu, 8);
payload_mtu -= payload_mtu % 8;            // fragment offsets are in 8-byte units
```
(`udp_proxy_engine.rs:334-337`, asserted `%8==0` at `:349`), then re-fragments the synthesized IPv4
reply via `compose_ipv4_packet` (`:372-393`). 1280 is the IPv6 minimum MTU and the smallest value
every path is required to carry; it is also exactly the smoltcp device MTU
(`gateway/smoltcp/stack.rs:30`). The reasoning is: responses are *manufactured* IPv4 packets injected
into a tunnel whose real path MTU is unknown, so pick the universally safe floor and fragment
locally rather than risk silent black-holing. Contrast the *overlay* MTU default of 1380
(`config/toml.rs:47`).

**For us:** we are not synthesizing IP packets, so the constant itself is irrelevant. The *lesson* is
relevant and load-bearing for S1 audio: pick a conservative datagram ceiling for relayed UDP
(1200-1280 payload), publish it, and never rely on path MTU discovery through a relay.

## 3. `peers/relay_peer_map.rs` — the data-plane relay session

The relay session model: a **1-RTT Noise IK handshake carried inside the data plane itself**, not a
separate control connection. Params `Noise_IK_25519_ChaChaPoly_SHA256` (`:380`), prologue
`b"easytier-relay-noise"` (`:29`), version 1 (`:28`), 5s handshake timeout, 200ms base backoff,
3 attempts (`:30-32`). IK is the right pattern here: the initiator already knows the responder's
static key (fetched from routing state via `get_remote_static_pubkey`, `:175-187`), so msg1 can carry
payload and msg2 completes the session — one round trip.

Mechanics worth stealing:

- **Encrypt-on-send with transparent buffering.** `send_msg` calls `ensure_session`; if no session
  exists it returns `Err` *immediately* and spawns the handshake in the background, while the caller's
  packet is pushed into `pending_packets` (cap 32 per peer, `:33`, `:252-258`) and the send reported
  as `Ok`. On handshake completion `flush_pending_packets` encrypts and drains them in order
  (`:260-282`, called at `:328`, `:349`, `:665`). Overflow silently drops (`:257`). Net effect: the
  first packet to a new peer is never lost to a cold session, and no caller blocks on crypto setup.
- **Per-peer handshake mutex** via `try_lock_owned` so exactly one handshake is in flight
  (`:189-194`, `:304-312`); the guard is moved into the spawned task.
- **Deterministic simultaneous-open resolution:** if msg1 arrives while we have our own pending
  handshake, the peer with the *smaller* peer_id keeps the initiator role, the other cancels and
  becomes responder (`:551-579`). No timers, no coin flips.
- **Responder pins the initiator's identity:** after reading msg1 it compares
  `hs.get_remote_static()` against the pubkey advertised in routing info and aborts on mismatch
  (`:611-620`). This is the difference between "encrypted" and "authenticated".
- **Session reuse/generation:** msg1 carries `a_session_generation`, msg2 replies with an action
  `Join | Sync | Create` (`:454-460`, `:635-647`) and optionally a 32-byte root key + initial epoch.
  Reconnects `Join` an existing session instead of rekeying.
- **GC:** `evict_idle_sessions(idle)` drops per-peer state, pending handshakes, handshake locks and
  buffered packets, then `shrink_dashmap`s all four (`:697-715`). Driven at 60s idle / 30s period
  (`foreign_network/mod.rs:560-568`). Crucially `remove_peer` does **not** delete the crypto session
  (`:721-737`) — session lifetime is decoupled from connection lifetime so a reconnect is a `Join`.

**What makes the relay operable by an untrusted third party:** the relay decrypts only what is
addressed *to itself* (`foreign_network/mod.rs:1305-1322` — handshake packets and `is_encrypted()`
data destined for `my_node_id`); anything being forwarded is passed through opaque. Combined with §4,
the third-party operator sees peer ids, packet types, sizes and timing — not payloads.

## 4. `peers/foreign_network/mod.rs` — relaying for a network you have no secret for

This is the genuinely good idea. When a peer of network `X` connects to a public node whose own
network is `Y`, the node does not reject it; it materialises a **`ForeignNetworkEntry` for X**.

The trust model hinges on what the relay actually holds. `PeerConn::get_network_identity()`
(`conn/peer_conn.rs:1374-1385`) returns `NetworkIdentity { network_name, network_secret: **None**,
network_secret_digest: Some([32 bytes]) }`. The relay only ever learns the *digest* of X's secret,
which peers send during handshake (`peer_conn.rs:508-531`), never the secret. From that it builds an
isolated context (`foreign_network/mod.rs:83-137`): fresh `instance_id` UUID, hostname prefixed
`PublicServer_` (`:62`), its own `PeerMap`, `PeerRoute`, `PeerRpcManager`, `RelayPeerMap`,
`TrafficMetricRecorder` and rate limiter (`ForeignNetworkEntry::new`, `:367-509`). Each foreign
network is a separate routing graph with a separate peer id.

Admission rules (`:895-1011`) are the policy surface an operator gets:

1. `relay_network_whitelist` wildcard match on the network name (`:900-910`;
   matcher at `peers/whitelist.rs:5-18`, space-separated `wildmatch` globs, default `"*"` at
   `config/toml.rs:53`).
2. A network can only be *created* by a peer that presented a non-zero secret digest
   (`network_secret_digest_is_empty`, `:773-778`; enforced `:909-921`). A digest-less
   (credential-only) peer may **join** an existing foreign network but never bootstrap one — this is
   what stops an attacker from squatting a network name.
3. Identity must match the entry, or the peer's Noise static pubkey must be in the entry's
   credential-trusted set (`credential_pubkey_is_trusted`, `:784-794`), and credential-trusted peers
   may not claim `PeerIdentityType::Admin` (`:780-782`, `:957-985`).
4. `max_direct_conns_per_peer_in_foreign_network` caps conns per peer (`:993-1004`).
5. Entries are reference-counted by liveness: `remove_peer` drops the network map entry once its peer
   map is empty (`:640-656`), and `Drop` unregisters RPC services by domain and clears trusted keys
   (`:610-621`).

**The limitation to name.** Because the relay has no secret, it cannot verify the HMAC on credential
announcements. `credential_proof_is_valid` returns `true` when `network_secret` is `None`
(`route/peer_ospf_route.rs:979-998`, `.unwrap_or(true)`), and the same "trust admin claims without
proof" flag is passed to group verification (`:3006-3008`). So a shared relay's view of who is
trusted is *advisory*: it is derived from what members claim. That is defensible — the relay is not
the enforcement point, end peers re-verify with the real secret — but it means relay-side ACLs on a
shared node are DoS/quota controls, not security boundaries. Any productized console must not present
them as security.

## 5. Ephemeral revocable credentials

`peers/credential_manager.rs`: a credential **is** an X25519 keypair. `build_entry` (`:205-234`)
generates `StaticSecret::random_from_rng(OsRng)`, base64s both halves, and stores
`CredentialEntry { pubkey, secret, groups, allow_relay, allowed_proxy_cidrs, reusable, expiry_unix,
created_at_unix }` (`:34-46`). `generate_credential_with_options` sweeps expired entries first, then
supports **idempotent fixed ids**: re-requesting an existing id returns the same secret with
`changed: false` (`:174-190`) — exactly what a web console needs for "show me the join token again".
`revoke_credential` is a map removal + persist (`:236-247`); `remove_expired_credentials_at` retains
on `expiry_unix > now` (`:249-263`). Persistence is a pluggable `CredentialStorage` trait
(`:93-96`) serialising the whole map as JSON (`:312-327`), and malformed storage degrades to empty
rather than failing startup (`:121-124` + test `:487-496`). Every read path filters by expiry
(`:265-302`), so an expired credential is dead even if GC hasn't run.

Propagation and revocation are network-wide with no central authority: admin nodes (those holding the
secret) publish `TrustedCredentialPubkeyProof` in their `RoutePeerInfo` field 19
(`easytier-proto/proto/peer_rpc.proto:8-49`); the proof is `HMAC-SHA256(network_secret,
"easytier credential proof" || proto-encoded credential)` (`easytier-proto/src/peer_rpc.rs:47-94`).
Receivers union the credentials published by admin peers only, skip expired ones, and tag each key
with `TrustedKeySource::{OspfNode, OspfCredential}` + expiry
(`route/peer_ospf_route.rs:1000-1055`). Revoking = removing from the published list; the next routing
sync makes every node drop the peer and disconnect (`:3014-3016`, `disconnect_untrusted_peers`).
The design doc (`easytier/docs/credential_peer.md:12, 33-40, 195-232, 300-320`) is explicit that only
`NetworkSecretConfirmed` publishers are trusted, and that a post-handshake fast-reject is
**mandatory**, not an optimisation, precisely because the handshake was relaxed to allow missing
secret proofs.

**Adversarial:** the manager stores the **private key** alongside the pubkey (`:38`, `:215`,
`:226`) so the issuing node can re-display it — a credential file leak is a full compromise of every
live credential. `reusable` is recorded and propagated (`proto:14`, `:60`) but concurrency isn't
enforced in this module. Revocation latency equals the routing-sync period. `groups`/
`allowed_proxy_cidrs` are asserted by the issuer with no proof beyond the network HMAC.

## 6. ACL model, SOCKS5, bandwidth, device identity — briefly

**ACL** (`easytier-proto/proto/acl.proto`): three chains `Inbound | Outbound | Forward`
(`:22-29`), rules with `priority`, `enabled`, protocol, port/IP/port-range lists, `source_groups` /
`destination_groups`, `action ∈ Noop|Allow|Drop`, `rate_limit`+`burst_limit`, `stateful`
(`:43-71`), per-chain `default_action` (`:79-85`), and `GroupIdentity{group_name, group_secret}`
(`:92-95`) so group membership is HMAC-provable (`easytier-proto/src/peer_rpc.rs:14-44`). The runtime
(`peers/acl/processor.rs`) precompiles rules into `FastLookupRule`, memoises verdicts in a
`DashMap<AclCacheKey, AclCacheEntry>` with a 20s cleanup interval and 15s idle eviction
(`:265`, `:394-400`), tracks connections in `DashMap<String, ConnTrackEntry>` keyed by a **formatted
string** `"src:port->dst:port"` (`:724-733`) — one `String` allocation per packet on a cache miss —
and does per-rule packet-rate limiting with a token bucket (`:770-798`). The `Drop` action is silent
by design (`acl.proto:20`). Verdict: the *schema* is excellent and worth copying almost verbatim
(priority + named chains + groups + per-rule rate limit is a complete productizable model); the
string-keyed conntrack and cached-verdict-with-stale-policy behaviour are not.

**SOCKS5** (`gateway/socks5/`): `Config::allow_udp` defaults to `false`
(`server.rs:43`), `UDP ASSOCIATE` is rejected with `CommandNotSupported` at both parse and execute
time (`:474-478`, `:522-529`), and the gateway adapter never turns it on — it sets only timeout,
`skip_auth`, `allow_no_auth` (`adapter.rs:95-98`). Why: the UDP association implementation that
*does* exist pins the first client that sends a datagram and silently drops all others
(`host.rs:170-176`), bails out entirely on any fragmented request (`:167-170`), and refuses domain
targets (`:174-181`) — i.e. it is a single-client toy. Shipping it enabled on a public relay would be
an open UDP reflector. **Drop SOCKS5 entirely** for our tool: it does not serve S2 (the robot can't
speak SOCKS5) and only partly serves S1.

**Bandwidth governance.** Two knobs, both `u64::MAX` = unlimited by default
(`config/toml.rs:73, 81`; CLI at `easytier/src/core.rs:614-623`; diffed as strings for TOML
round-trip at `config/toml.rs:180`, tests `:1254-1272`). `foreign_relay_bps_limit` is **per foreign
network** — the limiter key is `peer:foreign:{network_name}:forward` for forwarding and
`peer:foreign:{network_name}:recv` for receive (`peers/context.rs:1002-1015`) — while
`instance_recv_bps_limit` is one shared `peer:instance:recv` bucket. Deliberately, the foreign
forward limiter does **not** fall back to the instance limit (test at
`peers/context.rs:1430-1443`). Enforcement is non-blocking `try_consume(payload_len)` on relayed data
packets only, dropping on failure (`foreign_network/mod.rs:1351-1356`). The bucket is an on-demand
refill token bucket with fractional-nanosecond remainder carry (`foundation/token_bucket.rs:96-127`),
`MIN_FILL_RATE = 8196` (`:31`), default capacity = 1 second of fill (`:62-66`), and a
`TokenBucketManager` that GCs buckets whose only holder is the map every 5s (`:219-253`). This is
exactly per-tenant governance and it is the right shape.

**Device identity.** `resolve_machine_id` (`easytier/src/common/machine_id.rs:22-46`) prefers an
explicit id (parsed as UUID, else hashed, `:48-59`), then a persisted state file, then legacy
locations, then a derived id, then a random v4. The persisted-file path is the notable engineering:
per-OS state dir (`XDG_DATA_HOME` → `~/.local/share` → `/var/lib`, macOS `Application Support`,
Windows `LOCALAPPDATA`; Android *must* be explicit, `:73-122`), `flock`-guarded double-checked write
(`:286-299`, `:378-412`), and atomic `create_new` temp + `rename` + `sync_all` (`:301-343`).
Derivation on Linux mixes `machine_uid` + hostname + up to 3 sorted non-loopback MACs (`:232-284`) —
hardware-derived but *only as a seed for the first persisted value*, so later hardware changes don't
change identity. Heartbeat: `HeartbeatRequest { machine_id, inst_id (a per-session UUID),
user_token, easytier_version, report_time (RFC3339), hostname, running_network_instances[],
device_os, support_config_source }` (`easytier-proto/proto/web.proto:13-25`), fired on a
**1-second** interval and breaking the loop on first error (`management/full/web_client.rs:319-352`).
`device_os` is `{os_type, version, distribution}` sniffed from `/etc/os-release`, `sw_vers`, `ver`,
`uname -r` (`easytier/src/common/os_info.rs:5-114`) — it shells out to subprocesses.
A 1s heartbeat is indefensible at fleet scale; 15-30s with a server-driven interval is the fix.

---

## 7. Verdicts and Go sketches

| Idea | Verdict | Go design |
|---|---|---|
| (a) relay-without-secret | **Adopt, reframed** | Relay stores only `tenantID + sha256(tenant_key)`. Forwarded frames are opaque; relay decrypts only frames addressed to itself. Per-tenant `struct Tenant{ id string; keyDigest [32]byte; router *Router; lim *rate.Limiter; quota Quota }` in a `xsync.Map[string,*Tenant]`, created only by a digest-presenting client, refcounted to zero. Console must label relay-side rules as quota/abuse controls, not security. |
| (b) ephemeral revocable credentials | **Adopt** | Credential = Ed25519 keypair (`crypto/ed25519`) or X25519 for a Noise-style handshake. `Credential{ID, PubKey, Groups []string, AllowRelay bool, AllowedTargets []netip.Prefix, ExpiresAt time.Time, Reusable bool, MaxConcurrent int}`. Store **pubkey only** server-side; return the private half exactly once at issuance (fixes EasyTier's private-key-at-rest flaw). Revocation = DB delete + version bump pushed over the control channel; enforce at accept time and on a ≤5s tick for live sessions. |
| (c) UDP NAT session table | **Adopt** | `type udpKey struct{ rule ruleID; client netip.AddrPort }`; `sessions *xsync.MapOf[udpKey,*udpSession]` with `udpSession{ conn *net.UDPConn; lastActive atomic.Int64 /*unixnano*/; done context.CancelFunc }`. One goroutine per session for the return path; `SetReadDeadline` so it self-exits. Idle **60-90s**, sweep every 10s, hard cap sessions per rule and per client IP. Buffers from a `sync.Pool` sized 1500 (not 8192-per-packet). Read with `ReadMsgUDPAddrPort`; consider `x/net/ipv4.PacketConn.ReadBatch` for the A/V path. |
| (d) per-tenant bandwidth governance | **Adopt** | `golang.org/x/time/rate.Limiter` per tenant per direction, keys `tenant:{id}:fwd` / `tenant:{id}:recv`; `AllowN(now, len(pkt))` non-blocking for UDP (drop, count the drop), `WaitN` for TCP (backpressure). Burst = 1s of rate, floor ~8 KiB. Do **not** let a tenant limit fall back to the global limit. GC idle limiters. Export drop counters per tenant — the console needs "you were throttled". |
| (e) machine_id device identity | **Adopt, simplified** | `DeviceID` = random UUIDv4 persisted once to `os.UserConfigDir()/nomifun/device_id` via temp-file + `os.Rename` + `Sync`, guarded by a lockfile (`github.com/gofrs/flock`). **No** MAC/hostname derivation — it fingerprints users, breaks on NIC changes, and buys nothing once the value is persisted. Heartbeat every 20s: `{device_id, session_id, version, os{type,version}, hostname, active_tunnels[], reported_at}`; `runtime.GOOS` + one `/etc/os-release` read, never a subprocess; server returns the next interval. |

Also: **adopt** the ACL schema (chains × priority × groups × per-rule rate limit) with `netip.Prefix`
matching and an integer-keyed conntrack (`struct{src,dst netip.AddrPort; proto uint8}` as a map key —
comparable, zero allocation). **Adopt** the encrypt-on-send + bounded pending-packet buffer and the
smaller-id-wins simultaneous-open rule. **Adopt** the 1280-ish relayed-datagram ceiling as a
published constant. **Drop** smoltcp/userspace TCP (no TUN ⇒ no need; `copy_bidirectional`'s Go
equivalent is two `io.Copy` goroutines with `CloseWrite`, or `splice` via `TCPConn.ReadFrom`).
**Drop** SOCKS5. **Drop** the 1s heartbeat and the L3 UDP-response re-fragmentation entirely.
