# 12 — Threat model, security design, and operations for a public-facing relay

Design input dossier. Evidence base: `../net-infra/frp` (Go, v0.71.0) and `../net-infra/EasyTier` (Rust),
both sibling checkouts. Every claim below is anchored to `file:line` in the two checkouts.

Scenarios under judgement: **S1** phone (public internet) → HTTP/WS/UDP on a home desktop behind NAT; **S2** factory robot
configured with only "relay IP + port" → designated remote desktop, zero client software on the robot.

---

## Part A — Threat model

### A1. Tunnel registration and identity spoofing

frp's entire agent identity is a shared token. `pkg/auth/token.go:40` sets
`loginMsg.PrivilegeKey = util.GetAuthKey(auth.token, loginMsg.Timestamp)`, and `pkg/util/util/util.go:50-56` defines
`GetAuthKey` as `hex(MD5(token || strconv(timestamp)))` — plain MD5, no HMAC construction, no salt, no key separation.
Verification at `pkg/auth/token.go:64-69` does a constant-time compare of that digest and **nothing else**: there is no
freshness window, no nonce cache, no replay ledger. A grep for `Timestamp` across non-test server code
(`server/service.go:892`, `pkg/auth/token.go:40-88`, `pkg/nathole/controller.go:189`) finds no clock-skew check anywhere.
Consequence: one captured login message is a permanent bearer credential replayable forever with the same timestamp.

That matters because the control channel is not authenticated by default. `pkg/transport/tls.go:99-106` generates a
**random self-signed cert** when `certFile`/`keyFile` are unset, and `conf/frps_full_example.toml:44` ships
`transport.tls.force = false`. The client enables TLS by default (`pkg/config/v1/client.go:183`) but with no CA pinned it
gets encryption without server authentication. The token proof is not bound to the channel, so an on-path attacker
terminates TLS, harvests `PrivilegeKey`, and registers as the victim.

Worse, identity is fully fungible. `server/service.go:788-793`: if `loginMsg.RunID == ""` the **server** mints a `RandID`
— so RunID is a session handle, not an identity. `server/service.go:895-897` carries an explicit
`TODO(deprecation)` allowing visitor connections with no RunID and empty user for pre-v0.50 compat, and
`server/service.go:804-807` swaps in `auth.AlwaysPassVerifier` (`pkg/auth/pass.go:21-31`, which returns `nil` for
everything) whenever `internal && loginMsg.ClientSpec.AlwaysAuthPass`. Port ownership is equally weak: `allowPorts`
and `maxPortsPerClient` (`conf/frps_full_example.toml:126-134`) are **global**, not per-tenant, so any token holder can
claim any allowed port and, via `Activate`/`errControlReplaced` (`server/service.go:834-841`), evict an incumbent.

**Design for the new tool.** *Drop* shared-token-as-identity. *Adopt* EasyTier's shape: per-agent X25519/Ed25519 keypair
generated on first boot, enrolled by a short-lived one-time console code (EasyTier makes credential TTL mandatory —
`easytier/docs/credential_peer.md:711-716`), and a login proof that is **channel-bound**. EasyTier already does exactly
this: `secret_proof = HMAC-SHA256(derive(network_secret), role_byte || handshake_hash)`
(`easytier/docs/peer_conn_secure_mode_v3.md:461-466`) plus static-pubkey pinning
(`easytier/docs/peer_conn_secure_mode_v3.md:470-474`). In Go, use `crypto/tls` with `RequireAndVerifyClientCert` (frp
already has the plumbing at `pkg/transport/tls.go:121`) or a TLS exporter secret via `ConnectionState.ExportKeyingMaterial`
signed by the agent key. Never accept a client-chosen session ID without re-proof. Keep a server-side lease table
`(tenant, resource) → agent_pubkey` so a port/hostname claim from a different tenant is rejected, persisted across restarts.

### A2. The S2 "bare public port, no application-layer auth" problem

A frp `remotePort` listener is a **bare public port — anyone who can route to it can connect**, and the
only admission hook, `NewUserConn`, can allow/deny but never sees application-layer credentials.
`pkg/plugin/server/types.go:66-71` — `NewUserConnContent{User, ProxyName, ProxyType, RemoteAddr}`.
That is the entire decision input, and it is consumed at `server/proxy/proxy.go:275-285` before any bytes are read. There
is **no source-CIDR facility at all**: a repo-wide grep for `allowlist|whitelist|allowIP|sourceIP|CIDR` returns only
`pkg/vnet/*`, `pkg/nathole/utils.go:56` and test names. `secretKey`/`allowUsers` exist only on stcp/xtcp/sudp
(`pkg/config/v1/proxy.go:447-448,477-478,511-512`; `server/proxy/proxy.go:202-207`) — which requires an frpc *visitor* on
the caller side, i.e. it breaks S2's premise.

Honest verdict on each candidate, against "robot only fills IP+port, zero software":

| Mechanism | Achievable in S2? | Verdict |
|---|---|---|
| Source-IP/CIDR allowlist | **Yes**, zero robot changes | **Adopt as the primary control.** |
| PROXY-protocol identity preservation | Yes (relay→home side) | **Adopt**, but as *audit + defence-in-depth*, not auth. |
| mTLS for the robot | No — needs a client cert in the robot's stack | **Drop for S2**; keep as an opt-in for capable appliances. |
| Lightweight pre-auth handshake | No — needs client software | **Drop for S2**; use for S1 (our own client). |
| Per-port shared secret | No place to put it if the config is only IP+port | **Drop**; see below. |

"Port as secret" deserves an explicit rejection: a random high port is ~16 bits of entropy and is trivially enumerated by
Shodan-class scanners. It is obscurity, not a control, and must not be presented in the console as security.

So the achievable boundary in S2 is **network-layer**, and the product's job is to make that boundary loud and easy:

1. `allowCIDRs` defaults to **empty = deny all**. Opening `0.0.0.0/0` requires typed confirmation and leaves a persistent
   console banner + an audit event. (frp's default is the opposite: bind and hope.)
2. Evaluate the CIDR check inside `Accept()` *before* requesting a work-conn — not in an out-of-process HTTP plugin the
   way `server/proxy/proxy.go:281` does, which adds an RPC to every connection.
3. **Learn mode**: the relay records the first N distinct source IPs that hit a new listener and offers a one-click "pin to
   these" in the console. This is the single highest-value productisation gap versus frp.
4. Per-listener caps: max concurrent conns, accept rate, and idle timeout — all per tenant.
5. Emit PROXY protocol v2 to the home service (frp already has `pkg/util/net/proxyprotocol.go:25-33`) so the home service
   can enforce its own policy and so logs are truthful. Document loudly that a PROXY header is spoofable unless the home
   service trusts *only* the tunnel socket.
6. Time-boxed listeners: a port lease with a TTL, auto-closed, renewable from the console. A factory integration window of
   two weeks should not leave a port open for two years.
7. Offer the escape hatch: bind the listener to loopback and front it with an mTLS/OIDC terminator for tenants who *can*
   install a cert. Do not pretend it applies to S2.

Also fix the timing bug the pattern invites: `pkg/util/vhost/http.go:201` and `:205` compare vhost basic-auth with plain
`user == rc.Username && passwd == rc.Password`, unlike the dashboard which correctly uses `ConstantTimeEqString`
(`pkg/util/net/http.go:49-50`).

### A3. Relay operator as adversary — E2E vs L7, resolved

frp is fully trusted: the vhost layer runs a real `httputil.ReverseProxy` whose `Rewrite` hook edits `X-Forwarded-For`,
overwrites `req.Host` from `RewriteHost`, and injects arbitrary headers (`pkg/util/vhost/http.go:57-98`), TLS is
terminated at the relay, and `UseEncryption` derives its key from the shared token — `EncryptionKey: svr.auth.EncryptionKey()`
(`server/service.go:816`, feeding `pkg/auth/auth.go:94-96` → `[]byte(resolved.Token)` at `:114`) is handed to
`libio.WithEncryption` at `server/proxy/proxy.go:298` and `server/proxy/udp.go:208` — so the relay operator holds the key
by construction. EasyTier takes the opposite position:
「数据包在源端加密、目的端解密，relay 节点（含 `allow_relay` 的临时节点）无法看到明文」
(`easytier/docs/credential_peer.md:658`). Infrastructure nodes deliberately do not hold the user's `network_secret`
(`easytier/docs/peer_conn_secure_mode_v3.md:22`), and until pinning or `network_secret_confirmed` succeeds a link is only
`encrypted_unauthenticated` (`:29`, `:482-485`).

**Decision: two planes, explicit per tunnel.**

- **Plane A (opaque, default for S1 and for anything the tenant marks confidential).** The relay is a byte pump. Routing
  comes from a *plaintext outer header* chosen at publish time, exactly like EasyTier's 16-byte `PeerManagerHeader`
  carrying `from_peer_id`/`to_peer_id` (`easytier/docs/peer_conn_secure_mode_v3.md:92-105`). Payload is AEAD'd end to end,
  with per-epoch traffic keys `k(epoch, dir) = HKDF(root_key, "et-traffic" || epoch || dir)` (`:254`) and a 256-bit replay
  bitmap (`:193`) — about 212 B of state per peer, which is the right order of magnitude for an IoT fleet.
- **Plane B (terminating, required for S2 and for ACME/Host routing/WAF).** Relay decrypts. Console shows a
  "relay can read this traffic" badge; every enable is an audit event.

The stated tension — "you cannot route by HTTP Host if you can't read the stream" — dissolves once you notice **SNI is
plaintext**. In Plane A the client *registers* a hostname at publish time and the relay routes on the ClientHello SNI while
passing every byte through untouched: L7-shaped routing with zero plaintext access. Caveat to write into the design:
Encrypted ClientHello (ECH) kills this, so keep two fallbacks — ALPN token, or a dedicated port per tunnel. Anything
needing header rewriting, path routing, or response inspection is Plane B, full stop.

### A4. UDP amplification, scanning, resource exhaustion

frp's server UDP path is the weakest thing in either repo. `pkg/proto/udp/udp.go:58-70`: read from the public socket,
wrap, `select { case sendCh <- udpMsg: default: }`. No per-source state, no 5-tuple session table, no cookie, no rate
limit, silent drop on a 1024-deep channel (`server/proxy/udp.go:106-107`), and one single work-conn per proxy
(`server/proxy/udp.go:50-51`: "there are always only one workConn at the same time"). Two consequences: (a) a spoofed
source address makes the relay a reflector — the home service's reply is written to `udpMsg.RemoteAddr`
(`pkg/proto/udp/udp.go:51`), i.e. to the victim; (b) because there is no per-source accounting, the relay cannot even
*measure* its own amplification factor.

Design: per-5-tuple session table with idle TTL, a hard cap on table size, and a global packets/sec budget. For S1 (our
client) require a **QUIC-Retry-style stateless cookie** — 32-byte HMAC over `(src_ip, src_port, listener, epoch)` — echoed
before a mapping is installed; this is free when we own the caller. For S2's UDP a bare appliance cannot do a cookie
exchange, so gate on CIDR *and* enforce an egress/ingress byte-ratio cap per 5-tuple (drop above K, default K≈3) so the
amplification factor is bounded by construction. Steal EasyTier's per-network byte limiter:
`easytier-core/src/peers/foreign_network/mod.rs:1351-1355` drops when `bps_limiter.try_consume(payload_len)` fails, and
`:1340-1350` supports a hard `disable_relay_data` kill switch.

Conn floods and slowloris: `server/service.go:686-740` spawns a goroutine per accepted connection with **no semaphore and
no accept-rate limit**; `connReadTimeout = 10s` (`server/service.go:62`) is the only brake. Worse, yamux is layered on
before authentication with `MaxStreamWindowSize = 6 * 1024 * 1024` (`server/service.go:719`), so a *single* unauthenticated
TCP connection can open many streams, each with a 6 MiB window and a live goroutine. That is a memory-amplifying DoS.
Design: bounded accept semaphore, per-IP connection cap, handshake deadline before any buffer allocation, cap streams per
pre-auth session at 1, and shrink the mux window until after login. Adopt EasyTier's reasoning verbatim:
`easytier/docs/credential_peer.md:665-670` argues the post-handshake fast reject must be **mandatory, not optional**,
precisely because an unauthenticated peer otherwise holds a valid encrypted connection while consuming resources. Also
adopt the anti-DoS session rule at `easytier/docs/peer_conn_secure_mode_v3.md:342-346`: a peer must not be able to force
key/session rotation by redialing.

Port scanning: with `allowCIDRs` deny-by-default the scan surface collapses to the control port and the console. Return
identical behaviour for "no such tunnel" and "denied" (frp's `detailedErrorsToClient = true`,
`conf/frps_full_example.toml:94`, does the reverse and leaks debug info to any client that completes login).

### A5. SSRF via the client's arbitrary local target

`pkg/config/v1/proxy.go:155` defaults `LocalIP` to `127.0.0.1`, and validation is a no-op:
`validateTCPProxyConfigForClient` and `validateUDPProxyConfigForClient` both `return nil`
(`pkg/config/v1/validation/proxy.go:129-135`). Nothing stops `localIP = "169.254.169.254"`. The client plugins
`pkg/plugin/client/http_proxy.go` and `socks5.go` are unrestricted forward proxies by design. In our product this is
sharper than in frp, because a **console** will push tunnel definitions to agents: console compromise then becomes a
home-LAN and cloud-metadata pivot.

Design: the **agent** holds the authoritative target policy in its local file, and rejects console-pushed tunnels that
violate it with a visible event — neither frp nor EasyTier does this. Default-deny `169.254.0.0/16`,
`::ffff:169.254.0.0/112`, `100.100.100.200`, `fd00:ec2::254`, plus `metadata.google.internal`. Enforce the check on the
resolved address at **every dial** (not once at config parse) to defeat DNS rebinding against the target. Reuse EasyTier's
`allowed_proxy_cidrs` subset-filter idea (`easytier/docs/credential_peer.md:702-709`), which exists for exactly this class
of lying-about-your-scope attack.

### A6. Console security

Both repos are instructive, mostly as counterexamples.

frp: static HTTP Basic auth (`pkg/util/net/http.go:45-59`) with a 200 ms failure delay
(`pkg/util/http/server.go:86`) and **no lockout, no per-IP budget, no session concept**. If both user and password are
empty the middleware waves everything through (`pkg/util/net/http.go:48`). The shipped example is
`webServer.user = "admin"` / `webServer.password = "admin"` (`conf/frps_full_example.toml:71-72`), with optional pprof on
the same listener (`:80`). No CSRF token, no `Host` validation anywhere.

EasyTier is closer to right — `axum-login` + `tower-sessions` with a SQLite session store and Argon2 password hashing
(`easytier-web/Cargo.toml:22-31`) — but has concrete defects worth avoiding: `easytier-web/src/restful/mod.rs:222`
`.with_secure(false)` (cookie sent over plain HTTP); `:223` `SameSite::Lax`; `:281`
`CorsLayer::very_permissive()` on the same router; `:219` `Key::generate()` on every boot, so a restart invalidates all
sessions; `:340` compares the internal bearer token with plain `==`. The device-token path is the standout:
`easytier-web/src/db/mod.rs:135-140` carries `// TODO: currently we don't have a token system, so we just use the user
name as token`, and `easytier-web/src/client_manager/session.rs:479-495` auto-creates a user for any unknown
`user_token` when `allow_auto_create_user` is set — unauthenticated tenant creation from the device channel. The one thing
to steal outright is `easytier-web/src/db/mod.rs:125-131`: generate a **random** password on user creation and store only
`password_auth::generate_hash(...)`.

Our design:
- Server-side sessions, `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`; **refuse to serve the console over
  plain HTTP on a non-loopback bind**. Persist the session key in the data dir, don't regenerate it.
- CSRF: double-submit token **plus** `Origin`/`Referer` check on every state-changing verb. No permissive CORS; an explicit
  origin allowlist.
- **DNS rebinding**: validate the `Host` header against configured console hostnames + literal bind IP + `localhost`,
  return 421 otherwise. This is the attack that turns a loopback-bound console into a browser-driven takeover; frp has no
  such check.
- **First run**: generate a 128-bit password, print it to stdout/journal *and* write it `0600` to
  `<datadir>/initial-admin-password`; force rotation on first login; refuse to boot with a default/empty credential on a
  non-loopback listener.
- Brute force: per-IP and per-account token bucket, exponential backoff, lockout with admin unlock, all comparisons via
  `crypto/subtle`.
- Agent/API tokens: opaque 256-bit random, format `nrly_<prefix8>_<secret>`, stored as SHA-256 (fast verify — Argon2 is
  for human passwords only), prefix-indexed, per-agent scoped, revocable, TTL'd.
- Secrets at rest: SQLite, with tunnel secrets sealed under a KEK from env/file/OS keyring — never plaintext in the DB.
  Keep `/healthz` outside the auth middleware and `/metrics` inside it; frp gets this right
  (`server/api_router.go:28` vs `:31,36`).

### A7. Supply chain

frp signs nothing. `.goreleaser.yml:3-7` produces only a sha256 checksum file — generated in the *same* job that builds
the artifacts, so it defends against corruption, not compromise. `.github/workflows/goreleaser.yml:35` pins
`version: latest` for goreleaser itself, and actions are pinned to mutable major tags
(`checkout@v6`, `goreleaser-action@v7`). Docker builds are properly multi-arch —
`platforms: linux/amd64,linux/arm/v7,linux/arm64,linux/ppc64le` (`.github/workflows/build-and-push-image.yml:68,79`) —
but unsigned. EasyTier depends on a **git branch**: `service-manager = { git = ..., branch = "main" }`
(`easytier/Cargo.toml:202`).

Ship: pinned action SHAs; `actions/attest-build-provenance` (SLSA build provenance) for every archive and image; cosign
keyless signatures over archives *and* the multi-arch manifest; a Syft SPDX SBOM attached as an attestation; reproducible
builds via `-trimpath -ldflags "-s -w -buildid="` and `CGO_ENABLED=0` (frp's Dockerfiles already do the first two —
`dockerfiles/Dockerfile-for-frps:17`); `GOFLAGS=-mod=readonly` and `go mod verify` in CI; and a documented
`cosign verify-blob` one-liner in the install docs. The install script must verify the signature before executing
anything.

---

## Part B — Operations

### B1. Deployment artifacts

Target: one static binary per platform, `CGO_ENABLED=0`. That constraint drives one real decision — use
**`modernc.org/sqlite`** (pure Go), not `mattn/go-sqlite3` (CGO), or the static-binary promise dies. Embed the console SPA
with `embed.FS`; frp's split (`web/frps/embed.go` + `embed_stub.go`, built behind `-tags frps`,
`dockerfiles/Dockerfile-for-frps:17`) is the pattern to copy so a headless build stays small.

Dockerfile: adapt frp's three-stage node → golang → alpine layout (`dockerfiles/Dockerfile-for-frps:1-25`) but change two
things — final stage `gcr.io/distroless/static:nonroot` instead of `alpine:3` (no shell, no package manager, non-root
UID), and add `HEALTHCHECK` against `/healthz`. Keep frp's multi-arch platform list
(`.github/workflows/build-and-push-image.yml:68`) and add `linux/riscv64`.

Ship a `docker-compose.yml` with a named volume for `/data` (SQLite + certs), `network_mode: host` documented for
UDP-heavy S1 deployments, and no default password anywhere.

systemd unit: EasyTier generates its own at `easytier/src/service_manager/mod.rs:225-256` — `Type=simple`,
`Restart=always`, `RestartSec=1`, `LimitNOFILE=infinity`, `After=network.target syslog.target`,
`StartLimitIntervalSec=0`. Take the restart semantics; add what is **missing**: `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`CapabilityBoundingSet=`/`AmbientCapabilities=CAP_NET_BIND_SERVICE`, a dedicated `relay` user,
`StateDirectory=nomifun-relay`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, and `LimitNOFILE=1048576` (a real
number — `infinity` disables the guard rail that catches fd leaks).

One-line installer: detect OS/arch, download archive **and** cosign bundle, verify, install, write the unit, print the
generated admin password. Fail closed if verification fails.

### B2. Client-side service installation on Windows/macOS/Linux

EasyTier's approach is a per-platform dispatch (`easytier/src/service_manager/mod.rs:51-84`): a forked `service-manager`
crate, `windows-service = "0.7.0"` (`easytier/Cargo.toml:253`), `LaunchdServiceManager::system()` with
`KeepAlive::conditions().crashed(true).successful_exit(false)` on macOS, and `TypedServiceManager::native()` elsewhere.
Its `install` is really "stop, uninstall, reinstall" (`:22-42`), which means an upgrade drops the tunnel — a UX bug to
avoid.

In Go the equivalent is **`github.com/kardianos/service`**, verified live on pkg.go.dev: v1.3.0 published **2026-07-06**,
Zlib licence, no deprecation notice, ~1,431 importers. It covers Windows SCM, systemd, Upstart, SysV, OpenRC, procd,
launchd, FreeBSD rc.d, AIX and Solaris SMF, with options including `StartType`, `OnFailure`, `DelayedAutoStart`,
`LimitNOFILE`, and a `Shutdowner` interface added in v1.2.0. Two upgrade traps: it replaced `text/template` with a
mini-engine (custom unit templates using `{{.Name}}` or `eq`/`and` now fail with "unknown template key"), and
`WorkingDirectory`/`ChRoot` are unsupported on Windows; `Dependencies` is unimplemented on Linux and launchd. Effort:
about a day for `install|uninstall|start|stop|status` plus the `Interface`/`Shutdowner` wiring, and a second day for
Windows code signing and macOS notarisation — which is the actual cost. Use the custom `SystemdScript` option to inject
the hardening directives from B1.

### B3. Zero-downtime reload and graceful shutdown

frp has reload on the **client only** — `client/service.go:385-408` (`UpdateConfigSource`, guarded by `reloadMu`) reached
via `GET /api/reload` (`client/api_router.go:36`), with the actual re-application in `reloadConfigFromSourcesLocked`
(`client/service.go:491-496`). There is no reload in `cmd/frps/` or `server/`; a grep finds nothing. Server config changes
mean a restart, which drops every tunnel.

Design: hold listeners in a map keyed by `(proto, addr, port)`; on `SIGHUP` or a console apply, diff desired vs actual,
close only removed listeners, bind only added ones, leave established connections untouched. Bump a `config_generation`
counter, validate-then-swap (never partially apply), and keep the last-known-good config so a bad apply is a no-op with an
event, not an outage.

Graceful shutdown: frp's client has `GracefulClose(d)` (`client/service.go:418-437`, wired to SIGINT/SIGTERM at
`cmd/frpc/sub/root.go:117-119`) but the **server never drains**. Ours must: (1) stop accepting, (2) fail readiness while
keeping liveness green, (3) push a `Draining{deadline}` control frame so agents re-dial a sibling relay, (4) wait
`min(drain_deadline, all-conns-closed)`, (5) `http.Server.Shutdown(ctx)` for the console, (6) close. Drain deadline
configurable, default 30 s.

### B4. Observability

frp's metric set is thin and cardinality-hazardous: `frp_server_client_counts` (gauge),
`proxy_counts{type}`, `proxy_counts_detailed{type,name}`, `connection_counts{name,type}`, `traffic_in{name,type}`,
`traffic_out{name,type}` (`pkg/metrics/prometheus/server.go:61-97`). `name` is **client-chosen**, so
`proxy_counts_detailed` (`:73-78`) is an unbounded-cardinality footgun. There are no latency histograms, no rejection
counters, and no login-outcome counters at all.

Proposed set (bounded labels only — `tenant`/`tunnel` are server-issued IDs, never raw remote IPs):

```
relay_build_info{version,commit,go_version}                              gauge
relay_tunnels{tenant,tunnel,type,state}                                  gauge
relay_tunnel_conns_active{tenant,tunnel,type}                            gauge
relay_tunnel_conns_total{tenant,tunnel,type,outcome}                     counter
    outcome = ok|denied_cidr|denied_lease|no_workconn|ratelimited|drained
relay_tunnel_bytes_total{tenant,tunnel,type,dir}                         counter  dir=in|out
relay_tunnel_first_byte_seconds{tunnel,type}                             histogram
relay_udp_sessions{tenant,tunnel}                                        gauge
relay_udp_packets_total{tenant,tunnel,dir,outcome}                       counter
    outcome = ok|drop_queue_full|drop_no_cookie|drop_ratio|drop_table_full
relay_udp_amplification_ratio{tenant,tunnel}                             histogram
relay_agent_sessions{state}                                              gauge   state=handshaking|connected|draining
relay_agent_login_total{outcome}                                         counter
    outcome = ok|bad_signature|replay|unknown_key|revoked|version_reject|ratelimited
relay_agent_rtt_seconds{tenant}                                          histogram
relay_console_login_total{outcome}                                       counter
relay_port_leases{tenant} / relay_ports_available                        gauge
relay_config_generation / relay_config_reload_total{outcome}             gauge / counter
```

Logs: `log/slog` JSON, one line per connection decision with `tenant`, `tunnel`, `src_ip`, `outcome`, `bytes_in/out`,
`duration_ms`; never log tokens or `PrivilegeKey`-equivalents. Endpoints: `/healthz` (liveness, unauthenticated — as frp
does at `server/api_router.go:28`) and `/readyz` (drain-aware, unauthenticated), `/metrics` behind auth
(`server/api_router.go:31,36`). Console event stream: SSE over the authenticated session — a bounded ring buffer per
tenant with `Last-Event-ID` resume, which is simpler and more proxy-friendly than WebSocket for a one-way feed.

### B5. Upgrade and compatibility policy

frp does essentially nothing. `pkg/util/version/version.go:17-21` is a bare `var version = "0.71.0"` with a `Full()`
getter; the server logs the client's version (`server/service.go:799-800`) and echoes its own
(`server/service.go:484,500`) but **never gates on it**. There is one real precedent worth generalising:
`server/service.go:773-782` explicitly validates the negotiated `wireProtocol` (`v1`/`v2`) against the
`udpPacketCodec` and rejects unsupported combinations.

Design: a numeric `protocol_version uint32` plus a **capability set** (string tokens: `udp.cookie`, `plane.opaque`,
`sni.route`, `proxyproto.v2`, …) in the ClientHello. Server replies with the intersection and its
`min_supported_protocol`. Below the minimum → a structured error the console surfaces as "agent too old, upgrade to ≥ X",
never a bare disconnect. Protocol version bumps only on breaking wire changes; new features arrive as capabilities so N-2
agents keep working. Newer agents MUST degrade to the negotiated set rather than fail. Signed release manifest at
`/api/v1/updates` for agent self-update, verified with the cosign chain from A7.

### B6. Backup and restore

State is one SQLite file plus a sealed secrets blob plus the TOML config. Use `VACUUM INTO 'snapshot.db'` for a consistent
hot snapshot without stopping the relay; `relayctl backup` bundles snapshot + config + schema version + KEK-wrapped
secrets, and `restore` refuses a backup whose schema version is newer than the binary. Migrations forward-only and
idempotent, with the pre-migration file copied aside. Don't repeat EasyTier's two self-flagged gaps: credentials held only
in memory are lost on restart and silently evict every device using them (`easytier/docs/credential_peer.md:685-693`), so
persist leases and enrollment credentials from day one; and one credential reused across nodes means one revocation kicks
them all (`:695-700`) — model agents 1:1 with keys.

---

## Cross-cutting: what to reject from EasyTier

`easytier-core/src/peers/foreign_network/mod.rs:902-908` reads
`if ret.is_err() && !parent_flags.relay_all_peer_rpc { return ret }` — when `relay_all_peer_rpc` is enabled, a network
that fails the relay whitelist (`easytier-core/src/peers/whitelist.rs:5-18`, wildcard matching, empty string = deny) still
proceeds to entry creation and control-plane relaying. A single boolean that silently converts a deny into an allow is
exactly the kind of flag that ends up on in production. Our equivalent knobs must be enumerations with explicit scopes,
and the console must render the *effective* policy, not the flags.
