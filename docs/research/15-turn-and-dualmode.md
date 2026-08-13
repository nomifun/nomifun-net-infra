# 15 — Embedded TURN + the dual-mode data path

Research date: 2026-08-07. Versions resolved live via `proxy.golang.org` and `pkg.go.dev`; Go source
quotes are from the local toolchain `go1.26.5` (`/usr/local/go`).

---

## Part A — Embedded TURN in Go

### A1. Library identity and status

| Fact | Value | Source |
|---|---|---|
| Current major | `github.com/pion/turn/v5` | https://pkg.go.dev/github.com/pion/turn/v5 |
| Latest | **v5.0.12**, `2026-07-01T21:08:50Z` | `https://proxy.golang.org/github.com/pion/turn/v5/@latest` |
| Previous major (still tagged) | v4.1.4, `2026-01-08` | `https://proxy.golang.org/github.com/pion/turn/v4/@latest` |
| RFCs | 5389 (STUN), 5766 (TURN), 6062 (TCP allocations), 6156 (IPv6) | https://github.com/pion/turn README |
| License | MIT | pkg.go.dev |

Maintenance is healthy and *recent*: v5.0.3 (Mar) → v5.0.12 (Jul 2026), with substantive interop work —
"Coturn interop tests" (#555), "Upgrade dtls to fix compatibility with firefox" (v5.0.9), "Fix
PermissionHandler not enforced for TURN TCP" (#570, v5.0.8), FINGERPRINT ordering fix (#556).
Source: https://github.com/pion/turn/releases

**Use v5, not v4.** v4→v5 is a real API break in the two places we touch:

```go
// v4:  type AuthHandler func(username, realm string, srcAddr net.Addr) (key []byte, ok bool)
// v5:
type AuthHandler func(ra *RequestAttributes) (userID string, key []byte, ok bool)
type RequestAttributes struct {
    Username string
    Realm    string
    SrcAddr  net.Addr
    TLS      *tls.ConnectionState   // TLS state IS exposed -> mTLS auth possible
    Method   stun.Method            // pion/stun/v3
}
```
(source: `internal/auth/auth.go`, https://raw.githubusercontent.com/pion/turn/master/internal/auth/auth.go)

`RelayAddressGenerator` also changed shape in v5: `AllocatePacketConn(AllocateListenerConfig)`,
`AllocateListener(AllocateListenerConfig)`, `AllocateConn(AllocateConnConfig)`.

### A2. Embedding shape

`ServerConfig` (v5, `server_config.go#L136`):

```go
type ServerConfig struct {
    PacketConnConfigs []PacketConnConfig  // UDP
    ListenerConfigs   []ListenerConfig    // TCP / TLS / DTLS
    LoggerFactory     logging.LoggerFactory
    Realm             string
    AuthHandler       AuthHandler
    QuotaHandler      QuotaHandler   // func(username, realm string, srcAddr net.Addr) (ok bool)
    EventHandler      EventHandler   // = allocation.EventHandler
    ChannelBindTimeout time.Duration // default 10m
    PermissionTimeout  time.Duration // default 10m
    AllocationLifetime time.Duration // default 10m
    StrictAddressFamily bool         // RFC 6156 default when REQUESTED-ADDRESS-FAMILY omitted
    InboundMTU int                   // default 1600
}
type PacketConnConfig struct { PacketConn net.PacketConn; RelayAddressGenerator; PermissionHandler }
type ListenerConfig   struct { Listener   net.Listener;   RelayAddressGenerator; PermissionHandler }
```
Server surface is tiny: `NewServer(ServerConfig) (*Server, error)`, `(*Server).AllocationCount() int`,
`(*Server).Close() error`. There is **no** allocation-enumeration API.

**Critical property: pion/turn never opens a socket for its client-facing listeners — we do.**
Verified in both examples: `net.ListenPacket("udp4", ...)` for UDP
(`examples/turn-server/lt-cred-turn-rest/main.go`) and `tls.Listen("tcp4", ..., &tls.Config{MinVersion:
tls.VersionTLS12, Certificates: ...})` for TURNS (`examples/turn-server/tls/main.go`). The example
comments say the library "doesn't allocate any TLS listeners, but lets the user pass them in", which
"gives room for logging, storage or modify inbound/outbound traffic". That hook is how we get metering
(see A6).

Simultaneous UDP + TCP + TLS = one `NewServer` call with three entries across the two slices, each with
its own `RelayAddressGenerator`:

```go
udp,  _ := net.ListenPacket("udp4", ":3478")
tcp,  _ := net.Listen("tcp4",  ":3478")
tlsL, _ := tls.Listen("tcp4",  ":5349", tlsCfg) // tlsCfg.GetCertificate = magic.GetCertificate
rag := func() turn.RelayAddressGenerator {
    return &turn.RelayAddressGeneratorPortRange{
        RelayAddress: net.ParseIP(publicIP), Address: "0.0.0.0",
        MinPort: 49160, MaxPort: 49400, MaxRetries: 10,
    }
}
srv, err := turn.NewServer(turn.ServerConfig{
    Realm:             realm,
    AuthHandler:       turn.LongTermTURNRESTAuthHandler(sharedSecret, logger),
    QuotaHandler:      quota.Allow,
    EventHandler:      metering.Handler(),
    PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp,  RelayAddressGenerator: rag()}},
    ListenerConfigs: []turn.ListenerConfig{
        {Listener: tcp,  RelayAddressGenerator: rag()},
        {Listener: tlsL, RelayAddressGenerator: rag()},
    },
})
```

### A3. Port and allocation model

- Client-facing: **TCP+UDP 3478** (`turn:`), **TCP 5349** (`turns:`) — RFC 7065 defaults.
- Relayed: `RelayAddressGeneratorPortRange{MinPort, MaxPort uint16, MaxRetries int}` bounds the range;
  **one relayed UDP port per allocation**, so `MaxPort-MinPort+1` is your hard concurrency ceiling.
  Open that whole range inbound UDP.
- `RelayAddressGeneratorStatic`/`PortRange` advertise `RelayAddress` *verbatim* while binding `Address`
  (`0.0.0.0`). The relay host must therefore hold a real public IP; behind 1:1 NAT you set
  `RelayAddress` to the public IP and `Address` to the private one.
- Total cap: `QuotaHandler` returns `false` → TURN error **486 Allocation Quota Reached**. Combine with
  `AllocationCount()` for a global ceiling and a per-tenant counter keyed on `username`/`realm`.

### A4. Auth — long-term and ephemeral

`GenerateAuthKey(username, realm, password) []byte` produces the RFC 5389/8489 long-term key that
`MESSAGE-INTEGRITY` is computed over; store *keys*, never passwords.

Ephemeral ("TURN REST API") creds are **built in**. From `lt_cred.go`
(https://raw.githubusercontent.com/pion/turn/master/lt_cred.go): `hmac.New(sha1.New, []byte(secret))`
over the username, `base64.StdEncoding.EncodeToString(mac.Sum(nil))`.

| Func | username | notes |
|---|---|---|
| `GenerateLongTermCredentials(secret, dur)` | `"<expiryUnix>"` | timestamp only |
| `GenerateLongTermTURNRESTCredentials(secret, user, dur)` | `"<expiryUnix>:<userid>"` | **what we want** |
| `NewLongTermAuthHandler(secret, logger)` | validates timestamp-only | RFC 8489 §9.2 |
| `LongTermTURNRESTAuthHandler(secret, logger)` | validates `"timestamp:userid"` | draft-uberti-behave-turn-rest-00 |

This is byte-identical to coturn's `use-auth-secret`: its shipped config states
`usercombo -> "timestamp:userid"`, `turn password -> base64(hmac(secret key, usercombo))`,
`rest-api-separator=:` (https://raw.githubusercontent.com/coturn/coturn/master/docker/coturn/turnserver.conf).
So our console's mint-credential API is provider-agnostic.

Handler behaviour to know: expiry is parsed with `strconv.Atoi`, and `t == now` still passes;
`LongTermTURNRESTAuthHandler` splits on `:` and uses field[0] as timestamp, field[1] (if present) as the
returned `userID` — the HMAC is always over the **full** username.

### A5. What the console hands a browser

`RTCIceServer` in the current W3C WebRTC REC (13 Mar 2025) has exactly three members — there is **no
`credentialType`** any more (https://www.w3.org/TR/webrtc/#rtciceserver-dictionary):

```
dictionary RTCIceServer { required (DOMString or sequence<DOMString>) urls;
                          DOMString username; DOMString credential; };
```

URI grammar, RFC 7065 §3.1: `turnURI = scheme ":" host [":" port] ["?transport=" transport]`,
`scheme = "turn"/"turns"`, `transport = "udp"/"tcp"`. The RFC warns: "Developers MUST NOT use a generic
hierarchical URI parser to parse a 'turn' or 'turns' URI." `turns:` MUST be used for TLS-over-TCP.

```json
{
  "iceServers": [{
    "urls": ["stun:relay.example.com:3478",
             "turn:relay.example.com:3478?transport=udp",
             "turn:relay.example.com:3478?transport=tcp",
             "turns:relay.example.com:5349?transport=tcp"],
    "username": "1785000000:tenant-42",
    "credential": "hV6bF0k9pQ2s1zLmR8yTqA3wXcE="
  }],
  "ttlSeconds": 600
}
```
All four URLs share one credential pair because the HMAC covers only the username. Mint TTL ≈ 10 min
with client-side refresh (`setConfiguration` / re-ICE), not hours.

### A6. Interop, metrics, quotas — the gaps

- **Browser interop:** pion/turn is the TURN implementation underneath pion/ice and pion/webrtc, and the
  release stream shows explicit Firefox-DTLS and coturn-interop fixes. Standard TURN, so Chrome/Safari
  work. **Watch `StrictAddressFamily`**: v5.0.10 changed the default for an omitted
  `REQUESTED-ADDRESS-FAMILY` to follow the listener's family, and the field doc calls this out as
  browser compat. If you ever bind a dual-stack/IPv6 listener, a browser omitting the attribute will get
  an IPv6 relay. **Recommendation: bind a separate `udp4`/`tcp4` listener set for v1** and treat IPv6
  relay as an explicit follow-up with a real Chrome/Safari test.
- **ICE-lite:** not a pion/turn concern — it is not an ICE agent. TURN allocations show up as ordinary
  `relay` candidates in full ICE.
- **TURN over TCP/TLS:** supported (client-to-server leg). Note RFC 6062 *TCP allocations* (peer leg over
  TCP) exist but browsers never request them; browser media relayed through TURNS still goes out UDP to
  the peer.
- **Bandwidth accounting: NOT exposed.** `EventHandler` (`internal/allocation/event_handler.go`) has
  `OnAuth`, `OnAllocationCreated(srcAddr, dstAddr, protocol, userID, realm, relayAddr, requestedPort)`,
  `OnAllocationDeleted`, `OnAllocationError`, `OnPermissionCreated/Deleted`, `OnChannelCreated/Deleted`
  — **no byte counters**. Nor is there a `GetAllocations()`.
  **Wrap it:** implement a custom `RelayAddressGenerator` that delegates to
  `RelayAddressGeneratorPortRange` and returns a counting `net.PacketConn`/`net.Listener`. The relay
  socket is per-allocation, so bytes attribute cleanly; correlate to tenant via
  `OnAllocationCreated`'s `relayAddr` + `userID`. Also wrap the client-facing listeners for the
  ingress leg. Export as Prometheus counters; that wrapper is ~120 LoC and is the only sane hook.

### A7. Recommendation — embed pion/turn v5

**Embed.** Reasons, in order of weight:

1. Single binary is a product requirement. pion's own README: it "is an API for building STUN/TURN
   clients and servers, not a binary you deploy then configure… No need to manage another service."
2. Credential minting needs no IPC either way (both sides just share the HMAC secret), but *quota
   enforcement does*. `QuotaHandler` + a per-allocation counting `RelayAddressGenerator` gives us
   per-tenant caps against the same tenant DB the console writes. With coturn you'd be reconciling
   `total-quota`/`user-quota`/`bps-capacity` in a second config file plus its own DB.
3. We already need to own the 443 TCP listener for the dual-mode mux (Part B). Because pion/turn accepts
   a `net.Listener`, a *terminated-TLS* connection can later be fed into a TURNS `ListenerConfig` via a
   synthetic listener — letting `turns:` share port 443 for 443-only-egress networks. coturn cannot
   participate in our mux at all.
4. Cost of embedding is bounded and known: no bandwidth metering, no allocation enumeration (A6).
   coturn's advantages (battle-hardening at scale, built-in quotas, `denied-peer-ip`, mobility) are real
   — keep a documented `turn.mode: external` escape hatch that just points `iceServers` at a coturn
   host and shares the same `static-auth-secret`. Because the credential format is identical, that
   switch is a config change, not a code change.

---

## Part B — The dual-mode data path

### B1. Discriminator order on a shared TCP port

Evaluate in this exact order; first match wins, and each step is cheap-before-expensive:

0. **Dedicated-port binding.** If the listener is configured as a single-tunnel passthrough port (the S2
   robot case), **do not peek at all** — `splice` immediately. The ESP32 sends no SNI and may send an
   IP-literal or absent `Host`; any parsing is pure risk. Port *is* the discriminator.
1. **PROXY protocol v1/v2** — consumed only if the listener is flagged `trustProxyProtocol` (i.e. behind
   our own LB). v1 magic `"PROXY "`, v2 12-byte `\r\n\r\n\0\r\nQUIT\n`. Never parse from an untrusted
   peer; it is a source-IP spoofing primitive.
2. **First byte.** `0x16` (TLS handshake record) → step 3. Printable ASCII (`G`,`P`,`H`,`O`,`D`,…) →
   step 5. Anything else → the port's default raw-L4 binding, else reject. (DTLS shares `0x16` but is
   UDP-only, so a TCP mux is unambiguous.)
3. **ALPN `acme-tls/1`** → terminate locally in certmagic unconditionally, so TLS-ALPN-01 challenges
   complete even on a port that also carries passthrough tunnels.
4. **TLS SNI** → route table lookup by `(port, sni)`. The matched tunnel's `mode` field decides
   passthrough vs gateway. No SNI (IP-literal dial) → port default binding.
5. **Cleartext HTTP `Host` + path prefix** → `(port, host, pathPrefix)`. IP-literal or absent `Host` →
   port default binding.
6. **Reject.** For TLS, reject by emitting a real `unrecognized_name` alert (see B2), not by a bare
   `close()` — bare closes confuse browsers.

Registration-time invariants the console must enforce: (a) at most **one** default binding per shared
port, since IP-literal traffic has no discriminator; (b) a passthrough SNI may not equal a gateway
hostname on the same port; (c) HTTP/3 needs UDP 443 and cannot join a TCP mux — out of v1 scope.

### B2. Passthrough + SNI routing without terminating TLS

frp's technique, which we should copy (Apache-2.0, so vendoring is fine):

- `/mnt/hgfs/share/net-infra/frp/pkg/util/vhost/https.go:41` — `sc, rd := libnet.NewSharedConn(c)`
  splits the conn into a *replayable* conn (`sc`) and a tee'd reader (`rd`). Everything read from `rd`
  is buffered and will be re-served from the front of `sc`.
- `https.go:43-50` — `readClientHello(rd)`, then `reqInfoMap["Host"] = clientHello.ServerName`. The
  original `c` is discarded in favour of `sc`.
- `https.go:53-71` — the peek itself: `tls.Server(readOnlyConn{reader: reader}, &tls.Config{
  GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) { hello = ...; return
  nil, nil }}).Handshake()`. The comment at `:56-58` is the whole trick: "Handshake always fails because
  the readOnlyConn is not a real connection… we only care about the error if hello was never set."
- `https.go:79-90` — `readOnlyConn` returns `io.ErrClosedPipe` on `Write`, so no bytes ever leave; the
  ClientHello is parsed, `GetConfigForClient` fires, then the handshake dies harmlessly.
- `https.go:73-77` — `vhostFailed` does a *real* `tls.Server(c, &tls.Config{}).Handshake()` purely to
  emit `alertUnrecognizedName` before closing. Copy this.
- `/mnt/hgfs/share/net-infra/frp/pkg/util/vhost/vhost.go:169-172` — a deadline is set **before** the
  peek (`c.SetDeadline(now + timeout)`) so a client that opens a socket and sends nothing cannot pin a
  goroutine. `vhost.go:174-188` then does the route lookup and calls `failHook` on miss.

`ClientHelloInfo` from `GetConfigForClient` yields **both** `ServerName` and `SupportedProtos` (ALPN) in
one peek — that is how steps 3 and 4 above share a single read. After routing, clear the deadline, then
either splice `sc` to the tunnel (passthrough — the buffered ClientHello replays first, so the backend
performs the real handshake and holds the private key) or hand `sc` to `tls.Server` (gateway).

### B3. Gateway mode: TLS termination + on-demand ACME

**certmagic v0.25.4, `2026-06-09T22:06:08Z`** (`proxy.golang.org`; https://pkg.go.dev/github.com/caddyserver/certmagic).
On-demand TLS is exactly the multi-tenant primitive we need — from the README: "When a TLS handshake is
received, CertMagic will read the Server Name Indication (SNI) value and either load and present that
certificate in the ServerHello, or if one does not exist, it will obtain it from a CA right
then-and-there."

Real v0.25.4 shape (source `certmagic.go`; **the README snippet is stale — the live signature takes a
`ctx`**):

```go
type OnDemandConfig struct {
    DecisionFunc func(ctx context.Context, name string) error // non-nil error => denied
    Managers     []Manager                                    // EXPERIMENTAL
    hostAllowlist map[string]struct{}                         // unexported; only used when DecisionFunc == nil
}
type Manager interface { GetCertificate(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error) }
// on Config:  OnDemand *OnDemandConfig   // non-nil enables the feature
```
The type doc says "To impose rate limits, specify your own DecisionFunc" — there is no built-in limiter,
so our `DecisionFunc` must do both jobs: *is there an enabled gateway-mode tunnel claiming this
hostname, owned by a tenant in good standing, and under its issuance rate budget?* `ClientHelloInfo` is
retrievable from the ctx via `certmagic.ClientHelloInfoCtxKey`, but the docs explicitly advise deciding
on the **name only** (using client IP to gate issuance is called out as inadvisable) — use the
ClientHello for logging.

Wiring: prefer `tlsCfg := magic.TLSConfig()`, which already appends `acmez.ACMETLS1Protocol` to
`NextProtos`; then prepend `"h2", "http/1.1"`. Retrofitting an existing config is two lines
(`GetCertificate = magic.GetCertificate` + the ALPN append). Keep both HTTP-01 (needs our :80) and
TLS-ALPN-01 (needs discriminator step 3) enabled; only add `DNS01Solver` if wildcards are required —
setting it **disables HTTP-01 and TLS-ALPN-01 for that issuer**. `ACMEIssuer` must be built via
`NewACMEIssuer(cfg, template)`: "It is NOT VALID to use an ACMEIssuer without calling NewACMEIssuer()."

### B4. The nomifun-tauri integration constraint (verified)

`/home/rika/src/nomifun-tauri/crates/backend/nomifun-app/src/desktop.rs:1204-1205` attaches
`host_guard_middleware` to the LAN app. The guard itself, `:1710-1723`:

```rust
if let Some(host) = headers.get(header::HOST)... && !host_is_ip_or_localhost(host)
    { return Err(StatusCode::FORBIDDEN); }
if let Some(origin) = headers.get(header::ORIGIN)... && !origin_is_ip_or_localhost(origin)
    { return Err(StatusCode::FORBIDDEN); }
```
`host_is_ip_or_localhost` (`:1726-1729`) accepts only `"localhost"` (case-insensitive) or something that
`parse::<IpAddr>()` accepts, after `strip_port` (`:1738-1747`, handles `[::1]:80`).
`origin_is_ip_or_localhost` (`:1731-1735`) splits on `"://"` and applies the same test. Comment at
`:1706-1709`: a DNS-rebinding guard, "Only applied to the LAN listener."

**Consequence that kills the obvious design:** `nomifun-realtime`'s WebSocket `validate_origin`
(`/home/rika/src/nomifun-tauri/crates/backend/nomifun-realtime/src/handler.rs:153-243`) *does* have an
escape hatch — it accepts an `Origin` matching the request `Host`, the first `X-Forwarded-Host`
(`:215-224`, `first_forwarded_host` at `:250-258`), or an operator-configured `allowed_origins`
(`:184-190`, built by `parse_allowed_origins` at `:272`). But `host_guard_middleware` is layered
*outside* the router and 403s a DNS-name `Origin` **before that handler ever runs**. So configuring
`allowed_origins` with the public hostname cannot work by itself. **Gateway mode must rewrite `Host`
*and* `Origin` to IP-literal form.** With `Origin` rewritten to the backend's own authority, the
handshake classifies as `SameOrigin` via the Host match, and no backend configuration is needed at all.

### B5. Exact header-rewrite table (gateway mode → nomifun-tauri LAN port)

Let `B = <backend-ip>:<backend-port>` (IP literal, from the tunnel registration) and `P = <public
hostname>`, `C = <true client IP>` (single value).

| Header | Action | Value | Why |
|---|---|---|---|
| `Host` | **set** | `B` | desktop.rs:1712-1716 403s DNS names. `ProxyRequest.SetURL` already does this — do **not** re-apply the doc's `r.Out.Host = r.In.Host` idiom. |
| `Origin` | **set if inbound had one; else omit** | `http://B` | desktop.rs:1717-1721; yields `SameOrigin` at handler.rs:215-224. Never forward `https://P`. |
| `X-Forwarded-Host` | **set (single value)** | `P` | handler.rs:250-258 reads it; informational once Origin matches Host. Must be ours, never the client's. |
| `X-Forwarded-For` | **delete then set (single value, no list)** | `C` | extract.rs:13-22 takes `split(',').next()` with **no trusted-proxy allowlist** — append-mode hands the internet a spoof primitive. |
| `X-Real-IP` | **delete then set** | `C` | extract.rs:25-30 fallback. |
| `X-Forwarded-Proto` | **set** | `https`/`http` per the *public* leg | informational. |
| `Forwarded` | **delete** | — | not parsed by the backend; strip to avoid ambiguity. |
| `X-Client-IP`, `CF-Connecting-IP`, `True-Client-IP` | **delete** | — | defence in depth against future backend changes. |
| `Connection`, `Upgrade` | leave to `ReverseProxy` | — | see B7. |

Path/query pass through unchanged; `/api` and `/ws` are on the same router (desktop.rs:1180).

### B6. Header sanitization rule (security)

Verified: `/home/rika/src/nomifun-tauri/crates/backend/nomifun-auth/src/extract.rs:13-32` trusts the
first `X-Forwarded-For` element
unconditionally, with no trusted-proxy list, falling back to `X-Real-IP` then `"unknown"`.

Relay rule: **in gateway mode, every one of the headers marked "delete" above is stripped from the
inbound request before any rewrite logic runs, and the identity headers are then set to exactly one
relay-computed value each.** Go's `httputil.ReverseProxy` helps but is not sufficient: when you use
`Rewrite` (not the deprecated `Director`), `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host` and
`X-Forwarded-Proto` are already stripped from `preq.Out` *before* `Rewrite` is called — but `X-Real-IP`
and vendor headers are not. Also: **never** use the doc's "emulate Director" snippet
(`r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]` before `SetXForwarded()`), which
re-introduces the client-controlled prefix. The `Director` field is deprecated for precisely this
reason, per its own doc: "X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto headers in inbound
requests are preserved by default, which can permit IP spoofing."

In **passthrough** mode we inject nothing, so there is no header primitive at all — but also no client
IP: the backend sees the tunnel's peer and `extract_client_ip` returns `"unknown"`. That is the correct
trade and should be surfaced in the console UI, not silently patched.

### B7. WebSocket through gateway mode

**Native — no Hijack code needed.** Verified in `/usr/local/go/src/net/http/httputil/reverseproxy.go`
(go1.26.5):

- `:477` `reqUpType := upgradeType(outreq.Header)`; `:482` `removeHopByHopHeaders(outreq.Header)`;
  `:494-497` "After stripping all the hop-by-hop connection headers above, add back any necessary for
  protocol upgrades, such as for websockets" → `outreq.Header.Set("Connection", "Upgrade")` /
  `Set("Upgrade", reqUpType)`.
- `:573-579` `if res.StatusCode == http.StatusSwitchingProtocols { … p.handleUpgradeResponse(rw,
  outreq, res); return }`.
- `:820-890` `handleUpgradeResponse` validates the request/response upgrade tokens match, asserts
  `res.Body.(io.ReadWriteCloser)`, calls `http.NewResponseController(rw).Hijack()` (`:839`), and runs a
  bidirectional `switchProtocolCopier` (`:876`, type at `:892`).

Note the pkg.go.dev doc comment does **not** mention any of this — it only says hop-by-hop headers
including `Upgrade` are removed. Trust the source. Operational requirements: (1) the inbound
`ResponseWriter` must support `Hijack`, i.e. serve HTTP/1.1 — do not force ALPN to `h2` only; WebSocket
over HTTP/2 (RFC 8441 Extended CONNECT) is not implemented by `ReverseProxy`, and browsers use h1 for
WS anyway; (2) set `FlushInterval: -1` for streaming/SSE routes; (3) do not set a `Transport`
`ResponseHeaderTimeout` short enough to kill a slow upgrade (it applies before the 101 only, but idle
timeouts elsewhere must not).

### B8. Blocking unknowns

1. **TURN metering has no upstream hook.** We must ship a counting `RelayAddressGenerator` +
   `EventHandler` correlation (A6). Estimate and schedule it; do not assume it exists.
2. **`StrictAddressFamily` × browser behaviour** is untested by us. Needs a real Chrome + Safari matrix
   before any IPv6 relay listener ships. v1 mitigation: `udp4`/`tcp4` only.
3. **certmagic `Managers` / `IssuerPolicy` are marked EXPERIMENTAL** and the README's `DecisionFunc`
   signature is stale vs v0.25.4. Pin `v0.25.4` exactly and compile-check on day one.
4. **`turns:` on shared 443** (A7 point 3) is attractive for restrictive networks but needs a synthetic
   `net.Listener` adapter and an SNI reservation rule. Descope from v1; keep the mux design able to
   accept it.
5. **One default binding per shared port** is a hard limit of IP-literal dialing. Confirm with the
   product owner that S2 robots get **dedicated ports**, not a shared 443.
