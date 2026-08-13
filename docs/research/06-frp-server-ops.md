# 06 — frp 服务端运维面 (Server Operational Surface)

Source tree read: `/mnt/hgfs/share/net-infra/frp` (module `github.com/fatedier/frp`, `go 1.25.0` — `go.mod:3`).
Every claim below is anchored to `file:line` in that tree. Verdicts are against **S1** (phone → HTTP/WS/UDP on
home-NAT desktop, A/V latency matters) and **S2** (factory robot configured with only `relay IP + port`, zero
client software).

---

## 1. Device registry embryo — `server/registry/registry.go`

`ClientInfo` (`registry.go:26-40`) is frp's entire notion of a "device": `Key, User, RawClientID, RunID,
ControlID, Hostname, IP, Version, WireProtocol, FirstConnectedAt, LastConnectedAt, DisconnectedAt, Online`.
It is **pure in-memory** — `ClientRegistry` is `map[string]*ClientInfo` + `runIndex map[string]string` guarded by
one `sync.RWMutex` (`registry.go:44-49`), with an injectable `clock.PassiveClock` for tests
(`registry.go:55-64`). No persistence, no WAL, no DB. Restart frps → every device disappears.

**Keying.** `composeClientKey` (`registry.go:207-216`) returns `user`, `id`, or `fmt.Sprintf("%s.%s", user, id)`.
`RegisterWithControlID` (`registry.go:74-135`) computes `effectiveID := rawClientID; if "" then runID`
(`registry.go:82-85`), so an frpc that sets no `clientID` gets an ephemeral key based on the random `runID`.
`enforceUnique := rawClientID != ""` (`registry.go:87`) — uniqueness is only enforced for *named* clients.

**Online/offline.** `Online` is a bool flipped by exactly two paths:
- Login commit: `Register*` sets `Online=true`, `DisconnectedAt=time.Time{}`, refreshes `LastConnectedAt`
  (`registry.go:126-133`). Called from `ControlManager.Activate` with `loginMsg.User, loginMsg.ClientID,
  ctl.runID, loginMsg.Hostname, loginMsg.Version, remoteAddr, WireProtocol, entry.id`
  (`server/control.go:202-215`).
- Control teardown: `MarkOfflineByRunIDAndControlID` → `setClientOffline` clears `RunID`/`ControlID`, sets
  `Online=false`, stamps `DisconnectedAt` (`registry.go:168-173`). Anonymous entries (`RawClientID==""`) are
  **deleted** instead, to avoid stale ghosts (`registry.go:157-161`).

`ControlID` is a process-local generation counter so a dying older control cannot offline the entry a newer
generation now owns (`registry.go:71-73`, guarded at `registry.go:156` and `control.go:246-259`). Duplicate named
login while online returns `conflict=true` (`registry.go:94-96`) surfaced as
`"client_id [%s] for user [%s] is already online"` (`control.go:211-213`) — i.e. **first writer wins**, the new
client is rejected. Contrast with unnamed clients, where the *new* control silently replaces the old.

### Adversarial findings

1. **Offline detection is effectively disabled by default.** `heartbeatWorker` returns immediately when
   `HeartbeatTimeout <= 0` (`server/control.go:639-642`), and `Complete()` defaults `HeartbeatTimeout = -1`
   whenever TCPMux is on — which is the default (`pkg/config/v1/server.go:187-191`, `TCPMux` defaults true at
   `server.go:183`). So liveness rides on yamux keepalive at 30 s (`server.go:184`,
   `server/service.go:716`). A robot on a dead-but-not-FIN'd LTE link stays `Online: true` for tens of seconds
   to minutes. For S2 fleet dashboards this is a correctness bug, not a nicety.
2. **Key ambiguity.** `composeClientKey` does raw string concat, so `user="a.b", id="c"` and `user="a",
   id="b.c"` both produce `"a.b.c"` (`registry.go:207-216`). Two tenants can alias into one registry slot.
3. **Unbounded growth.** Named-but-offline entries are never evicted (`registry.go:157-161` only deletes
   anonymous ones). A CI system that rotates `clientID` per build leaks one `ClientInfo` forever. There is no
   `PruneOfflineClients` — `/api/v2/system/prune` prunes *proxy* stats only
   (`server/http/controller_v2.go:93-105` → `mem.StatsCollector.PruneOfflineProxies`).
4. **`ClientID` is client-asserted and unverified.** It arrives in `msg.Login.ClientID`
   (`pkg/msg/msg.go:85`) and is trusted verbatim (`control.go:203`). With a shared token (§2) any client can
   claim any `{user, clientID}` that is currently offline.

**Verdict: ADAPT.** The shape (`Key`, first/last connected, wire protocol, generation counter) is right and worth
stealing. Replace the storage with a durable table and make identity server-issued.

---

## 2. Auth — `pkg/auth/`

Two methods only, selected by `AuthMethod` (`pkg/auth/auth.go:64-81` client, `auth.go:118-127` server).

**Token.** `TokenAuthSetterVerifier` (`pkg/auth/token.go:27-37`). The wire credential is
`GetAuthKey(token, timestamp) = hex(md5(token || strconv(timestamp)))`
(`pkg/util/util/util.go:50-56`), compared with `subtle.ConstantTimeCompare` (`util.go:134-136`,
used at `token.go:65`). Weaknesses, concretely: **MD5, not HMAC** — no keyed construction, and length-extension
is irrelevant only because the digest is compared whole; and **no freshness window** — `VerifyLogin`
recomputes over the *client-supplied* `m.Timestamp` (`token.go:64-68`), so a captured `(timestamp,
privilege_key)` pair replays forever. There is no nonce cache, no clock-skew bound anywhere in `pkg/auth/`.

**`tokenSource`.** `AuthServerConfig.TokenSource *ValueSource` (`pkg/config/v1/server.go:132`) and the client
twin (`pkg/config/v1/client.go:200-202`) resolve once at startup via `BuildServerAuth` /`BuildClientAuth`
(`auth.go:100-116`, `auth.go:42-62`). `ValueSource` supports `type: file` (`FileSource.Path`) and `type: exec`
(command+args+env) (`pkg/config/v1/value_source.go:28-49`, dispatch at `value_source.go:74-87`). Resolution is
**one-shot** — rotating the file does not rotate the live token without a restart.

**OIDC.** Client side is OAuth2 **client_credentials** (`clientcredentials.Config` at `pkg/auth/oidc.go:146-152`)
with `audience` injected as an endpoint param (`oidc.go:142-144`) and a caching `TokenSource` wrapped by
`oidcTokenSource`, which falls back to a non-caching source when the IdP omits `expires_in`
(`oidc.go:98-124`) — a genuinely good detail. Server side verifies the JWT with `go-oidc`
(`oidc.go:276-288`) and then enforces **subject pinning**: the subject seen at `Login` is recorded
(`oidc.go:298-307`) and every later Ping/NewWorkConn token must carry a subject already in that set
(`oidc.go:309-323`). Note `subjectsFromLogin` is a `map[string]struct{}` that is **never pruned** — an unbounded
per-process set, and pinning is global to the process rather than per-connection, so subject A's login
authorizes subject A's pings on *any* connection.

**Which messages are authenticated.** Only three, and two are opt-in:

| Message | Verified | Gate |
|---|---|---|
| `Login` | always | `service.go:807` `authVerifier.VerifyLogin` |
| `Ping` | only if `additionalScopes` contains `HeartBeats` | `token.go:71-80`, `oidc.go:325-331`; call site `control.go:780-783` |
| `NewWorkConn` | only if `additionalScopes` contains `NewWorkConns` | `token.go:82-91`, `oidc.go:333-339`; call site `service.go:874-879` |

`NewVisitorConn` is **not** in the `Verifier` interface (`auth.go:83-87`); STCP/SUDP visitors authenticate with the
per-proxy `Sk`/`AllowUsers` (`pkg/msg/msg.go:128-130`) instead. `msg.NewProxy` carries **no credential at all** —
proxy creation is authorized purely by owning a logged-in control.

**SSH bypass.** `auth.AlwaysPassVerifier` (`pkg/auth/pass.go:21-31`) is substituted when
`internal && loginMsg.ClientSpec.AlwaysAuthPass` (`server/service.go:803-806`), set by the SSH gateway when SSH
pubkey auth already ran (`pkg/ssh/server.go:127`). Correct, but it means the trust boundary is "is this conn
internal", which is a boolean passed down from the listener (`service.go:388`, `handleConnection(..., internal)`).

**Verdict:** token scheme **DROP** (replace with HMAC + bounded skew, or mTLS). `tokenSource`/`ValueSource`
**ADOPT** (add hot reload). OIDC client-credentials **ADAPT** — keep it as an optional enterprise path; the
`oidcTokenSource` expiry-probe trick is worth copying verbatim. `additionalScopes` **DROP the opt-in-ness**:
authenticate every control-plane message unconditionally.

---

## 3. Multi-user — `pkg/naming/names.go`

The whole multi-tenant model is three string functions: `AddUserPrefix(user, name) -> "user.name"`
(`names.go:6-11`), `StripUserPrefix` which removes exactly one `"{user}."` prefix (`names.go:15-23`), and
`BuildTargetServerProxyName` for visitors (`names.go:27-32`).

The prefix is applied **on the client**: `wireName: naming.AddUserPrefix(clientCfg.User, baseInfo.Name)`
(`client/proxy/proxy_wrapper.go:120`), `client/proxy/xtcp.go:88`, and stripped again on responses
(`client/control.go:158,169`). **The server never validates it.** `Control.RegisterProxy` takes
`pxyMsg.ProxyName` as given (`server/control.go:818-824`), builds `UserInfo` from `LoginMsg.User`
(`control.go:826-831`), and registers into a single flat namespace: `PxyManager.Add(pxyMsg.ProxyName, pxy)`
(`control.go:886`, map keyed by bare name at `server/proxy/proxy.go:571-576`). `grep -n HasPrefix server/**/*.go`
returns nothing. Consequence: with a shared token, tenant B logs in as `user=""` and registers proxy
`"tenantA.camera"`, squatting A's name and A's dashboard row. **Multi-user in frp is a display convention, not
an isolation boundary.**

**Verdict: DROP the string-prefix model.** Carry `tenant_id` as a first-class field derived from the *verified*
credential, never from a client-supplied string, and key all maps by `(tenant, name)`.

---

## 4. Port allocation & quota — `server/ports/ports.go`

`ports.Manager` holds `reservedPorts map[string]*PortCtx` (by proxy name), `usedPorts map[int]*PortCtx`,
`freePorts map[int]struct{}` (`ports.go:36-45`). Two instances exist, one per L4 protocol:
`TCPPortManager`/`UDPPortManager`, both seeded from the same `cfg.AllowPorts`
(`server/service.go:174-175`). `allowPorts` is `[]types.PortsRange{Start,End,Single}`
(`pkg/config/types/types.go:113-117`, parsed from `"1000-2000,3000"` at `types.go:137-160`); when empty, the
manager pre-materialises **all 65535 ports as map entries** (`ports.go:73-77`).

`Acquire(name, port)` (`ports.go:82-146`): for `port==0` it first retries the proxy's previously reserved port
(`ports.go:100-108`), then scans the `freePorts` map for at most **5** candidates
(`maxTryTimes := 5`, `ports.go:112-124`) — Go map iteration order is random, so with a fragmented range this
returns `ErrNoAvailablePort` spuriously. For an explicit port it distinguishes `ErrPortNotAllowed` vs
`ErrPortAlreadyUsed` vs `ErrPortUnAvailable` (`ports.go:128-144`). Liveness is checked by **actually
binding and closing** a listener (`isPortAvailable`, `ports.go:155-175`) — a TOCTOU race with any co-tenant
process, and it does the bind while holding `pm.mu` (`ports.go:91-97`), so a slow bind stalls all acquisitions.
Reservations are sticky for 24 h (`MaxPortReservedDuration`, `ports.go:18`) and swept hourly
(`ports.go:189-215`).

Quota is a single global integer: `MaxPortsPerClient` (`pkg/config/v1/server.go:84-86`), enforced per-control by
`ctl.portsUsedNum + pxy.GetUsedPortsNum() > MaxPortsPerClient` (`server/control.go:852-870`), decremented on
`CloseProxy` (`control.go:905-908`). **There is no per-user or per-tenant quota anywhere** — no `allowPorts` per
user, no proxy-count cap, no traffic cap. The `reservedPorts` map is keyed by bare proxy name, so it is also
cross-tenant shared state.

**Verdict: ADAPT.** Keep ranges + reservation-with-TTL + typed errors. Drop the 5-try scan (use a deterministic
allocator), drop bind-probing under lock, and make quota a per-tenant record.

---

## 5. Bandwidth limiting

One `*rate.Limiter` per proxy, created at proxy construction:
`rate.NewLimiter(rate.Limit(limitBytes), int(limitBytes))` — burst == 1 s of bytes — server side only when
`BandwidthLimitMode == "server"` (`server/proxy/proxy.go:536-539`, `basePxy.limiter` at `proxy.go:551`), and the
mirror-image on the client when mode == `"client"` (`client/proxy/proxy.go:66-70`). Default mode is `client`
(`pkg/config/v1/proxy.go:156`), i.e. **the tenant polices itself by default** — trivially defeated by a patched
frpc, since the server only forwards the advertised value (`msg.NewProxy.BandwidthLimit`,
`pkg/msg/msg.go:107-108`).

Application points: TCP user connections (`server/proxy/proxy.go:310-314`), vhost HTTP
(`server/proxy/http.go:141-144`), and the UDP work conn (`server/proxy/udp.go:219-223`). The wrapper is
`limit.NewReader` + `limit.NewWriter` sharing **one** limiter (`pkg/util/limit/reader.go:36-51`,
`writer.go:36-59`), so up and down traffic compete for the same budget, and `Reader.Read` truncates `p` to
`limiter.Burst()` before reading (`reader.go:37-40`) — with a 1 KB/s limit that clamps every read to 1024 bytes.
`WaitN(context.Background(), n)` (`reader.go:46`, `writer.go:47`) has no cancellation, so a shutdown blocks
behind the token bucket.

Two structural problems for S1: the limiter is **per proxy, never per tenant or per server**, so N proxies × limit
is the real ceiling; and for UDP the limiter sits on the single multiplexed work conn, so limiting one media
stream stalls every other flow in that proxy.

**Verdict: ADAPT.** Server-side enforcement must be the default and non-negotiable. Use a hierarchical limiter
(tenant → device → proxy), separate up/down buckets, and pass a real `context.Context` into `WaitN`. Never apply
a shared byte-bucket to a latency-sensitive UDP path (see §9).

---

## 6. Admin API — `server/api_router.go`

Everything except `/healthz` sits on one subrouter with `helper.AuthMiddleware` + request logging
(`api_router.go:28-32`). `AuthMiddleware` is HTTP **Basic** with a constant-time compare and a 200 ms failure
delay (`pkg/util/http/server.go:86`, `pkg/util/net/http.go:45-59`) — and it is **open when both user and
password are empty** (`http.go:48`). Single shared credential; no tokens, no roles, no expiry, no CSRF, no rate
limit.

Full endpoint inventory (`api_router.go:35-70`):

| Method | Path | Mutates? |
|---|---|---|
| GET | `/healthz` (no auth, `:28`) | no |
| GET | `/metrics` (only if `enablePrometheus`, `:35-37`) | no |
| GET | `/api/serverinfo` `:42` | no |
| GET | `/api/proxy/{type}` `:43`, `/api/proxy/{type}/{name}` `:44`, `/api/proxies/{name}` `:45` | no |
| GET | `/api/traffic/{name}` `:46` | no |
| GET | `/api/clients` `:47`, `/api/clients/{key}` `:48` | no |
| **DELETE** | `/api/proxies?status=offline` `:49` | **yes** — clears offline *stats* only (`server/http/controller.go:224-232`) |
| GET | `/api/v2/users` `:51`, `/api/v2/system/info` `:52`, `/api/v2/clients` `:54`, `/api/v2/clients/{key}` `:57`, `/api/v2/proxies` `:58`, `/api/v2/proxies/{name}` `:60`, `/api/v2/proxies/{name}/traffic` `:59` | no |
| **POST** | `/api/v2/system/prune?type=…` `:53` | **yes** — same stats prune (`controller_v2.go:93-105`) |
| GET | `/favicon.ico` `:63`, `/static/…` `:64`, `/` → redirect `:68` | no |

**Confirmed: the API cannot create, modify, stop, or restart anything.** The only two mutating routes both call
`clearUselessInfo(0)` on the in-memory stats collector (`pkg/metrics/mem/server.go:113-119`) — they don't even
touch live proxies or the client registry. There is no `POST /api/proxies`, no kick-client, no config reload.
Anything productized must be built as a server plugin (§7) or by editing frps.toml and restarting.

`/api/v2/users` is not a user table — it is a fold over the registry and proxy stats that *invents* user rows from
observed strings (`controller_v2.go:108-141`). frp has no user store.

**Bug worth naming:** when `webServer.pprofEnable = true`, pprof handlers are registered directly on the **root**
router inside `NewServer` (`pkg/util/http/server.go:74-76, 124-130`), *before* `RouteRegister` installs the
auth-bearing subrouter (`server.go:116-122`, `api_router.go:29-31`). gorilla/mux matches in registration order,
so `/debug/pprof/*` is served **unauthenticated**, including `/debug/pprof/cmdline` (argv) and heap dumps.

---

## 7. Server plugin hooks — `doc/server_plugin.md` + `pkg/plugin/server/`

Six ops, string constants at `pkg/plugin/server/plugin.go:24-29`: `Login`, `NewProxy`, `CloseProxy`, `Ping`,
`NewWorkConn`, `NewUserConn`. `APIVersion = "0.1.0"` (`plugin.go:22`). Transport is JSON over HTTP POST to
`{addr}{path}?version=&op=` with an `X-Frp-Reqid` trace header (`http.go:85-108`, doc `server_plugin.md:22-36`).
Response is `{reject, reject_reason, unchange, content}` (`types.go:27-32`); non-200 ⇒ hard failure
(`http.go:106-108`, doc `:40`).

`Manager` keeps one slice per op (`manager.go:27-34`, `Register` at `:108-127`) and runs them **sequentially,
chaining mutations**: `handleMutableContent` feeds each plugin's returned `*T` into the next
(`manager.go:70-106`). `res.Reject` aborts with the plugin's reason (`manager.go:96-98`); a transport error
aborts with a generic message (`manager.go:92-95`). Note the deliberate landmine at `manager.go:99-103`:
`content = retContent.(*T)` will **panic** on a malformed plugin response — commented as "by design".
`CloseProxy` is the odd one out: fan-out, errors collected, **never rejectable** (`manager.go:137-157`).

**What they can mutate.** Whatever is in the content struct, because `res.Content` is unmarshalled into a fresh
`*T` of the request type (`http.go:77-82`). So:
- `LoginContent` = `msg.Login` + `ClientAddress` (`types.go:34-38`) → a plugin **can rewrite `User`, `Metas`,
  `RunID`, `ClientID`, `PoolCount`, even `PrivilegeKey`** before verification, since the hook runs *before*
  `RegisterControl`/`VerifyLogin` (`server/service.go:456-473` → `service.go:807`). This is the single most
  powerful extension point in frp: it is where you implement a real user database.
- `NewProxyContent` = `UserInfo{User,Metas,RunID}` + `msg.NewProxy` (`types.go:46-49`) → can rewrite
  `RemotePort`, `CustomDomains`, `SubDomain`, `BandwidthLimit`/`Mode`, `Sk`, `Group`. This is where per-tenant
  port/quota/bandwidth policy actually lives today.
- `PingContent`, `NewWorkConnContent` (`types.go:56-64`) → mutable but mostly used to reject.
- `NewUserConnContent` = `{User, ProxyName, ProxyType, RemoteAddr}` (`types.go:66-71`) — **no connection object,
  no way to inject bytes**; it can only allow or reject, and only for `tcp/stcp/https/tcpmux`
  (doc `server_plugin.md:200`). It is logged at Info rather than Warn because it is expected to fire per
  connection (`manager.go:167-169`).

**What they cannot do:** no async/push direction (frps only ever calls out), no access to the data stream, no way
to create or tear down a proxy on their own, no `NewVisitorConn` hook, and one blocking HTTP round-trip is
inserted into the **per-connection accept path** for `NewUserConn` — the doc itself warns about `CloseProxy`
resource exhaustion (`server_plugin.md:145-146`). `httpPlugin` uses a bare `&http.Client{}` with **no timeout**
(`http.go:43-51`); a hung plugin wedges logins.

**Verdict: ADOPT the concept, ADAPT the wiring.** The reject/unchange/replace tri-state contract is excellent and
should be kept verbatim. Fix: mandatory timeouts, `errors.As`-style typed decode instead of a panicking type
assertion, an async event *egress* channel, and a `NewUserConn` variant that can attach metadata to the
connection (so the relay can do application-layer auth — see §10).

---

## 8. SSH tunnel gateway — `pkg/ssh/` + `doc/ssh_tunnel_gateway.md`

`ssh -R :80:127.0.0.1:8080 v0@relay -p 2200 tcp --proxy_name x --remote_port 9090` with **no frpc**
(doc `:51`, `:63`). Mechanism, precisely:

1. `Gateway` runs a `golang.org/x/crypto/ssh` server on `sshTunnelGateway.bindPort`
   (`gateway.go:93-102`). Host key from `privateKeyFile`, else read/generated at `autoGenPrivateKeyPath`
   (`gateway.go:52-72`). `NoClientAuth = (authorizedKeysFile == "")` (`gateway.go:74`) — **default is no auth**,
   which the doc flags as a risk (`ssh_tunnel_gateway.md:144-148`). `PublicKeyCallback` re-reads and re-parses
   the whole authorized_keys file **on every handshake** (`gateway.go:75-91`) and maps the key **comment** to a
   username (`gateway.go:143`) — that comment becomes `clientCfg.User` (`server.go:116-118`), i.e. tenancy is
   derived from a free-text comment field.
2. `TunnelServer.Run` waits ≤3 s for both a `tcpip-forward` global request (RFC 4254) and an `exec` payload
   carrying the CLI args (`server.go:98`, `waitForwardAddrAndExtraPayload` at `:200-255`,
   `parseExecPayload` at `:330-336`).
3. Those args are parsed by a **real cobra command** built from the same flag registrars frpc uses
   (`server.go:257-300`, `config.RegisterProxyFlags(cmd, pc, config.WithSSHMode())`), which is why `--help` works
   over SSH (`server.go:104-108`).
4. It then instantiates an **in-process virtual frpc** — `virtual.NewClient` with
   `ClientSpec{Type:"ssh-tunnel", AlwaysAuthPass: !NoClientAuth}` (`server.go:121-140`) — whose peer listener is
   spliced into the server's `InternalListener` (`server.go:147-156`). Work conns are joined to freshly opened
   `forwarded-tcpip` SSH channels via `libio.Join` (`server.go:129-139`, `openConn` at `:355-371`).
5. Status is polled from the virtual client's `StatusExporter` for 1 s and a human-readable banner written back
   to the SSH channel (`server.go:175-182`, `waitProxyStatusReady` at `:373-401`).

Costs and sharp edges: only `tcp/http/https/tcpmux/stcp` (`server.go:271`) — **no UDP**, which rules it out for
S1 media; a 30 s in-band `heartbeat` channel request replaces frp's heartbeat (`server.go:338-353`); rotating the
host key breaks every client's `known_hosts` (doc `:132`); and it drags the entire frpc client stack + cobra into
the server binary.

**Verdict: ADOPT, enthusiastically, for S2.** This is the closest thing in either upstream to "zero client
software", and the factory-robot scenario is exactly where it pays: an on-site engineer with only OpenSSH can
expose a device in one line, and pubkey enrolment doubles as device identity. Keep it as a **provisioning and
break-glass path**, not the media path. Concrete asks: replace file-comment usernames with a real key→tenant
table; support `-L`/`-D` too; publish an `authorized_keys` management API.

---

## 9. Metrics and the missing push channel

Two collectors behind one interface (`server/metrics/metrics.go:7-16`, no-op default at `:18-37`), aggregated
(`pkg/metrics/aggregate/server.go`). Prometheus exposes exactly six series under
`namespace/server_subsystem` (`pkg/metrics/prometheus/server.go:59-96`): `client_counts` (gauge, no labels),
`proxy_counts{type}`, `proxy_counts_detailed{type,name}`, `connection_counts{name,type}`,
`traffic_in{name,type}`, `traffic_out{name,type}`. Served at `/metrics` behind Basic auth, only when
`enablePrometheus` (`api_router.go:35-37`).

Note the deliberate label drop: `NewProxy(name, proxyType, user, clientID)` in the interface, but the Prometheus
impl **discards `user` and `clientID`** (`prometheus/server.go:33-36`, `func (m *serverMetrics) NewProxy(name,
proxyType string, _ string, _ string)`), so **per-tenant traffic accounting is impossible from `/metrics`** — you
must scrape the JSON API and join on `mem.ProxyStats.User`/`.ClientID`. And `proxy_counts_detailed{name}` is
unbounded-cardinality by design.

**Confirmed absent: any push.** `grep -rn "text/event-stream|EventSource|Flusher"` over `server/` and
`pkg/util/http/` returns nothing; `gorilla/websocket` appears only in `test/e2e/**`. The `websocketListener` in
`server/service.go:93-94, 288-293, 388` is a *tunnel transport* for frpc control connections
(`GET ` + `FrpWebsocketPath`), not an admin event stream. A console therefore has to poll `/api/v2/clients` —
which is O(clients × proxies) per call, because `buildV2ClientStatus` rescans **all** proxy stats for every
client (`controller_v2.go:520-536`). At 500 devices that is quadratic per dashboard refresh.

**Verdict: ADAPT metrics (add tenant labels), and treat the push gap as the headline product opportunity.**

---

## 10. Concrete design for the new Go relay

### 10.1 Identity: server-issued, three credential classes

```go
// Device credentials are issued, never asserted.
type Device struct {
    ID        string    // ULID, server-issued, immutable — the addressing key
    TenantID  string
    Name      string    // human label, per-tenant unique, renameable
    PubKey    ed25519.PublicKey // enrolled once; also usable as SSH authorized_key
    Revoked   bool
}
```

- **Device auth = mTLS or ed25519 challenge–response.** Server sends a 32-byte random nonce in a `ServerHello`;
  device returns `ed25519.Sign(priv, nonce || tenantID || deviceID)`. This kills the replay window that
  `GetAuthKey(token, timestamp)` leaves open (`pkg/util/util/util.go:50-56`) with zero extra round-trips versus
  frp's timestamp scheme. Keep `tokenSource`-style `ValueSource` (`pkg/config/v1/value_source.go:28-49`) for
  bootstrap secrets, but **watch the file** (`fsnotify`) instead of resolving once (`auth.go:105-111`).
- **Machine API tokens** — the gap the reports flag. `relay_pat_<ulid>_<32B base64url>`, stored as
  `argon2id` hash, with `scopes []string`, `tenant_id`, `expires_at`, `last_used_at`. Verify with
  `subtle.ConstantTimeCompare` on the hash. Bearer header, not Basic; Basic-with-empty-password-means-open
  (`pkg/util/net/http.go:48`) must never be reproduced.
- **Human console auth** — short-lived signed session cookie (`SameSite=Strict`) + per-tenant RBAC
  (`owner|admin|operator|viewer`). Every handler takes `(tenant, subject, scopes)` from middleware; no handler
  reads a tenant string from the request body.

`TenantID` is derived from the verified credential and **stamped server-side**. Delete the string-prefix
convention (`pkg/naming/names.go:6-11`) entirely; key every map by a struct, e.g.
`map[TenantScopedName]*Proxy` where `type TenantScopedName struct{ Tenant, Name string }` — this alone closes the
`PxyManager.Add(pxyMsg.ProxyName, …)` squatting hole (`server/control.go:886`).

### 10.2 Addressing: names, not port conventions

S2's "relay IP + port" constraint is real, but it should be an *output* of the model, not the model. Store
`Endpoint{TenantID, DeviceID, ServiceName, Proto, RelayPort}` in the DB, allocate `RelayPort` from a per-tenant
range, and expose it as `wss://relay/t/{tenant}/d/{device}/s/{api}` for S1 (name-addressed, TLS-terminated) while
the same row also yields a bare `relay:PORT` for the robot in S2. Bare ports must be **default-deny**: an
`Endpoint` gets an application-layer gate — allowed source CIDRs, an optional per-endpoint bearer token checked
before the first byte is forwarded, and `max_concurrent_conns`. frp cannot do this because `NewUserConn` sees only
`RemoteAddr` and cannot touch the stream (`pkg/plugin/server/types.go:66-71`).

### 10.3 Quota: one record, enforced in one place

```go
type Quota struct {
    TenantID          string
    PortRanges        []PortRange // per-tenant, unlike frp's single global AllowPorts (service.go:174-175)
    MaxDevices        int
    MaxEndpoints      int
    MaxPortsPerDevice int         // frp's MaxPortsPerClient (control.go:851-869), scoped properly
    MaxConnsPerEndpoint int
    IngressBytesPerMonth int64
    RateUp, RateDown  int64       // separate buckets, server-enforced, non-negotiable
}
```

Port allocator: keep frp's reservation-with-TTL (`ports.go:100-108`, `:189-215`) and typed errors
(`ports.go:23-27`); replace the 5-sample random scan (`ports.go:112-124`) with a per-tenant
`math/bits`-backed bitmap and a rotating cursor; **stop bind-probing under the mutex** (`ports.go:91-97`,
`:155-175`) — bind lazily and surface `EADDRINUSE` as a proxy-start error instead. Rate limiting:
`golang.org/x/time/rate` is still the right tool in 2026, but one limiter per direction per level
(tenant → device → endpoint), and always `WaitN(ctx, …)` with a real ctx, never
`context.Background()` (`pkg/util/limit/reader.go:46`).

### 10.4 UDP for S1 — do not copy frp

frp funnels **all** UDP packets for a proxy through a single re-framed work conn
(`server/proxy/udp.go:205-236`: encryption → compression → rate limiter → `msg.NewUDPPacketReadWriter` on one
`workConn`). For A/V that means head-of-line blocking, TCP-over-TCP if the tunnel is TCP, and a byte-bucket in the
media path. Instead: a dedicated QUIC datagram (RFC 9221) or plain-UDP session per endpoint, per-flow 5-tuple NAT
state with an LRU, no compression, and pacing rather than a shared token bucket. `quic-go` is already a dependency
(`go.mod:24`) — reuse it rather than inventing framing.

### 10.5 Control plane: push first

Replace polling with `GET /api/v1/events` as SSE (stdlib `http.ResponseController.Flush` in Go 1.20+; no
dependency needed) carrying `device.online/offline`, `endpoint.up/down`, `quota.exceeded`, `traffic.tick`.
Back it with a per-tenant fan-out hub with **bounded per-subscriber buffers and drop-oldest** semantics plus a
`Last-Event-ID` resume cursor. Add WebSocket only if the console needs a request/response channel. Fix the
quadratic status build (`controller_v2.go:520-536`) by maintaining `deviceID → []endpoint` indices in the
registry rather than rescanning.

Registry: keep `ClientInfo`'s shape (`registry.go:26-40`) and the `ControlID` generation guard
(`registry.go:71-73`, `control.go:246-259`) — that guard is subtle and correct, and a naive reimplementation will
get it wrong. But persist to SQLite/Postgres, make offline detection **explicit** (an application heartbeat with a
real timeout — never default `HeartbeatTimeout = -1` as `pkg/config/v1/server.go:189` does), add
`last_seen_at` + a `stale` state distinct from `offline`, and add a prune job for the offline entries frp leaks
(`registry.go:157-161`).

Admin API: full CRUD (`POST/PATCH/DELETE` on tenants, devices, endpoints, quotas, tokens), `POST
/devices/{id}:kick`, `POST /config:reload`, an append-only audit log of every mutation with `(subject, tenant,
before, after)`, and per-token rate limits. Keep the plugin hook contract (`{reject, unchange, content}`,
`pkg/plugin/server/types.go:27-32`) as the *external* policy escape hatch — with a mandatory client timeout, which
`pkg/plugin/server/http.go:43-51` conspicuously lacks.
