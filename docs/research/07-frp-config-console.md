# Dossier 07 — frp's Configuration System and Web Console: Productization Lessons

Source tree: `/mnt/hgfs/share/net-infra/frp` (module `github.com/fatedier/frp`, `go 1.25.0`, `go.mod:3`).
All line numbers are from that checkout. Judgement column: **ADOPT / ADAPT / DROP** against
S1 (phone → HTTP+WS+UDP on home-NAT desktop) and S2 (robot → relay IP:port → designated desktop).

---

## 1. The versioned config model — versioned in name only

`pkg/config/v1/api.go:17-19` is the entire "API versioning" story:

```go
type APIMetadata struct {
    Version string `json:"version"`
}
```

It is embedded into `ClientCommonConfig` (`pkg/config/v1/client.go:33`) and `ServerConfig`
(`pkg/config/v1/server.go:25`). **Nothing ever reads it.** A grep across `pkg/config/`, `cmd/`,
`client/`, `server/` for a consumer of that field finds only the two declarations. So a user who
writes `version = "v2"` gets no error, no warning, no behavioural change. frp's config is not
versioned; it merely has a field named `version` that is accepted and discarded. The real "v1" is a
Go package name, and the migration story is one-way INI→v1 conversion (§5).

The shape is a polymorphic document. `ClientConfig` (`client.go:25-30`) is common config plus
`[]TypedProxyConfig` / `[]TypedVisitorConfig`. `TypedProxyConfig` (`proxy.go:196-214`) hand-rolls
`UnmarshalJSON`/`MarshalJSON`, dispatching on a `type` discriminator through a registry
(`NewProxyConfigurerByType`, `proxy.go:252`). The decoder in `pkg/config/v1/decode.go` peels a
`typedEnvelope{Type, Plugin}` (`decode.go:39-42`), instantiates the concrete struct, then decodes
twice — once for the proxy, once for the nested plugin options (`decode.go:44-70`). Errors are
indexed: `decode proxy at index %d` (`decode.go:175`).

Defaults are `Complete()` methods, not struct tags:

| Site | Defaults applied |
|---|---|
| `client.go:85-100` | `serverAddr=0.0.0.0`, `serverPort=7000`, `loginFailExit=true`, `natHoleStunServer=stun.easyvoip.com:3478`, `udpPacketSize=1500` |
| `client.go:147-166` | `protocol=tcp`, `wireProtocol=v1`, `dialServerTimeout=10`, `keepAlive=7200`, `poolCount=1`, `tcpMux=true`; **heartbeat becomes -1/-1 when tcpMux is on**, else 30/90 |
| `client.go:182-185` | `tls.enable=true`, `disableCustomTLSFirstByte=true` |
| `proxy.go:154-161` | `localIP=127.0.0.1`, `bandwidthLimitMode=client` |
| `common.go:71-73` | `webServer.addr=127.0.0.1` — **but `server.go:117` overrides it to `0.0.0.0` when port>0** |

The `Complete()` pattern is genuinely good: `util.EmptyOr` + `*bool` for tri-state booleans means
"unset" is distinguishable from "false", which is what lets `Enabled *bool` (`proxy.go:124`, nil or
true = enabled) coexist with the global `start` allowlist. **ADOPT** the `*bool` tri-state and the
explicit `Complete()`/`Validate()` split. **DROP** the un-enforced `version` field — either version
the document for real (reject unknown majors, run migrators) or omit it.

Validation lives in `pkg/config/v1/validation/`, ~1444 lines. It is split client-side
(`ValidateProxyConfigurerForClient`, `proxy.go:102-120`) vs server-side
(`validateProxyBaseConfigForServer`, `proxy.go:67-72`) — a real distinction worth copying, because
the client can check `localPort` but only the server can check `allowPorts`/`subDomainHost`
(`proxy.go:81-100`). Errors accumulate via `errors.Join` (`validation.go:67-72`) so one run reports
every problem, and `Warning` is a distinct type from `error` (`validation.go:65`). **ADOPT both.**

Adversarial: `validateWebServerConfig` (`validation/common.go:24-35`) validates only TLS file
presence and port range. It never requires `user`/`password`. See §7 for why that is a hole.

---

## 2. Loading: env templating, format sniffing, includes

`pkg/config/load.go` is 538 lines and does four things.

**Env templating.** `init()` snapshots `os.Environ()` into `glbEnvs` (`load.go:43-53`), exposed to
`text/template` as `.Envs` (`load.go:55-63, 84-98`). Two custom funcs, `parseNumberRange` and
`parseNumberRangePair` (`template.go:28-52`), enable the port-range idiom documented at
`README.md:1237-1244`:

```
{{- range $_, $v := parseNumberRangePair "6000-6006,6007" "6000-6006,6007" }}
[[proxies]]
name = "tcp-{{ $v.First }}"
...
{{- end }}
```

This is the single highest-leverage config feature in frp. It also has two flaws: the env map is a
**process-start snapshot** (never refreshed on reload, `load.go:43`), and rendering happens before
parsing, so a template typo yields a template error with no config context.
**ADOPT** templating (`text/template` from stdlib, zero cost) but re-read env on each reload.

**Format sniffing.** `LoadConfigure` (`load.go:176-217`) attempts **TOML first for every buffer**
(`load.go:186`) regardless of file extension; on success it round-trips TOML→`any`→JSON
(`load.go:190`) and then decodes JSON. If the buffer looks like JSON (`yaml.IsJSONBuffer`,
`load.go:200`) it decodes directly. Otherwise YAML. The extension hint from
`detectFormatFromPath` (`load.go:117-128`) is used only to decide whether a TOML parse failure
should be reported as an error (`load.go:194-197`) rather than silently falling through to YAML.
Net effect: **one internal representation (JSON) and three surface syntaxes** — a good trick worth
stealing, since it means only one decoder needs to be correct.

The strict YAML path is a hack: `parseYAMLWithDotFieldsHandling` (`load.go:132-153`) unmarshals to
`any`, **deletes every top-level key starting with `.`** to allow YAML-anchor scratch space, then
re-marshals to JSON and decodes with `DisallowUnknownFields`. Line numbers in strict mode are then
recovered by `findFieldLineInContent` (`load.go:250-276`) — a **substring grep** for the last
component of the field path, matching `key =` or `[[key]]`. It is a heuristic that will point at
the wrong line whenever a name repeats. **DROP** this; see §9 for the fix.

**Includes.** `includes = ["./confd/*.toml"]` (`client.go:79`, `README.md:540`) is handled by
`LoadAdditionalClientConfigs` (`load.go:502-537`). Concrete limitations, all citable:

1. Non-recursive. It does `os.ReadDir(filepath.Abs(filepath.Dir(path)))` and `filepath.Match` on the
   basename (`load.go:513, 522`). `**` is not supported; subdirectories are skipped (`load.go:518-520`).
2. **Only `Proxies` and `Visitors` are consumed from included files** (`load.go:528-533`). If a user
   puts `serverAddr = "1.2.3.4"` in an included file, it parses fine, passes strict mode (it is a
   *known* field), and is **silently discarded**. This is a first-class footgun.
3. `includes` inside an included file is ignored — no transitive includes.
4. A missing include directory is a hard error (`load.go:510-512`), so `includes` cannot be optional.
5. Legacy INI takes a completely different path (`load.go:380-388`).

Duplicate names are rejected (`validateNoDuplicateNames`, `load.go:427-447`) with an explicit comment
that entries are keyed by name and a dup would otherwise be silently dropped. Post-load filtering is
`FilterClientConfigurers` (`load.go:465-500`): the global `start` allowlist first, then per-entry
`enabled`. `conf/frpc_full_example.toml:148-158` documents that `start` is applied *after* config and
store are merged — a subtle interaction the new tool should avoid having at all.

**Verdict for S1/S2:** ADOPT env templating + single-IR multi-syntax. ADAPT includes into a proper
recursive glob that merges *whole documents* with explicit precedence, not just proxy arrays. For S2
(a robot with a fixed relay IP:port) the important consequence is that the relay's own config must be
declarative and reloadable without dropping live sessions.

---

## 3. Store mode — the runtime CRUD API, and its exact storage format

This is frp's most interesting productization move and the closest thing to a console-first model.

Enable by setting one field (`pkg/config/v1/store.go:18-25`, `client.go:82`):

```toml
[store]
path = "./db.json"
```

`IsEnabled()` is literally `Path != ""` (`store.go:24-26`). `README.md:601-612` is the only prose
documentation; **`conf/frpc_full_example.toml` never mentions `[store]`** — a whole runtime API is
absent from the reference config.

**Source model.** `pkg/config/source/` defines `Source.Load()` (`source.go:25-37`) and an
`Aggregator` that merges a base `ConfigSource` (from the file) with an optional `StoreSource`
overlay, keyed by name, **store wins on conflict** (`aggregator.go:59-96`). The contract comment at
`source.go:28-30` is precise and worth quoting in our own design: *"A disabled entry in one source is
source-local filtering, not a cross-source tombstone for entries from lower-priority sources."*

**On-disk format** (`source/store.go:31-34, 125-178`) is JSON with two arrays, written via
`MarshalIndent` into `path + ".tmp"` at mode `0o600`, `Sync()`ed, then `os.Rename`d — proper
atomic-replace. Because `TypedProxyConfig.MarshalJSON` emits the configurer directly
(`v1/proxy.go:212-214`), entries are **flat**, mirroring the config-file shape:

```json
{
  "proxies": [
    { "name": "ssh", "type": "tcp", "localIP": "127.0.0.1", "localPort": 22, "remotePort": 6000 }
  ],
  "visitors": []
}
```

Two defects: the arrays are built by iterating a Go **map** (`store.go:131-136`), so element order is
**nondeterministic across saves** — the file churns on every write, which is hostile to git/backup
diffing. And restore decodes with `DisallowUnknownFields: false` (`store.go:96-97, 110-111`), so a
hand-edited store file with a typo'd key loads silently with that setting dropped.

**Mutation semantics.** `addStoreEntry`/`updateStoreEntry`/`removeStoreEntry`
(`store.go:199-265`) mutate the in-memory map first, then persist, and **roll back the map if the
write fails** (`persistOrRollbackUnlocked`, `store.go:180-186`). Sentinels `ErrAlreadyExists` /
`ErrNotFound` (`store.go:41-44`) map to HTTP 409/404 upstream. **ADOPT this whole pattern** — it is
the cheapest correct way to keep RAM and disk agreed without a database.

**Endpoints** (`client/api_router.go:44-55`, registered only when `svr.storeSource != nil`):

```
GET    /api/store/proxies              -> {"proxies":[ProxyDefinition...]}   (sorted by name)
POST   /api/store/proxies              <- ProxyDefinition -> 201-ish body echo
GET    /api/store/proxies/{name}
PUT    /api/store/proxies/{name}       (name in URL must equal name in body)
DELETE /api/store/proxies/{name}
GET|POST /api/store/visitors , GET|PUT|DELETE /api/store/visitors/{name}
```

Each write is *validate → persist → reload the whole config from sources → return the persisted
clone*: `withStoreProxyMutationAndReload` (`client/config_manager.go:390-414`) calls
`reloadConfigFromSourcesLocked()` inside `reloadMu`, then re-reads and `Clone()`s the entry so the
caller sees exactly what was stored. Validation is `Clone → Complete → ValidateProxyConfigurerForClient`
(`config_manager.go:442-452`) — **client-side only**: a `remotePort` outside the relay's
`allowPorts`, or a duplicate `remotePort`, is accepted by the store API and only fails later at
server registration, surfacing as a proxy in `error` phase rather than a 400 on the write.

**The wire shape diverges from the file shape.** The REST payload is `model.ProxyDefinition`
(`client/http/model/proxy_definition.go:10-22`): `{name, type, tcp?, udp?, http?, ...}` with the
type-specific fields **nested under a per-type key**, validated to have exactly one block matching
`type` (`proxy_definition.go:24-43`). So the same logical object has two representations — flat in
both the config file and the store file, nested in the API. The frontend then has to unwrap it
(`web/frpc/src/stores/proxy.ts:82-100`, `const block = (def as any)[def.type]`, complete with `any`
casts). **DROP the dual shape.** One canonical JSON shape for file, store, API, and UI.

**Verdict:** **ADOPT store mode aggressively.** For S2 the console *is* the interface — a factory
operator configures "robot at relay:8443 → desktop-A" from a browser, and that must survive a relay
restart with no file editing. For S1 the phone-side developer wants the same for HTTP/WS/UDP
endpoints. But validate server-side constraints at write time, and unify the shapes.

---

## 4. The rest of the client API

`client/api_router.go:26-64`. `/healthz` is registered **before** the auth subrouter and is
unauthenticated (`:30`); everything else goes through `helper.AuthMiddleware` and a request logger
(`:33-35`).

- `GET /api/reload?strictConfig=<bool>` (`:36`) → `ReloadFromFile` (`config_manager.go:26-54`):
  load file → `FilterClientConfigurers` → `Complete*` → `ValidateAllClientConfig` → `UpdateConfigSource`.
  Validation happens **before** anything is applied. Good. Note the verb is **GET** for a mutating
  operation — a CSRF-shaped smell.
- `POST /api/stop` (`:37`) → `GracefulClose(100ms)` in a goroutine (`controller.go:85-88`).
- `GET /api/status` (`:38`) → `map[proxyType][]ProxyStatusResp` sorted by name
  (`controller.go:91-111`); each entry is `{name,type,status,err,local_addr,plugin,remote_addr,source}`
  (`client/http/model/types.go:23-32`), with `source:"store"` tagging store-managed entries
  (`controller.go:159-162`). `remote_addr` is string-concatenated as `serverAddr + ":port"` for
  tcp/udp (`controller.go:152-157`) — no structured host/port.
- `GET /api/config` (`:39`) returns the **raw file text** (`controller.go:114-120`).
- `PUT /api/config` (`:40`) → `WriteConfigFile` = `os.WriteFile(path, body, 0o600)` with
  **no parse, no validation, no backup** (`config_manager.go:68-77`). The frpc UI then calls reload
  (`web/frpc/src/views/ClientConfigure.vue:91-92`). So a syntactically broken paste is **persisted to
  disk**, reload fails with a toast, and the next process start fails outright. This is the single
  worst productization bug in the codebase and is trivially avoidable.
- `GET /api/proxy/{name}/config` and `/api/visitor/{name}/config` (`:41-42`) read from the running
  proxy manager first, falling back to the store (`config_manager.go:83-123`).

Error→status mapping is centralized in `toHTTPError` (`client/http/controller.go:53-68`):
`ErrInvalidArgument`→400, `ErrNotFound`/`ErrStoreDisabled`→404, `ErrConflict`→409, else 500.
**ADOPT** the sentinel-error → HTTP-code table; it keeps handlers dumb.

Same API drives the CLI: `frpc reload|status|stop` (`cmd/frpc/sub/admin.go:34-49`) talk to the web
port with Basic auth (`admin.go:75-85`), which is why `webServer.port` must be set for the CLI to
work (`admin.go:62-65`). **ADOPT**: one API, consumed by both console and CLI. `frpc verify`
(`cmd/frpc/sub/verify.go:44-62`) validates without starting. **ADOPT.**

---

## 5. Migration path: one-way, and unfinished

`pkg/config/legacy/` is ~1827 lines: an INI parser plus `Convert_ClientCommonConf_To_v1`,
`Convert_ServerCommonConf_To_v1`, `Convert_ProxyConf_To_v1`, `Convert_VisitorConf_To_v1`
(`legacy/conversion.go:26+`). Detection is a sniff for an INI `[common]` section
(`load.go:65-74`), branching at `load.go:301-317` (server) and `load.go:352-364` (client). There is
**no v1→vNext machinery at all** — no migrator registry, no `frpc migrate` command, no schema
registry. `doc/deprecations.md:17-25` lists the INI format as deprecated with **"Removal target:
TBD"**, and `doc/deprecations.md:36-37` says *"Removed: None yet."* The deprecation doc itself is the
best artifact here: a per-item table of *deprecated since / removal target / replacement / code
references / notes*. **ADOPT the doc discipline; DROP the "convert-only" approach** — build a real
`migrate` command with a versioned schema from day one, because retrofitting is what left frp with
1827 lines of dead-end INI code.

---

## 6. The dashboards: what they actually show and let you do

`web/` is an npm workspace of `shared`, `frpc`, `frps` (`web/package.json:4`). Stack: Vue 3.5,
vue-router 5, element-plus 2.14, Vite 7, vitest 4; pinia only in frpc
(`web/frps/package.json:15-40`, `web/frpc/package.json:15-41`). Hash-history routing in both.

### frps (relay) console — read-only telemetry

Router: 5 routes (`web/frps/src/router/index.ts:13-39`) — `/`, `/clients`, `/clients/:key`,
`/proxies/:type?`, `/proxy/:name`. Sidebar has exactly three links: Overview, Clients, Proxies
(`App.vue:54-83`), plus a GitHub link and a dark-mode switch (`App.vue:22-38`).

- **Overview** (`ServerOverview.vue`): four stat cards — Clients, Proxies, Connections, Traffic today
  (`:3-38`); an inbound/outbound totals card (`:40-75`); a proxy-type count grid (`:76-99`); and a
  "Server Configuration" read-only grid of `bindPort, kcpBindPort, quicBindPort, vhostHTTPPort,
  vhostHTTPSPort, tcpmuxHTTPConnectPort, subdomainHost, maxPoolCount, maxPortsPerClient, allowPorts,
  tlsForce, heartbeatTimeout` (`:102-159`). **It fetches once in `onMounted` and never refreshes**
  (`:232-234`).
- **Clients** (`Clients.vue`): all/online/offline tabs, debounced search, card list, pagination;
  **5-second `setInterval` auto-refresh** (`:163-167, 189-192`) — the only live screen.
- **Proxies** (`Proxies.vue`): search, type tabs, a manual **Refresh** button (`:11-13`), a
  **Clear Offline** destructive action (`:15-17`), pagination. No auto-refresh. The tab list is
  `all,tcp,udp,http,https,tcpmux,stcp,xtcp` (`:112-120`) — **`sudp` is missing**, so SUDP proxies are
  only reachable via the "all" tab even though `SUDPProxy` is imported at `:98`.
- **ProxyDetail** (`ProxyDetail.vue`): a "Configuration" section limited to Encryption, Compression,
  Custom Domains, Subdomain, Locations, Host Rewrite, Multiplexer, Route-By-HTTP-User (`:96-190`) —
  no bandwidth limit, no health check, no plugin, no annotations. Plus "Traffic Statistics" (`:207`)
  rendered by `Traffic.vue`, a **hand-rolled CSS `<div>` bar chart** with day granularity and a
  3-tick y-axis (`Traffic.vue:1-50`), fed by `/api/v2/proxies/{name}/traffic`.

Backend surface (`server/api_router.go:42-60`): v1 `/api/serverinfo`, `/api/proxy/{type}[/{name}]`,
`/api/proxies/{name}`, `/api/traffic/{name}`, `/api/clients[/{key}]`; v2 `/api/v2/{users,
system/info, system/prune, clients, clients/{key}, proxies, proxies/{name},
proxies/{name}/traffic}`. v2 wraps everything in `{code,msg,data}` and **always returns HTTP 200 on
success** (`pkg/util/http/handler.go:29-33, 75-96`) — dual-protocol drift the frontend has to
handle with two client functions, `request` and `requestV2` (`web/frps/src/api/http.ts:29-82`).

**The relay console has exactly one mutating capability**: `DELETE /api/proxies?status=offline`, which
clears offline stats (`server/http/controller.go:224-232`). There is **no reload, no config read,
no config write, no proxy CRUD, no client kick, no token rotation, no log view** on the relay side.

### frpc (agent) console — the CRUD half

Routes (`web/frpc/src/router/index.ts:14-68`): `/proxies`, `/proxies/detail/:name`,
`/proxies/create`, `/proxies/:name/edit`, the same four for visitors, and `/config`. A router guard
checks `requiresStore` and, if the store is off, toasts *"Store is disabled. Enable Store in frpc
config to create or edit store entries."* and redirects (`:71-86`). `ProxyList.vue` has Status | Store
tabs; the Store tab, when disabled, prints a TOML snippet for the user to paste into their config
(`ProxyList.vue:70-74`) — a dead end in a GUI. The proxy form is decomposed into 11 section
components (`web/frpc/src/components/proxy-form/*.vue`), which is the right shape for a
469-line-config surface (`conf/frpc_full_example.toml`).

`/config` (`ClientConfigure.vue`) is a bare `<el-input type="textarea">` holding the raw config text
with an "Update & Reload" button (`:25-36, 79-100`). No syntax highlighting, no linting, no schema
help, no diff preview, no backup, no rollback — and, per §4, no server-side validation before the
write lands on disk.

### Asset embedding and serving

`web/frps/embed.go:1-16`: `//go:build !noweb`, `//go:embed dist`, and an `init()` that calls
`assets.Register(EmbedFS)`, which does `fs.Sub(fs, "dist")` (`assets/assets.go:52-58`).
`assets.Load(path)` picks a disk directory when `webServer.assetsDir` is set, else the embedded FS,
else an `emptyFS` that 404s everything (`assets/assets.go:40-50`). `embed_stub.go` provides the
package under `//go:build noweb`, and `Makefile:4` auto-adds the `noweb` tag when `web/*/dist` is
missing so `go build` works in a fresh clone. Serving: `/favicon.ico`, a gzip-wrapped
`http.FileServer` under `/static/`, and `/` → 301 to `/static/`
(`server/api_router.go:63-70`; identically `client/api_router.go:57-63`).
**ADOPT the embed + `noweb` build-tag + `assetsDir` escape hatch verbatim** — it is clean, and in Go
2026 `embed` + `http.FileServerFS` needs no third-party help. **DROP** the blanket
`MakeHTTPGzipHandler` (`pkg/util/net/http.go:66-82`): it re-gzips already-compressed assets and sets
`Content-Encoding: gzip` unconditionally whenever the client advertises gzip.

---

## 7. Dashboard auth: a hole, not a feature

`pkg/util/http/server.go:86` builds the middleware:

```go
s.authMiddleware = netpkg.NewHTTPAuthMiddleware(cfg.User, cfg.Password).
    SetAuthFailDelay(200 * time.Millisecond).Middleware
```

and `pkg/util/net/http.go:45-60` is HTTP Basic with a constant-time compare and a 200 ms failure
delay. The first clause of the condition (`http.go:48`) is:

```go
if (authMid.user == "" && authMid.passwd == "") || (hasAuth && ...constant-time-equal...)
```

**If both credentials are empty, every request is allowed.** Now compose three facts:
`validateWebServerConfig` never requires credentials (`validation/common.go:24-35`);
`ServerConfig.Complete()` sets `webServer.addr` to **`0.0.0.0`** whenever the port is non-zero
(`server.go:117`); and `README.md:595-599` teaches `webServer.user = "admin"`,
`webServer.password = "admin"`. So `webServer.port = 7500` alone yields an **unauthenticated
dashboard on all interfaces**, and following the docs yields admin/admin.

Everything else is downstream of Basic auth: no login page, no session, no cookie, no token, no
logout, no CSRF token, no rate limit beyond the 200 ms sleep, no audit log (only
`log.Infof("http request: [%s]", path)` in `pkg/util/http/middleware.go:33-39`), no RBAC, no
multi-user. The frontend just sets `credentials: 'include'` and relies on the browser's Basic dialog
(`web/frps/src/api/http.ts:30-32`). **DROP all of it.**

---

## 8. Enumerated UX shortcomings of frp's console — the bar to beat

1. **No relay-side write path.** The frps console cannot create, edit, disable, or delete a tunnel;
   only `DELETE /api/proxies?status=offline` mutates anything (`server/http/controller.go:224-232`).
2. **Overview never refreshes** (`ServerOverview.vue:232-234`); Proxies needs a manual click
   (`Proxies.vue:11-13`); only Clients polls, at 5 s (`Clients.vue:163-167`). No WebSocket/SSE
   anywhere — inconsistent liveness across screens.
3. **Traffic history is in-RAM and lost on restart**: `ReserveDays = 7`
   (`pkg/metrics/mem/types.go:24`), confirmed by `README.md:616`.
4. **No latency, jitter, loss, or RTT anywhere.** The entire telemetry vocabulary is bytes and
   connection counts (`web/frps/src/types/proxy.ts:109-116`). For S1's audio/video this is useless.
5. **No log view, no event timeline, no per-tunnel error history.** `ProxyStatusResp.Err` is a single
   current string (`client/http/model/types.go:27`).
6. **`PUT /api/config` persists unvalidated bytes** (`client/config_manager.go:68-77`), bricking the
   next start; the UI is a raw textarea (`ClientConfigure.vue:25-36`).
7. **Store-disabled dead end**: the GUI tells the user to hand-edit TOML
   (`ProxyList.vue:70-74`; router guard `router/index.ts:82-85`).
8. **Two client console apps, two API dialects.** frps and frpc are separate SPAs; frps mixes v1 raw
   and v2 enveloped responses (`web/frps/src/api/http.ts:29-82`).
9. **Three shapes for one object** — flat in config file, flat in store file, nested-by-type in the
   REST API (`client/http/model/proxy_definition.go:10-22`), forcing `any` casts in the UI
   (`web/frpc/src/stores/proxy.ts:82-100`).
10. **No onboarding.** No first-run wizard, no token generation, no copy-pasteable client snippet, no
    connectivity test, no QR/pairing. A new user must read `README.md` and hand-write TOML.
11. Missing SUDP tab (`Proxies.vue:112-120`). English-only, no i18n. No keyboard/URL-shareable
    filter state on Overview. Hand-rolled CSS bar chart (`Traffic.vue:1-50`).

---

## 9. Recommendations for the new Go relay console

**Primary on-screen object: the Tunnel** — not "proxy", not "client". A Tunnel is
`{id, name, mode, listen, target, protocol, policy, state}` where `mode ∈ {service (S1), reverse (S2)}`,
and it owns its endpoints. The relay is the authoritative store; agents are peers that a Tunnel
references. This inverts frp, where the *client* owns proxy config and the relay is a dumb registry —
which is precisely why frp cannot offer a relay-side write path.

**Information architecture (6 screens):**

1. **Home / Health** — one live tile row (tunnels up/down, active sessions, aggregate throughput,
   **p50/p95 RTT**, loss%), plus a recent-events feed. Live via SSE.
2. **Tunnels** — the CRUD table. Columns: name, mode, protocol chips (HTTP/WS/UDP), public endpoint
   (one-click copy), target agent, state pill, sessions, RTT sparkline, 24 h bytes. Row actions:
   enable/disable, edit, duplicate, **Test** (synthetic probe), delete.
3. **Tunnel detail** — three tabs: *Live* (sessions table, RTT/jitter/loss timeseries, UDP
   pps/reorder), *Config* (form ⟷ YAML toggle over the **same canonical JSON**), *History*
   (state transitions with timestamps and error text, persisted).
4. **Agents / Peers** — per-agent: version, OS, NAT type and STUN result, direct-vs-relayed session
   ratio, last-seen, "regenerate join token", "kick".
5. **Settings** — listeners/ports, TLS/ACME, auth (users, API tokens, expiry), retention, feature
   gates, backup/restore. Every field shows its effective value *and* its source
   (`file` / `console` / `default`).
6. **Diagnostics** — live log tail with filters, a NAT/STUN self-test, a port-reachability checker,
   and a "Download support bundle" (redacted config + last N events + version).

**Onboarding: working tunnel in <2 minutes.** First HTTP request to an unconfigured relay lands on a
setup wizard: (1) create admin user — generate a strong password, refuse empty, never ship
admin/admin; (2) relay shows its public address and generates a **one-line join command** with an
embedded short-lived enrolment token, plus a QR code for the mobile/Tauri path; (3) the console
*waits live* on that screen and flips to "Agent connected" via SSE; (4) pick a template —
"HTTP+WS API", "UDP media", "TCP/SSH" — pre-filling target `127.0.0.1:<port>`; (5) press **Test**:
the relay dials the tunnel end-to-end and reports pass/fail with the exact failing hop. No file
editing on the happy path.

**Config-file-first vs console-first — recommendation: layered, with declared ownership.**
Neither purely. Adopt frp's `Aggregator` idea (`pkg/config/source/aggregator.go:59-96`) but make it
explicit and bidirectional-safe:

- Layer 0: built-in defaults (`Complete()`, per `client.go:85-100`).
- Layer 1: `relay.yaml` — declarative, git-friendly, the only place *infrastructure* lives
  (listeners, TLS, auth backend, retention). **The console renders these read-only** and shows
  "managed by file: /etc/relay/relay.yaml:42".
- Layer 2: the store — the only place *tunnels and agents* live, owned by the console/API, persisted
  as canonical JSON via the temp-file+fsync+rename pattern of `source/store.go:125-178`, but with
  **sorted keys** to fix the map-order churn at `store.go:131-136`.
- Layer 3: environment/flags for secrets only.

An operator who wants GitOps declares tunnels in `relay.yaml`; those become **read-only in the
console with an explicit "file-managed" badge and a "copy to store to edit" action**. Never
round-trip the console's changes back into the user's YAML — that is where every config UI loses
comments and formatting. `GET /api/config` returns the **effective merged config with per-field
provenance**, and `PUT` is replaced by `POST /api/config:validate` + `POST /api/config:apply` so a
broken document can never reach disk (fixing `client/config_manager.go:68-77`).

**Go implementation cost, 2026 stdlib-first:**
- Router: `net/http` + `http.ServeMux` method+wildcard patterns (Go 1.22+) — drop `gorilla/mux`
  (used at `pkg/util/http/server.go:61`).
- Multi-syntax config: keep frp's single-IR trick but reverse the order — parse by extension, never
  sniff. YAML: `sigs.k8s.io/yaml` or `goccy/go-yaml` (which gives real line/column, killing the
  substring guesser at `load.go:250-276`). TOML: `pelletier/go-toml/v2` already yields
  `*toml.DecodeError` with `Position()` (`load.go:220-231`). JSON: `encoding/json/v2` for
  `DisallowUnknownFields`-style strictness without a second decode pass.
- Schema + form generation: emit JSON Schema from the Go structs at build time and drive both
  server-side validation and the console's form widgets from it — eliminating frp's 11 hand-written
  form sections and 1444 lines of hand-rolled validators.
- Live data: SSE over `http.ResponseController.Flush()`; no WebSocket needed for one-way telemetry.
- Assets: `embed` + `http.FileServerFS`, `//go:build noweb` tag and `assetsDir` override, exactly as
  `web/frps/embed.go:11-16` + `assets/assets.go:40-50` + `Makefile:4`.
- Auth: cookie session (`gorilla/securecookie` or plain HMAC) + `golang.org/x/crypto/bcrypt` for the
  admin password + bearer API tokens with expiry; keep the constant-time compare
  (`pkg/util/net/http.go:49-50`) and add real rate limiting instead of a 200 ms sleep.
- Timeseries: SQLite (`modernc.org/sqlite`, CGO-free) with rollups — replaces the volatile 7-day
  in-RAM counters at `pkg/metrics/mem/types.go:24` and is what makes RTT history possible for S1.
