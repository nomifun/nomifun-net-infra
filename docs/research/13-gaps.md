# 13 — Completeness critique: what the architect still lacks

Read in full: 01, 04, 06, 07, 09–12, 14, 15; 02, 03, 05, 08 swept.

## 1. Nobody designed the agent. Fourteen dossiers designed the relay.

The entire agent spec is one parenthesis in 10 §15 — "`nfagent` (carrier + dialer, no SQLite)"; 02 §7 and 09 §5.1 add
only carrier dialing. Absent: config schema; state machine (enrol → register → reconcile → drain → upgrade → revoked);
credential storage and rotation; boot behaviour when the relay is unreachable (01 §8 kills `LoginFailExit=true` with no
replacement); local API; self-update. **Write the agent chapter.**

## 2. Binary layout: 10 §15 is right; 11 and 12 break it

I verified §15's reason: `modernc.org/sqlite@v1.56.0/lib` ships no **mips** port, so a MIPS router builds only a storeless
binary — two binaries beats `relayd/relayc/relayctl`. But 11 line 189 installs `nomifun-relay agent`, a
subcommand that drags the store into MIPS and breaks §15's `go list -deps` gate; and 12 §B6 invents `relayctl backup`,
which also needs it. **Two binaries; backup is an `nfrelay` verb.**

## 3. 12 §A7 violates a binding constraint; §B1/§B5 inherit it

§A7 prescribes pinned Action SHAs, provenance attestation, and **cosign keyless** — which needs CI OIDC, unavailable
with Actions banned. 10 §15 is right (Makefile, `SHA256SUMS`, `make sign`, offline key), yet §B1's installer and §B5's
signed update manifest rest on it. **Pick an offline-key scheme, name where the key lives, state the release ritual** —
including the Windows/macOS signing 12 §B2 calls "the actual cost".

## 4. Who owns a tunnel definition

12 §A5: "the **agent** holds the authoritative target policy… and rejects console-pushed tunnels that violate it." 07
§9 and 11 Part B: the **relay** is authoritative, console-first CRUD. Neither models disagreement. **Relay owns the
Tunnel record, agent owns a target allowlist gating it, add `rejected_by_agent` with a reason** — a state no dossier has.

## 5. 无代理端 is first-class in the UI, designed nowhere, and mostly cannot work

11's onboarding step 3 says it "must not be buried"; nobody designs it (nearest: 08 §1). The relay gains an outbound
dialer, so 12 §A5's SSRF defence loses its host and console compromise
becomes a network pivot — and S2's target is a *NAT'd* desktop, undialable anyway. **Spec that dialer (default-deny
CIDRs, re-resolve each dial); relabel it "target reachable from the relay".**

## 6. Two nomifun-tauri facts nobody carried into the design

**(a) S1 media rests on a false premise.** 04 §4.7 sends A/V to WebRTC + TURN, but
`grep -c webrtc /home/rika/src/nomifun-tauri/Cargo.lock` → **0**, nor `srtp`/`str0m`: the sibling ships Opus over
`tungstenite` WebSocket behind a transport-agnostic seam (`nomifun-robot/src/link.rs:5-6,78-82`). **Decide the S1
client** — browser makes TURN and 11's 媒体中继 real; native/tauri means v1 relays that Opus/WS link and 04 §4.1/§4.3 are
S2-only.
**(b) Passthrough cannot serve a tauri target.** 15 §B4 verifies `desktop.rs:1710-1723` 403s non-IP-literal `Host`
*outside* the router; gateway rewrites it (§B5), passthrough cannot. **Feed target-kind into the chooser.**

## 7. pion/ice is in v1's deps, and drags a permanently-zero metric

10 §16 lists `pion/ice/v4` for "the P2P path", but 09 (header, §4, §6) says "**v1 is relay-only. P2P is deferred**",
`pion/ice` = "Use in v2". 09 is right. Yet 11's 概览 and 代理端 show **direct-vs-relayed ratio**, "the number that predicts
the bandwidth bill" — without our own ICE it reads 0/100 forever. **Drop `pion/ice`; make that metric TURN-only.** 09 §6's
`pion/turn` "Optional" is stale too.

## 8. Tenancy is designed twice, oppositely

06 §10.1–10.3: server-stamped `TenantID`, per-tenant quotas/port ranges, RBAC `owner|admin|operator|viewer`. 11: no
tenant object, no org screen. 12 §A6: one admin. This decides the schema and every path. **Rule single-tenant for v1
(`tenant_id` non-null, one row), or build multi-tenant now.**

## 9. No multi-relay story — but a control frame already assumes one

12 §B3 pushes `Draining{deadline}` "so agents re-dial a **sibling relay**", but nothing defines relay-set membership or
discovery, and 10 §7's `SetMaxOpenConns(1)` SQLite forecloses two relays sharing a store (06 asks SQLite-vs-Postgres,
unanswered). **v1 = one relay, but define `relays: []` and a `RelayHint` frame now.** Also **no dossier states the
default listener set**: 443 TCP+UDP, 80, console, TURN 3478/5349, 49160–49400 UDP.

## 10. Five conflicting UDP session keys, and no reload table

04 §4.3 `flowKey{proxyID, AddrPort}`+`flowID`; 06 §10.4 "5-tuple NAT state"; 09 §5.4 "**if v1 keys sessions by 5-tuple
anywhere, path upgrade becomes drop-and-reconnect**"; 08 §7(c) `{rule,client}` vs §6 `{src,dst,proto}`. 04 wins — alone in having
migration, per-IP quota and reflection defence — but inherits 14 §4's gap: no target discriminator, so one tunnel can't
carry multiple UDP services. **Publish one normative frame spec: `tunnelID`+`flowID`+`targetID`, widths, nonce
derivation.** PROXY protocol (12 §A2 and 10 §5 want it; 04 §4.8/14 §5 reject it in-payload) belongs at LB ingress and
the agent's local dial. And 12 §B3 reloads *listeners only* — silent on target change, passthrough→gateway (fatal to live
TLS), allowlists, revocation, TURN. **Produce a keep/drain/kill table.**

## 11. Uncovered areas, named

**IPv6:** three incidental mentions and no posture, though 15 §A6 recommends `udp4`/`tcp4`-only while CN carriers hand
out IPv6-only/464XLAT. **DNS/wildcard UX:** 03 §10 Q2 unanswered, 15 §B3 warns `DNS01Solver` disables the other
challenges, and 10 §1 warns `ServeMux` host patterns are literal-only — so precedence is unspecified and no screen names
the records to add. **Audit retention:** 11 ships the screen and 06 §10.5 the log, but 10 §7 retains only
metrics. **i18n:** 11 needs `message_zh`/`message_en` while 10 §1 makes `slog` the only logger — use a Go
error-code enum, translated client-side.

## 12. Scenario 3: three seams free now, wire-breaking later

Every Tunnel is public-ingress→agent, but S3 needs **agent↔agent** — reserve `kind = peer` in 11's enum now. It needs an
**agent-terminated capability backend** (screenshot/PTY/input), not a dialed target — 05 §8's `Backend: addr | unix |
handler` is the only dossier with that shape. Also reserve `agent.capabilities[]` in the hello, with per-capability scopes
(10 §10's token has none).

## 13. Verify before committing

SSE is **not** contested (06 §10.5, 10 §6, 11, 12 §B4); the real issue is 10 §1 pinning gateway listeners to HTTP/1 for
the ESP32 while SSE wants HTTP/2 — console and gateway cannot share one. **smux (10 §3) beats yamux (01 §7, 02 §7)** — but
confirm `smux.Server()` can `OpenStream`; 01 §6's workConn-pool deletion needs a symmetric muxer.
**Unverified and load-bearing:** 09 §4.2's "both hops typically 15–40 ms" carries relay-only-v1; quic-go+AEAD on mips
softfloat is unbenchmarked. Collapse the rival metric namespaces (12 §B4 vs 10 §12) and retention ladders (11 vs 10 §7);
make 12 §A4's UDP cap K≈3 per-tunnel (11's wireframe shows 2.7). Finally, **`nomifun-bridge-server` appears once in
36 000 words** (10 §2), though decision 1 demands coexistence.
