package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func desktopInviteSpec() PairingInviteSpec {
	return PairingInviteSpec{
		TenantID: tunnel.DefaultTenantID, Scopes: []string{"desktop:bootstrap"},
		Backend:        tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:25811"},
		PublicHostname: "desktop.example.test", PublicPort: 443, TLS: tunnel.TLSGateway,
		BootstrapVersion: 2, BusinessURL: "https://desktop.example.test", TTL: time.Hour,
	}
}

func desktopRedeemRequest() PairingInviteRedeemRequest {
	return PairingInviteRedeemRequest{
		TenantID: tunnel.DefaultTenantID, Scopes: []string{"desktop:bootstrap"},
		Backend: desktopInviteSpec().Backend, UsedBy: "desktop-bootstrap-v2",
	}
}

func createDesktopInvite(t *testing.T, db *DB, spec PairingInviteSpec) (string, *PairingInvite) {
	t.Helper()
	plain, invite, err := db.CreatePairingInvite(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return plain, invite
}

func provisionDesktop(t *testing.T, db *DB, token, attempt string) (*PairingInvite, string, string, *tunnel.Tunnel) {
	t.Helper()
	tn := new(tunnel.Tunnel)
	invite, enrol, control, err := db.ProvisionDesktop(context.Background(), token, attempt,
		desktopRedeemRequest(), tn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return invite, enrol, control, tn
}

func advanceStoreClock(t *testing.T, seconds int64) {
	t.Helper()
	original := now
	ts := original()
	now = func() int64 { return ts + seconds }
	t.Cleanup(func() { now = original })
}

func assertDesktopRows(t *testing.T, db *DB, invites, enrols, tunnels int) {
	t.Helper()
	for _, tc := range []struct {
		table string
		want  int
	}{{"pairing_invites", invites}, {"enrol_tokens", enrols}, {"tunnels", tunnels}} {
		var got int
		if err := db.read.QueryRow(`SELECT COUNT(*) FROM ` + tc.table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%s rows = %d, want %d", tc.table, got, tc.want)
		}
	}
}

func TestDesktopProvisioningRecoversLostResponseAcrossRestart(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	spec := desktopInviteSpec()
	spec.TTL = time.Second
	token, original := createDesktopInvite(t, db, spec)
	attempt := strings.Repeat("ab", 32)

	peek, err := db.PeekPairingInvite(ctx, token)
	if err != nil || peek.BootstrapVersion != 2 || peek.BusinessURL != spec.BusinessURL || !peek.UsedAt.IsZero() {
		t.Fatalf("peek did not preserve invitation metadata: %+v, %v", peek, err)
	}
	tn := &tunnel.Tunnel{
		ID: "untrusted-id", TenantID: "untrusted-tenant", AgentID: "untrusted-agent",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "10.0.0.1:80"},
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP, CatchAll: true},
	}
	first, enrol, control, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), tn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(enrol) != len("nf_enrol_")+64 || len(control) != len("nf_desktop_")+64 ||
		!strings.HasPrefix(enrol, "nf_enrol_") || !strings.HasPrefix(control, "nf_desktop_") ||
		strings.TrimPrefix(enrol, "nf_enrol_") == strings.TrimPrefix(control, "nf_desktop_") {
		t.Fatal("derived credentials are not distinct 256-bit tokens")
	}
	if first.ID != original.ID || first.UsedAt.IsZero() || first.EnrolExpiresAt.IsZero() ||
		first.AgentID != EnrolAgentID(enrol) || first.TunnelID != DesktopTunnelID(first.ID) {
		t.Fatalf("missing durable provisioning facts: %+v", first)
	}
	if tn.ID != first.TunnelID || tn.AgentID != first.AgentID || tn.Backend != spec.Backend ||
		tn.TenantID != spec.TenantID || tn.Exposure != tunnel.ExposureShared || tn.ListenPort != 0 ||
		tn.Router.HostRewrite != spec.Backend.Addr || tn.Router.CatchAll ||
		!reflect.DeepEqual(tn.Router.Domains, []string{spec.PublicHostname}) || tn.ShortID == 0 {
		t.Fatalf("provisioning did not apply authoritative invitation bounds: %+v", tn)
	}

	var attemptHash, controlHash, enrolHash string
	if err := db.read.QueryRow(`SELECT attempt_hash, control_hash, enrol_token_hash FROM pairing_invites WHERE id = ?`,
		first.ID).Scan(&attemptHash, &controlHash, &enrolHash); err != nil {
		t.Fatal(err)
	}
	if attemptHash != hashToken(attempt) || controlHash != hashToken(control) || enrolHash != hashToken(enrol) {
		t.Fatal("database did not retain exactly the credential hashes")
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, attempt, enrol, control, attemptHash, controlHash, enrolHash} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("public connection metadata exposed a credential or full credential hash")
		}
	}
	if err := db.SetTunnelState(ctx, tn.ID, tunnel.StateActive, "connected"); err != nil {
		t.Fatal(err)
	}
	assertDesktopRows(t, db, 1, 1, 1)
	path, log := db.path, db.log
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Options{Path: path, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	advanceStoreClock(t, 10) // The invite has expired, but its committed attempt remains recoverable.
	recoveryInput := &tunnel.Tunnel{ID: "changed", Slug: "changed", ListenPort: 12345}
	recovered, gotEnrol, gotControl, err := reopened.ProvisionDesktop(ctx, token, attempt,
		desktopRedeemRequest(), recoveryInput, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, recovered) || gotEnrol != enrol || gotControl != control ||
		recoveryInput.ID != tn.ID || recoveryInput.Slug != tn.Slug ||
		recoveryInput.State != tunnel.StateActive || recoveryInput.StateReason != "connected" {
		t.Fatalf("recovery changed the result: invite=%+v tunnel=%+v", recovered, recoveryInput)
	}
	if _, _, _, err := reopened.ProvisionDesktop(ctx, token, strings.Repeat("cd", 32),
		desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrPairingInviteUsed) {
		t.Fatalf("a different attempt must not recover the consumed invitation: %v", err)
	}
	status, err := reopened.DesktopConnection(ctx, first.ID, control)
	if err != nil || !reflect.DeepEqual(status, first) {
		t.Fatalf("control authentication failed after restart: %+v, %v", status, err)
	}
	assertDesktopRows(t, reopened, 1, 1, 1)
}

func TestDesktopProvisioningRollbackPreservesInviteForRetry(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	spec := desktopInviteSpec()
	spec.TLS = tunnel.TLSPassthrough
	spec.PublicPort = 30443
	spec.BusinessURL = "http://desktop.example.test:30443"
	token, invite := createDesktopInvite(t, db, spec)
	occupied := mkTunnel("occupied", spec.PublicPort)
	if err := db.PutTunnel(ctx, occupied); err != nil {
		t.Fatal(err)
	}
	attempt := strings.Repeat("01", 32)
	input := &tunnel.Tunnel{ID: "caller-id", Slug: "original-input", ShortID: 50}
	before := input.Clone()
	if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), input,
		time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("port conflict should fail provisioning: %v", err)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("failed transaction mutated the caller's tunnel")
	}
	peek, err := db.PeekPairingInvite(ctx, token)
	if err != nil || !peek.UsedAt.IsZero() || !peek.EnrolExpiresAt.IsZero() || peek.AgentID != "" {
		t.Fatalf("failed provisioning consumed the invite: %+v, %v", peek, err)
	}
	var attemptHash, controlHash, enrolHash string
	if err := db.read.QueryRow(`SELECT attempt_hash, control_hash, enrol_token_hash FROM pairing_invites WHERE id = ?`,
		invite.ID).Scan(&attemptHash, &controlHash, &enrolHash); err != nil {
		t.Fatal(err)
	}
	if attemptHash != "" || controlHash != "" || enrolHash != "" {
		t.Fatal("failed transaction retained credentials")
	}
	assertDesktopRows(t, db, 1, 0, 1)
	if err := db.DeleteTunnel(ctx, occupied.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), input, time.Hour); err != nil {
		t.Fatalf("same invite and attempt could not retry after rollback: %v", err)
	}
	if input.ShortID != 1 || input.ListenPort != spec.PublicPort || input.Exposure != tunnel.ExposurePort ||
		input.Router != nil || input.Backend != spec.Backend {
		t.Fatalf("rollback leaked a short ID or port binding: %+v", input)
	}
	assertDesktopRows(t, db, 1, 1, 1)
}

func TestDesktopProvisioningConcurrentAttempts(t *testing.T) {
	for _, sameAttempt := range []bool{true, false} {
		t.Run(fmt.Sprintf("same-attempt=%v", sameAttempt), func(t *testing.T) {
			db := open(t)
			token, _ := createDesktopInvite(t, db, desktopInviteSpec())
			const callers = 16
			type result struct {
				err            error
				enrol, control string
			}
			results := make(chan result, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					attempt := fmt.Sprintf("%064x", i+1)
					if sameAttempt {
						attempt = strings.Repeat("01", 32)
					}
					_, enrol, control, err := db.ProvisionDesktop(context.Background(), token, attempt,
						desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour)
					results <- result{err, enrol, control}
				}()
			}
			wg.Wait()
			close(results)
			var success, used int
			var enrol, control string
			for result := range results {
				switch {
				case result.err == nil:
					success++
					if enrol == "" {
						enrol, control = result.enrol, result.control
					} else if enrol != result.enrol || control != result.control {
						t.Fatal("same committed attempt returned different credentials")
					}
				case errors.Is(result.err, ErrPairingInviteUsed):
					used++
				default:
					t.Fatalf("unexpected concurrent provisioning error: %v", result.err)
				}
			}
			if (sameAttempt && (success != callers || used != 0)) ||
				(!sameAttempt && (success != 1 || used != callers-1)) {
				t.Fatalf("concurrent results: success=%d used=%d", success, used)
			}
			assertDesktopRows(t, db, 1, 1, 1)
		})
	}
}

func TestDesktopProvisioningOriginConflictPreservesInvite(t *testing.T) {
	for _, generic := range []bool{false, true} {
		t.Run(fmt.Sprintf("generic-route=%v", generic), func(t *testing.T) {
			db := open(t)
			ctx := context.Background()
			spec := desktopInviteSpec()
			var occupiedID, occupiedControl string
			if generic {
				tn := mkTunnel("generic-route", 0)
				tn.TLS, tn.Exposure = tunnel.TLSGateway, tunnel.ExposureShared
				tn.Router = &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{spec.PublicHostname}}
				if err := db.PutTunnel(ctx, tn); err != nil {
					t.Fatal(err)
				}
				occupiedID = tn.ID
			} else {
				token, _ := createDesktopInvite(t, db, spec)
				invite, _, control, _ := provisionDesktop(t, db, token, strings.Repeat("09", 32))
				occupiedID, occupiedControl = invite.ID, control
			}
			spec.PublicHostname = strings.ToUpper(spec.PublicHostname)
			spec.BusinessURL = "https://" + spec.PublicHostname
			token, _ := createDesktopInvite(t, db, spec)
			attempt := strings.Repeat("0a", 32)
			if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate hostname should fail provisioning: %v", err)
			}
			peek, err := db.PeekPairingInvite(ctx, token)
			if err != nil || !peek.UsedAt.IsZero() {
				t.Fatalf("origin conflict consumed invitation: %+v, %v", peek, err)
			}
			if generic {
				if err := db.DeleteTunnel(ctx, occupiedID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := db.RevokeDesktopConnection(ctx, occupiedID, occupiedControl); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); err != nil {
				t.Fatalf("origin release did not allow retry: %v", err)
			}
		})
	}
}

func TestDesktopProvisioningAndOrdinaryTunnelsShareAtomicShortIDs(t *testing.T) {
	db := open(t)
	const connections = 12
	tokens := make([]string, connections)
	for i := range connections {
		spec := desktopInviteSpec()
		spec.PublicHostname = fmt.Sprintf("desktop-%d.example.test", i)
		spec.BusinessURL = "https://" + spec.PublicHostname
		tokens[i], _ = createDesktopInvite(t, db, spec)
	}
	errs := make(chan error, 2*connections)
	var wg sync.WaitGroup
	for i := range connections {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _, err := db.ProvisionDesktop(context.Background(), tokens[i], fmt.Sprintf("%064x", i+1),
				desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour)
			errs <- err
		}()
		go func() {
			defer wg.Done()
			errs <- db.PutTunnel(context.Background(), mkTunnel(fmt.Sprintf("ordinary-%d", i), 0))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent short-ID allocation failed: %v", err)
		}
	}
	tunnels, err := db.ListTunnels(context.Background(), tunnel.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint16]bool)
	for _, tn := range tunnels {
		if tn.ShortID == 0 || seen[tn.ShortID] {
			t.Fatalf("duplicate or zero short ID: %+v", tn)
		}
		seen[tn.ShortID] = true
	}
	if len(seen) != 2*connections {
		t.Fatalf("got %d tunnels, want %d", len(seen), 2*connections)
	}
}

func TestDesktopProvisioningAuthorizationAndVersionBoundaries(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	token, invite := createDesktopInvite(t, db, desktopInviteSpec())
	legacyToken, _ := createDesktopInvite(t, db, pairingInviteSpec())
	attempt := strings.Repeat("02", 32)
	if _, err := db.RedeemPairingInvite(ctx, token, desktopRedeemRequest()); !errors.Is(err, ErrPairingInviteVersionMismatch) {
		t.Fatalf("legacy redemption consumed v2 invite: %v", err)
	}
	if _, _, _, err := db.ProvisionDesktop(ctx, legacyToken, attempt, pairingRedeemRequest(),
		new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrPairingInviteVersionMismatch) {
		t.Fatalf("v2 provisioning accepted legacy invite: %v", err)
	}
	for _, committed := range []bool{false, true} {
		if committed {
			provisionDesktop(t, db, token, attempt)
		}
		for _, tc := range []struct {
			name string
			req  PairingInviteRedeemRequest
			want error
		}{
			{"tenant", PairingInviteRedeemRequest{TenantID: "other", Scopes: []string{"desktop:bootstrap"}, Backend: invite.Backend}, ErrPairingInviteTenantMismatch},
			{"scope", PairingInviteRedeemRequest{TenantID: invite.TenantID, Scopes: []string{"admin"}, Backend: invite.Backend}, ErrPairingInviteScopeDenied},
			{"backend", PairingInviteRedeemRequest{TenantID: invite.TenantID, Scopes: invite.Scopes, Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:25808"}}, ErrPairingInviteBackendMismatch},
		} {
			if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, tc.req, new(tunnel.Tunnel), time.Hour); !errors.Is(err, tc.want) {
				t.Fatalf("%s authorization committed=%v: got %v, want %v", tc.name, committed, err, tc.want)
			}
		}
		peek, err := db.PeekPairingInvite(ctx, token)
		if err != nil || peek.UsedAt.IsZero() == committed {
			t.Fatalf("failed authorization changed invitation consumption: %+v, %v", peek, err)
		}
	}
	if _, err := db.RevokeDesktopConnection(ctx, invite.ID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty control credential selected admin mode: %v", err)
	}
}

func TestDesktopProvisioningExpiryBeforeAndAfterEnrolment(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enrolled=%v", enrolled), func(t *testing.T) {
			db := open(t)
			ctx := context.Background()
			spec := desktopInviteSpec()
			spec.TTL = time.Second
			token, _ := createDesktopInvite(t, db, spec)
			attempt := strings.Repeat("03", 32)
			_, enrol, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if enrolled {
				if _, _, err := db.RedeemEnrolToken(ctx, enrol, nil); err != nil {
					t.Fatal(err)
				}
			}
			advanceStoreClock(t, 10)
			_, recoveredEnrol, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour)
			if enrolled {
				if err != nil || recoveredEnrol != enrol {
					t.Fatalf("enrolled connection lost response recovery after expiry: %v", err)
				}
			} else if !errors.Is(err, ErrDesktopEnrolExpired) {
				t.Fatalf("unredeemed expired enrol token should require a new invite: %v", err)
			}
			assertDesktopRows(t, db, 1, 1, 1)
		})
	}
	t.Run("never provisioned", func(t *testing.T) {
		db := open(t)
		spec := desktopInviteSpec()
		spec.TTL = time.Second
		token, _ := createDesktopInvite(t, db, spec)
		advanceStoreClock(t, 10)
		if _, _, _, err := db.ProvisionDesktop(context.Background(), token, strings.Repeat("04", 32),
			desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrPairingInviteExpired) {
			t.Fatalf("unconsumed expired invitation was accepted: %v", err)
		}
		assertDesktopRows(t, db, 1, 0, 0)
	})
}

func TestDesktopRevocationIsExactAndIdempotent(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enrolled=%v", enrolled), func(t *testing.T) {
			db := open(t)
			ctx := context.Background()
			token, _ := createDesktopInvite(t, db, desktopInviteSpec())
			attempt := strings.Repeat("05", 32)
			invite, enrol, control, tn := provisionDesktop(t, db, token, attempt)
			spec := desktopInviteSpec()
			spec.PublicHostname, spec.BusinessURL = "other.example.test", "https://other.example.test"
			otherToken, _ := createDesktopInvite(t, db, spec)
			other, otherEnrol, otherControl, otherTunnel := provisionDesktop(t, db, otherToken, strings.Repeat("06", 32))
			extra := mkTunnel("unrelated-same-agent", 0)
			extra.AgentID = invite.AgentID
			if err := db.PutTunnel(ctx, extra); err != nil {
				t.Fatal(err)
			}
			if enrolled {
				id, _, err := db.RedeemEnrolToken(ctx, enrol, nil)
				if err != nil || id != invite.AgentID || !db.AgentExists(ctx, id) {
					t.Fatalf("enrolment failed: %s, %v", id, err)
				}
			}
			for _, wrong := range []string{"", "wrong", otherControl} {
				if _, err := db.DesktopConnection(ctx, invite.ID, wrong); !errors.Is(err, ErrNotFound) {
					t.Fatalf("status accepted another credential: %v", err)
				}
				if _, err := db.RevokeDesktopConnection(ctx, invite.ID, wrong); !errors.Is(err, ErrNotFound) {
					t.Fatalf("revocation accepted another credential: %v", err)
				}
			}
			revoked, err := db.RevokeDesktopConnection(ctx, invite.ID, control)
			if err != nil || revoked.RevokedAt.IsZero() {
				t.Fatalf("connection was not revoked: %+v, %v", revoked, err)
			}
			if _, _, err := db.RedeemEnrolToken(ctx, enrol, nil); !errors.Is(err, ErrTokenUsed) {
				t.Fatalf("revocation left enrol token usable: %v", err)
			}
			if db.AgentExists(ctx, invite.AgentID) {
				t.Fatal("revocation left agent authentication valid")
			}
			if _, ok := db.AgentSecret(ctx, invite.AgentID); ok {
				t.Fatal("revocation left agent handshake secret available")
			}
			if _, err := db.GetTunnel(ctx, tn.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("owned tunnel survived revocation: %v", err)
			}
			for _, id := range []string{otherTunnel.ID, extra.ID} {
				if _, err := db.GetTunnel(ctx, id); err != nil {
					t.Fatalf("revocation deleted unrelated tunnel %s: %v", id, err)
				}
			}
			if otherStatus, err := db.DesktopConnection(ctx, other.ID, otherControl); err != nil || !otherStatus.RevokedAt.IsZero() {
				t.Fatalf("revocation changed another connection: %+v, %v", otherStatus, err)
			}
			if _, _, err := db.RedeemEnrolToken(ctx, otherEnrol, nil); err != nil {
				t.Fatalf("revocation invalidated another enrol credential: %v", err)
			}
			for _, revoke := range []func() (*PairingInvite, error){
				func() (*PairingInvite, error) { return db.RevokeDesktopConnection(ctx, invite.ID, control) },
				func() (*PairingInvite, error) { return db.RevokeDesktopConnectionAsAdmin(ctx, invite.ID) },
			} {
				again, err := revoke()
				if err != nil || !again.RevokedAt.Equal(revoked.RevokedAt) {
					t.Fatalf("repeated revocation changed durable result: %+v, %v", again, err)
				}
			}
			status, err := db.DesktopConnection(ctx, invite.ID, control)
			if err != nil || !status.RevokedAt.Equal(revoked.RevokedAt) {
				t.Fatalf("revoked status became unreadable: %+v, %v", status, err)
			}
			if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrDesktopConnectionRevoked) {
				t.Fatalf("revoked invitation recovered usable credentials: %v", err)
			}
			assertDesktopRows(t, db, 2, 2, 2)
		})
	}
}

func TestDesktopRevocationRollsBackAllObjectsOnDeleteFailure(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	token, _ := createDesktopInvite(t, db, desktopInviteSpec())
	invite, enrol, control, tn := provisionDesktop(t, db, token, strings.Repeat("07", 32))
	if _, _, err := db.RedeemEnrolToken(ctx, enrol, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.write.Exec(`CREATE TRIGGER fail_desktop_delete BEFORE DELETE ON tunnels
		BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RevokeDesktopConnection(ctx, invite.ID, control); err == nil {
		t.Fatal("injected delete failure should fail the revocation transaction")
	}
	status, err := db.DesktopConnection(ctx, invite.ID, control)
	if err != nil || !status.RevokedAt.IsZero() || !db.AgentExists(ctx, invite.AgentID) {
		t.Fatalf("failed revocation left partial revoked state: %+v, %v", status, err)
	}
	if _, err := db.GetTunnel(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	var expiry int64
	if err := db.read.QueryRow(`SELECT expires_at FROM enrol_tokens WHERE token_hash = ?`, hashToken(enrol)).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if expiry != invite.EnrolExpiresAt.Unix() {
		t.Fatal("failed revocation changed enrol token expiry")
	}
	if _, err := db.write.Exec(`DROP TRIGGER fail_desktop_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RevokeDesktopConnection(ctx, invite.ID, control); err != nil {
		t.Fatalf("revocation could not retry after rollback: %v", err)
	}
}

func TestDesktopAdminCanCancelUnusedInviteAndListOnlyV2(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	token, invite := createDesktopInvite(t, db, desktopInviteSpec())
	createDesktopInvite(t, db, pairingInviteSpec())
	spec := desktopInviteSpec()
	spec.TenantID = "other"
	createDesktopInvite(t, db, spec)
	listed, err := db.ListDesktopConnections(ctx, tunnel.DefaultTenantID)
	if err != nil || len(listed) != 1 || listed[0].ID != invite.ID || !listed[0].UsedAt.IsZero() {
		t.Fatalf("list mixed legacy or other-tenant invitations: %+v, %v", listed, err)
	}
	revoked, err := db.RevokeDesktopConnectionAsAdmin(ctx, invite.ID)
	if err != nil || revoked.RevokedAt.IsZero() {
		t.Fatalf("admin could not cancel an unused invitation: %+v, %v", revoked, err)
	}
	if _, _, _, err := db.ProvisionDesktop(ctx, token, strings.Repeat("08", 32), desktopRedeemRequest(),
		new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrDesktopConnectionRevoked) {
		t.Fatalf("cancelled invitation could still provision: %v", err)
	}
	assertDesktopRows(t, db, 3, 0, 0)
}
