package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func TestDesktopBootstrapCancelLostResponseAfterExpiryAndRestart(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	spec := desktopInviteSpec()
	spec.TTL = time.Minute
	token, _ := createDesktopInvite(t, db, spec)
	attempt := strings.Repeat("c1", 32)
	tn := new(tunnel.Tunnel)
	invite, enrol, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), tn, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	spec.PublicHostname, spec.BusinessURL = "keep.example.test", "https://keep.example.test"
	otherToken, _ := createDesktopInvite(t, db, spec)
	other, otherEnrol, otherControl, otherTunnel := provisionDesktop(t, db, otherToken, strings.Repeat("c2", 32))
	if _, _, err := db.RedeemEnrolToken(ctx, otherEnrol, nil); err != nil {
		t.Fatal(err)
	}
	path, log := db.path, db.log
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Options{Path: path, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	advanceStoreClock(t, 120)
	if _, _, _, err := reopened.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Minute); !errors.Is(err, ErrDesktopEnrolExpired) {
		t.Fatalf("fixture should have lost recoverable enrol authority to expiry: %v", err)
	}
	if _, err := reopened.CancelDesktopBootstrap(ctx, token, strings.Repeat("c3", 32)); !errors.Is(err, ErrPairingInviteUsed) {
		t.Fatalf("different committed attempt gained cancellation authority: %v", err)
	}
	before, err := reopened.PeekPairingInvite(ctx, token)
	if err != nil || !before.RevokedAt.IsZero() {
		t.Fatalf("wrong attempt changed connection state: %+v, %v", before, err)
	}
	revoked, err := reopened.CancelDesktopBootstrap(ctx, token, attempt)
	if err != nil || revoked.RevokedAt.IsZero() || revoked.ID != invite.ID {
		t.Fatalf("expired lost response could not be cancelled after restart: %+v, %v", revoked, err)
	}
	if _, err := reopened.GetTunnel(ctx, invite.TunnelID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancellation left its tunnel live: %v", err)
	}
	if _, _, err := reopened.RedeemEnrolToken(ctx, enrol, nil); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("cancellation left its expired enrol token redeemable: %v", err)
	}
	if _, err := reopened.CancelDesktopBootstrap(ctx, token, strings.Repeat("c3", 32)); !errors.Is(err, ErrPairingInviteUsed) {
		t.Fatalf("revoked connection accepted the wrong committed attempt: %v", err)
	}
	again, err := reopened.CancelDesktopBootstrap(ctx, token, attempt)
	if err != nil || !reflect.DeepEqual(revoked, again) {
		t.Fatalf("repeated cancellation changed its result: %+v, %v", again, err)
	}
	otherStatus, err := reopened.DesktopConnection(ctx, other.ID, otherControl)
	if err != nil || !otherStatus.RevokedAt.IsZero() || !reopened.AgentExists(ctx, other.AgentID) {
		t.Fatalf("cancellation changed another Desktop: %+v, %v", otherStatus, err)
	}
	if otherPersisted, err := reopened.GetTunnel(ctx, otherTunnel.ID); err != nil || !reflect.DeepEqual(otherTunnel, otherPersisted) {
		t.Fatalf("cancellation changed another tunnel: %+v, %v", otherPersisted, err)
	}
	assertDesktopRows(t, reopened, 2, 2, 1)
}

func TestDesktopBootstrapCancelExpiredUnusedInviteAndInputBoundaries(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	spec := desktopInviteSpec()
	spec.TTL = time.Minute
	token, _ := createDesktopInvite(t, db, spec)
	legacyToken, _ := createDesktopInvite(t, db, pairingInviteSpec())
	advanceStoreClock(t, 120)
	for _, malformed := range []string{"", "00", strings.Repeat("g", 64), strings.Repeat("0", 65), strings.Repeat("0", 63) + " "} {
		if _, err := db.CancelDesktopBootstrap(ctx, token, malformed); err == nil {
			t.Fatalf("malformed attempt %q was accepted", malformed)
		}
		peek, err := db.PeekPairingInvite(ctx, token)
		if err != nil || !peek.RevokedAt.IsZero() {
			t.Fatalf("malformed cancellation changed invitation: %+v, %v", peek, err)
		}
	}
	attempt := strings.Repeat("d1", 32)
	if _, err := db.CancelDesktopBootstrap(ctx, "", attempt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty invitation token selected another authorization mode: %v", err)
	}
	if _, err := db.CancelDesktopBootstrap(ctx, "unknown", attempt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown invitation token was accepted: %v", err)
	}
	if _, err := db.CancelDesktopBootstrap(ctx, legacyToken, attempt); !errors.Is(err, ErrPairingInviteVersionMismatch) {
		t.Fatalf("legacy invitation could be cancelled using v2: %v", err)
	}
	revoked, err := db.CancelDesktopBootstrap(ctx, token, attempt)
	if err != nil || revoked.RevokedAt.IsZero() || !revoked.UsedAt.IsZero() || revoked.AgentID != "" {
		t.Fatalf("unused expired invitation could not be cancelled: %+v, %v", revoked, err)
	}
	// No attempt owns an unprovisioned result; possession of its bearer remains enough.
	again, err := db.CancelDesktopBootstrap(ctx, token, strings.Repeat("d2", 32))
	if err != nil || !reflect.DeepEqual(revoked, again) {
		t.Fatalf("unused cancellation was not idempotent: %+v, %v", again, err)
	}
	if _, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour); !errors.Is(err, ErrDesktopConnectionRevoked) {
		t.Fatalf("cancelled unused invitation subsequently provisioned: %v", err)
	}
	legacy, err := db.PeekPairingInvite(ctx, legacyToken)
	if err != nil || !legacy.RevokedAt.IsZero() || !legacy.UsedAt.IsZero() {
		t.Fatalf("v2 cancellation changed legacy invitation: %+v, %v", legacy, err)
	}
	assertDesktopRows(t, db, 2, 0, 0)
}

func TestDesktopBootstrapCancelAndProvisionAreAtomic(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	spec := desktopInviteSpec()
	spec.PublicHostname, spec.BusinessURL = "unrelated.example.test", "https://unrelated.example.test"
	otherToken, _ := createDesktopInvite(t, db, spec)
	other, otherEnrol, otherControl, otherTunnel := provisionDesktop(t, db, otherToken, strings.Repeat("e1", 32))
	if _, _, err := db.RedeemEnrolToken(ctx, otherEnrol, nil); err != nil {
		t.Fatal(err)
	}
	otherSecret, ok := db.AgentSecret(ctx, other.AgentID)
	if !ok {
		t.Fatal("unrelated fixture did not enrol")
	}
	const rounds = 16
	for i := range rounds {
		spec.PublicHostname = fmt.Sprintf("race-%d.example.test", i)
		spec.BusinessURL = "https://" + spec.PublicHostname
		token, invite := createDesktopInvite(t, db, spec)
		attempt := fmt.Sprintf("%064x", i+1)
		start := make(chan struct{})
		provisionResult := make(chan error, 1)
		cancelResult := make(chan error, 1)
		go func() {
			<-start
			_, _, _, err := db.ProvisionDesktop(ctx, token, attempt, desktopRedeemRequest(), new(tunnel.Tunnel), time.Hour)
			provisionResult <- err
		}()
		go func() {
			<-start
			_, err := db.CancelDesktopBootstrap(ctx, token, attempt)
			cancelResult <- err
		}()
		close(start)
		provisionErr, cancelErr := <-provisionResult, <-cancelResult
		if provisionErr != nil && !errors.Is(provisionErr, ErrDesktopConnectionRevoked) {
			t.Fatalf("round %d: unexpected provisioning result: %v", i, provisionErr)
		}
		if cancelErr != nil {
			t.Fatalf("round %d: authorized concurrent cancellation failed: %v", i, cancelErr)
		}
		status, err := db.PeekPairingInvite(ctx, token)
		if err != nil || status.RevokedAt.IsZero() {
			t.Fatalf("round %d: cancellation left invitation usable: %+v, %v", i, status, err)
		}
		if _, err := db.GetTunnel(ctx, DesktopTunnelID(invite.ID)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("round %d: race left an owned tunnel: %v", i, err)
		}
		if !status.UsedAt.IsZero() {
			enrol := desktopProvisioningToken("enrol", "nf_enrol_", token, attempt)
			if _, _, err := db.RedeemEnrolToken(ctx, enrol, nil); !errors.Is(err, ErrTokenUsed) {
				t.Fatalf("round %d: race left enrol authority active: %v", i, err)
			}
		}
		if _, err := db.CancelDesktopBootstrap(ctx, token, attempt); err != nil {
			t.Fatalf("round %d: concurrent result could not be cancelled again: %v", i, err)
		}
	}
	status, err := db.DesktopConnection(ctx, other.ID, otherControl)
	if err != nil || !status.RevokedAt.IsZero() {
		t.Fatalf("concurrent cancellation changed unrelated connection: %+v, %v", status, err)
	}
	if secret, ok := db.AgentSecret(ctx, other.AgentID); !ok || !reflect.DeepEqual(otherSecret, secret) {
		t.Fatal("concurrent cancellation changed unrelated agent authentication")
	}
	if persisted, err := db.GetTunnel(ctx, otherTunnel.ID); err != nil || !reflect.DeepEqual(otherTunnel, persisted) {
		t.Fatalf("concurrent cancellation changed unrelated tunnel: %+v, %v", persisted, err)
	}
	tunnels, err := db.ListTunnels(ctx, tunnel.DefaultTenantID)
	if err != nil || len(tunnels) != 1 || tunnels[0].ID != otherTunnel.ID {
		t.Fatalf("race left orphaned owned tunnels: %+v, %v", tunnels, err)
	}
}

func TestDesktopBootstrapCancelRollsBackRevocationFailure(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	token, _ := createDesktopInvite(t, db, desktopInviteSpec())
	attempt := strings.Repeat("f1", 32)
	invite, enrol, control, tn := provisionDesktop(t, db, token, attempt)
	if _, _, err := db.RedeemEnrolToken(ctx, enrol, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.write.Exec(`CREATE TRIGGER fail_cancel_delete BEFORE DELETE ON tunnels
		BEGIN SELECT RAISE(ABORT, 'injected cancellation delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CancelDesktopBootstrap(ctx, token, attempt); err == nil {
		t.Fatal("injected cancellation failure was ignored")
	}
	status, err := db.DesktopConnection(ctx, invite.ID, control)
	if err != nil || !status.RevokedAt.IsZero() || !db.AgentExists(ctx, invite.AgentID) {
		t.Fatalf("cancellation failure left partial revoked state: %+v, %v", status, err)
	}
	if _, err := db.GetTunnel(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.write.Exec(`DROP TRIGGER fail_cancel_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CancelDesktopBootstrap(ctx, token, attempt); err != nil {
		t.Fatalf("cancellation could not retry after rollback: %v", err)
	}
	if db.AgentExists(ctx, invite.AgentID) {
		t.Fatal("successful cancellation left agent authentication valid")
	}
}
