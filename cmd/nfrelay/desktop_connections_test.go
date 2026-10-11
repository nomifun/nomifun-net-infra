package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/store"
)

func TestDesktopBootstrapPublicURLBoundary(t *testing.T) {
	for _, tc := range []struct {
		url        string
		dev, valid bool
	}{
		{"", false, true},
		{"https://relay.example.com:9444/api/bootstrap/desktop/v2", false, true},
		{"http://relay.example.com/api/bootstrap/desktop/v2", true, false},
		{"http://127.0.0.1:9443/api/bootstrap/desktop/v2", false, false},
		{"http://127.0.0.1:9443/api/bootstrap/desktop/v2", true, true},
		{"https://localhost:9443/api/bootstrap/desktop/v2", true, true},
		{"https://localhost:9443/api/bootstrap/desktop/v2", false, false},
		{"https://relay.example.com/api/bootstrap/desktop", false, false},
		{"https://relay.example.com/api/bootstrap/desktop/v2?invite=secret", false, false},
	} {
		if err := validateDesktopBootstrapURL(tc.url, tc.dev); (err == nil) != tc.valid {
			t.Errorf("URL %q dev=%v error=%v", tc.url, tc.dev, err)
		}
	}
}

func TestDesktopV2RuntimeRecoveryAndScopedRevoke(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	t.Cleanup(rt.closeEntries)
	rt.bindAddr = "127.0.0.1:8443"
	rt.desktopDevInsecure = true
	rt.desktopBootstrapURL = "http://127.0.0.1:9443/api/bootstrap/desktop/v2"
	invite, err := rt.CreateDesktopInviteV2(ctx, time.Minute, console.DesktopInviteV2Request{Note: "test desktop"})
	if err != nil {
		t.Fatal(err)
	}
	if invite.BootstrapURL != rt.desktopBootstrapURL || !strings.HasPrefix(invite.BusinessURL, "http://127.0.0.1:") {
		t.Fatal("invite addresses must come from explicit relay configuration")
	}
	first, err := rt.BootstrapDesktopV2(ctx, invite.Token, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.State != "pending" {
		t.Fatalf("offline agent must not be ready: %q", first.State)
	}
	if first.Tunnel.Backend.Addr != console.DesktopBackendAddrV2 {
		t.Fatal("v2 backend must be reserved loopback")
	}
	second, err := rt.BootstrapDesktopV2(ctx, invite.Token, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.EnrolToken != second.EnrolToken || first.ControlToken != second.ControlToken || first.Tunnel.ID != second.Tunnel.ID {
		t.Fatal("response loss retry created a different identity")
	}
	if _, err := rt.BootstrapDesktopV2(ctx, invite.Token, strings.Repeat("b", 64)); !errors.Is(err, store.ErrPairingInviteUsed) {
		t.Fatalf("another attempt must be denied: %v", err)
	}
	if _, err := rt.RevokeDesktopConnection(ctx, invite.ID, "wrong", false); err == nil {
		t.Fatal("invalid control bearer revoked connection")
	}
	for i := 0; i < 2; i++ {
		revoked, err := rt.RevokeDesktopConnection(ctx, invite.ID, first.ControlToken, false)
		if err != nil {
			t.Fatal(err)
		}
		if !revoked.Revoked || revoked.State != "revoked" {
			t.Fatal("revoke must remain observable and idempotent")
		}
	}
	if _, err := rt.BootstrapDesktopV2(ctx, invite.Token, strings.Repeat("a", 64)); !errors.Is(err, store.ErrDesktopConnectionRevoked) {
		t.Fatalf("revoked connection must not reprovision: %v", err)
	}
}

func TestDesktopV2PreflightFailsBeforeIssuingAnInvite(t *testing.T) {
	rt := newTestRuntime(t)
	if rt.DesktopPreflight().Ready {
		t.Fatal("default deployment must not claim public Desktop readiness")
	}
	if _, err := rt.CreateDesktopInviteV2(context.Background(), time.Minute, console.DesktopInviteV2Request{}); !errors.Is(err, console.ErrDesktopPrecondition) {
		t.Fatalf("missing public addresses should block issuing invite: %v", err)
	}
}

func TestDesktopV2RuntimeExpiredPendingCanCancel(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	t.Cleanup(rt.closeEntries)
	rt.bindAddr = "127.0.0.1:8443"
	rt.desktopDevInsecure = true
	rt.desktopEnrolTTL = time.Second
	rt.desktopBootstrapURL = "http://127.0.0.1:9443/api/bootstrap/desktop/v2"
	invite, err := rt.CreateDesktopInviteV2(ctx, time.Minute, console.DesktopInviteV2Request{})
	if err != nil {
		t.Fatal(err)
	}
	attempt := strings.Repeat("a", 64)
	first, err := rt.BootstrapDesktopV2(ctx, invite.Token, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if first.L2Port != 0 {
		t.Fatal("without shared listener L2 must be explicitly unavailable")
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err := rt.BootstrapDesktopV2(ctx, invite.Token, attempt); !errors.Is(err, store.ErrDesktopEnrolExpired) {
		t.Fatalf("enrol should really expire: %v", err)
	}
	if _, err := rt.CancelDesktopBootstrap(ctx, invite.Token, strings.Repeat("b", 64)); !errors.Is(err, store.ErrPairingInviteUsed) {
		t.Fatal("different pending attempt cannot cancel")
	}
	for i := 0; i < 2; i++ {
		out, err := rt.CancelDesktopBootstrap(ctx, invite.Token, attempt)
		if err != nil || !out.Revoked || out.State != "revoked" {
			t.Fatalf("cancel failed: %v", err)
		}
	}
	if _, err := rt.db.GetTunnel(ctx, first.Tunnel.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cancel must remove its owned tunnel")
	}
}
