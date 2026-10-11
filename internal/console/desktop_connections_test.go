package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type desktopV2Fake struct {
	bootstrapFake
	bootstrapCalls int
	controlCalls   int
	controlAdmin   bool
	cancelCalls    int
}

func (f *desktopV2Fake) DesktopPreflight() DesktopPreflight {
	return DesktopPreflight{ProtocolVersion: 2}
}
func (f *desktopV2Fake) CreateDesktopInviteV2(context.Context, time.Duration, DesktopInviteV2Request) (DesktopPairingInviteResponse, error) {
	return DesktopPairingInviteResponse{}, nil
}
func (f *desktopV2Fake) BootstrapDesktopV2(context.Context, string, string) (DesktopBootstrapV2Response, error) {
	f.bootstrapCalls++
	return DesktopBootstrapV2Response{ProtocolVersion: 2, State: "pending"}, nil
}
func (f *desktopV2Fake) ListDesktopConnections(context.Context) ([]DesktopConnection, error) {
	return []DesktopConnection{}, nil
}
func (f *desktopV2Fake) DesktopConnection(context.Context, string, string, bool) (DesktopConnection, error) {
	return DesktopConnection{State: "pending"}, nil
}
func (f *desktopV2Fake) RevokeDesktopConnection(_ context.Context, _ string, _ string, admin bool) (DesktopConnection, error) {
	f.controlCalls++
	f.controlAdmin = admin
	return DesktopConnection{Revoked: true, State: "revoked"}, nil
}

func (f *desktopV2Fake) CancelDesktopBootstrap(context.Context, string, string) (DesktopConnection, error) {
	f.cancelCalls++
	return DesktopConnection{ProtocolVersion: 2, Revoked: true, State: "revoked"}, nil
}

func TestDesktopV2PendingCancelRequiresOriginalAttempt(t *testing.T) {
	fake := &desktopV2Fake{}
	s, _ := newBootstrapTestServer(t, &fake.bootstrapFake)
	s.snapshot = fake
	for _, tc := range []struct {
		body   map[string]any
		bearer bool
		status int
	}{
		{map[string]any{"attempt_id": strings.Repeat("a", 64)}, false, http.StatusUnauthorized},
		{map[string]any{"attempt_id": "bad"}, true, http.StatusBadRequest},
		{map[string]any{"attempt_id": strings.Repeat("a", 64), "backend": "127.0.0.1:22"}, true, http.StatusBadRequest},
		{map[string]any{"attempt_id": strings.Repeat("a", 64)}, true, http.StatusOK},
	} {
		r := req(http.MethodPost, "/api/bootstrap/desktop/v2:cancel", tc.body)
		if tc.bearer {
			r.Header.Set("Authorization", "Bearer test-invite")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d expected=%d", w.Code, tc.status)
		}
	}
	if fake.cancelCalls != 1 {
		t.Fatal("invalid requests must never reach cancellation")
	}
}

func TestDesktopV2BootstrapRequiresPersistableAttemptAndRejectsBackendInjection(t *testing.T) {
	fake := &desktopV2Fake{}
	s, _ := newBootstrapTestServer(t, &fake.bootstrapFake)
	s.snapshot = fake
	for _, tc := range []struct {
		body   map[string]any
		bearer bool
		status int
	}{
		{map[string]any{"attempt_id": strings.Repeat("a", 64)}, false, http.StatusUnauthorized},
		{map[string]any{"attempt_id": "bad"}, true, http.StatusBadRequest},
		{map[string]any{"attempt_id": strings.Repeat("a", 64), "backend": "127.0.0.1:22"}, true, http.StatusBadRequest},
		{map[string]any{"attempt_id": strings.Repeat("a", 64)}, true, http.StatusOK},
	} {
		r := req(http.MethodPost, "/api/bootstrap/desktop/v2", tc.body)
		if tc.bearer {
			r.Header.Set("Authorization", "Bearer test-invite")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d expected=%d", w.Code, tc.status)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("credential response must disable caching")
		}
	}
	if fake.bootstrapCalls != 1 {
		t.Fatalf("invalid input called provisioner %d times", fake.bootstrapCalls)
	}
}

func TestDesktopConnectionControlKeepsBearerAndAdminCSRFSeparate(t *testing.T) {
	fake := &desktopV2Fake{}
	s, _ := newBootstrapTestServer(t, &fake.bootstrapFake)
	s.snapshot = fake
	auth := bootstrapSetupAndLogin(t, s)
	unauthorized := req(http.MethodDelete, "/api/desktop-connections/pinv-test", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, unauthorized)
	if w.Code != http.StatusUnauthorized || fake.controlCalls != 0 {
		t.Fatal("missing control and admin credentials must not revoke")
	}
	admin := auth(req(http.MethodDelete, "/api/desktop-connections/pinv-test", nil))
	admin.Header.Del("X-NFR-CSRF")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, admin)
	if w.Code != http.StatusForbidden || fake.controlCalls != 0 {
		t.Fatal("admin deletion requires CSRF")
	}
	bearer := req(http.MethodDelete, "/api/desktop-connections/pinv-test", nil)
	bearer.Header.Set("Authorization", "Bearer test-control")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, bearer)
	if w.Code != http.StatusOK || fake.controlAdmin {
		t.Fatal("control bearer must never select administrator mode")
	}
	admin = auth(req(http.MethodDelete, "/api/desktop-connections/pinv-test", nil))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, admin)
	if w.Code != http.StatusOK || !fake.controlAdmin {
		t.Fatal("authenticated admin must be able to revoke connection")
	}
}
