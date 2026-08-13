package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
)

type bootstrapFake struct {
	invite DesktopPairingInviteResponse
	out    DesktopBootstrapResponse
	err    error
	got    string
}

func (f *bootstrapFake) Snapshot() Snapshot {
	return Snapshot{RelayVersion: "test", Agents: []AgentStatus{}, Tunnels: []TunnelStatus{}}
}

func (f *bootstrapFake) IssueEnrolToken(time.Duration, string) (string, string, error) {
	return "nf_enrol_test", "nfagent -relay x -pin y -token nf_enrol_test", nil
}

func (f *bootstrapFake) ApplyTunnels() error { return nil }

func (f *bootstrapFake) CreateDesktopPairingInvite(
	_ context.Context, _ time.Duration, _ uint16, _ string,
) (DesktopPairingInviteResponse, error) {
	return f.invite, f.err
}

func (f *bootstrapFake) BootstrapDesktop(_ context.Context, token string) (DesktopBootstrapResponse, error) {
	f.got = token
	return f.out, f.err
}

func newBootstrapTestServer(t *testing.T, fake *bootstrapFake) (*Server, *store.DB) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "bootstrap.db"),
		Log:  log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(Options{DB: db, Snapshot: fake, Log: log, BindAddr: "127.0.0.1:9443"})
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func bootstrapSetupAndLogin(t *testing.T, s *Server) func(*http.Request) *http.Request {
	t.Helper()
	r := req(http.MethodPost, "/api/setup", setupRequest{
		Username: "admin",
		Password: "a-very-long-password",
	})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("首启失败：%d %s", w.Code, w.Body.String())
	}
	var login LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	return func(r *http.Request) *http.Request {
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		r.Header.Set(CSRFHeaderName, login.CSRFToken)
		r.Header.Set("Origin", "http://127.0.0.1:9443")
		return r
	}
}

func decodeAPIError(t *testing.T, w *httptest.ResponseRecorder) APIError {
	t.Helper()
	var out APIError
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析错误响应失败：%v；body=%s", err, w.Body.String())
	}
	return out
}

func TestDesktopBootstrapUnauthenticatedInviteOnly(t *testing.T) {
	fake := &bootstrapFake{
		out: DesktopBootstrapResponse{
			InviteID:    "pinv-test",
			Relay:       "127.0.0.1:18444",
			BusinessURL: "http://127.0.0.1:19091",
			ProbeURL:    "http://127.0.0.1:19091",
			Pin:         "pin",
			EnrolToken:  "secret-enrol",
		},
	}
	s, _ := newBootstrapTestServer(t, fake)

	r := req(http.MethodPost, "/api/bootstrap/desktop", nil)
	r.Header.Set("Authorization", "Bearer invite-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("invite bearer 应可直接 bootstrap，状态码=%d body=%s", w.Code, w.Body.String())
	}
	if fake.got != "invite-secret" {
		t.Fatalf("bootstrapper 收到的 invite=%q", fake.got)
	}
	if strings.Contains(w.Body.String(), "admin") {
		t.Fatalf("bootstrap 响应不应泄露管理员身份：%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"probe_url":"http://127.0.0.1:19091"`) {
		t.Fatalf("bootstrap 响应必须包含独立就绪探测地址：%s", w.Body.String())
	}
}

func TestDesktopPairingInviteRequiresAdminCSRFAndOrigin(t *testing.T) {
	fake := &bootstrapFake{
		invite: DesktopPairingInviteResponse{
			ID:         "pinv-1",
			Token:      "invite-secret",
			Relay:      "127.0.0.1:18444",
			Pin:        "pin",
			ListenPort: 19091,
		},
	}
	s, _ := newBootstrapTestServer(t, fake)
	auth := bootstrapSetupAndLogin(t, s)

	t.Run("unauthenticated", func(t *testing.T) {
		r := req(http.MethodPost, "/api/pairing-invites", map[string]any{"listen_port": 19091})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("状态码=%d，期望 401", w.Code)
		}
	})

	t.Run("missing csrf", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/pairing-invites", map[string]any{"listen_port": 19091}))
		r.Header.Del(CSRFHeaderName)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码=%d，期望 403", w.Code)
		}
	})

	t.Run("bad origin", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/pairing-invites", map[string]any{"listen_port": 19091}))
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("状态码=%d，期望 403", w.Code)
		}
	})

	t.Run("valid", func(t *testing.T) {
		r := auth(req(http.MethodPost, "/api/pairing-invites", map[string]any{
			"ttl_seconds": 600,
			"listen_port": 19091,
			"note":        "fresh-e2e",
		}))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("状态码=%d body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"token":"invite-secret"`) {
			t.Fatalf("有效响应应包含一次性 invite：%s", w.Body.String())
		}
	})
}

func TestDesktopPairingInviteRejectsBackendInjectionAndUnknownFields(t *testing.T) {
	fake := &bootstrapFake{
		invite: DesktopPairingInviteResponse{ID: "pinv-1", Token: "invite-secret", ListenPort: 19091},
	}
	s, _ := newBootstrapTestServer(t, fake)
	auth := bootstrapSetupAndLogin(t, s)

	for _, body := range []string{
		`{"listen_port":19091,"backend":{"addr":"169.254.169.254:80"}}`,
		`{"listen_port":19091,"agent_id":"evil"}`,
		`{"listen_port":19091,"tunnel":{"backend":{"addr":"10.0.0.1:80"}}}`,
	} {
		r := req(http.MethodPost, "/api/pairing-invites", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r = auth(r)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: 状态码=%d，期望 400", body, w.Code)
		}
	}
}

func TestDesktopBootstrapRejectsBodyFieldsAndMapsInviteFailures(t *testing.T) {
	t.Run("body injection", func(t *testing.T) {
		fake := &bootstrapFake{}
		s, _ := newBootstrapTestServer(t, fake)
		r := req(http.MethodPost, "/api/bootstrap/desktop", map[string]any{
			"backend": "169.254.169.254:80",
		})
		r.Header.Set("Authorization", "Bearer invite-secret")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("状态码=%d，期望 400", w.Code)
		}
		if fake.got != "" {
			t.Fatal("非法 body 不应调用 bootstrapper")
		}
	})

	for _, tc := range []struct {
		name string
		err  error
		code int
		want string
	}{
		{"used", store.ErrPairingInviteUsed, http.StatusConflict, "invite_used"},
		{"expired", store.ErrPairingInviteExpired, http.StatusGone, "invite_expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &bootstrapFake{err: tc.err}
			s, _ := newBootstrapTestServer(t, fake)
			r := req(http.MethodPost, "/api/bootstrap/desktop", nil)
			r.Header.Set("Authorization", "Bearer invite-secret")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("状态码=%d，期望 %d body=%s", w.Code, tc.code, w.Body.String())
			}
			if got := decodeAPIError(t, w); got.Code != tc.want {
				t.Fatalf("错误码=%q，期望 %q", got.Code, tc.want)
			}
		})
	}
}

func TestDesktopPairingInviteDoesNotPutSecretsInEvent(t *testing.T) {
	fake := &bootstrapFake{
		invite: DesktopPairingInviteResponse{
			ID: "pinv-secret-id", Token: "invite-secret", Relay: "127.0.0.1:18444",
		},
	}
	s, db := newBootstrapTestServer(t, fake)
	auth := bootstrapSetupAndLogin(t, s)

	r := auth(req(http.MethodPost, "/api/pairing-invites", map[string]any{"listen_port": 19091}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("创建 invite 失败：%d %s", w.Code, w.Body.String())
	}
	events, err := db.ListEvents(r.Context(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "invite-secret") ||
			strings.Contains(event.Message, "secret-enrol") ||
			strings.Contains(event.Subject, "invite-secret") {
			t.Fatalf("事件包含敏感凭据：%+v", event)
		}
	}
}

func TestStatusForPairingInviteErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
		name string
	}{
		{store.ErrPairingInviteUsed, http.StatusConflict, "invite_used"},
		{store.ErrPairingInviteExpired, http.StatusGone, "invite_expired"},
		{store.ErrPairingInviteScopeDenied, http.StatusForbidden, "invite_denied"},
		{store.ErrPairingInviteBackendMismatch, http.StatusForbidden, "invite_denied"},
		{store.ErrPairingInviteTenantMismatch, http.StatusForbidden, "invite_denied"},
	} {
		code, name := statusFor(tc.err)
		if code != tc.code || name != tc.name {
			t.Errorf("statusFor(%v)=(%d,%q)，期望 (%d,%q)", tc.err, code, name, tc.code, tc.name)
		}
	}
	if errors.Is(store.ErrPairingInviteUsed, store.ErrPairingInviteExpired) {
		t.Fatal("invite sentinel errors must remain distinct")
	}
}
