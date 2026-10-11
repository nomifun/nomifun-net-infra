package console

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
)

// DesktopBackendAddrV2 is reserved for the authenticated, loopback-only relay listener.
const DesktopBackendAddrV2 = "127.0.0.1:25811"

var ErrDesktopPrecondition = errors.New("Desktop 接入配置未就绪")

type DesktopCheck struct {
	Code    string `json:"code"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type DesktopPreflight struct {
	ProtocolVersion    int            `json:"protocol_version"`
	BootstrapURL       string         `json:"bootstrap_url"`
	DefaultBusinessURL string         `json:"default_business_url"`
	Ready              bool           `json:"ready"`
	Checks             []DesktopCheck `json:"checks"`
}

type DesktopInviteV2Request struct {
	TTLSeconds  int    `json:"ttl_seconds"`
	ListenPort  uint16 `json:"listen_port"`
	Note        string `json:"note"`
	BusinessURL string `json:"business_url"`
}

type DesktopBootstrapV2Response struct {
	DesktopBootstrapResponse
	ProtocolVersion int    `json:"protocol_version"`
	L2Port          uint16 `json:"l2_port"`
	ControlURL      string `json:"control_url"`
	ControlToken    string `json:"control_token"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
}

type DesktopConnection struct {
	ProtocolVersion int    `json:"protocol_version"`
	InviteID        string `json:"invite_id"`
	Note            string `json:"note"`
	TunnelID        string `json:"tunnel_id"`
	AgentID         string `json:"agent_id"`
	BusinessURL     string `json:"business_url"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	Revoked         bool   `json:"revoked"`
}

// Control credentials authorize only this connection; administrator sessions remain separate.
type DesktopConnections interface {
	DesktopPreflight() DesktopPreflight
	CreateDesktopInviteV2(context.Context, time.Duration, DesktopInviteV2Request) (DesktopPairingInviteResponse, error)
	BootstrapDesktopV2(context.Context, string, string) (DesktopBootstrapV2Response, error)
	ListDesktopConnections(context.Context) ([]DesktopConnection, error)
	DesktopConnection(context.Context, string, string, bool) (DesktopConnection, error)
	RevokeDesktopConnection(context.Context, string, string, bool) (DesktopConnection, error)
}

type DesktopBootstrapCanceler interface {
	CancelDesktopBootstrap(context.Context, string, string) (DesktopConnection, error)
}

func (s *Server) desktopConnections(w http.ResponseWriter) (DesktopConnections, bool) {
	api, ok := s.snapshot.(DesktopConnections)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented", "Relay 不支持 Desktop v2 接入")
	}
	w.Header().Set("Cache-Control", "no-store")
	return api, ok
}

func decodeDesktopBody(w http.ResponseWriter, r *http.Request, out any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体必须是支持的 JSON 对象")
		return false
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体包含多余内容")
		return false
	}
	return true
}

func (s *Server) handleDesktopPreflight(w http.ResponseWriter, r *http.Request, sess *session) {
	api, ok := s.desktopConnections(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, api.DesktopPreflight())
}

func (s *Server) handleCreateDesktopInviteV2(w http.ResponseWriter, r *http.Request, sess *session) {
	api, ok := s.desktopConnections(w)
	if !ok {
		return
	}
	var req DesktopInviteV2Request
	if !decodeDesktopBody(w, r, &req) {
		return
	}
	ttl := defaultDesktopPairingInviteTTL
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl <= 0 || ttl > maxDesktopPairingInviteTTL || len(req.Note) > 200 {
		writeError(w, http.StatusBadRequest, "invalid", "邀请期限应在 1 秒到 24 小时内；名称最多 200 字节")
		return
	}
	out, err := api.CreateDesktopInviteV2(r.Context(), ttl, req)
	if err != nil {
		writeDesktopError(w, err)
		return
	}
	_ = s.db.AppendEvent(r.Context(), store.Event{Kind: store.KindPairingInviteCreated, Level: store.LevelInfo, Message: "创建 Desktop v2 配对邀请", Actor: sess.Username})
	writeJSON(w, http.StatusOK, out)
}

func desktopBearer(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func writeDesktopError(w http.ResponseWriter, err error) {
	code, name := statusFor(err)
	writeError(w, code, name, err.Error())
}

func (s *Server) handleBootstrapDesktopV2(w http.ResponseWriter, r *http.Request) {
	api, ok := s.desktopConnections(w)
	if !ok {
		return
	}
	invite := desktopBearer(r)
	if invite == "" {
		writeError(w, http.StatusUnauthorized, "missing_invite", "需要一次性配对邀请")
		return
	}
	attempt, valid := desktopAttempt(w, r)
	if !valid {
		return
	}
	out, err := api.BootstrapDesktopV2(r.Context(), invite, attempt)
	if err != nil {
		writeDesktopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func desktopAttempt(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		AttemptID string `json:"attempt_id"`
	}
	if !decodeDesktopBody(w, r, &req) {
		return "", false
	}
	raw, err := hex.DecodeString(req.AttemptID)
	if err != nil || len(raw) != 32 || len(req.AttemptID) != 64 {
		writeError(w, http.StatusBadRequest, "invalid_attempt", "attempt_id 必须是客户端持久保存的 32 字节随机 hex 值")
		return "", false
	}
	return req.AttemptID, true
}

func (s *Server) handleCancelDesktopBootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	api, ok := s.snapshot.(DesktopBootstrapCanceler)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented", "Relay 不支持取消 Desktop v2 配对")
		return
	}
	invite := desktopBearer(r)
	if invite == "" {
		writeError(w, http.StatusUnauthorized, "missing_invite", "取消需要原配对邀请")
		return
	}
	attempt, valid := desktopAttempt(w, r)
	if !valid {
		return
	}
	out, err := api.CancelDesktopBootstrap(r.Context(), invite, attempt)
	if err != nil {
		writeDesktopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListDesktopConnections(w http.ResponseWriter, r *http.Request, sess *session) {
	api, ok := s.desktopConnections(w)
	if !ok {
		return
	}
	out, err := api.ListDesktopConnections(r.Context())
	if err != nil {
		writeDesktopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}

func (s *Server) handleDesktopConnection(w http.ResponseWriter, r *http.Request) {
	api, ok := s.desktopConnections(w)
	if !ok {
		return
	}
	handle := func(w http.ResponseWriter, r *http.Request, admin bool, token string) {
		var out DesktopConnection
		var err error
		if r.Method == http.MethodDelete {
			out, err = api.RevokeDesktopConnection(r.Context(), r.PathValue("id"), token, admin)
		} else {
			out, err = api.DesktopConnection(r.Context(), r.PathValue("id"), token, admin)
		}
		if err != nil {
			writeDesktopError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
	if token := desktopBearer(r); token != "" {
		handle(w, r, false, token)
		return
	}
	s.requireAuth(func(w http.ResponseWriter, r *http.Request, sess *session) { handle(w, r, true, "") })(w, r)
}
