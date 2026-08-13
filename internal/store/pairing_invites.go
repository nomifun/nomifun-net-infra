package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// PairingInvite ???? Desktop ???????????
//
// ?? token ???????????????????????
// CreatePairingInvite ??????????Backend ?????????
// Desktop ?????????????????? provisioning ???? SSRF?
type PairingInvite struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Scopes         []string       `json:"scopes"`
	Backend        tunnel.Backend `json:"backend"`
	PublicHostname string         `json:"public_hostname,omitempty"`
	PublicPort     uint16         `json:"public_port,omitempty"`
	TLS            tunnel.TLSMode `json:"tls"`
	CreatedAt      time.Time      `json:"created_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	UsedAt         time.Time      `json:"used_at,omitzero"`
	UsedBy         string         `json:"used_by,omitempty"`
	Note           string         `json:"note,omitempty"`
}

// PairingInviteSpec ????????????????
type PairingInviteSpec struct {
	TenantID       string
	Scopes         []string
	Backend        tunnel.Backend
	PublicHostname string
	PublicPort     uint16
	TLS            tunnel.TLSMode
	TTL            time.Duration
	Note           string
}

// PairingInviteRedeemRequest ? Desktop ???????????????
//
// Scopes ????? scopes ????Backend ????????? backend
// ?????TenantID ?????????? invite bearer token ????
// ???????????????????
type PairingInviteRedeemRequest struct {
	TenantID string
	Scopes   []string
	Backend  tunnel.Backend
	UsedBy   string
}

var (
	ErrPairingInviteUsed            = errors.New("store: pairing invite ????")
	ErrPairingInviteExpired         = errors.New("store: pairing invite ???")
	ErrPairingInviteScopeDenied     = errors.New("store: pairing invite scope ?????")
	ErrPairingInviteBackendMismatch = errors.New("store: pairing invite backend ?????")
	ErrPairingInviteTenantMismatch  = errors.New("store: pairing invite tenant ?????")
)

// CreatePairingInvite ???????? Desktop ????????? token
// ??? token ????????? token ??????????? invite URL?
func (d *DB) CreatePairingInvite(ctx context.Context, spec PairingInviteSpec) (string, *PairingInvite, error) {
	if err := validatePairingInviteSpec(spec); err != nil {
		return "", nil, err
	}

	plain, tokenHash, err := newPairingInviteToken()
	if err != nil {
		return "", nil, err
	}
	id := "pinv-" + tokenHash[:16]
	scopes := canonicalScopes(spec.Scopes)
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return "", nil, fmt.Errorf("store: ?? pairing invite scopes ???%w", err)
	}
	backendJSON, err := json.Marshal(spec.Backend)
	if err != nil {
		return "", nil, fmt.Errorf("store: ?? pairing invite backend ???%w", err)
	}

	ts := now()
	expiresAt := ts + int64(spec.TTL/time.Second)
	_, err = d.write.ExecContext(ctx, `
		INSERT INTO pairing_invites (
			id, token_hash, tenant_id, scopes_json, backend_json,
			public_hostname, public_port, tls_mode, created_at, expires_at, note
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		id, tokenHash, spec.TenantID, string(scopesJSON), string(backendJSON),
		spec.PublicHostname, spec.PublicPort, string(spec.TLS), ts, expiresAt, spec.Note)
	if err != nil {
		return "", nil, fmt.Errorf("store: ?? pairing invite ???%w", err)
	}

	return plain, &PairingInvite{
		ID:             id,
		TenantID:       spec.TenantID,
		Scopes:         scopes,
		Backend:        spec.Backend,
		PublicHostname: spec.PublicHostname,
		PublicPort:     spec.PublicPort,
		TLS:            spec.TLS,
		CreatedAt:      time.Unix(ts, 0),
		ExpiresAt:      time.Unix(expiresAt, 0),
		Note:           spec.Note,
	}, nil
}

// GetPairingInvite ??? ID ?????????? token?
func (d *DB) getPairingInvite(ctx context.Context, id string) (*PairingInvite, error) {
	row := d.read.QueryRowContext(ctx, pairingInviteSelect+` WHERE id = ?`, id)
	return scanPairingInvite(row)
}

// RedeemPairingInvite ?????? pairing invite?
//
// ????????? used_at ??? UPDATE ?????????????
// ????????????????????? ErrPairingInviteUsed?
// ????tenant?scope?backend ???????????
func (d *DB) RedeemPairingInvite(
	ctx context.Context,
	plainToken string,
	req PairingInviteRedeemRequest,
) (*PairingInvite, error) {
	if plainToken == "" {
		return nil, ErrNotFound
	}
	if err := validatePairingInviteRedeemRequest(req); err != nil {
		return nil, err
	}

	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ???????%w", err)
	}
	defer tx.Rollback()

	var invite PairingInvite
	var scopesJSON, backendJSON, tlsMode string
	var createdAt, expiresAt int64
	var usedAt sql.NullInt64
	var usedBy sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, tenant_id, scopes_json, backend_json, public_hostname,
		       public_port, tls_mode, created_at, expires_at, used_at, used_by, note
		FROM pairing_invites WHERE token_hash = ?`, hashToken(plainToken)).
		Scan(&invite.ID, &invite.TenantID, &scopesJSON, &backendJSON,
			&invite.PublicHostname, &invite.PublicPort, &tlsMode, &createdAt,
			&expiresAt, &usedAt, &usedBy, &invite.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ???%w", err)
	}
	if usedAt.Valid {
		return nil, ErrPairingInviteUsed
	}

	ts := now()
	if ts > expiresAt {
		return nil, ErrPairingInviteExpired
	}
	if invite.TenantID != req.TenantID {
		return nil, ErrPairingInviteTenantMismatch
	}
	if err := decodePairingInviteFields(&invite, scopesJSON, backendJSON, tlsMode, createdAt, expiresAt); err != nil {
		return nil, err
	}
	if !scopesContain(invite.Scopes, req.Scopes) {
		return nil, ErrPairingInviteScopeDenied
	}
	if !equalBackend(invite.Backend, req.Backend) {
		return nil, ErrPairingInviteBackendMismatch
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE pairing_invites
		SET used_at = ?, used_by = ?
		WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?`,
		ts, req.UsedBy, hashToken(plainToken), ts)
	if err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ???%w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ???????%w", err)
	}
	if n != 1 {
		// ????????????????????????????
		var consumed sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT used_at FROM pairing_invites WHERE token_hash = ?`, hashToken(plainToken)).
			Scan(&consumed); err == nil && consumed.Valid {
			return nil, ErrPairingInviteUsed
		}
		return nil, ErrPairingInviteExpired
	}

	invite.UsedAt = time.Unix(ts, 0)
	invite.UsedBy = req.UsedBy
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ?????%w", err)
	}
	return &invite, nil
}

const pairingInviteSelect = `
	SELECT id, tenant_id, scopes_json, backend_json, public_hostname,
	       public_port, tls_mode, created_at, expires_at, used_at, used_by, note
	FROM pairing_invites`

func scanPairingInvite(sc rowScanner) (*PairingInvite, error) {
	var (
		invite                       PairingInvite
		scopesJSON, backendJSON, tls string
		createdAt, expiresAt         int64
		usedAt                       sql.NullInt64
		usedBy                       sql.NullString
	)
	err := sc.Scan(&invite.ID, &invite.TenantID, &scopesJSON, &backendJSON,
		&invite.PublicHostname, &invite.PublicPort, &tls, &createdAt, &expiresAt,
		&usedAt, &usedBy, &invite.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: ?? pairing invite ???%w", err)
	}
	if err := decodePairingInviteFields(&invite, scopesJSON, backendJSON, tls, createdAt, expiresAt); err != nil {
		return nil, err
	}
	if usedAt.Valid {
		invite.UsedAt = time.Unix(usedAt.Int64, 0)
	}
	if usedBy.Valid {
		invite.UsedBy = usedBy.String
	}
	return &invite, nil
}

func decodePairingInviteFields(
	invite *PairingInvite,
	scopesJSON, backendJSON, tlsMode string,
	createdAt, expiresAt int64,
) error {
	if err := json.Unmarshal([]byte(scopesJSON), &invite.Scopes); err != nil {
		return fmt.Errorf("store: ?? pairing invite scopes ???%w", err)
	}
	if err := json.Unmarshal([]byte(backendJSON), &invite.Backend); err != nil {
		return fmt.Errorf("store: ?? pairing invite backend ???%w", err)
	}
	invite.TLS = tunnel.TLSMode(tlsMode)
	invite.CreatedAt = time.Unix(createdAt, 0)
	invite.ExpiresAt = time.Unix(expiresAt, 0)
	return nil
}

func validatePairingInviteSpec(spec PairingInviteSpec) error {
	if strings.TrimSpace(spec.TenantID) == "" {
		return errors.New("store: pairing invite tenant ????")
	}
	if err := validateScopes(spec.Scopes); err != nil {
		return err
	}
	if err := validatePairingBackend(spec.Backend); err != nil {
		return err
	}
	if spec.TTL < time.Second {
		return errors.New("store: pairing invite TTL ????? 1 ?")
	}
	if spec.TLS != tunnel.TLSPassthrough && spec.TLS != tunnel.TLSGateway {
		return fmt.Errorf("store: pairing invite tls ???%q", spec.TLS)
	}
	if spec.PublicPort == 0 && spec.PublicHostname != "" {
		return errors.New("store: pairing invite public hostname ?????? public port")
	}
	return nil
}

func validatePairingInviteRedeemRequest(req PairingInviteRedeemRequest) error {
	if strings.TrimSpace(req.TenantID) == "" {
		return ErrPairingInviteTenantMismatch
	}
	if err := validateScopes(req.Scopes); err != nil {
		return err
	}
	return nil
}

func validateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return ErrPairingInviteScopeDenied
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, "\t\r\n") {
			return fmt.Errorf("store: pairing invite scope ???%q", scope)
		}
		if _, ok := seen[scope]; ok {
			return fmt.Errorf("store: pairing invite scope ???%q", scope)
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func canonicalScopes(scopes []string) []string {
	out := slices.Clone(scopes)
	slices.Sort(out)
	return out
}

func scopesContain(allowed, requested []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}
	return true
}

func validatePairingBackend(backend tunnel.Backend) error {
	if backend.Kind != tunnel.BackendAddr {
		return errors.New("store: pairing invite backend ??? addr")
	}
	host, port, err := net.SplitHostPort(backend.Addr)
	if err != nil {
		return fmt.Errorf("store: pairing invite backend ?????%w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return errors.New("store: pairing invite backend ??? loopback IP ??")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return errors.New("store: pairing invite backend ??????")
	}
	return nil
}

func equalBackend(a, b tunnel.Backend) bool {
	return a.Kind == b.Kind && a.Addr == b.Addr && a.Path == b.Path
}

func newPairingInviteToken() (plain, tokenHash string, err error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("store: 生成 pairing invite 令牌失败：%w", err)
	}
	plain = "nf_pair_" + hex.EncodeToString(raw)
	return plain, hashToken(plain), nil
}
