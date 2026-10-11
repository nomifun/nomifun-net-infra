package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// PeekPairingInvite reads invitation metadata without consuming its bearer token.
// ProvisionDesktop repeats all authorization checks inside its writer transaction.
func (d *DB) PeekPairingInvite(ctx context.Context, plainToken string) (*PairingInvite, error) {
	if plainToken == "" {
		return nil, ErrNotFound
	}
	return scanPairingInvite(d.read.QueryRowContext(ctx,
		pairingInviteSelect+` WHERE token_hash = ?`, hashToken(plainToken)))
}

// DesktopTunnelID identifies the one tunnel owned by a v2 invitation.
func DesktopTunnelID(inviteID string) string {
	return "t-desktop-" + strings.TrimPrefix(inviteID, "pinv-")
}

// ProvisionDesktop consumes a v2 invitation, creates its enrol token and writes
// its tunnel atomically. The same secret attempt can recover the exact credentials
// after a lost response, without storing plaintext credentials in the database.
// The returned tunnel is copied into t only after the transaction succeeds.
func (d *DB) ProvisionDesktop(
	ctx context.Context, inviteToken, attemptID string,
	req PairingInviteRedeemRequest, t *tunnel.Tunnel, enrolTTL time.Duration,
) (*PairingInvite, string, string, error) {
	if inviteToken == "" {
		return nil, "", "", ErrNotFound
	}
	if err := validatePairingInviteRedeemRequest(req); err != nil {
		return nil, "", "", err
	}
	if err := validateDesktopAttempt(attemptID); err != nil {
		return nil, "", "", err
	}
	if t == nil {
		return nil, "", "", errors.New("store: desktop provisioning requires a tunnel")
	}
	if enrolTTL < time.Second {
		return nil, "", "", errors.New("store: desktop enrol TTL must be at least one second")
	}

	enrolToken := desktopProvisioningToken("enrol", "nf_enrol_", inviteToken, attemptID)
	controlToken := desktopProvisioningToken("control", "nf_desktop_", inviteToken, attemptID)
	attemptHash := hashToken(attemptID)
	enrolHash := hashToken(enrolToken)
	controlHash := hashToken(controlToken)

	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("store: begin desktop provisioning: %w", err)
	}
	defer tx.Rollback()

	record, err := scanPairingInviteRecord(tx.QueryRowContext(ctx,
		pairingInviteSelect+` WHERE token_hash = ?`, hashToken(inviteToken)))
	if err != nil {
		return nil, "", "", err
	}
	invite := &record.PairingInvite
	if invite.BootstrapVersion != 2 {
		return nil, "", "", ErrPairingInviteVersionMismatch
	}
	if invite.TenantID != req.TenantID {
		return nil, "", "", ErrPairingInviteTenantMismatch
	}
	if !scopesContain(invite.Scopes, req.Scopes) {
		return nil, "", "", ErrPairingInviteScopeDenied
	}
	if !equalBackend(invite.Backend, req.Backend) {
		return nil, "", "", ErrPairingInviteBackendMismatch
	}
	if !invite.RevokedAt.IsZero() {
		return nil, "", "", ErrDesktopConnectionRevoked
	}

	ts := now()
	if !invite.UsedAt.IsZero() {
		if subtle.ConstantTimeCompare([]byte(record.attemptHash), []byte(attemptHash)) != 1 {
			return nil, "", "", ErrPairingInviteUsed
		}
		if subtle.ConstantTimeCompare([]byte(record.enrolTokenHash), []byte(enrolHash)) != 1 ||
			subtle.ConstantTimeCompare([]byte(record.controlHash), []byte(controlHash)) != 1 {
			return nil, "", "", errors.New("store: inconsistent desktop provisioning credentials")
		}
		var expiresAt int64
		var usedAt sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT expires_at, used_at FROM enrol_tokens WHERE token_hash = ? AND tenant_id = ?`,
			enrolHash, invite.TenantID).Scan(&expiresAt, &usedAt); err != nil {
			return nil, "", "", fmt.Errorf("store: recover desktop enrol token: %w", err)
		}
		if !usedAt.Valid && ts > expiresAt {
			return nil, "", "", ErrDesktopEnrolExpired
		}
		persisted, err := scanTunnel(tx.QueryRowContext(ctx,
			tunnelSelect+` WHERE id = ? AND tenant_id = ? AND agent_id = ?`,
			invite.TunnelID, invite.TenantID, invite.AgentID))
		if err != nil {
			return nil, "", "", fmt.Errorf("store: recover desktop tunnel: %w", err)
		}
		*t = *persisted
		return invite, enrolToken, controlToken, nil
	}
	if ts > invite.ExpiresAt.Unix() {
		return nil, "", "", ErrPairingInviteExpired
	}
	if err := checkDesktopOriginTx(ctx, tx, invite); err != nil {
		return nil, "", "", err
	}

	prepared := t.Clone()
	prepared.ID = DesktopTunnelID(invite.ID)
	if prepared.Slug == "" {
		prepared.Slug = strings.TrimPrefix(prepared.ID, "t-")
	}
	prepared.TenantID = invite.TenantID
	prepared.AgentID = EnrolAgentID(enrolToken)
	prepared.Backend = invite.Backend
	prepared.Kind = tunnel.KindService
	prepared.L4 = tunnel.L4TCP
	prepared.TLS = invite.TLS
	if invite.TLS == tunnel.TLSGateway {
		prepared.Exposure = tunnel.ExposureShared
		prepared.ListenPort = 0
		prepared.Router = &tunnel.Router{
			Kind: tunnel.RouterHTTP, Domains: []string{invite.PublicHostname},
			HostRewrite: invite.Backend.Addr,
		}
	} else {
		prepared.Exposure = tunnel.ExposurePort
		prepared.ListenPort = invite.PublicPort
		prepared.Router = nil
	}

	// First provisioning never overwrites an independently created object with
	// the deterministic ID. Retrying a committed attempt takes the branch above.
	var occupied int
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM tunnels WHERE id = ?) OR
		EXISTS(SELECT 1 FROM agents WHERE id = ?)`,
		prepared.ID, prepared.AgentID).Scan(&occupied); err != nil {
		return nil, "", "", fmt.Errorf("store: check desktop provisioning ownership: %w", err)
	}
	if occupied != 0 {
		return nil, "", "", ErrConflict
	}

	enrolExpiresAt := ts + int64(enrolTTL/time.Second)
	if _, err := tx.ExecContext(ctx, `
		UPDATE pairing_invites SET used_at = ?, used_by = ?, attempt_hash = ?,
			control_hash = ?, enrol_token_hash = ?, enrol_expires_at = ?
		WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`,
		ts, req.UsedBy, attemptHash, controlHash, enrolHash, enrolExpiresAt, invite.ID); err != nil {
		return nil, "", "", fmt.Errorf("store: consume desktop invite: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO enrol_tokens (token_hash, tenant_id, created_at, expires_at, note)
		VALUES (?,?,?,?,?)`, enrolHash, invite.TenantID, ts, enrolExpiresAt,
		"Desktop bootstrap "+invite.ID); err != nil {
		return nil, "", "", classifyConstraint(err)
	}
	if err := putTunnelTx(ctx, tx, prepared); err != nil {
		return nil, "", "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", "", fmt.Errorf("store: commit desktop provisioning: %w", err)
	}

	invite.UsedAt = time.Unix(ts, 0)
	invite.UsedBy = req.UsedBy
	invite.EnrolExpiresAt = time.Unix(enrolExpiresAt, 0)
	invite.AgentID = prepared.AgentID
	invite.TunnelID = prepared.ID
	*t = *prepared
	return invite, enrolToken, controlToken, nil
}

func checkDesktopOriginTx(ctx context.Context, tx *sql.Tx, invite *PairingInvite) error {
	if invite.TLS != tunnel.TLSGateway {
		return nil // The unique listen-port index reserves independent HTTP entries.
	}
	var occupied int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM pairing_invites WHERE bootstrap_version = 2 AND id != ?
		AND used_at IS NOT NULL AND revoked_at IS NULL AND tls_mode = ?
		AND lower(public_hostname) = lower(?) AND public_port = ?)`,
		invite.ID, string(tunnel.TLSGateway), invite.PublicHostname, invite.PublicPort).Scan(&occupied); err != nil {
		return fmt.Errorf("store: check desktop business origin: %w", err)
	}
	if occupied != 0 {
		return fmt.Errorf("%w: desktop business origin is already bound", ErrConflict)
	}
	rows, err := tx.QueryContext(ctx, tunnelSelect+` WHERE exposure = ? AND tls_mode = ?`,
		string(tunnel.ExposureShared), string(tunnel.TLSGateway))
	if err != nil {
		return fmt.Errorf("store: check desktop shared routes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		existing, err := scanTunnel(rows)
		if err != nil {
			return err
		}
		if !existing.IsEnabled() || existing.Router == nil {
			continue
		}
		for _, domain := range existing.Router.Domains {
			if strings.EqualFold(domain, invite.PublicHostname) {
				return fmt.Errorf("%w: desktop hostname is already routed", ErrConflict)
			}
		}
	}
	return rows.Err()
}

func desktopProvisioningToken(domain, prefix, inviteToken, attemptID string) string {
	// Each field is separated; the two derived credentials use different domains.
	sum := sha256.Sum256([]byte("nomifun-desktop-bootstrap-v2\x00" + domain + "\x00" + inviteToken + "\x00" + attemptID))
	return prefix + hex.EncodeToString(sum[:])
}

// DesktopConnection authenticates only the control credential belonging to id.
// Revoked metadata remains readable so a disconnected Desktop can show the reason.
func (d *DB) DesktopConnection(ctx context.Context, id, controlToken string) (*PairingInvite, error) {
	record, err := scanPairingInviteRecord(d.read.QueryRowContext(ctx,
		pairingInviteSelect+` WHERE id = ? AND bootstrap_version = 2`, id))
	if err != nil {
		return nil, err
	}
	if !desktopControlMatches(record, controlToken) {
		return nil, ErrNotFound
	}
	return &record.PairingInvite, nil
}

// ListDesktopConnections returns v2 invitations and their durable connection state.
// It deliberately omits credential hashes and plaintext credentials.
func (d *DB) ListDesktopConnections(ctx context.Context, tenantID string) ([]*PairingInvite, error) {
	rows, err := d.read.QueryContext(ctx,
		pairingInviteSelect+` WHERE tenant_id = ? AND bootstrap_version = 2 ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list desktop connections: %w", err)
	}
	defer rows.Close()
	connections := make([]*PairingInvite, 0)
	for rows.Next() {
		invite, err := scanPairingInvite(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, invite)
	}
	return connections, rows.Err()
}

// RevokeDesktopConnection revokes the invitation, exact enrol credential, agent
// credential and owned tunnel in one transaction. Repeating it is safe.
func (d *DB) RevokeDesktopConnection(ctx context.Context, id, controlToken string) (*PairingInvite, error) {
	return d.revokeDesktopConnection(ctx, id, controlToken, false)
}

// RevokeDesktopConnectionAsAdmin requires authorization by its administrator caller.
// It is explicit; an empty Desktop control token never selects administrator mode.
func (d *DB) RevokeDesktopConnectionAsAdmin(ctx context.Context, id string) (*PairingInvite, error) {
	return d.revokeDesktopConnection(ctx, id, "", true)
}

// CancelDesktopBootstrap recovers the cancellation authority of a lost bootstrap
// response. An unused invite needs its bearer; a committed invite additionally
// needs the same secret attempt. Expiry never prevents cleaning up its own result.
func (d *DB) CancelDesktopBootstrap(ctx context.Context, inviteToken, attemptID string) (*PairingInvite, error) {
	if inviteToken == "" {
		return nil, ErrNotFound
	}
	if err := validateDesktopAttempt(attemptID); err != nil {
		return nil, err
	}
	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin desktop bootstrap cancellation: %w", err)
	}
	defer tx.Rollback()
	record, err := scanPairingInviteRecord(tx.QueryRowContext(ctx,
		pairingInviteSelect+` WHERE token_hash = ?`, hashToken(inviteToken)))
	if err != nil {
		return nil, err
	}
	if record.BootstrapVersion != 2 {
		return nil, ErrPairingInviteVersionMismatch
	}
	if !record.UsedAt.IsZero() &&
		subtle.ConstantTimeCompare([]byte(record.attemptHash), []byte(hashToken(attemptID))) != 1 {
		return nil, ErrPairingInviteUsed
	}
	invite, err := revokeDesktopConnectionTx(ctx, tx, record)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit desktop bootstrap cancellation: %w", err)
	}
	return invite, nil
}

func (d *DB) revokeDesktopConnection(ctx context.Context, id, controlToken string, admin bool) (*PairingInvite, error) {
	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin desktop revocation: %w", err)
	}
	defer tx.Rollback()
	record, err := scanPairingInviteRecord(tx.QueryRowContext(ctx,
		pairingInviteSelect+` WHERE id = ? AND bootstrap_version = 2`, id))
	if err != nil {
		return nil, err
	}
	if !admin && !desktopControlMatches(record, controlToken) {
		return nil, ErrNotFound
	}
	invite, err := revokeDesktopConnectionTx(ctx, tx, record)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit desktop revocation: %w", err)
	}
	return invite, nil
}

func revokeDesktopConnectionTx(ctx context.Context, tx *sql.Tx, record *pairingInviteRecord) (*PairingInvite, error) {
	invite := &record.PairingInvite
	if !invite.RevokedAt.IsZero() {
		return invite, nil
	}

	ts := now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE pairing_invites SET revoked_at = ? WHERE id = ?`, ts, invite.ID); err != nil {
		return nil, fmt.Errorf("store: revoke desktop invite: %w", err)
	}
	if record.enrolTokenHash != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE enrol_tokens SET expires_at = MIN(expires_at, ?), used_at = COALESCE(used_at, ?)
			WHERE token_hash = ? AND tenant_id = ?`,
			ts, ts, record.enrolTokenHash, invite.TenantID); err != nil {
			return nil, fmt.Errorf("store: revoke desktop enrol token: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE agents SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND tenant_id = ?`,
			ts, invite.AgentID, invite.TenantID); err != nil {
			return nil, fmt.Errorf("store: revoke desktop agent: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM tunnels WHERE id = ? AND tenant_id = ?`,
			invite.TunnelID, invite.TenantID); err != nil {
			return nil, fmt.Errorf("store: delete desktop tunnel: %w", err)
		}
	}
	invite.RevokedAt = time.Unix(ts, 0)
	return invite, nil
}

func validateDesktopAttempt(attemptID string) error {
	if len(attemptID) != 64 {
		return errors.New("store: desktop provisioning attempt must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(attemptID); err != nil {
		return errors.New("store: desktop provisioning attempt must be 64 hexadecimal characters")
	}
	return nil
}

func desktopControlMatches(record *pairingInviteRecord, plainToken string) bool {
	return plainToken != "" && record.controlHash != "" &&
		subtle.ConstantTimeCompare([]byte(record.controlHash), []byte(hashToken(plainToken))) == 1
}
