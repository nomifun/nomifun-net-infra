-- +goose Up
-- A v2 invite owns one recoverable provisioning attempt and its exact enrol token.
-- All credentials remain SHA-256 hashes; no response or plaintext token is stored.
ALTER TABLE pairing_invites ADD COLUMN bootstrap_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE pairing_invites ADD COLUMN business_url TEXT NOT NULL DEFAULT '';
ALTER TABLE pairing_invites ADD COLUMN attempt_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE pairing_invites ADD COLUMN control_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE pairing_invites ADD COLUMN enrol_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE pairing_invites ADD COLUMN enrol_expires_at INTEGER;
ALTER TABLE pairing_invites ADD COLUMN revoked_at INTEGER;

-- +goose Down
ALTER TABLE pairing_invites DROP COLUMN revoked_at;
ALTER TABLE pairing_invites DROP COLUMN enrol_expires_at;
ALTER TABLE pairing_invites DROP COLUMN enrol_token_hash;
ALTER TABLE pairing_invites DROP COLUMN control_hash;
ALTER TABLE pairing_invites DROP COLUMN attempt_hash;
ALTER TABLE pairing_invites DROP COLUMN business_url;
ALTER TABLE pairing_invites DROP COLUMN bootstrap_version;
