-- +goose Up
-- ??? Desktop pairing invite?
--
-- token_hash ?? SHA-256?scope/backend ?????? invite ?????
-- ??????????????????????????
CREATE TABLE pairing_invites (
    id              TEXT    PRIMARY KEY,
    token_hash      TEXT    NOT NULL UNIQUE,
    tenant_id       TEXT    NOT NULL DEFAULT 'default',
    scopes_json     TEXT    NOT NULL,
    backend_json    TEXT    NOT NULL,
    public_hostname TEXT    NOT NULL DEFAULT '',
    public_port     INTEGER NOT NULL DEFAULT 0,
    tls_mode        TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    used_by         TEXT,
    note            TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_pairing_invites_tenant ON pairing_invites(tenant_id);
CREATE INDEX idx_pairing_invites_expiry ON pairing_invites(expires_at);

-- +goose Down
DROP TABLE pairing_invites;
