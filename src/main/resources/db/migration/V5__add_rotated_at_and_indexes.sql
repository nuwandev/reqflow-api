-- V5: Add rotated_at column to auth_sessions
-- Tracks the exact moment a session was rotated into a successor token.
-- This timestamp is distinct from revoked_at and enables the 15-second
-- multi-tab grace-period guard in RefreshTokenService, preventing a second
-- concurrent browser tab from being mistakenly flagged as a token-reuse attack.

ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS rotated_at timestamptz NULL;

-- Composite index to support the tenant-scoped, hash-based lookup used by
-- findByRefreshTokenHashForUpdate. Covers the WHERE clause:
--   refresh_token_hash = ? AND tenant_id = ?
-- The partial WHERE revoked_at IS NULL keeps the index small by excluding
-- already-invalidated sessions from the hot lookup path.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant_token_hash_active
    ON auth_sessions (tenant_id, refresh_token_hash)
    WHERE revoked_at IS NULL;

-- Index to accelerate the background cleanup scheduler DELETE query which
-- filters on expires_at and revoked_at across all tenants.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_revoked
    ON auth_sessions (expires_at, revoked_at);
