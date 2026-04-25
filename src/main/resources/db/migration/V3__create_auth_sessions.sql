CREATE TABLE auth_sessions (
    id uuid CONSTRAINT pk_auth_sessions PRIMARY KEY,
    tenant_id uuid NOT NULL CONSTRAINT fk_auth_sessions_tenants REFERENCES tenants(id),
    user_id uuid NOT NULL CONSTRAINT fk_auth_sessions_users REFERENCES users(id),
    refresh_token_hash text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    replaced_by_session_id uuid NULL CONSTRAINT fk_auth_sessions_auth_sessions REFERENCES auth_sessions(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT chk_auth_sessions_expires_after_issued CHECK (expires_at > issued_at)
);

CREATE INDEX idx_auth_sessions_tenant_id_user_id_expires_at ON auth_sessions (tenant_id, user_id, expires_at);
CREATE INDEX idx_auth_sessions_tenant_id_refresh_token_hash_active ON auth_sessions (tenant_id, refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_tenant_id_user_id_revoked_at ON auth_sessions (tenant_id, user_id, revoked_at);
