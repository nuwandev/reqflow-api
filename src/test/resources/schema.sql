CREATE TABLE IF NOT EXISTS tenants (
    id UUID CONSTRAINT pk_tenants PRIMARY KEY,
    slug VARCHAR(255) NOT NULL CONSTRAINT uq_tenants_slug UNIQUE,
    name VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id UUID CONSTRAINT pk_teams PRIMARY KEY,
    tenant_id UUID NOT NULL CONSTRAINT fk_teams_tenants REFERENCES tenants (id),
    name VARCHAR(255) NOT NULL,
    description VARCHAR(255) NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    row_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_teams_tenant_id_name UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS users (
    id UUID CONSTRAINT pk_users PRIMARY KEY,
    tenant_id UUID NOT NULL CONSTRAINT fk_users_tenants REFERENCES tenants (id),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    team_id UUID NULL CONSTRAINT fk_users_teams REFERENCES teams (id),
    is_active BOOLEAN NOT NULL DEFAULT true,
    row_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_users_tenant_id_email UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID CONSTRAINT pk_auth_sessions PRIMARY KEY,
    tenant_id UUID NOT NULL CONSTRAINT fk_auth_sessions_tenants REFERENCES tenants (id),
    user_id UUID NOT NULL CONSTRAINT fk_auth_sessions_users REFERENCES users (id),
    refresh_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NULL,
    user_agent VARCHAR(255) NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NULL,
    replaced_by_session_id UUID NULL CONSTRAINT fk_auth_sessions_auth_sessions REFERENCES auth_sessions (id) ON DELETE SET NULL,
    rotated_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_auth_sessions_expires_after_issued CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS idx_teams_tenant_id ON teams (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id_role ON users (tenant_id, role);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id_team_id ON users (tenant_id, team_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant_id_user_id_expires_at ON auth_sessions (tenant_id, user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant_id_refresh_token_hash_active ON auth_sessions (tenant_id, refresh_token_hash, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant_id_user_id_revoked_at ON auth_sessions (tenant_id, user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant_token_hash_active ON auth_sessions (tenant_id, refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_revoked ON auth_sessions (expires_at, revoked_at);
