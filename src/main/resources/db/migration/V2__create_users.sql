
CREATE TABLE users (
    id uuid CONSTRAINT pk_users PRIMARY KEY,
    tenant_id uuid NOT NULL CONSTRAINT fk_users_tenants REFERENCES tenants(id),
    email text NOT NULL,
    password_hash text NOT NULL,
    full_name text NOT NULL,
    role text NOT NULL CONSTRAINT chk_users_role CHECK (role IN ('REQUESTOR', 'AGENT', 'MANAGER', 'ADMIN')),
    team_id uuid NULL CONSTRAINT fk_users_teams REFERENCES teams(id),
    is_active boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_users_tenant_id_email UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant_id_role ON users (tenant_id, role);
CREATE INDEX idx_users_tenant_id_team_id ON users (tenant_id, team_id);
