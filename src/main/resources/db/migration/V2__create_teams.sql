CREATE TABLE teams
(
    id          uuid
        CONSTRAINT pk_teams PRIMARY KEY,
    tenant_id   uuid        NOT NULL
        CONSTRAINT fk_teams_tenants REFERENCES tenants (id),
    name        text        NOT NULL,
    description text        NULL,
    is_active   boolean     NOT NULL DEFAULT true,
    row_version bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    CONSTRAINT uq_teams_tenant_id_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_teams_tenant_id ON teams (tenant_id);

