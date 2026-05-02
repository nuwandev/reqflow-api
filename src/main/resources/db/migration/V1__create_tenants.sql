CREATE TABLE tenants
(
    id         uuid
        CONSTRAINT pk_tenants PRIMARY KEY,
    slug       text        NOT NULL
        CONSTRAINT uq_tenants_slug UNIQUE,
    name       text        NOT NULL,
    is_active  boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);