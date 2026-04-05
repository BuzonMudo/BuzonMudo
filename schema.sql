-- Buzon Mudo — Esquema de Base de Datos

CREATE TABLE IF NOT EXISTS drops (
    id              VARCHAR(64)     PRIMARY KEY,
    encrypted_text  TEXT,
    encrypted_file  BYTEA,
    ip_hash         VARCHAR(64)     NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drops_expires ON drops (expires_at);


