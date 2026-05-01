-- =====================================================================
-- Tex Memory System — Master Schema (Migration 001)
--
-- This migration is the single source of truth for the durable memory
-- layer described in MEMORY.md. Every table below is required by the
-- locked spec. All statements are idempotent (CREATE ... IF NOT EXISTS)
-- so this file can be re-run on every deploy.
--
-- Layered design:
--   Layer 1 — Postgres (this file)      : system of record, durable
--   Layer 2 — In-process write-through  : performance cache (per-store)
--   Layer 3 — Append-only JSONL chain   : tamper-evident audit (file)
--                                         + tex_evidence_records mirror
--
-- Naming convention: every table is prefixed `tex_` for namespacing
-- against the leaderboard schema and any future co-tenanted apps.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. decisions — durable record of every PDP verdict.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_decisions (
    decision_id            UUID PRIMARY KEY,
    request_id             UUID NOT NULL,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    action_type            TEXT NOT NULL,
    channel                TEXT NOT NULL,
    environment            TEXT NOT NULL,
    recipient              TEXT,

    verdict                TEXT NOT NULL,
    confidence             DOUBLE PRECISION NOT NULL,
    final_score            DOUBLE PRECISION NOT NULL,

    content_excerpt        TEXT NOT NULL,
    content_sha256         TEXT NOT NULL,
    payload_fingerprint    TEXT NOT NULL,

    policy_id              TEXT,
    policy_version         TEXT NOT NULL,

    scores                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    findings               JSONB NOT NULL DEFAULT '[]'::jsonb,
    reasons                JSONB NOT NULL DEFAULT '[]'::jsonb,
    uncertainty_flags      JSONB NOT NULL DEFAULT '[]'::jsonb,
    asi_findings           JSONB NOT NULL DEFAULT '[]'::jsonb,
    retrieval_context      JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,

    determinism_fingerprint TEXT,
    evidence_hash          TEXT,
    latency                JSONB,

    decided_at             TIMESTAMPTZ NOT NULL,
    inserted_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_decisions_request_idx
    ON tex_decisions (request_id);
CREATE INDEX IF NOT EXISTS tex_decisions_tenant_decided_idx
    ON tex_decisions (tenant_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS tex_decisions_verdict_idx
    ON tex_decisions (verdict, decided_at DESC);
CREATE INDEX IF NOT EXISTS tex_decisions_policy_idx
    ON tex_decisions (policy_version, decided_at DESC);
CREATE INDEX IF NOT EXISTS tex_decisions_content_hash_idx
    ON tex_decisions (content_sha256);

-- ---------------------------------------------------------------------
-- 2. decision_inputs — full original input bytes per request, for
--                      faithful replay. Separated from tex_decisions
--                      because inputs may be large and are read rarely.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_decision_inputs (
    request_id             UUID PRIMARY KEY,
    decision_id            UUID,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    full_input             JSONB NOT NULL,
    input_sha256           TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_decision_inputs_decision_idx
    ON tex_decision_inputs (decision_id);
CREATE INDEX IF NOT EXISTS tex_decision_inputs_tenant_idx
    ON tex_decision_inputs (tenant_id, created_at DESC);

-- ---------------------------------------------------------------------
-- 3. policy_snapshots — versioned, immutable PolicySnapshot records.
--                       Replay uses this to reconstitute the exact
--                       config that produced a historical decision.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_policy_snapshots (
    policy_version         TEXT PRIMARY KEY,
    policy_id              TEXT NOT NULL,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    config                 JSONB NOT NULL,
    config_sha256          TEXT NOT NULL,
    is_active              BOOLEAN NOT NULL DEFAULT FALSE,
    created_at             TIMESTAMPTZ NOT NULL,
    activated_at           TIMESTAMPTZ,
    inserted_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_policy_snapshots_policy_id_idx
    ON tex_policy_snapshots (policy_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tex_policy_snapshots_active_idx
    ON tex_policy_snapshots (tenant_id, is_active);

-- Ensure exactly one active snapshot per (tenant, policy_id).
CREATE UNIQUE INDEX IF NOT EXISTS tex_policy_snapshots_one_active_idx
    ON tex_policy_snapshots (tenant_id, policy_id)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------
-- 4. permits — signed release tokens minted from PERMIT verdicts.
--              expiry + nonce make them single-use.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_permits (
    permit_id              UUID PRIMARY KEY,
    decision_id            UUID NOT NULL,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    nonce                  TEXT NOT NULL,
    signature              TEXT NOT NULL,
    expiry                 TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS tex_permits_nonce_idx
    ON tex_permits (tenant_id, nonce);
CREATE INDEX IF NOT EXISTS tex_permits_decision_idx
    ON tex_permits (decision_id);
CREATE INDEX IF NOT EXISTS tex_permits_expiry_idx
    ON tex_permits (expiry);

-- ---------------------------------------------------------------------
-- 5. verifications — record of every permit verification attempt.
--                    consumed_nonce ties the verification to the
--                    permit's nonce so double-use can be detected.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_verifications (
    verification_id        UUID PRIMARY KEY,
    permit_id              UUID NOT NULL,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    result                 TEXT NOT NULL,           -- VALID | EXPIRED | REVOKED | REUSED | INVALID_SIG
    consumed_nonce         TEXT NOT NULL,
    reason                 TEXT,
    metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_verifications_permit_idx
    ON tex_verifications (permit_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tex_verifications_result_idx
    ON tex_verifications (result, created_at DESC);

-- ---------------------------------------------------------------------
-- 6. evidence_records — Postgres mirror of the append-only JSONL
--                       evidence chain, indexed for query/export.
--                       The JSONL file remains the immutable source.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tex_evidence_records (
    record_id              UUID PRIMARY KEY,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    kind                   TEXT NOT NULL,           -- decision | outcome | snapshot | other
    aggregate_id           UUID NOT NULL,           -- decision_id, outcome_id, etc.
    request_id             UUID,
    policy_version         TEXT,
    payload_json           TEXT NOT NULL,
    payload_sha256         TEXT NOT NULL,
    record_hash            TEXT NOT NULL,
    previous_hash          TEXT,
    sequence_number        BIGSERIAL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS tex_evidence_records_record_hash_idx
    ON tex_evidence_records (record_hash);
CREATE INDEX IF NOT EXISTS tex_evidence_records_aggregate_idx
    ON tex_evidence_records (aggregate_id, created_at);
CREATE INDEX IF NOT EXISTS tex_evidence_records_kind_idx
    ON tex_evidence_records (tenant_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS tex_evidence_records_sequence_idx
    ON tex_evidence_records (tenant_id, sequence_number);
