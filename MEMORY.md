# Tex Memory System — Production Implementation Guide (Final)

## Objective

Define a production-grade memory system for Tex that guarantees:

- Durability
- Auditability
- Replayability
- Deterministic behavior
- High-performance reads

## Core Principle

**Postgres is the system of record. Everything else supports it.**

---

## 1. Architecture

### Layer 1 — Durable Memory (Primary)

- Technology: Postgres
- Role: Single source of truth

### Layer 2 — In-Memory Cache (Performance)

- Technology: Python in-memory cache (or Redis later)
- Role: Fast reads for real-time evaluation

### Layer 3 — Evidence Log (Audit)

- Technology: Append-only JSONL + hash chain
- Role: Tamper-evident audit trail

---

## 2. Required Postgres Tables

### `tex_decisions`

- `decision_id` (PK)
- `tenant_id`
- `action_type`
- `content_hash` (`content_sha256`)
- `payload_fingerprint`
- `verdict`
- `confidence`
- `scores` (JSON)
- `reasons` (JSON)
- `policy_version`
- `created_at` (`decided_at`)

### `tex_decision_inputs`

- `request_id` (PK)
- `tenant_id`
- `full_input` (JSON)
- `created_at`

### `tex_outcomes`

- `outcome_id` (PK)
- `decision_id` (FK)
- `tenant_id`
- `label`
- `trust_level`
- `confidence_score`
- `reporter` (`reporter_id`)
- `created_at` (`recorded_at`)

### `tex_policy_snapshots`

- `policy_version` (PK)
- `tenant_id`
- `config` (JSON)
- `created_at`

### `tex_calibration_proposals`

- `proposal_id` (PK)
- `tenant_id`
- `proposed_changes` (JSON)
- `status`
- `created_by`
- `approved_by`
- `created_at`
- `approved_at`

### `tex_agent_registry`

- `agent_id` (PK)
- `tenant_id`
- `name`
- `type`
- `trust_tier`
- `capabilities` (JSON)
- `created_at`

### `tex_reporter_reputation`

- `reporter` (PK)
- `tenant_id`
- `accuracy_score`
- `disagreement_rate`
- `volume`
- `last_updated`

### `tex_permits`

- `permit_id` (PK)
- `decision_id`
- `tenant_id`
- `expiry`
- `nonce`
- `signature`
- `created_at`

### `tex_verifications`

- `verification_id` (PK)
- `permit_id`
- `result`
- `consumed_nonce`
- `created_at`

### `tex_evidence_records`

- `record_id` (PK)
- `tenant_id`
- `kind`
- `aggregate_id`
- `record_hash`
- `previous_hash`
- `created_at`

---

## 3. Write-Through Pattern

1. Write to Postgres
2. If success → update cache
3. If failure → abort

## 4. Read Pattern

- Cache first
- Fallback to Postgres

## 5. Evidence Log

- Append-only
- Hash chained
- Exportable for audits

## 6. Replay

Replay must:

1. Load decision
2. Load policy snapshot
3. Load original input
4. Re-run evaluation
5. Compare outputs

## 7. Learning System

- Derived from Postgres only
- Generates proposals only
- Never auto-mutates policy

## 8. Critical Rules

- Everything linked by IDs
- No orphan records
- No silent failures

## 9. Avoid

- Vector DB as source of truth
- Kafka / streaming as core memory
- Multiple conflicting databases

## 10. Production Ready When

- All stores in Postgres
- Cache is write-through
- Evidence is immutable
- Replay is deterministic
- Learning is approval-gated

## Final Statement

Tex is a system of record for AI decisions. Build it like one.

---

## Appendix A — Code map

| Spec section | Module |
| --- | --- |
| Migration (every table in §2) | `src/tex/db/migrations/001_memory_system.sql` |
| Sync Postgres helper | `src/tex/memory/_db.py` |
| §2.1 `tex_decisions` | `src/tex/memory/decision_store.py` (`DurableDecisionStore`) |
| §2.2 `tex_decision_inputs` | `src/tex/memory/decision_input_store.py` |
| §2.3 `tex_outcomes` | `src/tex/stores/outcome_store.py` (pre-existing) |
| §2.4 `tex_policy_snapshots` | `src/tex/memory/policy_snapshot_store.py` (`DurablePolicyStore`) |
| §2.5 `tex_calibration_proposals` | `src/tex/stores/calibration_proposal_store.py` (pre-existing) |
| §2.6 `tex_agent_registry` | `src/tex/stores/agent_registry_postgres.py` (pre-existing) |
| §2.7 `tex_reporter_reputation` | `src/tex/learning/reporter_reputation.py` (pre-existing) |
| §2.8 `tex_permits` | `src/tex/memory/permit_store.py` |
| §2.9 `tex_verifications` | `src/tex/memory/verification_store.py` |
| §2.10 `tex_evidence_records` | `src/tex/memory/evidence_store.py` (mirror of JSONL) |
| §3 Write-through | `src/tex/memory/system.py` (`MemorySystem.record_decision`) |
| §4 Read pattern | every `Durable*` store: cache first, Postgres fallback |
| §5 Evidence log | `src/tex/evidence/recorder.py` + `evidence_store.py` mirror |
| §6 Replay | `src/tex/memory/replay.py` (`MemoryReplayEngine`) |
| §7 Learning | `src/tex/learning/*` (proposals only; gate via `tex_calibration_proposals.status`) |

## Appendix B — Operational notes

### Configuration

- `DATABASE_URL` — required for durability. When unset, every store
  logs a warning and runs in-memory only. Restart loses everything.
- `TEX_EVIDENCE_PATH` (consumed at the call site of `MemorySystem`) —
  filesystem path for the JSONL chain. Default: `./data/evidence.jsonl`.

### Migrations

`ensure_memory_schema()` runs `001_memory_system.sql` on first connection
and is process-idempotent. Every statement uses `IF NOT EXISTS` so it
is also database-idempotent. New migrations ship under
`src/tex/db/migrations/NNN_*.sql` and are applied via
`apply_migration(name)`.

### Failure semantics

The locked spec rule "no silent failures" is enforced by the
`MemorySystem` orchestrator: a Postgres write that raises propagates
out of `record_decision` and the caller decides what to do. The
in-memory cache is **never** updated when the durable write fails.
Two consequences:

1. There is no quiet drift between cache and Postgres.
2. Bursts of database errors will surface as evaluation errors, not
   as undetected data loss. This is intentional.

### Replay determinism

`MemoryReplayEngine` compares fingerprints first, then verdict, then
confidence, then final_score. The `determinism_fingerprint` is the
ground truth — if it matches, the deterministic + specialist + semantic
score paths reproduced exactly. A verdict mismatch with matching
fingerprint indicates a fusion-weight or threshold change, which is
exactly what calibration replay (`tex/learning/replay.py`) is for.

### What's intentionally NOT in this layer

- **Vector retrieval.** The retrieval layer (`src/tex/retrieval/`) keeps
  its own indices. The locked spec forbids using a vector DB as the
  system of record; we honour this by keeping retrieval purely a
  derived read structure rebuilt from Postgres.
- **Streaming.** No Kafka / Redpanda / pub-sub. Cross-process
  invalidation, if it ever becomes necessary, will be a `LISTEN`/
  `NOTIFY` channel on Postgres, not a separate broker.
- **Auto-mutating learners.** The calibrator generates `CalibrationProposal`
  rows; nothing auto-applies them. Approval is logged in
  `tex_calibration_proposal_events`.

---

## §11. Runtime integration (V18 production wiring)

This section documents how the memory layer plugs into the live runtime.

### One MemorySystem per process

`build_runtime()` constructs **exactly one** `MemorySystem` instance and
exposes it as `runtime.memory`. The runtime's `decision_store`,
`policy_store`, and `evidence_recorder` fields are aliases for
`runtime.memory.decisions`, `runtime.memory.policies`, and
`runtime.memory.recorder` respectively. Two parallel decision stores
would write the same rows twice — there is exactly one source of truth
per aggregate.

### Atomic write path

Every `EvaluateActionCommand.execute(...)` call routes through
`MemorySystem.record_decision_with_policy(...)`, which performs:

```
BEGIN
  INSERT INTO tex_decisions          (decision_id, ...)
  INSERT INTO tex_decision_inputs    (request_id, full_input, decision_id)
  INSERT INTO tex_policy_snapshots   (policy_version, config, ...)   [idempotent]
COMMIT
APPEND  → evidence.jsonl              (hash-chained record)
INSERT  → tex_evidence_records        (mirror, ON CONFLICT DO NOTHING)
```

The three Postgres writes are wrapped in a single transaction
(`connect_tx()`). Either all three commit or none of them do. The JSONL
chain append happens after the transaction commits because it's the
file-backed source of truth for evidence; the Postgres mirror is
idempotent and never blocks the chain.

### Backward compatibility

`EvaluateActionCommand` accepts an optional `memory_system` constructor
arg. When provided (the production runtime), it routes the write path
through `MemorySystem`. When `None` (legacy unit tests, factories,
ad-hoc command construction), it falls back to the historical
`decision_store.save()` + `evidence_recorder.record_decision()`
sequence. Both paths produce identical `EvidenceRecord` payloads — the
only difference is durability and atomicity.

### Cache invalidation

`DurableDecisionStore` and `DurablePolicyStore` expose a `cache_version`
counter, monotonically incremented on every successful save/delete.
This is the foundation for cross-process invalidation; single-process
deployments never see drift, but the hook is there for the eventual
`LISTEN`/`NOTIFY` channel on Postgres.

### Permit / verification linkage

`MemorySystem.link_permit_to_decision(decision=...)` enforces the
spec's permit/decision linkage at the type level: a permit cannot be
issued without a `Decision` object, so `decision_id` is always present
on the resulting `tex_permits` row. Verification attempts are logged
to `tex_verifications` keyed by `permit_id`, completing the chain.

### Failure semantics (locked spec § "no silent failures")

| Failure                       | Behavior                                     |
| ---                           | ---                                          |
| Postgres tx fails             | Raises; nothing committed; caller decides    |
| JSONL append fails after tx   | Raises; Postgres has the decision but no chain entry. The chain self-heals on the next successful append. |
| Mirror insert fails           | Raises; JSONL is authoritative.              |
| `DATABASE_URL` unset          | All stores log a warning and run in pure in-memory mode. Replay still works within the process lifetime. |

### Tests

`tests/test_runtime_memory_integration.py` asserts every spec
invariant against the real `build_runtime()` output. Combined with
`tests/test_memory_system.py`, the memory layer has 29 tests covering
every documented behavior.
