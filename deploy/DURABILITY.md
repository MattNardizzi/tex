# Tex durability — what survives a restart, and what we will not pretend

> Track: `durable`. Scope: `stores/`, `db/`, `memory/`, `deploy/`, `render.yaml`,
> `Dockerfile`, one self-contained `observability/metrics.py` + a 1-line wire in
> `main.py`. Claims below are backed by `path:line` in the live code; re-verify
> against the code before relying on them (per CLAUDE.md).

## The honest one-line positioning

**Tex ships today as a single-replica, single-worker durable pilot.** With a
persistent volume at `/app/var/tex` and `DATABASE_URL` set, one Tex web instance
survives a restart with **zero evidence-chain loss**, and all shared aggregates
write through to Postgres. It is **not** multi-replica / HA, and Postgres is an
**audit mirror, not a rebuildable chain**. A provable single-process pilot beats
a false HA badge — so we state the limit instead of hiding it.

## What is durable behind `DATABASE_URL` (the default, when set)

When `DATABASE_URL` is set, the stores write through to Postgres synchronously
and bootstrap their schema idempotently on construction (no manual migration
step). When it is unset, every store falls back to in-memory and a restart
erases state — the app logs a warning and keeps running (dev mode).

| Surface | Durable when `DATABASE_URL` set? | Evidence |
|---|---|---|
| decisions, inputs, policies, permits, verifications, evidence **mirror** | yes (write-through, schema on boot) | `memory/system.py:121` (`ensure_memory_schema`), `memory/_db.py` |
| precedent / agent registry / discovery ledger / action ledger | yes (Postgres variant selected) | `main.py:557` (`if database_configured:`) |
| outcome, governance snapshots, drift events, scan runs, connector health | yes (each self-reads `DATABASE_URL` at construction) | `stores/outcome_store.py:108`, `stores/governance_snapshots.py`, `stores/drift_events.py`, `stores/scan_runs.py`, `stores/connector_health.py` |
| C2PA manifest mirror, legacy evidence mirror, provenance-proof store (zkprov) | yes | `main.py:603,610`; `api/zkprov_routes.py:62` |
| entity store, tenant baseline | n/a — re-seeded / rebuilt on boot by design | `main.py:577,580` |

You can see the live state on `GET /metrics`: `tex_database_configured`,
`tex_memory_durable`, and per-store `tex_store_durable{store="…"}`.

## The evidence chain — file-authoritative, volume-backed

The authoritative evidence record is a **hash-chained, append-only JSONL file**
(`main.py:118` → `var/tex/evidence/evidence.jsonl`; under the image's
`WORKDIR=/app` that is `/app/var/tex/evidence/evidence.jsonl`). On boot,
`EvidenceRecorder` reads the file's last record and **continues the chain** from
its hash (`evidence/recorder.py:78`, `:673-695`). Therefore:

- **The chain survives a restart *iff the file survives*.** On an ephemeral
  container filesystem the file is gone on reschedule and the recorder silently
  restarts from genesis. ⇒ a persistent volume at the evidence dir is mandatory.
- **The evidence-seal signing key** persists to `var/tex/keys/evidence_seal_key.json`
  and is **regenerated if missing** (`evidence/seal.py:171-224`). A lost key
  breaks signature-authorship continuity across restarts. ⇒ the volume is mounted
  at the **parent** `/app/var/tex` so it covers both `evidence/` and `keys/`.
- **Postgres does not rebuild the chain.** The mirrors are INSERT-only audit
  copies (`evidence/postgres_mirror.py:24-28` declares JSONL the source of truth;
  the mirror is `INSERT … ON CONFLICT DO NOTHING`, `:173`); the recorder never
  reads Postgres to set its chain head. "Rebuild the chain from Postgres" is
  **false** — the mirror is for query/audit, the volume is for continuity.

> **Scope of "zero evidence-chain loss":** this is the `EvidenceRecorder` JSONL
> decision/outcome chain. The *behavioral provenance ledger* (the identity
> "continuous witness", `provenance/ledger.py`) is a **separate** log that is
> in-memory only and does **not** survive a restart (fresh signing key per boot,
> `ledger.py:60-67`). Making it durable is truth-track work — see the deferred
> list below. Do not read "zero evidence-chain loss" as "all logs persist."

## Why `replicas: 1` (and `--workers 1`) — not an oversight

Two facts make a second PDP instance unsafe **today**:

1. **The chain head lives in per-process memory off a per-process file.** Each
   `EvidenceRecorder` holds `_last_record_hash` under a process-local lock
   (`recorder.py:78`). Two instances writing two files = **two divergent chains**
   that cannot be reconciled into one append-only log. The Postgres mirror cannot
   serialize the head (`ON CONFLICT DO NOTHING` drops the loser, it does not
   order writers).
2. **Caches, the discovery scheduler, and `/metrics` counters are
   process-local.** A second instance runs a second `BackgroundScanScheduler`
   (double scans/alerts; presence transitions race —
   `discovery/presence.py:397-423`) and serves a different counter view per
   scrape.

So the Helm chart pins `replicas: 1` + `strategy: Recreate` (an RWO volume can't
be held by two pods during a rollout), the Dockerfile runs `--workers 1`, and a
Render disk forces a single instance. A guard test
(`tests/test_durable_single_writer_guard.py`) fails if either knob regresses.

## What multi-replica / HA would require (deferred — and to whom)

This is **truth-track** work (it changes `evidence/` + `provenance/`, which the
durable lane does not own). It cannot be faked from a `stores/` wrapper — doing
so would be a nanozk-class lie. The conditions:

- **DB-serialized chain append** (`evidence/recorder.py`): the recorder must read
  the chain head from a shared row under a row lock *inside* append, and write
  the canonical chain to that shared row, not a per-pod file. This matches the
  2025–2026 transparency-log state of the art: Rekor v2 (GA) delegates sequencing
  to the storage backend (Trillian-Tessera over Spanner / Aurora-MySQL / POSIX);
  the **DB is the single point of serialization**, and Tessera explicitly does
  not guarantee in-batch ordering, so strict chaining must block on the DB.
  (sigstore.dev `rekor-v2-ga`; `transparency-dev/trillian-tessera`, retrieved
  2026-06-09.)
- **Durable provenance ledger** (`provenance/ledger.py`, `provenance/__init__.py`):
  `BehavioralProvenanceLedger` is in-memory with a fresh signing key per boot
  (`ledger.py:60-67`); `build_default_provenance_engine()` (used at `main.py:676`)
  never wires the existing `PostgresBehavioralProvenanceLedger`
  (`stores/behavioral_provenance_ledger_postgres.py`, currently unwired). It must
  be wired and made the source `rebuild_from_ledger()` replays from.
- **Leader election** for the discovery scheduler, or move presence transitions
  behind an exclusive lock.
- *(Optional, robustness)* honor `TEX_EVIDENCE_PATH` in `create_app()` so the
  chain location is env-driven rather than relying on `WORKDIR`+mount alignment
  (a 1-line `main.py` follow-up; the Dockerfile already pins `WORKDIR=/app`).

Until those land, **do not raise `replicas` / `numInstances` / `--workers`.**

## Observability

`GET /metrics` is a top-level Prometheus/OpenMetrics surface
(`observability/metrics.py`) aggregating process + HTTP + durability + discovery
+ learning counters — zero new hard deps, rendered by hand like the existing
`learning/observability.py`. It is **single-process** (consistent with one
worker); multiple workers/replicas would make the counters per-process and
require a multiprocess collector. An optional OTLP push bridge activates only
when `opentelemetry-sdk` is installed (`requirements-otel.txt`) **and**
`OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise it is a fail-open no-op.
