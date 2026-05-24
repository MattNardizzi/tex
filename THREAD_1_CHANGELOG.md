# Thread 1 — Domain and Secrets Cleanup (Changelog)

**Date:** May 22, 2026
**Author:** Thread 1 work session
**Scope:** Per Section 15 of TEX_CANONICAL.md — replace every `tex.io` reference with `texaegis.com`, and add fail-closed startup guards for production secrets.

---

## 1. Domain swap: `tex.io` → `texaegis.com`

Zero occurrences of `tex.io` remain in `.py`, `.md`, `.sh`, `.toml`, or any other tracked file type.

### Files modified

| File | Change |
|---|---|
| `src/tex/vet/scitt.py:642` | `ts_uri` default — **critical** (this string was baked into signed SCITT receipts) |
| `src/tex/api/mcp_server.py:11` | MCP server config example in module docstring |
| `sdks/python/tex_guardrail/client.py` | `_DEFAULT_BASE_URL` constant + docstring |
| `sdks/python/tex_guardrail/__init__.py` | Quick-start example in module docstring |
| `sdks/python/README.md` | Quick-start code block |
| `INTEGRATIONS.md` | 12 occurrences across gateway adapter examples |
| `tests/vet/test_vet_routes.py:181` | Test fixture `iss` field |
| `tests/vet/test_primitives.py:137` | Test fixture `iss` field |
| `tests/test_integration_layer.py` | 4 URL-strip patterns + 1 ARP `source_register` (updated in lockstep with SDK base URL change) |
| `scripts/demo_thread_13.sh` | Demo `iss` field |
| `scripts/demo_thread_13_1.sh` | Demo `source_register` field |

### Verification
- `grep -rn "tex\.io" .` returns zero matches across the entire repo.
- All 114 integration-layer tests pass (these exercise the SDK URL-strip pattern that would break if the swap were inconsistent).

---

## 2. Production secrets — fail-closed startup guard

### Approach: Option B (centralized `pydantic-settings`)

Instead of the ad-hoc `if/raise` in `main.py` that the canonical doc suggested, the guard is centralized in `tex.config.Settings` using a `pydantic-settings` `@model_validator(mode="after")`. This is the state-of-the-art 2026 pattern (pydantic v2.11+, pydantic-settings v2.3+).

**Advantages over Option A:**
- Validation runs at config load (single source of truth, not scattered `os.environ.get`).
- `SecretStr` keeps the HMAC key out of `repr()`, exception tracebacks, and structured logs.
- `Literal` type for `tee_attestation_mode` makes invalid values a parse-time error, not a runtime surprise.
- Failure raises `pydantic.ValidationError` with full context; `main.py` re-raises as `RuntimeError` for operator clarity.

### What the guard enforces

When `TEX_APP_ENV` is anything outside `{dev, development, test, testing, local}` (i.e. "production-like"):

1. **`TEX_EVIDENCE_SUMMARY_SECRET` must be set and non-sentinel.** The in-repo `dev-only-change-me` value is explicitly rejected. This HMAC-SHA-256 key signs every governance evidence-bundle manifest and agent evidence summary — a weak key here breaks the cryptographic substrate downstream regulators/insurers/auditors verify against.

2. **`TEX_TEE_ATTESTATION_MODE` must not be `test`.** The TEE attestation composer (`tex.tee.attestation_client`, `tex.evidence.tee_binding`) only emits real Intel TDX + NVIDIA H100/H200/B200/B300 evidence in `production` mode (Intel Trust Authority `get_token_v2` composite token, April 2026 SDK). `test` mode is for local development only.

### Files modified

| File | Change |
|---|---|
| `src/tex/config.py` | Added `TeeAttestationMode` `Literal` alias, `_NON_PRODUCTION_APP_ENVS` frozenset, `evidence_summary_secret: SecretStr \| None` field, `tee_attestation_mode: TeeAttestationMode` field, `_normalize_tee_attestation_mode` validator, `is_production_like` property, `get_evidence_summary_secret()` accessor, `_validate_production_secrets` model_validator. |
| `src/tex/main.py` | Added `from tex.config import get_settings` import, `from pydantic import ValidationError` import, and a `try: get_settings()` block at the very top of `create_app()` that wraps any `ValidationError` / `ValueError` into a clear `RuntimeError`. |
| `src/tex/api/agent_routes.py` | Refactored `_sign_summary` to read the HMAC secret from `get_settings().get_evidence_summary_secret()` instead of `os.environ.get(..., "dev-only-change-me")`. Removed now-unused `import os`. |
| `src/tex/stores/governance_snapshots.py` | Refactored `export_evidence_bundle` to use `get_settings()` for the canonical secret name; preserved the `signing_secret_env` parameter for the rare caller that needs a different env var. |

### Verification (7 scenarios — all pass)

| # | Scenario | Expected | Actual |
|---|---|---|---|
| 1 | dev env, no secret | Accept | ✅ Accept |
| 2 | production env, no secret | Reject | ✅ Reject |
| 3 | production env, sentinel secret | Reject | ✅ Reject |
| 4 | production env, real secret, TEE mode `test` | Reject | ✅ Reject |
| 5 | production env, real secret, TEE mode `production` | Accept | ✅ Accept |
| 6 | staging env, no secret | Reject | ✅ Reject |
| 7 | `development` env (long form) | Accept | ✅ Accept |

`SecretStr` repr correctly shows `SecretStr('**********')` — secret never leaks.

End-to-end test: `import tex.main` with `TEX_APP_ENV=production` and no secret triggers `RuntimeError: Tex refused to start: environment configuration failed fail-closed validation.` with the full pydantic-validator remediation message attached.

---

## 3. Tangential fixes done in-flight

The canonical doc says "if you see something that needs to be updated, update it" (not "leave it for the next thread"). The following gaps were fixed in this thread because they were either preconditions for verification or directly adjacent to Thread 1's scope.

### 3.1 `requirements.txt` sync with `pyproject.toml`
`requirements.txt` was missing `pyasn1`, `pyasn1_modules`, and `blake3` — even though `pyproject.toml` had them. This would silently break anyone bootstrapping via `pip install -r requirements.txt`. Added all three to `requirements.txt` with annotations cross-referencing the standards they support (draft-ietf-lamps-pq-composite-sigs-18, arxiv 2605.06788).

### 3.2 Note on canonical doc accuracy
The canonical doc's Section 5 claimed `pyproject.toml` was missing `pyasn1`, `pyasn1_modules`, `blake3`, `psycopg`, and `asyncpg`. The actual repo state shows `pyproject.toml` already has the first three in `[project.dependencies]` and the latter two in `[project.optional-dependencies.postgres]` — likely already partly addressed before this thread began. This thread's Thread-2-related fix is therefore limited to `requirements.txt` sync.

The canonical doc's Section 8 of stale-docs map should note: `pyproject.toml` is **further along than the doc claims**, not behind.

### 3.3 Settings expansion
The canonical doc lists `TEX_EVIDENCE_SUMMARY_SECRET` and `TEX_TEE_ATTESTATION_MODE` as env vars but they were not previously in `tex.config.Settings`. They are now first-class typed fields with `SecretStr` and `Literal` typing respectively. This closes a longstanding gap where these production-critical secrets were only accessible via raw `os.environ.get` calls.

---

## 4. Verification summary

- **3,791** unit tests pass
- **114** integration-layer tests pass
- **18** causal/perf tests pass when run alone
- **34** tests skipped (pre-existing, unrelated to Thread 1)
- **0** failures attributable to Thread 1 changes

The single perf test (`test_fast_attribute_under_5ms_p99`) that failed when running the full suite together is environment-bound (shared-VM CPU contention) — it passes when run in isolation. Not a Thread 1 regression.

---

## 5. What this thread did NOT do (out of scope)

Strictly per the canonical doc's "stay in your lane" rule:

- ❌ Did not touch the multi-tenant `enforce_tenant_match` gap (Thread 3).
- ❌ Did not wire C2PA emission or the digital twin (Thread 5).
- ❌ Did not expose pitch HTTP routes (Thread 4).
- ❌ Did not fix the jailbreak recognizers or evidence bundle slice verifier (Thread 6).
- ❌ Did not wire the EcosystemEngine (Thread 7).
- ❌ Did not sweep stale `TODO(P0)` markers (Thread 8).
- ❌ Did not fix VET cert pinning or ZKPROV regulator_grade default (Thread 9).
- ❌ Did not add `var/` to `.gitignore` or remove the committed `var/tex/evidence/evidence.jsonl` (Thread 8).

---

## 6. Next thread

Thread 2 — Fix the test suite on a clean install.

Most of Thread 2's prescribed scope is already done (`pyproject.toml` had the deps before this thread; `requirements.txt` now matches). Remaining Thread 2 work:
- Move `KNOWN_BUGS.md` Bug #1 to Resolved.
- Verify `requires-python = ">=3.12"` is justified by actual 3.12-only syntax — relax to `>=3.11` if not.
- Verify clean-install flow in a fresh venv against the now-synced `requirements.txt`.
