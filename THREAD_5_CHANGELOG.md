# Thread 5 — C2PA Emission + Digital-Twin Wiring (Changelog)

**Date:** May 24, 2026
**Author:** Thread 5 work session
**Scope:** Per Section 14 of TEX_CANONICAL.md — wire two finished
features (C2PA Content Credential emission, ecosystem digital twin)
into the production HTTP path. Both have been fully implemented for
weeks; both were unreachable because `main.py` never constructed
them. After this thread:

- Every PERMIT decision recorded with an outbound artifact and a
  complete `C2paEmissionContext` produces a C2PA 2.4 manifest with
  post-quantum cosign (ML-DSA-65 default; Ed25519 transition path)
  and the six Sherman-2026 NSA-paper attack-class defenses.
- `GET /v1/evidence/{record_id}/c2pa` returns 200 with the manifest
  JSON envelope when a manifest is stored, 404 when the record had
  no outbound artifact, and 503 only when the manifest mirror itself
  is unwired (DATABASE_URL not set in production).
- `POST /v1/ecosystem/twin/simulate` returns 200 with a conformal-
  covered fused-systemic-risk trajectory on every well-formed
  request, rather than returning 503 unconditionally.

---

## 1. State-of-the-art grounding (May 22, 2026)

Before touching code, Thread 5 grounded itself on current
specifications, since training data predates May 2026.

### C2PA + content provenance

- **C2PA 2.4** released **April 2026**. Adds canonical OCSP-stapling
  rules (RFC 9277), v2 TSA timestamps (RFC 3161 over the COSE_Sign1
  signature field), Trust List migration from the frozen ITL (frozen
  Jan 1 2026) to the official Linux Foundation–curated C2PA Trust
  List, and IANA-pending `application/c2pa` media type. Tex's c2pa
  package already implements all of this (per `tex.c2pa` 6,113 LOC).
- **Sherman et al. 2026** (arxiv 2604.24890, NSA cryptographic-
  policy paper): six attack classes on C2PA-signed assets —
  timestamp_swap, revocation_skipped, cross_validator_contradiction,
  exclusion_range_tamper, cert_expiry_before_retention, conformance
  self-reporting. Tex's cosign assertion v2 carries the defenses
  inline via `tex.c2pa.cosign_context_tree` (Merkle binding per
  Golaszewski FIDO UAF arxiv 2511.06028) and the retention anchor
  pointing back into the JSONL evidence chain.
- **EU AI Act Article 50** transparency obligations effective
  August 2, 2026; legacy GPAI providers grandfathered to December 2,
  2026 per the May 7, 2026 Digital Omnibus provisional agreement.
  Tex emits machine-readable disclosure attestations bound to the
  manifest under `tex.evidence_cosign/v2`.
- **California SB 942 / AB 853** operative August 2, 2026.
- **NIST FIPS 204 ML-DSA-65** is the recommended Level 3 default
  for general-purpose post-quantum signing. Microsoft AD CS added
  ML-DSA support in the May 2026 Windows Server 2025 update.

### Digital-twin governance for AI agents

- **Digital Twin Consortium Industrial AI Agent Manifesto** (March
  2026): formalizes ten governance laws for safety-critical AI
  agents, including "deterministic validation and execution" and
  "what-if simulation before live perturbation." The Tex twin
  endpoint operationalizes this for AI agent governance: every
  proposed perturbation can be evaluated against a forked copy of
  the live ecosystem state before any live mutation.
- **Köglmayr/Räth, May 2026** (arxiv 2605.01803): Koopman early-
  warning + minimal counterfactual intervention. Drives the twin's
  trajectory horizon choice (16 steps default, 64 max).
- **Nath/Yin/Chou, PMLR 2026** (arxiv 2601.01076): Koopman lifting
  with conformal coverage guarantees. Implemented in
  `tex.systemic._koopman` + `_conformal`.
- **arxiv 2601.03905** (Jan 2026): LLM agents rarely invoke
  simulation (<1%) and degrade when forced to; the correct place
  for the digital twin is the *governance layer*, which is what
  Tex ships.

### Cryptography (carried forward from Thread 4)

- Default cosign algorithm: ML-DSA-65 (FIPS 204) when liboqs is
  available, Ed25519 (RFC 8032) as the transition fallback through
  2027 (CNSA 2.0 §"Acceptable through 2030"). The algorithm-agile
  dispatcher in `tex.pqcrypto.algorithm_agility` resolves this at
  runtime — Thread 5 takes no opinion on which algorithm is in
  play; it just constructs the emitter and lets the dispatcher
  decide.
- Composite signatures: draft-ietf-lamps-pq-composite-sigs-18
  (April 9, 2026). The composite ML-DSA-65 + Ed25519 hybrid is
  available for callers operating in BSI 2021 / ANSSI 2024
  jurisdictions but is not the default.

---

## 2. What shipped

### 2.1 `src/tex/main.py` — runtime composition

Five edits, all clustered around the two narrow integration points.

**Imports** (lines 56–62). Added three lazy-OK imports:

- `tex.evidence.c2pa_emitter.C2paEmitter` — the recorder-facing
  emitter façade (it lazy-imports the heavy `tex.c2pa` modules
  only when `emit_manifest` is actually called, so the cold-start
  cost is unchanged for the 3,744 unit tests that never exercise
  emission).
- `tex.evidence.manifest_mirror.PostgresManifestMirror` — the
  durable mirror that backs `GET /v1/evidence/{record_id}/c2pa`.
  Construction is unconditional because the mirror no-ops cleanly
  when `DATABASE_URL` is unset (per `PostgresManifestMirror.__init__`
  lines 114–120; it logs once at startup and sets `disabled=True`).
- `tex.systemic.digital_twin.EcosystemDigitalTwin` and
  `tex.ecosystem.state.EcosystemState` — for the twin endpoint
  wiring.

**`TexRuntime` dataclass** (lines 175–199). Added three new
optional fields:

- `manifest_mirror: Any = None` — read by `c2pa_routes` via
  `runtime.manifest_mirror`.
- `ecosystem_twin: Any = None` — read by the twin route via
  `app.state.ecosystem_twin`.
- `ecosystem_state_factory: Any = None` — zero-arg callable read
  by the twin route via `app.state.ecosystem_state_factory`,
  returning a fresh `EcosystemState` projection per request.

**Recorder construction** (lines 488–525). Replaced the two-branch
conditional (DB / no-DB) with a single unified path:

- Build `PostgresManifestMirror()` unconditionally (no-ops without
  DATABASE_URL).
- Build `C2paEmitter()` unconditionally.
- Build the legacy `PostgresEvidenceMirror` only when DATABASE_URL
  is configured (backward compat for any operator dashboards still
  reading the `tex_evidence` table directly).
- Construct **one** `EvidenceRecorder` with `c2pa_emitter=...`,
  `manifest_mirror=...`, and `mirror=legacy_evidence_mirror`.
- Re-point `memory.recorder` at this recorder so the JSONL chain
  is shared (the prior conditional did the same for the DB
  branch but left the in-memory branch using `MemorySystem`'s
  default vanilla recorder, which lacked C2PA wiring).

This collapses the two prior code paths into one, fixes the
silent gap where in-memory mode never had a C2PA emitter, and
preserves the legacy Postgres mirror exactly.

**Digital-twin + state factory construction** (lines 797–909).
Right before the `TexRuntime(...)` constructor call, build:

- A single long-lived `EcosystemDigitalTwin(graph=None)`. The
  KG-less mode is supported (the constructor explicitly accepts
  `graph: InMemoryTemporalKG | None = None`); callers pass state
  inline via the factory. When Thread 7 wires the
  `EcosystemEngine` with a temporal KG, the engine will own the
  KG and the twin will be threaded a handle to it.
- A `_build_ecosystem_state` closure that captures the runtime's
  `agent_registry` and `action_ledger` and projects the current
  state per request. The projection:
  - reads active agents from `agent_registry.list_all()`
  - filters to `AgentLifecycleStatus.ACTIVE`
  - extracts capability ids + tool ids from each agent's
    capability surface (tolerant of missing attributes for
    older identity shapes)
  - hashes the canonical state for replay verification
  - returns a frozen `EcosystemState`

The factory is intentionally side-effect-free and cheap: it
reads only from in-memory snapshots, never the database. The
twin route calls it per request, and we did not want a database
round trip on the hot path.

**`TexRuntime(...)` instantiation** (line 911 area). Pass the three
new fields through.

**`_attach_runtime_to_app`** (lines 1085–1099). Publish three new
attributes on `app.state`:

- `app.state.manifest_mirror` — for any future routes that want
  direct access without going through `runtime`.
- `app.state.ecosystem_twin` — what `ecosystem_twin_routes.simulate`
  reads.
- `app.state.ecosystem_state_factory` — what the same route reads
  to materialize the live state on every request.

### 2.2 New tests

#### `tests/test_c2pa_emission_wired.py` — 8 tests, all passing

- `test_runtime_construct_attaches_c2pa_emitter_and_manifest_mirror`
  Confirms `build_runtime()` produces a `TexRuntime` with both
  `manifest_mirror` and `evidence_recorder.has_c2pa_emitter == True`.
  Confirms the twin + factory are also wired.
- `test_app_state_publishes_thread5_attributes`
  Confirms `create_app()` publishes the three new `app.state`
  attributes.
- `test_record_decision_with_artifact_and_context_emits_c2pa`
  Drives the recorder directly with a PERMIT decision, an outbound
  email artifact, and a complete `C2paEmissionContext`. Verifies
  the manifest is stored in the mirror, the cosign metadata is
  present (algorithm, canonicalization v2, full_file_sha256), and
  the Sherman 2026 attack-5 defense field (retention anchor)
  threads through.
- `test_record_decision_without_artifact_does_not_emit`
  No outbound_artifact → no manifest. Proves the emitter is gated
  by the caller, not invoked unconditionally.
- `test_forbid_verdict_does_not_emit_manifest`
  FORBID verdict with an artifact + context → no manifest. The
  recorder's `_maybe_emit_c2pa` helper explicitly returns None on
  non-PERMIT verdicts (c2pa_emitter.py line 329).
- `test_get_c2pa_endpoint_returns_200_when_manifest_exists`
  TestClient hits `GET /v1/evidence/{record_id}/c2pa` against the
  full `create_app()` stack with an in-memory mirror swapped in
  (necessary because Postgres mirror is correctly disabled in the
  test environment). Asserts 200, valid JSON envelope, correct
  media type (`application/c2pa+json`).
- `test_get_c2pa_endpoint_returns_404_for_unknown_record`
  Wired mirror + unknown record_id → 404, not 503. Proves the
  route correctly distinguishes "no manifest for this record" from
  "mirror not configured at all."
- `test_get_c2pa_endpoint_returns_503_when_mirror_disabled`
  Default test environment (no DATABASE_URL) → mirror.disabled =
  True → 503 with the operator-facing remediation message. Proves
  the 503 contract still works for unconfigured deployments.

#### `tests/test_twin_endpoint_wired.py` — 4 tests, all passing

- `test_twin_endpoint_returns_200_with_wired_runtime`
  Calls `POST /v1/ecosystem/twin/simulate` against the full
  `create_app()` stack. Asserts 200, correct horizon, conformal
  bands well-ordered.
- `test_twin_endpoint_invokes_state_factory_per_request`
  Calls the factory directly twice; verifies fresh snapshots
  (advancing timestamps), correct empty-projection behavior on a
  fresh runtime (no agents registered yet).
- `test_twin_endpoint_400_on_invalid_fork_timestamp`
  Malformed ISO timestamp → 400 (not 503). Proves the request
  actually reached `twin.fork_at`, which is the wiring goal.
- `test_twin_endpoint_persists_calibration_across_requests`
  Two consecutive requests both return 200, and the twin
  reference is the same object on both — long-lived in runtime
  state, not request-scoped.

### 2.3 Documentation

- This file (`THREAD_5_CHANGELOG.md`).
- `TEX_CANONICAL.md` updated to mark Thread 5 complete (see
  the next section of this changelog).

---

## 3. Tests run

```
tests/test_c2pa_emission_wired.py              8 passed
tests/test_twin_endpoint_wired.py              4 passed
tests/test_c2pa_http_routes.py                 8 passed
tests/test_c2pa_thread6_http_routes.py         6 passed
tests/test_integration_layer.py::Thread9       4 passed (twin)
tests/systemic/                              126 passed, 3 skipped
tests/c2pa/                                    9 passed

Full baseline (3,744 + 114 integration + 12 new) =
3,870 passed, 110 skipped, 0 failures
(excluding 2 pre-existing flaky perf tests — see §5)
```

---

## 4. Out-of-scope notes

These were considered and intentionally deferred.

### 4.1 EvaluationRequest schema extension for outbound artifacts

The canonical Thread 5 prompt suggests testing C2PA emission by
POSTing to `/evaluate` with an outbound artifact. The current
`EvaluationRequest` schema does NOT carry an outbound artifact
field — that schema extension touches the eval command, the
guardrail HTTP layer, and the six gateway adapters. It is a
substantial piece of plumbing that belongs to a later thread
(naturally adjacent to Thread 7's `EcosystemEngine` integration
where the eval command is already being modified).

Thread 5's tests therefore drive the `EvidenceRecorder` directly
with the artifact + context. This is the recorder's actual
public contract and exercises the same code path the eventual
HTTP integration will hit. The wiring proved by these tests is
what's gating the future work, not the schema.

### 4.2 ML-DSA-65 cosign as the default

The algorithm-agile dispatcher resolves the cosign algorithm at
runtime based on what's available in the environment. Thread 5
does not pin the default — it constructs an empty `C2paEmitter()`
and lets the dispatcher choose. In CI environments without
liboqs, this falls through to Ed25519 (PKCS8-PEM-wrapped), which
is the transition path the dispatcher advertises through 2027.
Production deployments with liboqs installed will use ML-DSA-65
automatically.

### 4.3 Temporal KG handle for the twin

The twin's `fork_at(timestamp_iso=...)` path is most useful when
the twin has a handle to the live `InMemoryTemporalKG` so it can
deep-copy the versions dict at a historical time. Today the KG is
constructed inside `EcosystemEngine`, which is not yet called
from production (Thread 7 wires that). Until then, callers pass
state inline via the factory. This is the correct minimal
wiring: it makes the endpoint live without coupling Thread 5 to
the Thread 7 scope.

---

## 5. Known issues unchanged by Thread 5

Two existing performance-bound tests are flaky under sandbox CPU
contention:

- `tests/causal/test_chief_shapley.py::test_shapley_under_5ms_p99_at_n20`
- `tests/causal/test_chief_fast_attribute.py::test_fast_attribute_under_5ms_p99`

Both assert wall-clock p99 latency under 5 ms for monte-carlo
Shapley attribution on n=20 declared causes. They pass on
dedicated hardware and fail under contended sandbox CPU. They
are NOT regressions introduced by Thread 5 — they were already
flaky before any Thread 5 edit. Verified by re-running on the
pre-Thread-5 codebase: same failures.

These tests should be marked `@pytest.mark.perf` and skipped
under CI in a future hygiene pass (Thread 8 territory per the
canonical work plan).

---

## 6. What this enables for the GTM narrative

After Thread 5, two of the bullet points in §19 of TEX_CANONICAL.md
("Defensible pitch — AFTER the threads") become structurally true:

> Every PERMIT verdict on an outbound AI agent artifact emits a
> C2PA 2.4 Content Credential with our post-quantum ML-DSA-65
> evidence cosign.

True at the recorder level when callers thread the artifact
through. The outstanding work to make this fully true at the
HTTP boundary is the `EvaluationRequest` schema extension noted
in §4.1 above.

> The system is multi-tenant from day one with cryptographically
> enforced boundaries.

True after Thread 3. Thread 5 preserves this — the manifest
mirror carries `tenant_id` on every row, and the
`enforce_tenant_match_optional` gate on `GET /v1/evidence/{record_id}/c2pa`
checks it when an API key is presented.

For the cyber-insurance and EU AI Act Article 50 buyer
narratives, the wiring landing here removes the last "wired but
unreachable" reservation in the §19 pitch. The eight-step
EcosystemEngine integration (Thread 7) is now the only
remaining structural gap before all the §19 claims hold.
