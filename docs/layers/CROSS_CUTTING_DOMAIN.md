# Cross-cutting — Domain Model

> **Working doc.** The Pydantic models every layer uses.

## What this concern covers

The shared vocabulary. Every layer in Tex talks in terms of these models: `EvaluationRequest`, `Decision`, `Policy`, `AgentRecord`, `AgentSignal`, etc. They are the contract that lets six independent layers fit together.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `src/tex/domain/` | 21 | 5,100 | WIRED (~236 imports across the codebase) |

## Key files

### Request / Response
- `src/tex/domain/request.py` — `EvaluationRequest` (the input to a PDP eval)
- `src/tex/domain/decision.py` — `Decision` (the durable output)

### Policy
- `src/tex/domain/policy.py` — `Policy`, `PolicyVersion`, `PolicyClause`, `PolicySnapshot`

### Agent
- `src/tex/domain/agent.py` — `AgentRecord`, `AgentLifecycleState`, `TrustTier`, `AttestationStatus`, `Capability`
- `src/tex/domain/agent_signal.py` — `AgentSignal` (per-stream), `AgentEvaluationResult`, `AgentEvaluationBundle`

### Evidence
- `src/tex/domain/evidence.py` — `EvidenceRecord`, `EvidenceBundle`, `ChainEntry`
- `src/tex/domain/findings.py` — `Finding`, `Severity`, `FindingSource`

### Specialists & semantic
- `src/tex/domain/specialist.py` — `SpecialistResult`, `SpecialistSuite`
- `src/tex/domain/semantic.py` — `SemanticAnalysisResult`, dimension scores

### Discovery
- `src/tex/domain/discovery.py` — `DiscoveryFinding`, `ConnectorHealth`, `ScanRun`, presence states

### Outcomes & learning
- `src/tex/domain/outcomes.py` — `OutcomeReport`, `OutcomeKind`, `OutcomeStatus`
- `src/tex/domain/calibration.py` — `CalibrationProposal`, `ProposalStatus`

### Ecosystem
- `src/tex/domain/ecosystem.py` — `EcosystemVerdict`, `EcosystemAxisScores`, `ViabilityIndex`

### Misc
- `src/tex/domain/recipients.py` — recipient classification
- `src/tex/domain/uncertainty.py` — uncertainty flags vocabulary
- `src/tex/domain/criticality.py` — policy criticality

## Conventions

- **Frozen dataclasses or `model_config = ConfigDict(frozen=True)`**. Domain types are immutable. To "modify" a Decision, construct a new one.
- **Every type has a `created_at` or `recorded_at` timestamp**. Domain events are timestamped at the point of creation.
- **No business logic in domain types**. Pure data + simple validators. Logic lives in the layer that owns the type.
- **Pydantic v2**. Don't use Pydantic v1 patterns.
- **Enum for vocabularies**. `Verdict`, `Severity`, `TrustTier`, etc. are enums, not free strings.

## Current state

✅ Solid:
- Comprehensive coverage of every concept the runtime needs
- Strict typing throughout
- ~236 import sites — the model is well-adopted

⚠ Watch:
- Some types have grown large. `Decision` is 100+ fields. Refactoring into nested types would improve readability but is a major change requiring updates across all importers.

## Improvement vectors

### 1. Decision type decomposition (medium impact, high effort)
`Decision` could decompose into `Decision { request_context, evaluation_result, evidence_metadata, ecosystem_verdict }`. Tightens the schema and lets layers depend on just the part they care about.

### 2. JSON-LD context for external interop (medium impact, low effort)
Some external standards (C2PA, SCITT, A2A) expect JSON-LD `@context`. Adding `@context` URIs to the serializers would smooth interop. (But: see Layer 5 constraint — schema URIs are permanent. Pick the right URIs.)

### 3. Protocol Buffers / gRPC variant (low impact, medium effort)
Some enterprise integrators want gRPC. Generating proto from the Pydantic models is mechanical; only worth doing on demand.

### 4. Schema versioning policy
Today the domain types evolve in-place. A real schema-versioning policy (e.g., `EvaluationRequestV1`, `EvaluationRequestV2`) would let the HTTP API evolve cleanly. Today new fields are optional, but a breaking change would be painful.

## Constraints

- **Domain types are the contract**. Changing a field breaks every importer. PR review for changes to `domain/` should be extra careful.
- **No imports from layers**. Domain types must not depend on `engine/`, `evidence/`, etc. (They define the language layers speak.) The reverse is normal and pervasive.
- **No I/O in domain types**. No file reads, no network calls, no DB queries.
- **Backward compatibility**: removing fields breaks Postgres rows and signed evidence. Don't remove; deprecate.

## Testing

Tests for the domain types live in `tests/contracts/` (7 files, 1,967 lines). The contract tests are the source of truth for what the types must accept and reject.

```bash
pytest tests/contracts/
```
