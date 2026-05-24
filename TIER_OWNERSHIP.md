# TIER_OWNERSHIP

This is the navigation map for Tex. Every `src/tex/*` subpackage gets **two tags**:

- **Dev tier** (A/B/C/D) — engineering blast radius. What to run when this changes.
- **Capability tier** — what this contributes to the product. The buyer-facing view.

See `CAPABILITY_TIERS.md` for the precise definition of each capability tier.
See `MODULES.md` for per-package detail (purpose, key files, public interface).
See `RUNBOOKS.md` for procedures keyed off these tiers.

**Capability tier abbreviations:**
- **D/I** — Discovery / Inventory
- **I/A** — Identity / Access
- **M/O** — Monitoring / Observability
- **E/G** — Execution Governance
- **E/R** — Evidence / Recording
- **kernel** — Cross-cutting infrastructure (no single capability)

---

## Dev Tier A — Product. Cannot break.

Every PR that touches these requires the **full Tier A test suite** plus the V18 readiness suite.

| package | dev | cap | purpose | LOC |
|---|---|---|---|---|
| `engine/` | A | E/G | PDP, router, contract bridge — the decision pipeline | 2,369 |
| `specialists/` | A | E/G | The 24 specialist judges | 9,754 |
| `agent/` | A | I/A + E/G | Identity (I/A), capability (I/A), behavioral (E/G) evaluators | 1,082 |
| `commands/` | A | kernel | CQRS write commands (evaluate_action, report_outcome) | 1,497 |
| `domain/` | A | kernel | Typed contracts: Decision, EvidenceRecord, PolicySnapshot | 5,081 |
| `evidence/` | A | E/R | Recorder, chain, exporter | 3,757 |
| `retrieval/` | A | E/G | Retrieval layer | 224 |
| `semantic/` | A | E/G | LLM semantic scoring layer | 2,081 |
| `deterministic/` | A | E/G | Deterministic rule layer | 675 |
| `contracts/` | A | E/G | Behavioral contracts + runtime enforcer | 2,390 |
| `learning/` | A | M/O (calibration: E/G) | Calibration governance — feedback monitoring + scoring updates | 4,688 |
| `memory/` | A | kernel | Memory system public API | 3,049 |
| `stores/` | A | kernel | All in-memory + Postgres stores | 7,555 |
| `governance/` | A | E/G (IFC: D/I overlap) | Path policy, kernel MCP, IFC, STPA, private data | 5,488 |

**Capability distribution across dev Tier A:** 8 packages in Execution Governance,
4 kernel, 1 Evidence, 1 Identity (split with E/G), 1 Monitoring (split with E/G).

Consistent with Tex's product thesis: the **core product is execution governance**,
with evidence and identity as adjacent capabilities and the rest as supporting
infrastructure.

**Tier A audit slice:**
```bash
pytest tests/specialists tests/contracts tests/governance tests/intervention \
       tests/test_agent_governance.py tests/test_api.py tests/test_v16_hardening.py \
       tests/test_calibration_safety.py tests/test_deterministic.py -q
```

---

## Dev Tier B — Buyer-facing surfaces. Demo-critical.

Changes need a wire-format smoke test. Full Tier A re-audit is not required
unless the change touches a Tier A import.

| package | dev | cap | purpose | LOC |
|---|---|---|---|---|
| `pitch/` | B | E/R | Insurer packet, CISO export, VP marketing packets | 1,440 |
| `api/` | B (subset A) | kernel | HTTP transport; carries all capability tiers | 12,125 |
| `discovery/` | B | D/I | Connectors, reconciliation, alerts | 4,620 |

**`api/` is split internally:** `auth.py`, `routes.py`, `guardrail.py`, `schemas.py`
are dev Tier A. Everything else (adapters, surface routes, MCP server) is dev Tier B.

**Tier B audit slice:**
```bash
pytest tests/test_api.py tests/test_governance_history_routes.py \
       tests/test_discovery_routes.py tests/frontier/test_pitch.py \
       tests/test_c2pa_http_routes.py tests/vet/test_vet_routes.py -q
```

---

## Dev Tier C — Frontier R&D / future-proofing.

Quality target: "interesting prototype." Failure here removes a differentiation
talking point but does **not** break the product.

| package | dev | cap | purpose | LOC |
|---|---|---|---|---|
| `nanozk/` | C | E/R | Layerwise ZK proofs of transformer inference | 6,026 |
| `pqcrypto/` | C | E/R | ML-DSA / hybrid post-quantum signing | 4,699 |
| `vet/` | C | I/A | Agent Identity Documents, web proofs | 5,370 |
| `zkprov/` | C | E/R | Training-data provenance | 4,259 |
| `tee/` | C | E/R | TEE attestation | 2,690 |
| `c2pa/` | C | E/R | Content credentials | 4,233 |
| `causal/` | C | M/O | CHIEF, ARM, Shapley attribution | 5,218 |
| `ecosystem/` | C | kernel | Ecosystem governance engine (cross-tier substrate) | 2,389 |
| `intervention/` | C | E/G | Cost-bounded steering | 2,450 |
| `systemic/` | C | M/O | Systemic risk, cascade predictor, digital twin | 3,152 |
| `pcas/` | C | E/G | Policy compiler for agentic systems | 2,656 |
| `runtime/` | C | E/G | clawguard, mage, planguard, mcpshield, agentarmor | 3,452 |
| `safeflow/` | C | E/G | Transactional execution with WAL + rollback | 892 |
| `adversarial/` | C | kernel | Adversarial test harness | 947 |
| `institutional/` | C | E/R | Governance graph, oracle, controller | 2,869 |
| `drift/` | C | M/O | Change-point detection, emergent norms | 2,734 |
| `camel/` | C | E/G | Capabilities for Machine Learning | 1,005 |
| `receipts/` | C | E/R | Tool execution receipts (NabaOS-style) | 697 |
| `ontology/` | C | kernel | Entity + event type registry | 1,206 |
| `graph/` | C | kernel | Temporal KG | 1,178 |
| `events/` | C | E/R | Append-only cryptographic ledger | 940 |
| `enforcement/` | C | I/A | Edge enforcement adapters | 1,691 |
| `observability/` | C | M/O | Observability hooks | 759 |
| `proofs/` | C | kernel | Formal proofs | 27 |
| `bench/` | C | kernel | Benchmark harnesses | 736 |
| `db/` | C | kernel | DB adapters | 629 |
| `policies/` | C | kernel | Policy primitives | 359 |

**Tier C audit slice:** run only the test subdirectory matching the package
you changed. Example: changed `src/tex/nanozk/X.py` → `pytest tests/nanozk -q`.

---

## Dev Tier D — Stubs and unfinished scaffolding.

Triage rule: does this stub block a sentence in `CLAIMS_CURRENT.md`, `pitch/`,
or the active GTM? If yes → promote to Tier B and finish. If no → leave or
delete.

See `STUB_REGISTRY.md` for the per-file breakdown.

| package | dev | cap | purpose | disposition |
|---|---|---|---|---|
| `_pending/interop/` | D | I/A | Microsoft, Okta, Ping, NIST, A2A interop stubs | **moved here 2026-05-21** — restore on demand |
| `compliance/` | D (mixed) | E/R | Compliance evidence emitters; mostly stub, Article 50 partial | promote per regulation as buyer demand surfaces |

---

## Capability tier — at-a-glance distribution

After tagging every package:

| capability tier | packages | notes |
|---|---|---|
| Execution Governance (E/G) | 12 | Largest tier. The decision pipeline + content adjudication. |
| Evidence / Recording (E/R) | 12 | The differentiator tier. Signed artifacts, compliance exports. |
| Monitoring / Observability (M/O) | 5 | Drift, systemic, learning, causal, observability. |
| Identity / Access (I/A) | 4 (1 split, 1 pending) | agent, vet, enforcement, interop (pending). |
| Discovery / Inventory (D/I) | 1 + IFC overlap | discovery, plus governance/ifc/ input classification. |
| kernel | 13 | Shared infrastructure. |

**Read across this distribution:** Tex is roughly equal parts governance and
evidence by package count. **The product is governance + evidence first**,
identity and monitoring second, discovery last — which matches the
"evidence-grade adjudication" GTM and is structurally different from
competitors who lead with discovery + monitoring.

---

## Cross-tier rules

- A file's tier follows its **package**, not its content.
- If a dev Tier A file imports from a Tier C/D file, that's a **dependency-tier
  violation** — Tier A should not depend on unstable code. Run
  `python scripts/audit.py --check-deps` to find these.
- A dependency from one capability tier to another is **fine** — that's how
  the product composes (Evidence importing from Governance is expected).

---

## Quick reference

| I want to... | Read |
|---|---|
| Know what dev tier and capability tier a package is in | This file |
| Know what a capability tier means precisely | `CAPABILITY_TIERS.md` |
| Know what a subpackage actually does | `MODULES.md` |
| Know what to run after changing X | `RUNBOOKS.md` |
| Find unfinished work | `STUB_REGISTRY.md` |
| See known defects | `KNOWN_BUGS.md` |
| Get all of the above for one package | `python scripts/audit.py <package>` |
