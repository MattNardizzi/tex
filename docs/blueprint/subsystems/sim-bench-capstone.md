# Subsystem Dossier — Simulation, Benchmark, Capstone (`sim` / `bench` / `capstone`)

Branch: `feat/proof-carrying-gate`. All paths absolute under `/Users/matthewnardizzi/dev/tex`.
Method: every claim traced in code (imports + call-sites), not docstrings. `.md`/comment claims are labelled "(claim, unverified)" unless confirmed in code.

---

## Overview

Three sibling units, all "tooling/composition" layer (own no crypto and no verdict logic of their own — they *drive* and *re-verify* the real engine):

- **`tex.sim`** — a service-virtualized synthetic enterprise estate ("Meridian Financial Group"). It generates a deterministic agent population, emits it in the *exact wire shapes the real discovery connectors parse*, and (in `live` mode) drives a wall-clock-paced action stream into a running Tex backend over HTTP. **This is the actual deployed entrypoint**: `render.yaml` `startCommand` is `PYTHONPATH=src python -m tex.sim live reference --wait-for-ignition --drive govern …` (render.yaml:103-111). Two of its surfaces are wired *into the running app*: (a) `connectors.build_sandbox_connectors` is invoked by `tex.main._build_discovery_connectors` under `TEX_SANDBOX=1`; (b) the `live` CLI hits real mounted API routes.

- **`tex.bench`** — proof-of-superiority + benchmark harnesses. The crown jewel is `evidence_bundle.py` (the offline court-exhibit verifier), reused across the codebase. Also: an AgentDojo indirect-prompt-injection harness (runs offline with a stub model; real-model mode is a gated stub), the Replay Trial / Honest-Decline demos, the public "forge target", and the Wave-2 calibration-corpus harness with sealed provenance.

- **`tex.capstone`** — the twelve-leap composition demo: drives one mixed epoch through the *real* ledger-wired PDP, composes a sealed manifest-of-digests binding one FORBID decision to all eight Wave-2 properties, ships an offline verifier and a 12-row tamper matrix. Each property is verified by the owning module's own verifier at composition time; the composer fails closed (`CompositionError`) if any refuses.

**Reachability summary (verified, see Wiring):**
- `sim` = **LIVE** — two confirmed call paths from the running app (`TEX_SANDBOX` connector branch + the live HTTP driver against mounted routes).
- `bench` = **INDIRECT / LIVE-by-reuse** — `bench.evidence_bundle` is imported by `adversarial`, `capstone`, and (`TYPE_CHECKING`-only) `voice.entailment_cert`. No `api/` route imports `bench` directly; the AgentDojo/Replay/forge CLIs are `__main__`/script entrypoints, not app-wired.
- `capstone` = **DEMO/TEST-ONLY** — no importer outside `capstone/` itself; reached only via tests and `scripts/`. (Challenges the spine pass's "capstone=INDIRECT": no production import edge found.)

---

## File Inventory

### `src/tex/sim/`
| File | LoC | Role |
|---|---|---|
| `__init__.py` | 34 | Package doc + re-exports `Estate`, `SimAgent`, `generate_estate`. |
| `__main__.py` | 104 | CLI: subcommands `run` / `live` / `describe` / `hook`. Lazy-imports per subcommand. |
| `live.py` | 500 | **The deployed entrypoint's body.** `LiveConfig`, `run_live`, onboarding, Poisson-paced HTTP driver, heartbeat + chain/voice invariants, self-heal-on-restart. |
| `runner.py` | 117 | `run(scenario)` — one-shot scenario: ignite → inventory → drive `/evaluate` → assert verdict/sealed/proof → report. |
| `estate.py` | 348 | `SimAgent`, `Estate`, `generate_estate`; wire emitters `entra_pages` / `cloudtrail_records` / `mcp_clients`. |
| `archetype.py` | 254 | Pure data: Meridian org, 8 departments, scope vocab, shadow profiles, MCP host/tool pools, `department_population`. |
| `actions.py` | 122 | `ActionTemplate` corpus authored to draw real PERMIT/ABSTAIN/FORBID; `render`, `template_for`. |
| `behavior.py` | 197 | `PlannedAction` (+ `to_evaluate_payload`/`to_decide_payload`), `plan_actions`, `golden_smoke_plan`. |
| `oracle.py` | 217 | Assertions: `check_verdict`, `check_sealed`, `check_proof_roundtrip`, `check_inventory`, `check_voice`, `check_chain_integrity`. |
| `report.py` | 94 | `Report` — tally, verdict-mix, console + JSON. |
| `scenarios.py` | 50 | `Scenario` + the three tiers `smoke`/`reference`/`soak`. |
| `connectors.py` | 71 | `estate_from_env`, `build_sandbox_connectors` (the **population seam**), `install_hint`. |
| `client.py` | 115 | Stdlib-only (`urllib`) HTTP client to a running backend. |
| `tests/test_sim_contract.py` | 88 | Contract tests: determinism, real-verdict, real-connector discovery. |

### `src/tex/bench/`
| File | LoC | Role |
|---|---|---|
| `__init__.py` | 12 | Layer markers only (`__layer__`, `__layer_kind__='tooling'`). |
| `evidence_bundle.py` | 393 | **Offline court-exhibit verifier.** `verify_bundle`, `BundleVerification`, canonical-bytes gate, dup-key rejection, `forge_record_by_resigning`. |
| `forge_target.py` | 203 | Public "forge dare" target: `load_published_pin` (out-of-band only), `verify_forge_target`, `__main__` CLI. |
| `honest_decline.py` | 155 | Demo: Tex ABSTAINs and names the missing fact (`cold_start`); seals + verifies it. |
| `replay_trial.py` | 355 | Flagship: structural FORBID survives 10 paraphrases; PEP boolean; offline tamper-evidence; seeded-neighborhood robustness trial. |
| `agentdojo/__init__.py` | 68 | Re-exports + benchmark doc (AgentDojo leaderboard context). |
| `agentdojo/__main__.py` | 137 | CLI `python -m tex.bench.agentdojo` — `--smoke` (stub) vs `--model` (gated stub). |
| `agentdojo/harness.py` | 404 | Eval driver: bundled fixture tasks, `StubAgentModel`, `AgentDojoHarness`, evidence-chained JSONL. |
| `agentdojo/pipeline_defense.py` | 126 | `TexPipelineDefense` adapter: maps PDP verdict → AgentDojo permit/refuse. |
| `wave2_corpus/__init__.py` | 100 | Re-exports of the calibration-corpus harness. |
| `wave2_corpus/builders.py` | 424 | Deterministic synthetic builders (L4 action-class, L12 neighborhood/QIF, L11 NLI). |
| `wave2_corpus/loaders.py` | 440 | **The kind gate**: `load_corpus` emits `field` only on sealed+pinned+digest-bound provenance. |
| `wave2_corpus/provenance.py` | 408 | Sealed corpus provenance: `synthetic_provenance` / `attest_field_provenance`, seal + offline verify. |
| `wave2_corpus/field_trial.py` | 233 | The separate FIELD entry point + minimum-corpus-size math. |

### `src/tex/capstone/`
| File | LoC | Role |
|---|---|---|
| `__init__.py` | 46 | Re-exports the public surface. |
| `flow.py` | 451 | `run_capstone_flow` — drives one mixed epoch through the real PDP (one stub: the LLM semantic seam). |
| `compose.py` | 1290 | `compose_capstone` — verify every property via its own module, write bundle, seal manifest, witness. |
| `manifest.py` | 524 | `CapstoneVerdict` (sealed manifest-of-digests) + hard honesty-pin validators. |
| `verify.py` | 986 | `verify_capstone` — fully offline verifier (files + pins → named checks). |
| `tamper.py` | 614 | `run_tamper_matrix` — 12 adversary rows, attribution-checked. |

---

## Internal Architecture

### `tex.sim` — generation → wire-shape → behavior → oracle

**Data model (estate.py).** `SimAgent` (estate.py:45-64) is a frozen dataclass: `external_id`, `plane` (`entra`/`shadow_audit`/`mcp`), `department`, `risk_profile`, `action_profiles`, `is_shadow`, plus plane-specific ids (`sp_id`, `arn`, `runtime_user_id`, `mcp_*`). `Estate` (estate.py:67-104) wraps the tuple plus `seed`/`tenant_id` and computes `idp_agents` / `shadow_agents` / `mcp_agents` views and a `summary()`.

`generate_estate` (estate.py:135-226) is fully deterministic on `seed`: builds the IdP-visible population split across departments by weight (`A.department_population`, archetype.py:242-254), assigns risk via `_risk_from_mix` (estate.py:125-132), scope bundles via `_pick_scopes` (estate.py:111-122), then a shadow cohort (skewed critical/high, empty scopes — "the directory has no scopes for it — that's the point", estate.py:193) and optional MCP hosts. Verified deterministic + sized live: `generate_estate(seed=7, idp=170, shadow=30)` → 200 agents, risk mix `{critical:72, high:84, low:44}`.

**Wire-shape emitters (the population seam).** `entra_pages` (estate.py:233-274) emits Microsoft-Graph-shaped fixture pages (`servicePrincipals`, `…/oauth2PermissionGrants`, `…/appRoleAssignments`) consumed by `EntraConsentGraphConnector` via `FixtureGraphTransport`. `cloudtrail_records` (estate.py:277-329) emits 2026 Bedrock AgentCore CloudTrail records (`eventSource: bedrock-agentcore.amazonaws.com`, `runtimeUserId` impersonation field, `InvokeMcp` JSON-RPC body) consumed by `OcsfAuditConnector(source_format="cloudtrail")`. `mcp_clients` (estate.py:332-348) emits MCP handshake records.

**Action corpus (actions.py).** `TEMPLATES` (actions.py:41-102) is the authored content corpus, grouped PERMIT/ABSTAIN/FORBID. The docstring claims "every phrase below was validated against the live DeterministicGate" — **this is enforced by a real test**: `test_authored_actions_draw_intended_verdict` (test_sim_contract.py:40-66) runs every template's content through the *real* `DeterministicGate` + `build_default_policy` and asserts no drift. So the "intended verdict" is a maintained contract, not a hand-wave.

**Behavior driver (behavior.py).** `PlannedAction` (behavior.py:37-96) carries the rendered action plus two payload builders: `to_evaluate_payload` (the full `EvaluateRequestDTO` with `agent_identity` block that doubles as a discovery signal) and `to_decide_payload` (the lean `DecideRequest` for the live PEP path — content + agent external id only). `plan_actions` (behavior.py:99-163) builds a risk-weighted, seeded plan; `golden_smoke_plan` (behavior.py:166-197) is the fixed 12-step screenplay hitting each verdict path.

**Oracle (oracle.py).** Per-action checks compare the *real* returned verdict against the template's intended verdict (`check_verdict`), confirm a `decision_id`+`evidence_hash` (`check_sealed`), and round-trip the proof by pulling `/decisions/{id}/evidence-bundle` and confirming the hash reappears (`check_proof_roundtrip`, oracle.py:74-101) with best-effort intra-bundle chain verification (`_chain_links_ok`, oracle.py:104-124). System checks: `check_inventory` (discovered count + shadow signal + resolve-one), `check_voice` (`/v1/vigil` speaking), `check_chain_integrity` (reads `/v1/system/state`, only `*_intact` flags decide — explicitly refuses to guess from substrings, oracle.py:180-199). A failed check is the product, not an error to swallow.

**Live mode (live.py) — the deployed body.** `run_live` (live.py:312-500): health-check → ignite (or `--wait-for-ignition`, never self-igniting, live.py:360-388) → `_onboard_governed_cohort` (warms up each governed agent with a cheap `/evaluate` so it auto-registers, resolves external_id→agent_id from `/v1/agents`, then `PATCH /v1/agents/{id}` to promote the trust tier; shadow left UNVERIFIED, live.py:220-284) → a Poisson-ish action loop (`rng.expovariate`, live.py:418) posting to `/v1/govern/decide` (`--drive govern`) or `/evaluate` (`--drive evaluate`). Heartbeats run chain/voice invariants and a **self-heal**: if the tenant goes un-ignited (backend restart wiped the in-memory inventory) it re-ignites + re-onboards (live.py:455-468). `LiveStats` keeps bounded ring-buffer latency percentiles (live.py:102-163). Exit is non-zero only if an invariant broke or *every* request errored.

`_next_action` (live.py:189-214) mirrors `behavior.plan_actions`'s per-tick logic but inline for the streaming loop (a deliberate duplication — same weighting, same `forbid_rate`/`abstain_rate` steering).

### `tex.bench` — the offline evidence core + harnesses

**`evidence_bundle.py` — the load-bearing module.** `verify_bundle` (evidence_bundle.py:233-344) is the offline court-exhibit verifier. It separates two properties precisely (documented at module top and enforced):
- **Integrity** is self-verifying: `verify_evidence_chain` re-derives every hash from `payload_json` (recomputes `payload_sha256` and `record_hash`), so reorder/deletion/one-byte edits surface. Re-derived, trusts nothing handed in.
- **Authorship** is NOT self-verifying: each signature embeds its own public key, so a re-signed forgery checks out against the attacker's key. Only **pinning Tex's key out-of-band** (`pinned_public_key_b64`) proves Tex wrote it. Without the pin, `authorship_ok` is `None` (UNVERIFIED), and `.valid` (court-grade) is False.

Two additional court-grade gates: a **canonical-bytes** gate (`_canonical_bytes_match`, evidence_bundle.py:83-95 — stored `payload_json` must be byte-identical to `_stable_json(parsed)`) and a **duplicate-key rejection** parse hook (`_reject_duplicate_keys`, evidence_bundle.py:67-80 — refuses last-wins ambiguity). `BundleVerification.valid` (evidence_bundle.py:196-198) = `integrity_ok AND authorship_ok is True`; `integrity_ok` itself requires chain intact + signatures self-verify + canonical bytes + `record_count > 0`. `forge_record_by_resigning` (evidence_bundle.py:350-382) is the attack simulator: re-signs a mutated payload with a foreign key, rebuilds hashes consistently — used by the Replay Trial and tamper matrix to prove the pin matters.

The live signer is read back verbatim from `pq_signature.algorithm` and reported (ECDSA-P256 today, ML-DSA when a backend is present) — the docstring is explicit that the bundle is "not post-quantum today" and claims "integrity and pinned-key authorship; nothing more." Verified import + run live (smoke harness ran clean).

**`replay_trial.py`.** `run_replay_trial` (replay_trial.py:138-247): (1) runs 10 paraphrases (`PARAPHRASES`, replay_trial.py:82-93) through the real runtime carrying `STRUCTURAL_METADATA` (a path-policy action graph: `F tool=confirm_identity`) — asserts all FORBID; (2) `pep_released = Verdict.FORBID.allows_release` (== False) and **honestly labels the eBPF kernel datapath as NOT EXECUTED off Linux** (replay_trial.py:166-177 — no pretense it ran eBPF on a laptop); (3) tamper-evidence: a byte-flip breaks the chain (`tamper_byteflip_caught`), and a tamper-then-resign forgery passes integrity but fails the pin (`tamper_resign_caught`). `run_seeded_neighborhood_trial` (replay_trial.py:288-345) upgrades the static 10 into a *seeded neighborhood* sampled from `generate_neighborhood`, computes a real one-sided lower bound `stability_p_low`, and mints a `VerdictCertificate` with `neighborhood_kind="synthetic"` (the honest label — replay_trial.py:328).

**`honest_decline.py`.** `run_honest_decline` (honest_decline.py:80-147) drives a never-before-seen agent to ABSTAIN, builds the hold from the *real* uncertainty flags via `tex.engine.hold.build_hold`, surfaces the pivotal flag (`cold_start`), seals + verifies offline pinned. The docstring carries an explicit honesty note that the pivot census was once carrying phantom keys and was reconciled 2026-06-10 with a tripwire test (claim, unverified — but the code does read flags from the live response, not a hand-picked list).

**`forge_target.py`.** `load_published_pin` (forge_target.py:70-108) reads the pin ONLY from a separate statement file (never the bundle), validates internal consistency (`fingerprint_consistent`: `sha256(decode(key)) == public_key_sha256`), and fails closed. `verify_forge_target` (forge_target.py:111-122) → `verify_bundle(..., pinned=...)`. Surfaces a second-channel fingerprint for human cross-check. CLI `__main__` prints the full report.

**`agentdojo/`.** `AgentDojoHarness` (harness.py:208-393) drives the tool-call loop: `StubAgentModel` (a deliberately *vulnerable* agent, harness.py:137-167) acts on the injection payload; `TexPipelineDefense.adjudicate` (pipeline_defense.py:102-123) maps the injected `PdpVerdict` (PERMIT pass / ABSTAIN pass+note / FORBID refuse). Per-task `TaskOutcome` is evidence-chained (`_hash_dict`, harness.py:200-205 → `evidence_hash`/`prev_hash`). `summarize` computes utility-mean / ASR / forbid-rate. `_build_default_pdp_callable` (\_\_main\_\_.py:38-63) is a simple "irreversible-tool ⇒ FORBID" fixture PDP. Verified live: `--smoke` runs 2 tasks, ASR 0.0, forbid_rate 0.71. **The real-model path (`--model`) is a gated stub** — `_run_real_benchmark` (\_\_main\_\_.py:116-133) checks for the `agentdojo` package, prints "wire your LiteLLM-backed AgentModel … here", and returns 0 *without running a benchmark*. No published Tex score exists (the `__init__` doc says "Not yet measured" — confirmed: there is no scoring code that produces one).

**`wave2_corpus/` — earned provenance.** `builders.py` produces synthetic corpora by **delegating verbatim** to the real in-tree truth models: `build_action_class_corpus` / `build_certifiable_action_class_corpus` (contracts/action_class.py:684 / present), `generate_neighborhood` (engine/verdict_certificate.py:178), plus locally-authored FIDES-tagged QIF points and closed-world NLI pairs. `provenance.py` is the anti-honor-system gate: `CorpusProvenance` (provenance.py:102-166) is a pydantic model whose validator forbids a synthetic record from omitting `generator_seed` or a field record from carrying the reserved `SYNTHETIC_METHOD`; `synthetic_provenance` hard-codes `KIND_SYNTHETIC` (no override param), and `attest_field_provenance` is the *only* constructor of `KIND_FIELD` (a deliberate human attestation). Records are sealed with the production `EvidenceChainSigner` and verified by `bench.evidence_bundle.verify_bundle` (provenance.py:242-272, 331-391). `loaders.py:load_corpus` (loaders.py:228-320) emits `kind="field"` ONLY when a sealed provenance bundle verifies (integrity + **pinned** authorship) AND its SHA-256 binds the exact corpus bytes AND its manifest matches; anything else is `synthetic` or a raised `CorpusProvenanceError`. `field_trial.py:run_field_neighborhood_trial` (field_trial.py:128-188) refuses any corpus the loader did not mark `field`, derives the certificate family from the sealed provenance (never the synthetic `NEIGHBORHOOD_FAMILY`), and `minimum_field_corpus_size` (field_trial.py:194-208) searches the in-tree `hoeffding_bentkus_ucb` for the smallest n (78 at α=δ=0.05). **No real field corpus exists** (stated repeatedly and consistent with code: every builder path hard-codes synthetic).

### `tex.capstone` — drive → compose → verify → tamper

**`flow.py` — the driven epoch.** `run_capstone_flow` (flow.py:222-243) scopes `TEX_ZKPDP_ALLOW_SHIM=1` (the honest L1 stand-in opt-in) and calls `_run` (flow.py:246-443), which wires a *real* `PolicyDecisionPoint` over a real `SealedFactLedger` + `RiskSpine`, with **exactly one stub**: `_PermitSemanticAnalyzer` (flow.py:122-158), the LLM-provider seam, returning a deterministic PERMIT recommendation. The epoch drives, in order: (1) a PQ-non-repudiation request whose outcome is environment-dependent and *both branches asserted exactly* (flow.py:289-302); (2) pre-checkpoint cosigned by 3 in-process `Witness`es; (3) the reflexive governor binds and a weakening `store.activate("v2")` is DENIED through the real policy-store chokepoint, then a drift breach lowers PERMIT→ABSTAIN (flow.py:312-326); (4) **request C — the capstone FORBID** carrying both an action-graph path policy and an IRREVERSIBLE×PUBLIC action-class step (flow.py:328-333); (5) the L12 seeded neighborhood through the SAME PDP (via a `SimpleNamespace` adapter, flow.py:339-347); (6) the L7 adaptive campaign through the SAME PDP, sealed with the evidence signer; (7) the L11 spoken seal on the voice chain with a cross-chain `proof_ref` back to C's DECISION fact; (8) post-checkpoint, then `compose_capstone`. Inline `assert`s enforce each leap's expected verdict.

**`manifest.py` — the sealed object.** `CapstoneVerdict` (manifest.py:272-502) is design (B): a *manifest-of-digests*, not a mega-blob (the doc names and rejects design (A) with a tree-specific reason: three chains use three different byte disciplines). It binds one `DecisionIdentity` + `EpochBinding` (pins the **pre-seal** head + record count to break the seal circularity, manifest.py:179-208) + `PinDigests` + a tuple of `PropertyAttestation`. The validator `_enforce_honesty_pins` (manifest.py:322-502) is the teeth: exactly the 12 leaps once each covering exactly properties {1..8}; per-leap honesty constraints (L1 only `green_test_mode`+`stand_in`; L2 a real JWS `alg != none`, no `alg=none` bypass; L4 `certificate.certified` must be False; L11 entailment `green` ONLY behind a real loaded neural scorer over a `field` corpus — otherwise `blocked`; L12 `certified=False`+`qif_estimate_only`); and a `BANNED_AUTHORED_PHRASES` scan (manifest.py:111-119: "guarantee", "proven correct", "regulator-grade", …) over all authored prose. Over-claiming is unconstructible.

**`compose.py` — verify-then-seal.** `compose_capstone` (compose.py:293-788) calls each leap module's own verifier (L1 `zkpdp.arbiter.verify_arbitration`, L2 `tee.verdict_binding.verify_verdict_binding` under a scoped production posture with a stand-in ITA key, L3 `evidence.negative_knowledge`, L4 `contracts.action_class.evaluate_action_class`, L6 `interchange.gix_witness.verify_cosigned_checkpoint`, L7 `bench.evidence_bundle.verify_bundle`, L11 `voice.entailment_cert.verify_entailment_commitment`, L12 `engine.verdict_certificate.stability_p_low`) and raises `CompositionError` on any refusal (compose.py:119-120, used ~30×). Sealing order (compose.py:711-778): write+digest-bind all artifacts, build the manifest, seal `manifest_sha256` as one `SealedFact(kind=ANSWER)` as the first record after the pre-seal epoch (asserts no concurrent appender), witness the post-seal head, export the full sealed-fact bundle, write pins.json (explicitly "DEMO CONVENIENCE ONLY", compose.py:758-763). `_build_property_attestations` (compose.py:839-1264) records each leap's status + verbatim module caveats + the verifier's own output.

**`verify.py` — offline re-verification.** `verify_capstone` (verify.py:364-978) needs no live ledger/runtime/network — only the bundle dir + out-of-band `CapstonePins`. It re-derives artifact digests from raw bytes *before parsing* (the manifest-swap catch), closes the seal loop (chain's final ANSWER fact must carry the recomputed manifest digest, verify.py:413-430), delegates every crypto check to the owning module, and asserts **no status drift** between the manifest's claims and the offline findings (verify.py:951-976). L1's shim is gated by `allow_shim` (the `zkpdp_shim_not_a_real_proof` gate intact without it); L2 is *not* a test-mode half — a real JWS verified against the pinned ITA key fail-closed. Every failure is a named `CheckResult`; tampered input never raises (try/except per phase). `_LedgerView` (verify.py:232-265) is a duck-typed read-only rehydration that delegates all verification to `verify_sealed_fact_bundle`.

**`tamper.py` — the adversary matrix.** `run_tamper_matrix` (tamper.py:576-596) runs 12 rows, each mutating a *copy* of the bundle (or replaying a protocol attack against the live witnesses) and asserting the attack is caught by the *right* proof: per-chain byte-flips → that chain's integrity; tamper-then-resign → integrity passes, only the pin catches; verdict swap → L2 nonce mismatch + L1 relation UNSAT; forged JWS signature → `signature_invalid` fail-closed; forked checkpoint → all witnesses `CONFLICT`; epoch-minus-one-PERMIT → L3 conservation `GATED-BROKEN` (and the roots break when the attempt is hidden too); swapped artifact → digest binding; edited manifest → seal binding. Attribution is asserted per row (`caught_by`).

---

## Public API

**`tex.sim`** (`__init__.py:32-34`): `Estate`, `SimAgent`, `generate_estate`. Effective entrypoints used by the deployment and tests:
- `sim.connectors.build_sandbox_connectors` / `estate_from_env` / `install_hint` (the seam imported by `tex.main`).
- `sim.__main__.main` (the `python -m tex.sim …` CLI).
- `sim.live.{LiveConfig, run_live, parse_duration}`; `sim.runner.run`; `sim.scenarios.{Scenario, get, SCENARIOS}`; estate emitters `entra_pages`/`cloudtrail_records`/`mcp_clients`.

**`tex.bench`**:
- `bench.evidence_bundle.{verify_bundle, BundleVerification, RecordSignatureCheck, write_bundle, read_bundle, trusted_public_key_b64, forge_record_by_resigning}` — **the unit's only externally-consumed surface** (imported by adversarial + capstone).
- `bench.replay_trial.{run_replay_trial, run_seeded_neighborhood_trial, PARAPHRASES, STRUCTURAL_METADATA, ReplayTrialResult, NeighborhoodTrialResult}` (imported by `capstone.flow`/`compose`).
- `bench.honest_decline.run_honest_decline`; `bench.forge_target.{load_published_pin, verify_forge_target}`; `bench.agentdojo.*`; `bench.wave2_corpus.*` (consumed by tests + `voice.entailment_cert` `TYPE_CHECKING`-only).

**`tex.capstone`** (`__init__.py:18-46`): `compose_capstone`, `verify_capstone`, `CapstoneVerdict`, `CapstoneMaterials`, `CapstonePins`, `CapstoneVerification`, `ComposeResult`, `CompositionError`, `DecisionIdentity`, `PropertyAttestation` — plus `flow.run_capstone_flow` and `tamper.run_tamper_matrix`.

---

## Wiring

### Wiring In (who imports the unit's symbols)

```
src/tex/main.py:1882                from tex.sim.connectors import build_sandbox_connectors   # gated TEX_SANDBOX=1
src/tex/adversarial/__main__.py:78  from tex.bench.evidence_bundle import trusted_public_key_b64, verify_bundle, write_bundle
src/tex/adversarial/seal.py:11,103  (doc + uses bench.evidence_bundle write/verify)
src/tex/capstone/compose.py:41,46   from tex.bench.evidence_bundle … ; from tex.bench.replay_trial import NeighborhoodTrialResult
src/tex/capstone/verify.py:54       from tex.bench.evidence_bundle import read_bundle, verify_bundle
src/tex/capstone/tamper.py:31       from tex.bench.evidence_bundle import …
src/tex/capstone/flow.py:62         from tex.bench.replay_trial import PARAPHRASES, STRUCTURAL_METADATA, run_seeded_neighborhood_trial
src/tex/voice/entailment_cert.py:98 if TYPE_CHECKING: from tex.bench.wave2_corpus.loaders import LoadedCorpus   # type-only, no runtime edge
```
No `api/` route imports `sim`, `bench`, or `capstone` directly. No module outside `capstone/` imports `capstone`.

### Live call path (from the running app)

**Path 1 — sim connector seam (LIVE).**
`create_app` (main.py:1309) → `build_runtime` (main.py:519) → `_build_discovery_connectors()` (called main.py:707 & 749) → at main.py:1881-1883, when `os.environ["TEX_SANDBOX"] == "1"`, returns `tex.sim.connectors.build_sandbox_connectors()`. That builds the **real** connector classes (`EntraConsentGraphConnector(transport=FixtureGraphTransport(entra_pages(est)))`, `OcsfAuditConnector(source=…cloudtrail_records…)`, optional `MCPServerConnector`, connectors.py:45-60) bound to the synthetic estate. **Guard/flag: `TEX_SANDBOX=1`** (env). This is exactly the deployment posture render.yaml documents for the web service (render.yaml:24-32). Verified: `_build_discovery_connectors` is the real function (main.py:1859) and is on `build_runtime`'s construction path.

**Path 2 — sim live HTTP driver (LIVE, deployed worker).**
render.yaml worker `tex-sim-driver` (render.yaml:92-114) `startCommand: PYTHONPATH=src python -m tex.sim live reference --wait-for-ignition --drive govern --rate 1 --onboard standard --duration 2d`. `__main__.main` → `live.run_live(LiveConfig(...))` → `TexClient` calls against the running web service, all hitting **real mounted routes** (verified registered + mounted):
- `POST /v1/govern/decide` — `governance_standing_routes.py:70`, router mounted main.py:1507.
- `POST /v1/surface/discovery/ignite` & `GET …/status` — `discovery_surface_routes.py:140/122`, router mounted main.py:1461.
- `PATCH /v1/agents/{id}`, `GET /v1/agents`, `GET …/ledger` — `agent_routes.py:9/7/12`.
- `POST /evaluate` — `routes.py:111`; `GET /decisions/{id}/evidence-bundle`, `GET /v1/vigil`, `GET /v1/system/state`, `GET /health` (client.py:64-115).

**bench — INDIRECT (reuse, not app-wired).** `bench.evidence_bundle` is reachable from the running app *only transitively* through whatever imports `adversarial`/`capstone` — but neither `adversarial.__main__`/`adversarial.seal` nor any `capstone` symbol is imported by an `api/` route or `build_runtime`. So bench's wiring is real **by code reuse** (it is the shared offline-verifier library), not a live request path. Its own CLIs (`agentdojo`, `forge_target`, replay/honest-decline via `scripts/`) are `__main__`/script entrypoints.

**capstone — DEMO/TEST-ONLY.** Grep for external importers returned nothing. Reached only by tests (`tests/capstone/…`, `tests/test_wave2_twelveleap_composition.py` referenced in docstrings) and `scripts/`. Not on any app path.

### Wiring Out (dependencies)

**`sim` → other tex subsystems (only at the HTTP seam / connector seam, never deep imports):**
- `tex.discovery.connectors.{entra_consent_graph, cloud_audit_ocsf, mcp_server}`, `tex.discovery.graph_transport.FixtureGraphTransport` (connectors.py:45-48).
- Test-only deep imports: `tex.deterministic.gate.DeterministicGate`, `tex.domain.evaluation.EvaluationRequest`, `tex.policies.defaults.build_default_policy`, `tex.discovery.connectors.base.ConnectorContext` (test_sim_contract.py:44-46, 70).
- External libs: stdlib only — `urllib`, `random`, `signal`, `statistics`, `json`, `argparse`, `dataclasses`, `collections`, `datetime`, `uuid`. **No third-party dependency** (deliberate, client.py doc).

**`bench` → tex + external:**
- `evidence_bundle` → `tex.domain.evidence.EvidenceRecord`, `tex.evidence.chain.{verify_evidence_chain, _build_record_hash, _sha256_hex, _stable_json}`, `tex.evidence.seal.{EvidenceChainSigner, verify_payload_signature, PQ_SIGNATURE_FIELD}`.
- `replay_trial` → `tex.domain.{evaluation, verdict}`, `tex.engine.verdict_certificate.*`, `tex.evidence.seal.build_evidence_chain_signer`.
- `honest_decline` → `tex.engine.hold.build_hold`, `tex.domain.*`, `evidence_bundle`.
- `agentdojo` → `pydantic`; **optional** `agentdojo` + `litellm` (import-guarded, \_\_main\_\_.py:117-125 — absent ⇒ message + return, never crash).
- `wave2_corpus` → `tex.camel.capability`, `tex.contracts.action_class`, `tex.engine.verdict_certificate`, `tex.domain.verdict`, `tex.evidence.{chain, seal}`, `tex.domain.evidence`, `pydantic`; stdlib `math`/`hashlib`/`re`/`uuid`.

**`capstone` → tex (broad, by design — it composes the whole system):** `adversarial.{adaptive, completeness}`, `bench.{evidence_bundle, replay_trial}`, `contracts.action_class`, `domain.*`, `engine.{pdp, risk_spine, verdict_certificate}`, `evidence.{seal, negative_knowledge}`, `interchange.{gix, gix_witness}`, `policies.defaults`, `pqcrypto.pq_durability`, `provenance.{ledger, models, bundle}`, `selfgov.governor`, `semantic.schema`, `stores.policy_store`, `tee.{attestation_client, verdict_binding}`, `voice.{attestation, entailment_cert, voice_gate}`, `zkpdp.arbiter`, `zkprov.commitment`. External: `pydantic`, stdlib.

---

## Implementation Reality

**REAL logic (no stubs):**
- `sim` is end-to-end real: deterministic generator, exact-shape wire emitters consumed by the *production* connectors, a real HTTP client, and an oracle that asserts against *real* backend verdicts. The action corpus's "intended verdict" is a live-tested contract (test_sim_contract.py:40-66 runs the real gate). The connector seam runs the production reconciliation/ledger/provenance untouched (connectors.py:38-60). Verified live: estate generation + module imports succeed.
- `bench.evidence_bundle` is fully real and is the shared offline verifier; it re-derives all hashes and signatures and draws the integrity/authorship line explicitly. Verified live (agentdojo smoke produced a real chained outcome; evidence_bundle imports clean).
- `bench.wave2_corpus` delegates the truth-bearing math **verbatim** to the in-tree `contracts.action_class` / `engine.verdict_certificate` (no second truth model), and the provenance gate is a real sealed-bundle verifier reusing `evidence_bundle.verify_bundle`.
- `capstone.flow/compose/verify/tamper`: the composition is real and replayable; every property is checked by the owning module's verifier; the manifest validators make over-claiming unconstructible; the tamper matrix asserts attribution. **Zero `NotImplementedError`/`TODO`/`FIXME`/`pass`-only across all three units** (grep returned empty).

**Stubs / labelled stand-ins (all honestly named in code, not hidden):**
- `agentdojo` real-model benchmark (`--model`) is a **gated stub**: `_run_real_benchmark` (\_\_main\_\_.py:116-133) checks for the package and prints "wire your LiteLLM-backed AgentModel … here", returning 0 without running. `StubAgentModel` is the deterministic CI agent (a deliberately vulnerable agent, by design). **No published AgentDojo score is produced anywhere** — consistent with the `__init__` doc's "Not yet measured".
- `capstone.flow._PermitSemanticAnalyzer` (flow.py:122-158) — THE one stub: the LLM-provider semantic seam, returns a deterministic PERMIT recommendation. The rest of the PDP path (gate, specialists, router, structural floor, CRC, risk spine, PQ-maturity, sealing) is the real wired stack.
- **L1 (zkPDP)** is a keyed-hash *stand-in* backend, gated by `TEX_ZKPDP_ALLOW_SHIM=1`; status is *only* `green_test_mode`+`stand_in` (manifest.py:341-352). Refused fail-closed without the opt-in.
- **L2 (TEE)** signature half is a **real JWS** (alg ≠ none) over a **stand-in** ITA keypair (`generate_standin_ita_keypair`); the hardware-rooted measurement half is `runtime_dependent` (dev-stub off real TDX). Honestly split in `halves` (compose.py:911-914) and pinned by the validator (manifest.py:354-372).
- **L10 (PQ)** live signer is ECDSA-P256; the `pq_signing` half is `runtime_dependent`. The maturity signal honestly lowers PERMIT→ABSTAIN when the backend isn't durable.
- **L11 entailment** half is `blocked` (no torch/transformers in-env, no field NLI corpus) — `green` is unconstructible without a real neural scorer over a `field` corpus.
- **L4/L12 certificates** are `certified=False` / `estimate_only` pending a real field corpus. `wave2_corpus` confirms no field corpus exists.
- Replay Trial honestly labels the **eBPF kernel datapath as NOT EXECUTED** off Linux (replay_trial.py:166-177).

**Crypto reality (real-with-context, not hollow):** Every signature path uses the production `EvidenceChainSigner` / `build_evidence_chain_signer` and the centralized `tex.evidence.chain` math. The pinned-authorship distinction is enforced (a re-signed forgery passes integrity, fails the pin — proven by `forge_record_by_resigning` + the tamper matrix). No fake crypto in scope.

---

## Technology / SOTA

- **Offline tamper-evident evidence**: SHA-256 hash chain (integrity) + signature with **out-of-band pinned public key** (authorship) + canonical-byte presentation gate + duplicate-key rejection. The tamper-then-resign attack and its only defense (the pin) are first-class.
- **AgentDojo** (Debenedetti et al., arXiv 2406.13352) indirect-prompt-injection harness; defense-adapter pattern; ASR/utility metrics; per-task evidence-chained JSONL.
- **Robustness certification**: seeded perturbation neighborhoods + a Hoeffding–Bentkus anytime-valid lower confidence bound (`stability_p_low` / `hoeffding_bentkus_ucb`); Clopper-Pearson documented for sizing only (field_trial.py:211-224).
- **Structural (graph) policy** vs lexical classifiers: a refund-after-identity LTL-style path policy that is invariant to 10 paraphrases — the explicit moat thesis.
- **Calibration corpora**: closed-world NLI (Mohri–Hashimoto conformal quantile), FIDES confidentiality×integrity QIF tagging, action-class reversibility×blast labels — with sealed, digest-bound, pinned-authorship **earned provenance** as the anti-honor-system gate.
- **Composition / transparency**: a manifest-of-digests over three cryptographically separate chains (sealed-fact ledger, evidence records, voice attestation); witness-cosigned Merkle checkpoints with consistency proofs (`interchange.gix`/`gix_witness`); negative-knowledge (non-membership) certificate over a sealed epoch; verdict-bound TEE attestation (Intel TDX / ITA model); zkPDP arbitration relation.
- **Patterns**: frozen dataclasses + pydantic `extra="forbid"` everywhere; deterministic seeded fixtures; verify-then-seal with fail-closed `CompositionError`; "name the stub" honesty doctrine enforced by validators + a banned-phrase scan.

---

## Persistence

- **`sim`**: stateless in-process; the only durable side effects are *the backend's* (sealed ledger, registry) — sim talks to it over HTTP. `live` keeps bounded in-memory stats (ring-buffer latencies, live.py:110). Optional JSON report written on stop (live.py:486-495) or by `runner.write_json`. **Critical operational note**: render.yaml warns the backend's ignition registry + discovered inventory are *in-memory*, wiped on Render sleep/redeploy — which is exactly why `live` self-heals (re-ignite + re-onboard) on the next heartbeat (live.py:455-468).
- **`bench`**: `evidence_bundle.write_bundle` writes JSONL bundles to disk (caller-supplied path). `agentdojo` writes `var/agentdojo/outcomes.jsonl`. `wave2_corpus.write_corpus` writes canonical (sorted-key, manifest-first) JSONL artifacts whose SHA-256 the provenance binds; `seal_provenance` writes one-record bundle files. Otherwise in-memory.
- **`capstone`**: writes a full bundle directory under a caller-supplied `work_dir` (`manifest.json`, `pins.json`, `ledger_bundle.json`, per-leap artifacts, checkpoints — compose.py:125-141). The sealed-fact epoch lives in an in-memory `SealedFactLedger` for the run; the exported bundle is the durable artifact. Tamper rows operate on disk copies under a scratch dir.

---

## Notable Findings

1. **The deployed entrypoint is `tex.sim live`, and it is genuinely live** (render.yaml:103-111). Both wiring paths confirmed: the `TEX_SANDBOX=1` connector seam (main.py:1881-1883, on `build_runtime`'s path) and the HTTP driver against real mounted routes (`/v1/govern/decide`, `/v1/surface/discovery/ignite`, `PATCH /v1/agents`, `/evaluate`). This corroborates the spine pass's `sim=LIVE`.

2. **`bench=INDIRECT` is accurate but the nuance matters**: `bench.evidence_bundle` is the *shared offline-verifier library* (imported by adversarial + capstone), so it is real and load-bearing — but **no `api/` route or `build_runtime` imports `bench`**. Its standalone benchmark CLIs are `__main__`/scripts, not app-wired. The `voice.entailment_cert` import is `TYPE_CHECKING`-only (no runtime edge, verified entailment_cert.py:97-98).

3. **`capstone` has NO importer outside itself** (grep empty) — it is **DEMO/TEST-ONLY**, reached via tests/scripts. This is a slight *downgrade* from the spine pass's `capstone=INDIRECT`: I found no production import edge.

4. **The AgentDojo real-model benchmark is a stub and there is no published Tex score.** `_run_real_benchmark` returns 0 without running anything (\_\_main\_\_.py:116-133); the `__init__` leaderboard prose (CaMeL/DRIFT/AgentSys numbers, "Tex's score: Not yet measured") is **documentation context, not a Tex result** — do not cite any Tex AgentDojo number. The smoke path is real but uses a fixture PDP + a deliberately vulnerable stub agent.

5. **Honesty doctrine is enforced in code, not just prose.** `manifest._enforce_honesty_pins` (manifest.py:322-502) makes over-claiming *unconstructible* (L4 `certified=True`, L11 entailment `green` without a field corpus, L2 `alg=none` bypass, L10 incoherent durable records all raise). A `BANNED_AUTHORED_PHRASES` scan blocks "guarantee"/"regulator-grade"/etc. in authored prose. `verify.py` independently re-derives the L11 entailment half and asserts no manifest status-drift. This is unusually rigorous self-policing.

6. **Every stand-in/stub is explicitly labelled** — L1 (zkPDP shim, opt-in gated), L2 (real JWS over stand-in ITA key; hardware measurement runtime-dependent), L10 (ECDSA-P256 today), L11 (entailment blocked), L4/L12 (uncertified pending field corpus), eBPF (NOT EXECUTED off Linux), flow's single LLM stub. No discovered case of a stub presented as real.

7. **`wave2_corpus` is a clean anti-fabrication design**: `field` provenance can be produced *only* by an explicit human `attest_field_provenance` (synthetic builders physically cannot, by validator), and the loader emits `field` only on sealed+pinned+digest-bound verification. No real field corpus exists, and the code is consistent with that (every builder hard-codes synthetic). The certifiers are reused verbatim from the engine — no parallel truth model.

8. **Deliberate logic duplication**: `live._next_action` (live.py:189-214) re-implements `behavior.plan_actions`'s per-tick selection inline for the streaming loop. Same weights/rates — a maintenance hazard if one drifts, but currently consistent. Not dead code.

9. **No dead code, no `NotImplementedError`/`TODO`/`FIXME`** anywhere in `sim`/`bench`/`capstone` (verified by grep). The optional `agentdojo`/`litellm` deps are import-guarded and degrade gracefully.

10. **Minor doc-vs-code nuance**: `sim/__main__.py`'s module docstring (lines 1-8) only documents `run`/`describe`/`hook` and omits `live` — yet `live` is the deployed subcommand. Cosmetic; the argparse definition (lines 30-48) and `run_live` are fully real.
