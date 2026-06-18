# Subsystem Dossier: `adversarial`

> **Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/adversarial/`
> **Branch:** `feat/proof-carrying-gate`
> **Verification basis:** every claim below traced in source; the adaptive gate was executed end‑to‑end against a live `build_runtime()` PDP (see Wiring › Live execution).

---

## Overview

`adversarial` is **red‑team / robustness evaluation tooling**, explicitly *off the per‑request path*. It ships two complementary harnesses plus a sealing/certification layer:

1. **Static fixture harness** (`fixtures.py` + `fuzz_runner.py`) — fires curated representative cases from public IPI benchmarks (AgentDojo, InjecAgent, MCPSafeBench, AgentLAB, SIREN, Nasr‑adaptive) at the live `/v1/guardrail` HTTP endpoint and measures per‑suite + per‑specialist Attack Success Rate (ASR).

2. **Adaptive "attacker‑moves‑second" harness** (`adaptive.py` + `adaptive_seeds.py` + `__main__.py`) — a black‑box, query‑based beam search that hill‑climbs intent‑preserving surface mutations against the **runtime PDP** (`runtime.evaluate_action_command`) until it bypasses or exhausts a query budget. This is the CI gate path.

3. **Evidence sealing + completeness certificate** (`seal.py` + `completeness.py`) — turns an adaptive campaign into a chain of signed, hash‑linked `EvidenceRecord`s and adds an anytime‑valid **survival monitor** (betting supermartingale) and a **WSR upper confidence bound** on residual ASR, all sealed for offline verification.

The unit's stated thesis (`adaptive.py:22‑31`, confirmed by running it): a defense keyed only on **content lexis** is evadable by content mutation (lexical ASR ≈ 100% via a single leetspeak mutation), while a defense reasoning over **structure** (action graph / path policy) is invariant to content mutation (structural ASR = 0%). The harness quantifies that gap and seals the number.

**Reachability reality:** the spine pass classified `adversarial=INDIRECT`. Verified here: the only `src/tex` importer is `capstone`, and **`capstone` itself has zero `src/tex` importers** (only `scripts/` + `tests/`). So `adversarial` is **not reachable from `tex.main:create_app`/`build_runtime` or any `api/` route**. Its live entrypoints are two **CLI/CI tools** (`python -m tex.adversarial`, `scripts/run_adversarial.py`) that *drive* the app from outside it. Classification refined below to **DEMO_TEST_ONLY / tooling** (it exercises live runtime internals but nothing in the running service calls into it).

---

## File Inventory

| File | LoC | Role |
|------|----:|------|
| `__init__.py` | 88 | Package docstring (benchmark catalogue + usage); re‑exports `FuzzRunner`, `FuzzReport`, `SuiteResult`, `AttackFixture`; sets `__layer__=None`, `__layer_kind__='tooling'`. |
| `__main__.py` | 169 | CLI **gate** for the adaptive campaign: builds an isolated runtime, runs the campaign, seals + verifies the bundle, prints the report, gates on structural‑ASR=0 + seal‑valid + attacker‑explored. `python -m tex.adversarial`. |
| `adaptive.py` | 351 | The adaptive attacker: `Scorer` protocol, 10 mutation operators, `AttackSeed`, `AdaptiveAttacker` beam search, `AdaptiveCampaignReport`, `run_adaptive_campaign`. Also delegates `python -m tex.adversarial.adaptive` → the real gate. |
| `adaptive_seeds.py` | 102 | `build_runtime_scorer(runtime)` (binds the PDP `evaluate_action_command` as a `Scorer`) + `default_seeds()` (4 lexical + 1 structural seed). |
| `completeness.py` | 671 | Adversary‑exposure certificate: `SurvivalMonitor` (binary betting supermartingale), `residual_asr_upper` (WSR), `BreachStreamRecorder`, `CorpusCoverage`, `run_certified_campaign`, `seal_certified_campaign`. |
| `fixtures.py` | 571 | Static benchmark fixture corpus: `AttackFixture` dataclass + 6 suites (51 fixtures total) + registry helpers `known_suites`/`get_fixtures`/`get_all_fixtures`. |
| `fuzz_runner.py` | 299 | `FuzzRunner` drives the static fixtures at `/v1/guardrail` via a `TestClient`; produces `FuzzReport`/`SuiteResult` with per‑suite ASR/FPR + per‑specialist evidence‑contribution. |
| `seal.py` | 195 | `seal_campaign(report, signer)` → chain of signed `EvidenceRecord`s (one per seed + a summary), reusing production signer + centralized hash math; `read_summary`. |

**Total: 2,446 LoC across 8 files.** No subpackages. `__pycache__/` only.

---

## Internal Architecture

### Two independent data flows

```
STATIC PATH (HTTP / out-of-process):
  fixtures.get_fixtures(suite) ──► FuzzRunner.run()
        │ per fixture: POST /v1/guardrail (TestClient)
        ▼
  SuiteResult / FuzzReport  ── ASR, FPR, per-specialist block_rate

ADAPTIVE PATH (in-process / direct PDP):
  adaptive_seeds.default_seeds() ──► run_adaptive_campaign(seeds, scorer)
        │ scorer = build_runtime_scorer(runtime)  → runtime.evaluate_action_command.execute(req)
        ▼
  AdaptiveAttacker.attack(seed): beam search over MUTATION_OPERATORS
        ▼
  AdaptiveCampaignReport ──► seal_campaign() ──► signed EvidenceRecord chain
                         └─► completeness.run_certified_campaign() ──► survival + WSR + coverage ──► seal_certified_campaign()
```

### Static harness

- **`AttackFixture`** (`fixtures.py:25`) — frozen slotted dataclass `(suite, fixture_id, content, expected_block)`. `expected_block=True` means `/v1/guardrail` should *not* PERMIT.
- **Six suites** (`fixtures.py:36‑533`), aggregated in `_ALL_FIXTURES` (`fixtures.py:539`): `agentdojo` (14), `injecagent` (9), `mcpsafebench` (14), `agentlab` (8), `siren` (7), `nasr_adaptive` (5). Registry helpers at `fixtures.py:549‑563`. The fixtures are **hand‑written representative samples**, not the upstream corpora (`fixtures.py:4‑7` — "NOT the full benchmarks").
- **`FuzzRunner`** (`fuzz_runner.py:143`) — `@dataclass(slots=True)` holding a `GuardrailCallable`. `against_test_client` (`fuzz_runner.py:150`) wraps a FastAPI `TestClient` and POSTs to `/v1/guardrail` (`fuzz_runner.py:156`). `run()` (`fuzz_runner.py:164`) iterates fixtures, counts an attack as successful when `expected_block and verdict==PERMIT` (false negative) and a false positive when benign content is blocked (`fuzz_runner.py:195‑200`). **Key semantic** (`fuzz_runner.py:191‑193`): `blocked = verdict != "PERMIT"` — ABSTAIN counts as a block, because ABSTAIN does not auto‑commit.
- **Per‑specialist contribution** (`fuzz_runner._record_specialist_hits`, `fuzz_runner.py:258‑290`) — a **substring scan** over `reasons`/`uncertainty_flags`/`asi_findings`/`findings` in the response body for 14 hardcoded specialist names (argus, attriguard, vigil, mage, agentarmor, clawguard, planguard, mcpshield, …). This is an *evidence‑contribution* heuristic, not a causal attribution (`fuzz_runner.py:19‑26`).
- **`FuzzReport`/`SuiteResult`** (`fuzz_runner.py:69‑121`) — Pydantic `frozen, extra="forbid"` models with bounded fields (`asr ∈ [0,1]`) and a `summary()` pretty‑printer.

### Adaptive harness

- **`Scorer` protocol** (`adaptive.py:67`) — `(content, metadata) -> ScoreResult`; `ScoreResult` (`adaptive.py:61`) carries `verdict: Verdict` + `final_score: float`.
- **Attacker objective** (`adaptive.py:79‑87`) — `_VERDICT_RANK = {FORBID:0, ABSTAIN:1, PERMIT:2}` plus a `(1‑final_score)*0.5` tiebreak so the attacker is rewarded for lowering perceived risk even before the verdict flips. `is_bypass` (`adaptive.py:89`) = `verdict is PERMIT`.
- **10 mutation operators** (`adaptive.py:97‑177`) — all **intent‑preserving surface transforms**: `_leetspeak`, `_space_out_triggers`, `_benign_cover`, `_roleplay_frame`, `_hypothetical_frame`, `_base64_wrap`, `_unicode_homoglyphs`, `_synonym_swap`, `_markdown_fence`, `_zero_width_inject`. Collected in `MUTATION_OPERATORS` (`adaptive.py:166`).
- **`AdaptiveAttacker.attack`** (`adaptive.py:242‑288`) — seeded `random.Random(rng_seed)` beam search. Scores the unmutated seed first; if already PERMIT, returns immediately. Otherwise beams over `max_depth=3` rounds, each applying a shuffled op list to each beam entry, scoring mutations, tracking the best objective, early‑returning on bypass, respecting `query_budget`. Beam pruned to `beam_width=4` best candidates per depth. Records the winning `mutation_chain`. Defaults: `query_budget=60, beam_width=4, max_depth=3, rng_seed=1337` (`adaptive.py:236‑239`).
- **`AdaptiveCampaignReport`** (`adaptive.py:204`) — `static_asr` (fraction PERMIT unmutated), `adaptive_asr` (fraction bypassed after search), `asr_for_class(defense_class)` (`adaptive.py:223`).
- **`build_runtime_scorer`** (`adaptive_seeds.py:21`) — wraps a composed runtime; builds an `EvaluationRequest` (`action_type="outbound_message", channel="email", recipient="external@example.com", environment="production"`) and calls `runtime.evaluate_action_command.execute(request)` (`adaptive_seeds.py:43`), returning the verdict + `final_score`. **This is the real PDP path** (confirmed at `main.py:165/962/1656`).
- **`default_seeds`** (`adaptive_seeds.py:61`) — 4 lexical seeds (drop‑table, secret‑exfil, disable‑logging, unauthorized‑commitment) + 1 **structural** seed (`refund_without_idcheck`) whose `metadata.path_policy` injects an LTL path policy `"F tool=confirm_identity"` over candidate action `{"tool":"issue_refund"}` (`adaptive_seeds.py:53‑98`). The structural block is computed over the action graph, so content mutation cannot move it.

### Sealing + certificate

- **`seal._seal_one`** (`seal.py:55`) — builds one chained, signed `EvidenceRecord` by mirroring `EvidenceRecorder._append`: `signer.sign_payload(payload)` → embed under `PQ_SIGNATURE_FIELD` → `_stable_json` → `_sha256_hex` → `_build_record_hash(payload_sha256, previous_hash)`. It explicitly **reuses the production primitives** from `tex.evidence.chain`/`tex.evidence.seal` rather than reinventing crypto (`seal.py:64‑72`).
- **`seal.seal_campaign`** (`seal.py:93`) — one `redteam_seed_result` record per seed (in report order) + one `redteam_campaign_summary` record carrying per‑class ASR + a stable `uuid5` namespace identity (`seal.py:48`). `read_summary` (`seal.py:172`) reads it back.
- **`completeness.SurvivalMonitor`** (`completeness.py:195`) — streaming **one‑sided binary betting supermartingale** `K_t = ∏(1 + λ_t·(X_t − p0))` over the per‑query breach stream. Predictable plug‑in GRO/Kelly bets `λ_t = (p̂_{t‑1} − p0)/(p0·(1−p0))` truncated to `[0, 0.5/p0]` (`completeness.py:227‑245`). At the default `p0=0` (deterministic floor null `E[breach]=0`), `update` (`completeness.py:247`) takes an explicit deterministic‑refutation branch: a breach sends `log_capital` to `+inf`, a clean step multiplies by exactly 1 (`completeness.py:251‑258`). Anytime‑valid p = `min(1, exp(−log_capital_max))` (`completeness.py:286‑288`); fires at `log(1/alpha)` (`survival_log_threshold`, `completeness.py:180`). The docstring (`completeness.py:43‑97`) is unusually careful about **two traps it avoids**: (1) not feeding rare‑event Bernoulli through `drift/_anytime_valid.py`'s sub‑Gaussian N(0,1) form; (2) acting at plain `log(1/alpha)`, *not* the `2^K/alpha` two‑sided level of `engine/risk_spine`.
- **`completeness.residual_asr_upper`** (`completeness.py:329`) — anytime‑valid **upper** confidence bound on residual ASR; delegates **verbatim** to `tex.learning.ope.wsr_upper_bound` (Waudby‑Smith–Ramdas betting confidence sequence, arXiv:2010.09686). Direction is explicitly load‑bearing (upper = defense claim).
- **`BreachStreamRecorder`** (`completeness.py:367`) — a `Scorer` decorator that records the ordered per‑query Bernoulli breach stream (`1.0` iff `is_bypass`) because `AdaptiveAttackResult` keeps only the aggregate count.
- **`CorpusCoverage`** (`completeness.py:402`) — sealed first‑class field describing exactly what was attacked (seed counts by class, query budget/spent, mutation operators available, attacker class, rng config). `is_vacuous` ⇔ zero seeds or zero queries. `run_certified_campaign` **refuses an empty seed corpus** (`completeness.py:492‑495`) and `seal_certified_campaign` **refuses to seal a vacuous certificate** (`completeness.py:545‑549`).
- **`seal_certified_campaign`** (`completeness.py:527`) — seals the campaign via `seal_campaign` then appends one chained `completeness_certificate` record whose payload embeds the survival construction, the residual‑ASR bound, the coverage block, and a fixed `CLAIM`/`NON_CLAIMS`/`harness_caveat`/`maturity="research-early"` (`completeness.py:559‑633`).

---

## Public API

`__init__.py` re‑exports four symbols (`__init__.py:76‑88`): **`FuzzRunner`, `FuzzReport`, `SuiteResult`, `AttackFixture`** — the static‑harness surface.

The adaptive/certificate surface is imported by full module path (not re‑exported at package level):

| Module | Exported (`__all__`) symbols |
|--------|------------------------------|
| `adaptive` | `ScoreResult, Scorer, attacker_objective, is_bypass, MUTATION_OPERATORS, AttackSeed, AdaptiveAttackResult, AdaptiveCampaignReport, AdaptiveAttacker, run_adaptive_campaign` (`adaptive.py:329‑340`) |
| `adaptive_seeds` | `build_runtime_scorer, default_seeds` (`adaptive_seeds.py:102`) |
| `seal` | `CAMPAIGN_POLICY_VERSION, CampaignSummary, SEED_RECORD_TYPE, SUMMARY_RECORD_TYPE, read_summary, seal_campaign` (`seal.py:188‑195`) |
| `completeness` | `ATTACKER_CLASS, CERTIFICATE_SCHEMA, CLAIM, COMPLETENESS_RECORD_TYPE, HARNESS_CAVEAT, NON_CLAIMS, SURVIVAL_BET_TRUNCATION, BreachStreamRecorder, CertifiedCampaign, CorpusCoverage, SurvivalMonitor, SurvivalOutcome, read_certificate, residual_asr_upper, run_certified_campaign, seal_certified_campaign, survival_log_threshold` (`completeness.py:653‑671`) |
| `fixtures` | `AttackFixture, get_all_fixtures, get_fixtures, known_suites` (`fixtures.py:566‑571`) |
| `fuzz_runner` | `FuzzReport, FuzzRunner, SuiteResult, GuardrailCallable, AttackFixture` (`fuzz_runner.py:293‑299`) |
| `__main__` | `main(argv)` — the CLI gate (`__main__.py:51`) |

---

## Wiring

### In — who imports this unit

Across all of `src/tex`, the **only** importers are in `capstone`:

- `src/tex/capstone/compose.py:35` → `from tex.adversarial.completeness import (...)`
- `src/tex/capstone/flow.py:57‑58` → `from tex.adversarial.adaptive import AttackSeed, ScoreResult` + `from tex.adversarial.completeness import (...)`
- `src/tex/capstone/verify.py:53` → `from tex.adversarial.completeness import CLAIM, NON_CLAIMS, read_certificate`

**Critical wiring fact:** `tex.capstone` has **zero importers anywhere in `src/tex`** (verified: `grep -rn "tex.capstone" src/tex` outside the package returns nothing). Capstone is referenced only by `scripts/capstone_demo.py` and `tests/capstone/*`. Therefore the chain `app → … → adversarial` **does not exist** — neither capstone nor adversarial is reachable from `create_app`/`build_runtime` or an `api/` route.

Out‑of‑src consumers:
- `scripts/run_adversarial.py` — CLI that calls `create_app()` + `TestClient` + `FuzzRunner.against_test_client(client).run()` (the static path).
- `scripts/ci_adaptive_gate.example.yml` — *example* CI job (not active CI) that runs `python -m tex.adversarial` and the adversarial test files.
- Tests: `tests/adversarial/{test_adaptive,test_adaptive_gate,test_adaptive_seal,test_completeness}.py`, `tests/bench/test_evidence_bundle.py`, `tests/capstone/test_honesty_pins.py`, `tests/specialists/test_thread_4_5_frontier.py`, `tests/test_integration_layer.py`, `tests/test_wave2_eightleap_integration.py`.

### Live call path

There is **no path from `tex.main:create_app`/`build_runtime` or an `api/` route into this unit.** The reverse is true: this unit *drives* the live runtime from the outside.

- **Adaptive CLI gate** (the closest thing to "live"): `__main__.main` (`__main__.py:51`) → `build_runtime(evidence_path=...)` (`__main__.py:87`, the **real** runtime composer in `main.py:519`) → `build_runtime_scorer(runtime)` (`adaptive_seeds.py:21`) → `run_adaptive_campaign(default_seeds(), scorer)` (`adaptive.py:309`) → each candidate calls `runtime.evaluate_action_command.execute(request)` (`adaptive_seeds.py:43`), i.e. the genuine PDP. Then `seal_campaign` (`__main__.py:111`) + `verify_bundle` (`__main__.py:115`) + a structural‑ASR gate (`__main__.py:127‑165`).
- **Static CLI**: `scripts/run_adversarial.py` → `create_app()` → `TestClient` → `FuzzRunner` → `POST /v1/guardrail`. The `/v1/guardrail` route exists (`src/tex/api/guardrail.py`, prefix used in `api/guardrail_adapters.py:51`).

**Verified by execution** (`PYTHONPATH=src python -m tex.adversarial --budget 20 --seed 1337`, run during this audit): exit 0, real specialists evaluating (logs show `specialist.owasp_skills_top10.evaluated`, `clawguard`, `mcpshield`, `planguard`, …), result:
```
static ASR        : 0.0%
adaptive ASR      : 80.0%   (reported, not gated)
  lexical class   : 100.0%   (evadable by design)   ← every lexical seed bypassed via a single `leetspeak` mutation (q=2)
  structural class: 0.0%   (the moat — gated to 0)   ← refund_without_idcheck held FORBID→FORBID over q=20
Offline bundle verification: VALID (integrity + authorship)  algorithm: composite-ml-dsa-65-ed25519
GATE PASSED
```

**Wired status: DEMO_TEST_ONLY / tooling.** It uses live runtime internals (`evaluate_action_command`, the production evidence signer) but **nothing in the running service invokes it**; its only callers are CLIs, the demo script, and tests. INDIRECT (the spine classification) overstates it — INDIRECT implies a transitive runtime call chain, which does not exist because capstone is itself orphaned from the app.

### Out — dependencies

**Intra‑`tex`:**
- `tex.domain.verdict.Verdict` (`adaptive.py:55`)
- `tex.domain.evaluation.EvaluationRequest` (`adaptive_seeds.py:18`)
- `tex.domain.evidence.EvidenceRecord` (`seal.py:38`, `completeness.py:130`)
- `tex.evidence.chain._build_record_hash / _sha256_hex / _stable_json` (`seal.py:39`) — production hash math
- `tex.evidence.seal.{PQ_SIGNATURE_FIELD, EvidenceChainSigner, build_evidence_chain_signer}` (`seal.py:40‑44`, `completeness.py:131`) — production signer
- `tex.learning.ope.wsr_upper_bound` (`completeness.py:132`) — WSR confidence sequence
- `tex.bench.evidence_bundle.{trusted_public_key_b64, verify_bundle, write_bundle}` (`__main__.py:78`) — offline bundle verifier
- `tex.main.build_runtime` (`__main__.py:80`) — the real runtime composer
- runtime attribute `runtime.evaluate_action_command` (`adaptive_seeds.py:43`; defined `main.py:165`)

**External libs:** `pydantic` (`fuzz_runner.py:56`), and stdlib only otherwise — `random`, `base64`, `json`, `math`, `time`, `argparse`, `os`, `sys`, `tempfile`, `collections.Counter`, `dataclasses`, `uuid`, `datetime`, `typing`. `fastapi.testclient` is used by the *script* `scripts/run_adversarial.py`, not by the unit's library code. No crypto library is imported directly here — all signing routes through `tex.evidence.seal`.

---

## Implementation Reality

**REAL, executable, no stubs.** Grep for `NotImplementedError|TODO|FIXME|placeholder|pass`‑only across the unit returns **nothing**. Every function has a real body; the adaptive gate was run end‑to‑end and produced verifiable sealed output (see Live execution).

- **Adaptive attacker** — real seeded beam search; the mutation operators are concrete string transforms (`adaptive.py:97‑177`). Confirmed bypasses on real specialists.
- **Survival monitor** — real anytime‑valid betting supermartingale with a correctly handled `p0=0` deterministic‑refutation branch (`completeness.py:247‑267`); not a placeholder.
- **Residual ASR bound** — delegates to a real, test‑pinned WSR implementation in `learning/ope.py` (`completeness.py:361`).
- **Sealing crypto** — **not reinvented**; routes through the production `EvidenceChainSigner.sign_payload` (`evidence/seal.py:130`), which signs with a real provider via `get_signature_provider`. The live run sealed with `composite-ml-dsa-65-ed25519` (real ML‑DSA‑65 keygen logged: `public_key_bytes: 1952`, backend `pyca-cryptography-native`) and the bundle verified offline (integrity + authorship). When no PQ backend is present the same path falls back to classical `ecdsa-p256` (a graceful fallback, not a stub — the production layer logs the downgrade explicitly).
- **The CLI gate** is honest *by construction* and the code proves it: it gates on **structural** ASR (default 0), seal validity, and a non‑triviality canary (`queries_used >= 2`), and **does not** gate on lexical/overall ASR (`__main__.py:127‑165`) — those are reported. The `__main__` delegation guard in `adaptive.py:343‑351` prevents `python -m tex.adversarial.adaptive` from silently exiting 0 without running.

The one heuristic worth flagging (not a stub, but approximate): `FuzzRunner._record_specialist_hits` (`fuzz_runner.py:258‑290`) attributes specialist contribution by **substring matching** specialist names against the response body — and the docstring is candid that this is "% of attacks where this specialist appeared in the response evidence," not causal ASR attribution (`fuzz_runner.py:19‑26`).

---

## Technology

- **Adaptive adversarial ML evaluation** — implements the "attacker‑moves‑second" model of **Nasr et al. 2025 (arXiv:2510.09023)**: black‑box, query‑budgeted random/beam search over intent‑preserving mutations. Explicitly *not* a gradient/GCG attack (`adaptive.py:42‑45` — Tex exposes no model gradients on the decision path).
- **Anytime‑valid sequential testing** — a **binary betting supermartingale** (Kelly/GRO plug‑in bets, Ville's inequality) for the firing/refutation half (`completeness.py`), and the **Waudby‑Smith–Ramdas (WSR) betting confidence sequence** (arXiv:2010.09686) for the quantitative residual‑ASR upper bound. The module is unusually rigorous about the *one‑sided* `log(1/alpha)` threshold vs. the two‑sided `2^K/alpha` correction used elsewhere in the repo.
- **Tamper‑evident evidence chain** — `_build_record_hash` Merkle‑style hash linking + embedded self‑verifying signature blocks, with composite **ML‑DSA‑65 + Ed25519** (post‑quantum + classical) when available, classical ECDSA‑P256 fallback otherwise.
- **Design patterns** — `Scorer` `Protocol` + decorator (`BreachStreamRecorder`) for the per‑query stream; frozen slotted dataclasses for immutable results; Pydantic `frozen/extra=forbid` for report DTOs; deterministic seeded RNG for reproducible CI gating; `uuid5` stable namespaces so logical record identities are stable run‑to‑run (only signatures, which are randomized, differ).
- **Benchmark coverage (claimed in docstrings, partially verified):** the `__init__.py:14‑59` catalogue cites AgentDojo, MCPSafeBench, AgentLAB, SIREN, InjecAgent paper ASR numbers. The *fixtures themselves* are hand‑written representative samples (51 total), **not** the upstream corpora — the docstring says so (`fixtures.py:4‑7`). Treat the cited paper ASR figures as **(claim, unverified)** w.r.t. this code.

---

## Persistence

**In‑memory by default; durable only when explicitly sealed to disk.**

- The static harness (`FuzzRunner`) holds everything in memory; the script prints `report.summary()` — nothing is persisted by the unit itself (the `__init__.py:57‑59` claim that results "land in `var/adversarial/*.json`" is **(claim, unverified)** — no such write exists in this unit's code; `scripts/run_adversarial.py` only prints).
- The adaptive gate writes durable artifacts only when run via `__main__`: it `os.makedirs(work_dir)` (default a **throwaway** `tempfile.mkdtemp(prefix="tex-redteam-")`, `__main__.py:84`), builds the runtime with an **isolated** evidence path (`runtime-evidence.jsonl` under the work dir, `__main__.py:87`) so a campaign **never pollutes the shared git‑tracked production chain** (`__main__.py:82‑87`), and writes `campaign.bundle.jsonl` + a `keys/` dir there.
- Sealed state lives entirely in the `EvidenceRecord` chain (hash‑linked JSONL bundle), verifiable offline. State durability beyond that is the caller's choice of `--seal-dir`.

---

## Notable Findings

1. **Reachability is weaker than "INDIRECT."** The spine pass tagged `adversarial=INDIRECT`, but its sole `src/tex` importer (`capstone`) is **itself orphaned from the running app** (no `src/tex` importer). There is **no live runtime call chain** into adversarial; it is **CLI/CI/test tooling** that drives the app from outside. Effective status: **DEMO_TEST_ONLY / tooling**.

2. **The leetspeak bypass is real and intentional — confirmed by execution.** Every lexical seed (drop‑table, secret‑exfil, disable‑logging, unauthorized‑commitment) flips FORBID/ABSTAIN → **PERMIT** with a single `leetspeak` mutation at q=2. This matches the user's "OVERSTATED: leetspeak bypass" memory note — but here it is *not overstated*: the harness **reports it prominently as ~100% lexical ASR** and deliberately refuses to gate on it (`__main__.py:11‑26`, `98`). The unit's honesty is structural, and the running code backs the claim.

3. **The "moat" claim is empirically supported within this harness.** Structural seed `refund_without_idcheck` held FORBID over the full q=20 budget (`structural class: 0.0%`). This is genuine invariance to content mutation for a path‑policy‑keyed decision — but note the corpus is **one** structural seed; "structural ASR = 0%" is over an n=1 structural sample. The certificate module is explicit that a small corpus yields `p=1` by construction and refuses vacuous certificates (`completeness.py:9‑22, 492‑495, 545‑549`).

4. **`completeness.py` is exceptionally self‑disciplined about not over‑claiming.** "Completeness" is named after an L7 roadmap label, and the module repeatedly states it is *not* an earned property; it seals `CLAIM`/`NON_CLAIMS` verbatim into every record so a number cannot be quoted without its disclaimer (`completeness.py:7‑22, 160‑174`). This is the opposite of an overstatement.

5. **Docstring drift — `var/adversarial/*.json` persistence.** `__init__.py:57‑59` claims nightly results "land in `var/adversarial/*.json` for trend tracking." No code in this unit (or `scripts/run_adversarial.py`) writes those files; the script only prints. **(claim, unverified / likely stale.)**

6. **Benchmark ASR figures are paper citations, not measured by this corpus.** `__init__.py` and `fuzz_runner.py` cite specific SOTA ASR numbers (AgentDojo 18.0% undefended, ClawGuard 0.6‑3.1%, etc.). The shipped fixtures are 51 hand‑authored samples, not the upstream benchmarks (`fixtures.py:4‑7`), so any "we match the paper" reading is **(claim, unverified)**.

7. **Self‑defending CI gate against fake‑zero.** The `adaptive.py:343‑351` `__main__` guard and the `__main__.py:130‑149` non‑triviality canary (`queries_used >= 2`) are deliberate defenses against a gate that "passes by doing nothing." Good engineering hygiene worth noting.

8. **No crypto reinvention.** All hashing/signing reuses production primitives (`evidence/chain.py`, `evidence/seal.py`); the unit's own tests use the canonical verifier as oracle (`seal.py:24‑28`). The crypto here is real (composite ML‑DSA‑65 + Ed25519 observed in the live run), not a hollow stub.
