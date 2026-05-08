# CORRECTIONS COMPLETED — May 2026

All items previously listed in this file have been resolved as of
7 May 2026. This file is kept as a record of what was changed and a
forward-looking watch list.

---

## ✅ Resolved

### 1. C2PA spec version → 2.2

**Files patched:**
- `src/tex/c2pa/__init__.py` — bumped reference to "C2PA Specification 2.2 (2025-05-01)"
- `src/tex/c2pa/manifest.py` — bumped header + TODO references
- `src/tex/c2pa/signer.py` — bumped all §13.2 / §14.5 / §14 references; rewrote Trust List note for the 2026-01-01 ITL freeze and the official C2PA Trust List supersession
- `src/tex/c2pa/_canonical_claim.py` — bumped CDDL TODO reference
- `src/tex/c2pa/_cose_alg.py` — bumped allowed-list references
- `tests/frontier/test_c2pa.py` — docstring bump

The wrapper-level `c2pa.claim` → `c2pa.claim.v2` change does NOT require
a code edit: Tex emits assertion-level labels (already on `.v2` form),
not a wrapper-level claim label string. The canonicalizer in
`_canonical_claim.py` does not bake a label literal.

All 53 existing C2PA tests still pass after the version bump.

### 2. SB 942 effective date + AB 853 extensions

**Files patched:**
- `FRONTIER_COMPLIANCE.md` — table now lists "Operative 2 Aug 2026 (per AB 853)" and adds rows for the 2027 / 2028 AB 853 extensions
- `src/tex/compliance/state/california_sb942.py` — header (already correct from Thread 8) reflects AB 853

**Files added:**
- `src/tex/compliance/state/california_ab853_platforms.py` — large online platform + GenAI hosting platform stubs (effective 1 Jan 2027)
- `src/tex/compliance/state/california_ab853_capture.py` — capture device manufacturer stub (effective 1 Jan 2028)

Both new modules have been added to `tests/frontier/test_scaffolding_imports.py`'s
import registry.

### 3. FTC March 11 2026 framing

**Files patched:**
- `FRONTIER_COMPLIANCE.md` — FTC row now distinguishes "FTC §5 (in force; ongoing enforcement under Rytr / Air AI / Operation AI Comply)" from "FTC AI policy statement under EO 14365 (deadline lapsed 11 Mar 2026; not yet published)"
- `src/tex/compliance/__init__.py` — package docstring reframed to "FTC §5 (15 U.S.C. § 45) AI substantiation packets"
- `src/tex/compliance/ftc/policy_statement.py` — header (already correct from Thread 8) accurately documents the lapse

### 4. Colorado AI Act effective date

**File patched:**
- `src/tex/compliance/state/colorado_ai_act.py` — corrected to "Effective 30 June 2026 (delayed from 1 February 2026 by SB25B-004)"
- `FRONTIER_COMPLIANCE.md` — table updated to "Effective 30 Jun 2026"

### 5. FrontierFlags.compliance enforcement (opt-in)

**Files patched:**
- `src/tex/compliance/_common.py` — `_emit_evidence` accepts an `enforce_frontier_flag: bool = False` parameter. When True, the function consults `FrontierFlags.from_env().compliance` and raises `RuntimeError` if the flag is off. Default False keeps the library-friendly behavior intact (existing pipelines + tests don't need env vars).
- The three emit functions (`emit_article_50_evidence`,
  `emit_sb942_disclosure`, `emit_ftc_substantiation_packet`) all
  forward the parameter.

Tests added in `tests/frontier/test_compliance.py`:
- `test_frontier_flag_off_blocks_emission_when_enforced` — flag off + enforce=True raises
- `test_frontier_flag_on_permits_emission_when_enforced` — flag on + enforce=True succeeds

This honours the original "all flags default off, existing pipeline untouched"
contract while making the flag actually mean something to production code paths
that opt in.

---

## Watch list (not actionable yet)

- **C2PA Trust List migration:** The official C2PA Trust List has
  superseded the ITL as of 2026-01-01. Tex's signer documentation now
  notes this; actual cert procurement / cross-signing remains an
  ops task, not a code task.
- **EU AI Act Code of Practice — final version (June 2026):** The
  Article 50 emitter currently aligns to the 3 March 2026 second
  draft. When the final Code publishes, update
  `Article50DisclosurePayload.code_of_practice_alignment`'s default
  to `"final_2026_06"` and add a `benchmarks_passed` field if the
  Code prescribes a measurement methodology.
- **FTC §5 AI policy statement:** If/when the FTC actually publishes
  the EO 14365 statement, update `FTCSubstantiationPayload.section_5_basis`'s
  default to pin a specific focus area, and replace the lapsed-deadline
  TODO with a published-statement reference.
- **AB 853 — 1 Jan 2027:** Build out the platform-redistribution and
  GenAI-hosting evidence emitters in
  `california_ab853_platforms.py` ahead of the 1 January 2027
  effective date.
- **AB 853 — 1 Jan 2028:** Build out the capture-device evidence
  emitter in `california_ab853_capture.py` ahead of the 1 January 2028
  effective date.

---

## Test status (post-corrections)

- Full safe test sweep (frontier / events / ecosystem / specialists):
  **580 passed, 16 skipped, 0 failed**
- `tests/frontier/test_compliance.py`: **25/25 passed** (23 from
  Thread 8 + 2 new flag-enforcement tests)
- `tests/frontier/test_c2pa.py`: **53/53 passed** (unchanged after
  the C2PA 2.1 → 2.2 docstring bump)
- Coverage on the four Thread 8 modules: **100% line coverage**
  (123 / 14 / 15 / 14 stmts respectively, 0 miss)

---

*Sweep completed: 7 May 2026.*
