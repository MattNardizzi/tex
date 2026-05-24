# RUNBOOKS

Procedures for the common change scenarios. Each runbook gets you from "I changed something" to "I'm confident it works" in the minimum number of steps.

Naming note: these are runbooks (operating procedures), not playbooks (which in startup vocab usually means GTM/sales motion). Don't confuse with `pitch/`.

---

## Runbook 1 — I changed a Tier A file

Tier A is the product. Any change requires full Tier A confidence.

**Steps:**

1. **Identify the package.** Look up the file's directory in `TIER_OWNERSHIP.md`. Confirm it's Tier A.

2. **Read the module card** in `MODULES.md` for that package — specifically the "depended on by" line. That's your blast radius.

3. **Run the package's own test slice first** (the `Verify` line from the module card). This catches local breakage fast.

4. **Run the full Tier A audit slice:**
   ```bash
   pytest tests/specialists tests/contracts tests/governance tests/intervention \
          tests/test_agent_governance.py tests/test_api.py tests/test_v16_hardening.py \
          tests/test_calibration_safety.py tests/test_deterministic.py -q
   ```

5. **Run the V18 readiness suite** if you have it tagged (`pytest -k v18` or the explicit file).

6. **One live evaluation against a known fixture.** Start the server and `POST /v1/guardrail/portkey` with a known BEC payload — verdict must be FORBID. With a benign payload — verdict must be PERMIT.

7. If all green, commit. If anything red, the failing test name tells you which dependent module is affected; read its card in `MODULES.md`.

**Time budget:** 5–10 minutes if tests pass.

---

## Runbook 2 — I changed a Tier B file (adapter, surface route, pitch generator)

Tier B is buyer-facing. A change here is demo-critical but doesn't require full product re-audit.

**Steps:**

1. **Identify the surface.** Look up the file in `TIER_OWNERSHIP.md`. Confirm Tier B.

2. **Read the module card.** Specifically: what's the wire-format smoke test for this surface?

3. **Run the surface's local test slice.** Example for a guardrail adapter change:
   ```bash
   pytest tests/test_api.py -k guardrail -q
   ```

4. **Wire-format smoke test.** Start the server. Hit the actual endpoint with a known-good payload and a known-bad payload. Confirm responses match the published spec for that vendor (Portkey, LiteLLM, etc.).

5. **If you touched `pitch/`:** run
   ```bash
   pytest tests/frontier/test_pitch.py -q
   ```
   and generate one packet end-to-end via the `build_*` function, then verify it round-trips through the corresponding verification helper.

6. **Confirm no Tier A imports broke.** Quick check:
   ```bash
   python -c "import tex.engine, tex.api.routes, tex.commands.evaluate_action"
   ```

**Time budget:** 2–5 minutes if tests pass.

---

## Runbook 3 — I'm filling in a Tier D stub

You picked a stub from `STUB_REGISTRY.md`. Before writing code, confirm it should be filled now (not later).

**Decision check:**
- Does this stub block a sentence in CLAIMS.md, an active pitch, or the current GTM motion? If **no**, stop and pick a different one. P0 TODOs that don't block a current claim can wait.

**Steps:**

1. **Read the stub's row in `STUB_REGISTRY.md`** to understand the intended target tier (B or C) once filled.

2. **Write the implementation in the file where the stub lives.** Don't move the file yet.

3. **Write tests in the corresponding `tests/<package>/` directory.** If the test directory doesn't exist, create it. Goal: cover the intended behavior, not just the happy path.

4. **Run the local test slice** for that package:
   ```bash
   pytest tests/<package> -q
   ```

5. **Promote the file's tier:**
   - If the package is now buyer-facing and demo-critical → update `TIER_OWNERSHIP.md` to move it to Tier B and add a card to `MODULES.md`.
   - If it's R&D differentiation → leave it in Tier C in `TIER_OWNERSHIP.md`, no card needed.

6. **Remove the entry from `STUB_REGISTRY.md`.**

7. **Refresh audit data:**
   ```bash
   python scripts/audit.py --rebuild-data
   ```

8. **Run the appropriate runbook for the new tier** (Runbook 1 if Tier A, Runbook 2 if Tier B).

**Time budget:** scales with the stub. The wrapper steps (steps 5–8) take 5 minutes.

---

## Runbook 4 — Something broke and I don't know where

The 4-hour audit problem. This runbook is the answer.

**Steps:**

1. **Capture the failure.** Get the error message, the stack trace, or the test name. Don't start grepping yet.

2. **Find the package from the stack trace.** Top non-test frame → that's the package. Example: `tex/specialists/clawguard_specialist.py:87` → package is `specialists`.

3. **Run the package summary:**
   ```bash
   python scripts/audit.py specialists
   ```
   This tells you: tier, files, public interface, what imports it, what it imports, test files, known stubs and bugs in this package.

4. **Check `KNOWN_BUGS.md`** for that package. If it's a known bug, you have a workaround documented.

5. **Run the package's test slice** (from the audit output). If it passes locally but fails in your scenario, the issue is in a caller — look at "depended on by" in the audit output.

6. **If the issue is in a caller**, repeat step 3 with each caller package until you find the bad change.

7. **Once located, follow Runbook 1 or 2** to fix and verify.

**Time budget:** 5–15 minutes for a defect that previously took hours.

---

## Runbook 5 — I want to know what's actually shippable today

You're prepping for a customer call or demo and need to know what claims hold up right now.

**Steps:**

1. **Read `KNOWN_BUGS.md`.** Anything Sev 1 = do not demo that path.

2. **Check `STUB_REGISTRY.md` for "blocks current claim" entries.** Anything checked there = the claim isn't ready.

3. **Run the full Tier A + Tier B audit slices:**
   ```bash
   # Tier A
   pytest tests/specialists tests/contracts tests/governance tests/intervention \
          tests/test_agent_governance.py tests/test_api.py tests/test_v16_hardening.py \
          tests/test_calibration_safety.py tests/test_deterministic.py -q

   # Tier B
   pytest tests/test_api.py tests/test_governance_history_routes.py \
          tests/test_discovery_routes.py tests/frontier/test_pitch.py \
          tests/test_c2pa_http_routes.py tests/vet/test_vet_routes.py -q
   ```

4. **Start the server and run one live evaluation** against the Portkey BEC fixture. Confirm verdict + evidence bundle return.

5. **Generate one pitch artifact end-to-end** for whichever buyer you're meeting (insurer / CISO / VP Marketing).

6. If all green and no Sev 1 known bugs: that demo path is shippable.

**Time budget:** 15–20 minutes.

---

## Runbook 6 — I added a new subpackage

You created `src/tex/newthing/`. Make sure it doesn't become an unaudited dark corner.

**Steps:**

1. **Add a row to `TIER_OWNERSHIP.md`** under the correct tier. Be honest — if it's R&D, it's Tier C, not Tier A.

2. **If Tier A or B, write a module card in `MODULES.md`.** Use the format from the existing cards.

3. **Add tests under `tests/newthing/`.** At minimum: one happy-path test, one boundary test, one failure-mode test.

4. **Update `scripts/_audit_data.json`** by running:
   ```bash
   python scripts/audit.py --rebuild-data
   ```

5. **Confirm `python scripts/audit.py newthing` returns sensible output.**

6. **If the package has stubs, add them to `STUB_REGISTRY.md` immediately.** Stubs that aren't tracked become invisible.

**Time budget:** 10 minutes plus the actual implementation time.
