# BRIEF — Arm the Forge Challenge (track/w4-forge-arm)

Self-contained brief for the arming thread. Read `CLAUDE.md` at the repo root — it governs absolutely
(prove-or-label; **never flatten**; CORE-depth for anything touching evidence/crypto).

## The gap this thread closes (found 2026-06-15, verified by code-read + a fresh-clone run)
`CHALLENGE.md` dares the public to "forge a verdict the pinned-key verifier accepts." But as shipped,
the dare is **not armed**:
- A stranger who clones and runs `scripts/verify_it_yourself.py` gets a signer that **generates a
  fresh keypair locally on first use** (`key_dir` default `var/tex/keys`, gitignored — see
  `src/tex/evidence/seal.py:42` and `src/tex/main.py:624`). So they verify their OWN chain signed
  with their OWN key — there is nothing of Tex's to forge.
- The repo ships **no published Tex seal public key** and **no canonical Tex-signed bundle** (the
  "sample bundle downloadable" box in `launch/README.md` is unchecked).
- So the challenge today proves the **verifier mechanism** is sound (integrity + pinned-key authorship,
  real crypto, no shim on this path — `src/tex/bench/evidence_bundle.py`) but is **not an adversarial
  target**. Johann Rehberger (the intended first recipient) would spot this in 60 seconds.

## The goal
Make the dare real: a stranger can download a **canonical bundle signed by Tex's real private key**,
pin **Tex's published public key** (obtained out-of-band, not from the bundle), and genuinely try to
forge a record the verifier accepts — and fail, because they don't hold the private key.

## Hard constraints (founder standing rules)
- **Fresh key only.** Generate a brand-new seal keypair in this worktree. NEVER use or reference the
  old leaked v1 seal key (that issue is separately resolved; do not touch git history).
- **Commit the PUBLIC key + the signed canonical bundle. NEVER commit the PRIVATE key** — it is
  gitignored and only the founder holds it; that secrecy is exactly what makes the forge dare real.
  Surface the private-key path + a "store this securely" note for the founder.
- **Keep the existing self-test working** (`replay_trial_demo.py` / the "catches its own forgery" path).
- **Commit in this worktree only. Do NOT push. Do NOT touch `main`.** The founder reviews + publishes.
- **Never flatten:** no weakened/skipped tests to get green; a real attempt that surfaces a blocker is
  success, faking green is the one unrecoverable error.

## Done = evidence
- The published pubkey + canonical bundle committed here; `verify_it_yourself.py` / `CHALLENGE.md`
  updated so the dare points at them (with a forge-target path), self-test preserved.
- Adversarial tests that would FAIL if a no-private-key attacker could make `verify_bundle` return
  `valid=True` — run with `PYTHONPATH=src python -m pytest`, full output pasted.
- A red-team pass (no private key) that tried to forge and could not — holes listed or none, with
  evidence. Founder reviews this finished, attacked artifact before publishing.

This thread is driven by the `arm-forge-challenge` workflow (design → adversarial judge → build →
red-team). See the orchestration thread for the run.
