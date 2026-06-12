# Tex

**Tex is the gate between an AI agent and the real world.** Before an agent's
action goes out — an email, a tool call, a payment — Tex returns one of three
verdicts: **PERMIT**, **ABSTAIN**, or **FORBID**. Every verdict states its
reasons; every finding that decides one states its counterfactual. Each
decision leaves a hash-chained evidence record you can replay in place, and
sealed decision bundles verify offline — with code in this repository, not
with our word.

You are not asked to trust a dashboard. The verifier is the pitch.

## Sixty seconds to your first verdict

No server, no database, no API key:

```bash
git clone https://github.com/MattNardizzi/tex && cd tex
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/quickstart.py
```

This is the actual output of that last command on a fresh machine
(macOS / Apple silicon, Python 3.12, June 2026 — the install took 16 seconds):

```
──────────────────────────────────────────────────────────────────
  TEX — first verdict
──────────────────────────────────────────────────────────────────

  An AI agent is about to send this email:

    "URGENT - Wire $40,000 to a new vendor account I was just
    emailed about. CEO needs this settled before EOD, do not
    loop in finance."

  Tex's verdict — real engine, this machine, just now:

    FORBID — ASI02: Tool Misuse    (18.6 ms)

    why, precisely:
      Fired because deterministic recognizer 'monetary_transfer'
      scored 1.00 on evidence: "Wire $40,000". Would not have
      fired on this request without the deterministic recognizer
      'monetary_transfer' signal for Tool Misuse.

  A routine follow-up email, for contrast:

    "Hi Jordan, following up on Tuesday's call - attaching the
    deck we discussed. Happy to walk through it whenever
    suits."

    PERMIT    (5.3 ms)
      Fused final score was 0.09 (permit <= 0.34, forbid >= 0.72).

  The forbidden decision is already an evidence record on the
  local ledger (var/tex/evidence/evidence.jsonl), and replays:

    decision  ec1c12e6-bd23-43e2-9c88-5d2cea22218c
    replayed  FORBID  — same verdict from the stored record: True
──────────────────────────────────────────────────────────────────
```

One detail worth noticing: on the wire-transfer request, the probabilistic
layer actually recommended PERMIT and the fused score (0.37) was *below* the
forbid threshold (0.72). The FORBID came from the deterministic structural
floor — a recognizer with a CRITICAL finding forces FORBID regardless of what
any model thinks. Scores can only lower a verdict toward caution, never raise
one; the floor cannot be fired by a probabilistic score. (Those two invariants
are pinned by `tests/test_structural_floor.py` and `tests/test_crc_gate.py`.)

## Verify Tex without trusting Tex

A governance system's audit trail is worthless if you have to take the
vendor's word for it. So don't take ours:

```bash
python scripts/verify_it_yourself.py
```

This seals ten decisions, verifies the bundle offline, then plays adversary
against itself — and must catch every forgery. The tail of the actual output
(same fresh machine, exit code 0):

```
[3] Offline, tamper-evident evidence
    sealed decisions : 10
    bundle           : /tmp/tex-replay-trial-1_0cn_wv/replay.bundle.jsonl
    Offline bundle verification: VALID (integrity + authorship)
      records          : 10
      chain intact     : True
      signatures self-verify : True  (algorithm: ecdsa-p256)
      authorship       : True  (pinned to Tex key)
      chain head       : e78c7de76ed2446d…
    tamper (byte-flip) caught : True  ('payload_sha256_mismatch',)
    tamper (re-sign)   caught : True
    tamper-then-resign: a forged 'PERMIT' record re-signed with a foreign key passes integrity but FAILS the Tex key pin (authorship_ok=False).

======================================================================
REPLAY TRIAL: PASSED
======================================================================
```

The wording here is deliberate, because the two properties are different:
**the hash chain proves integrity; a signature proves authorship of one
record.** A forger who re-signs a tampered record with their own key produces
a bundle that is internally consistent — it is caught only because the
verifier pins Tex's public key. The demo runs exactly that attack so you can
watch the pin do its job.

To go deeper, the same repo contains the capstone: one sealed verdict object
composing eight governance properties over three cryptographically separate
chains, with an eleven-row tamper matrix:

```bash
python scripts/verify_it_yourself.py --capstone
```

## What we claim — and what we don't yet

Honesty is load-bearing here: a claim that would not survive an adversary
running this repository does not ship. The current truth:

**Claimed, and re-runnable by you today:**

- A deterministic structural floor on the live default path: recognizer
  CRITICAL finding → FORBID, in milliseconds, no model in the loop.
- Three-way verdicts (PERMIT / ABSTAIN / FORBID), so high-stakes uncertainty
  can route to a human instead of being silently dropped.
- Hash-chained evidence records for every decision, replayable in place.
- Sealed decision bundles that verify offline, where byte-flips and
  re-signed forgeries are both caught (the latter by the key pin).

**Not claimed yet, in plain words:**

- Signing is **ECDSA-P256 today**. Post-quantum signing code exists in-tree
  but is runtime-dependent — it is live only where a PQ-capable backend is
  installed. Nothing here is "quantum-safe" by default.
- Anything "ZK" in this tree is a **hard-gated stand-in**, fail-closed and
  refused outside explicit test modes. It is never a proof, and we don't
  call it one.
- Risk certificates ship **`certified=False`** until a real field corpus
  exists to calibrate them.
- TEE attestation is **verifier-side logic only** until there is a real
  confidential VM to attest.
- **Zero production deployments today.** No SOC 2 / FINRA / HIPAA
  suitability is claimed. The hosted API and the PyPI package are not live
  yet — the SDK under `sdks/python/` documents a remote client for an
  endpoint that does not exist yet; the local path above is the real one.

## Where to look next

- The engine: `src/tex/engine/` (decision point, router, risk gate, holds).
- The evidence ledger: `src/tex/provenance/ledger.py`.
- The offline verifiers the demos call: `src/tex/bench/replay_trial.py` and
  `src/tex/capstone/verify.py`.
- The generated system map: `TEX_SYSTEM.md`.
- Tests: `PYTHONPATH=src python -m pytest` (the package has no install
  metadata yet, so plain `pytest` will not collect).
