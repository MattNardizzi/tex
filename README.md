# Tex

**Tex is the gate between an AI agent and the real world.** Before an agent's
action goes out — an email, a tool call, a payment — Tex returns one of three
verdicts: **PERMIT**, **ABSTAIN**, or **FORBID**. Every verdict states its
reasons; every finding that decides one states its counterfactual. Each
decision leaves a hash-chained evidence record you can replay in place, and
sealed decision bundles verify offline — with code in this repository, not
with our word.

You are not asked to trust a dashboard. The verifier is the pitch. No decision
Tex makes asks you to trust a hardware vendor (Intel/AMD/NVIDIA TEE) or a
blockchain — only math you can re-run offline. **Try to break it:**
[CHALLENGE.md](CHALLENGE.md).

▶ **90-second demo:** [demo.tex.systems](https://demo.tex.systems) — a FORBID
landing as a kernel `EPERM`, and the sealed receipt that ruled it. Reproduce
it yourself in [REPRODUCE.md](REPRODUCE.md).

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

## The kernel says no: `rm` returns `EPERM`

A FORBID is not a log line. On a Linux host running the kernel leg, the same
signed verdict that seals into the offline-verifiable receipt also feeds an
in-kernel `(cgroup, inode)` deny map, and the kernel's BPF-LSM
Mandatory-Access-Control hooks return `-EPERM` *before* the effect commits:

```console
$ echo $$ | sudo tee /sys/fs/cgroup/texdemo/cgroup.procs   # this shell is now the governed agent
$ cat /tmp/tex_e2e/payroll.db                              # reading: allowed
ACCT  NAME      SALARY
0001  A. Ghost  $180,000
$ rm /tmp/tex_e2e/payroll.db                               # destroying: denied by the kernel
rm: cannot remove '/tmp/tex_e2e/payroll.db': Operation not permitted
$ ls /tmp/tex_e2e/payroll.db                               # intact
/tmp/tex_e2e/payroll.db
```

The forbidden inode becomes immutable, undeletable, and inexecutable — but
still readable — for the enrolled agent. The hooks match the
**kernel-resolved inode**, so TOCTOU path swaps, hardlink/symlink/
`/proc/self/fd` tricks, `renameat2(RENAME_EXCHANGE)`, `io_uring` ops, and
raw syscalls that bypass libc are caught at the same choke point. The
enforcer verifies an HMAC-signed verdict set before warming the map, so a
compromised agent cannot forge or strip a FORBID.

Scope, stated plainly: this holds against **L3 — a fully compromised agent
userspace in the enrolled cgroup**. It does **not** defend L4 — a rooted
host or a compromised kernel; root owns the kernel and can detach the
programs. The full threat model, the residual-bypass ledger (including the
one honest residual within L3), and the ~22–27µs kill switch are documented
in [pep/kernel/localpep/README.md](pep/kernel/localpep/README.md).

Run it yourself: [REPRODUCE.md](REPRODUCE.md) — exact manual steps,
**~30–35 minutes including VM provision** (macOS works via the committed
Lima template; a scripted one-command demo is coming). This leg governs the
agent-fleet host and needs `bpf` in the kernel's LSM list; the decide+prove
plane above runs anywhere.

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

**The lightest possible check — verify-anywhere, two dependencies.** The replay
trial above runs the real engine (full `requirements.txt`). To verify a *sealed
Tex bundle* offline — the core "trust the math, not us" claim — you don't need
the engine at all. In a fresh clone:

```bash
pip install -r requirements-verify.txt    # only cryptography + pydantic
python scripts/verify_it_yourself.py --forge-target --ecdsa
```

It checks a committed, Tex-signed ECDSA-P256 bundle against its out-of-band pin
using only `cryptography`, `pydantic`, and the standard library — no fastapi, no
numpy/scipy, and no governance engine on the import path. See
[CHALLENGE.md](CHALLENGE.md) for the forge dare built on it.

To go deeper, the same repo contains the capstone: one sealed verdict object
composing eight governance properties over three cryptographically separate
chains, with a twelve-row tamper matrix (eleven file-mutation rows plus one live forked-checkpoint protocol attack):

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
- On a Linux host with the BPF LSM active: a resource-attributable FORBID
  lands as a kernel `-EPERM` (delete / truncate / write-open / rename /
  exec) for the enrolled agent's cgroup — [REPRODUCE.md](REPRODUCE.md).

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
- The offline verifiers the demos call: `src/tex/bench/replay_trial.py`,
  `src/tex/capstone/verify.py`, and the verify-anywhere bundle verifier
  `src/tex/bench/evidence_bundle.py` (+ `src/tex/bench/forge_target.py`).
- The generated system map: `TEX_SYSTEM.md`.
- Tests: `PYTHONPATH=src python -m pytest` (the package has no install
  metadata yet, so plain `pytest` will not collect).

## Talk to me

- **See it live:** 20 minutes, my machine, against a policy *you* pick — the
  kernel stop and the sealed receipt it leaves behind. Open an
  [issue](https://github.com/MattNardizzi/tex/issues) or email the address
  on my GitHub profile.
- **Design partners:** a small number of teams running agents in production,
  with a written go-paid date. Same channels.
- **Break it:** [CHALLENGE.md](CHALLENGE.md) — the target is a kernel deny
  plus a receipt chain you verify offline.
