# The Forge Challenge

Every AI-agent-governance product asks you to trust something you can't check: a
dashboard, a detection-accuracy number, or — in the newest wave — a hardware
attestation rooted in an Intel, AMD, or NVIDIA chip.

Tex takes the other road. Every decision it makes — **PERMIT, ABSTAIN, or
FORBID** — is sealed into a signed, hash-chained record you can **replay and
verify offline, with the open code in this repository and a pinned public key —
trusting no hardware vendor, no blockchain, and not trusting us.**

So here is the dare.

## Try it right now (no signup, no network, ~60 seconds)

```bash
git clone https://github.com/MattNardizzi/tex && cd tex
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/verify_it_yourself.py
```

It seals ten decisions, verifies the bundle offline, then plays adversary
against itself — byte-flip a record (caught), re-sign a forged `PERMIT` with a
foreign key (passes integrity, **fails the key pin**). Exit code 0 means every
forgery was caught. The core verifier is one short file you can read
(`src/tex/bench/evidence_bundle.py`); it leans on a few small siblings — the
hash-chain check (`src/tex/evidence/chain.py`) and the signature seal
(`src/tex/evidence/seal.py`).

**The challenge:** forge a verdict the pinned-key verifier accepts. Alter a
sealed decision and make it replay clean. Make the verifier say a tampered
bundle is authentic. If you do it, I want to know exactly how — open an issue.

## Mechanical forge target (a real Tex-signed bundle to attack)

The above seals a *fresh local* chain — you verify your own key, so there is
nothing of Tex's to forge. The armed target is in [`forge/`](forge/): a bundle
of real Tex decisions signed by Tex's private key, plus the **published public
key** to pin.

**Verify-anywhere — the classical ECDSA bundle, two light dependencies, no
backend and no engine.** This is the path that runs on a bare machine:

```bash
# 1a. Install ONLY what an offline signature check needs (cryptography + pydantic):
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-verify.txt
python scripts/verify_it_yourself.py --forge-target --ecdsa
```

What you'll see — the genuine VALID starting point you have to defeat (paths
shown relative to the repo, long digests and the cross-check note elided with
`…`; no value altered):

```
======================================================================
FORGE TARGET — offline verification against the OUT-OF-BAND pin
======================================================================
bundle : forge/canonical_bundle.ecdsa.jsonl
pin    : forge/PUBKEY_STATEMENT.ecdsa.json  (read out of band, NOT from the bundle)
pin algorithm   : ecdsa-p256
pin key_id      : tex-forge-seal-ecdsa-v1
pin fingerprint : sha256:a71f3c146e5acdf06ff0953c0b7a5684d84d23c5cb53599b4f728e5b83ad4582
  …
Offline bundle verification: VALID (integrity + authorship)
  records          : 6
  chain intact     : True
  signatures self-verify : True  (algorithm: ecdsa-p256)
  canonical bytes  : True  (payload_json == canonical form)
  authorship       : True  (pinned to Tex key)
  chain head       : 1048a13bee06d93d…
======================================================================
FORGE TARGET: VALID
======================================================================
```

That verify path imports a small, named set of modules — the bundle verifier
(`bench/evidence_bundle.py`), the hash-chain check (`evidence/chain.py`), the
signature seal (`evidence/seal.py`), the ECDSA provider
(`events/_ecdsa_provider.py`), and the `EvidenceRecord` model
(`domain/evidence.py`) — and pulls in only `cryptography` + `pydantic` plus the
Python standard library. No fastapi, no numpy/scipy, no governance engine on the
import path.

**The headline composite post-quantum bundle** needs a PQ backend, so it rides
with the full install instead:

```bash
# 1b. The composite ML-DSA-65 + Ed25519 bundle (needs the full requirements):
pip install -r requirements.txt
python scripts/verify_it_yourself.py --forge-target
```

```bash
# 2. Download forge/canonical_bundle.pq.jsonl + forge/PUBKEY_STATEMENT.json.
#    Cross-check the pin's public_key_sha256 against the fingerprint posted
#    out of band (live site / signed git tag / tweet) — that external copy,
#    not the in-repo one, is the canonical root of trust.
```

```bash
# 3. Forge a record that makes verify_bundle return authorship_ok=True against
#    the PINNED key, WITHOUT holding the private key.
```

The rule, precisely: **integrity is not enough.** Re-signing a mutated record
with your own key (`forge_record_by_resigning`) passes integrity *and*
self-verification — but **fails the pin** (`authorship_ok=False`, `valid=False`).
You must defeat the *pin*, and the verifier reads the pin only from the statement
file, never from the bundle. The bytes are also gated to one canonical form, so a
non-canonical re-encoding is rejected too.

_Scope: this bundle proves the **authenticity and integrity** of the records it
contains — you cannot forge or alter one. It does **not** by itself prove
**completeness**; the no-dropped-record guarantee (epoch-commitment +
count-conservation) is checked in the capstone below, not in this single bundle._

Honest labeling: the `.pq` bundle is **composite-ml-dsa-65-ed25519** and its
verification is **RUNTIME-DEPENDENT** (it needs an ML-DSA backend, which
`pip install -r requirements.txt` provides). A host without that backend should
attack the `.ecdsa` bundle + pin, which verify with the two light dependencies in
`requirements-verify.txt` (`cryptography` + `pydantic`) — no PQ backend, no
engine. See [`forge/README.md`](forge/README.md).

## What makes this different — the artifact cannot over-claim

Sealed records aren't new, and on raw cryptography others are ahead of us (we
say so below). The part we haven't found anywhere else: **this verdict object
labels its own immaturity in machine-readable form that the verifier checks, and
a construction-time validator makes over-claiming physically unconstructible.**
You cannot build a manifest that marks the keyed-hash stand-in "a real ZK proof,"
marks an uncertified certificate "certified," or writes the word "guarantee" —
the constructor refuses. The failure mode that makes this whole category
untrustworthy — a stand-in dressed up as a proof — is *structurally impossible*
here, and you can prove that to yourself offline in about a minute.

```bash
# The full sealed verdict object: eight properties over three separate chains,
# re-verified offline from files + pins alone — no hardware root, no blockchain.
python scripts/verify_it_yourself.py --capstone
```

It passes 34 independent offline checks and runs a twelve-row tamper matrix
(eleven file-mutation rows plus one live forked-checkpoint attack) — every
forgery caught and attributed to the exact proof it violated.

**The escalated dare.** Make the offline verifier say `VALID` while you do any of these:

1. flip a `FORBID` to `PERMIT` and pass all 34 checks;
2. re-sign any chain with your own key and beat the authorship pin;
3. drop or hide a sealed record and beat the epoch-commitment + conservation checks;
4. forge the L2 attestation without breaking verdict-binding;
5. construct a manifest that **claims more than it proves** — mark the stand-in a
   real proof, mark an uncertified cert "certified," or write "guarantee" — and
   get our own constructor to emit it.

If you break any of them, open an issue and tell me exactly how.

**Stated against my own interest, because that's the whole point.** This
composition is **research-early**, with **zero production deployments**. The novel
thing is the *composition plus the enforced honesty labels the verifier checks* —
not any single primitive. On raw cryptography we are **behind** the field (others
ship post-quantum and real zero-knowledge today); anything labeled "ZK" in this
tree is a fail-closed stand-in and is **never** called a proof. The structural
floor is the only property genuinely on the live default path; the rest are
honestly marked test-mode / uncertified / blocked in the manifest — and the
verifier enforces those labels.

## What's coming

A hosted, no-signup attack surface and a cash bounty for the first forged
verdict go live shortly. This file is the standing dare; the hosted version just
makes it easier to take.

## Honest footer (the whole point is you don't take my word for it)

Zero production deployments today — this is a research artifact you can verify,
not a deployed claim. The local self-test above signs with whatever backend is
present (ECDSA-P256 on a bare box; composite ML-DSA-65 + Ed25519 where an ML-DSA
backend is installed). The **armed forge bundle** in `forge/` is published in two
forms: a headline **composite-ml-dsa-65-ed25519** bundle whose verification is
RUNTIME-DEPENDENT (needs an ML-DSA backend, which `pip install -r requirements.txt`
provides), and an **ECDSA-P256** verify-anywhere bundle alongside it — verifiable
with just `requirements-verify.txt` (`cryptography` + `pydantic`, no engine) —
each with its own out-of-band pin. The verifier now also enforces a **canonical-bytes gate**:
each record's `payload_json` must be byte-identical to its one canonical form.
Anything labeled "ZK" in this tree is a hard-gated stand-in, fail-closed, and is
never called a proof. The structural floor, the offline replay, and the
forgery-catching key pin above are real and re-runnable by you, now.

— Matt Nardizzi
