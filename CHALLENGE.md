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
forgery was caught. The verifier is one file you can read:
`src/tex/bench/evidence_bundle.py`.

**The challenge:** forge a verdict the pinned-key verifier accepts. Alter a
sealed decision and make it replay clean. Make the verifier say a tampered
bundle is authentic. If you do it, I want to know exactly how — open an issue.

## What's coming

A hosted, no-signup attack surface and a cash bounty for the first forged
verdict go live shortly. This file is the standing dare; the hosted version just
makes it easier to take.

## Honest footer (the whole point is you don't take my word for it)

Zero production deployments today — this is a research artifact you can verify,
not a deployed claim. Signing is ECDSA-P256 today (post-quantum code is in-tree
but runtime-dependent). Anything labeled "ZK" in this tree is a hard-gated
stand-in, fail-closed, and is never called a proof. The structural floor, the
offline replay, and the forgery-catching key pin above are real and re-runnable
by you, now.

— Matt Nardizzi
