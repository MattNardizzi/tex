# `anchors/` — external proof-of-age for the evidence chain

The Tex evidence/decision chain (`evidence/chain.py`, `provenance/ledger.py`)
proves **order, not time**: `record_hash = SHA-256(payload_sha256,
previous_hash)` — no external timestamp enters the hash, so anyone holding Tex's
signing key could mint a self-consistent multi-year chain *today*. Tex's moat is
a long, real, human-adjudicated history competitors cannot backfill — but that
only holds if the history's **age is provable to someone who does not trust
Tex's key**.

This directory holds the machinery that starts (and proves) the age clock.

## What lives here

| Path | What it is |
|---|---|
| `tsa/freetsa_cacert.pem` | The pinned external authority (freetsa.org Root CA). |
| `tsa/PIN_STATEMENT.md` | Out-of-band pin doc: fingerprint + how to verify it yourself. |
| `checkpoint_anchors.jsonl` | Append-only store of `CheckpointAnchorRecord`s — each binds a gix checkpoint tree-head to a TSA timestamp receipt (written by the daily job). |
| `PUBLISHED_TREE_HEADS.jsonl` | **The second channel.** Append-only, public log of `{origin, tree_size, root_hash, anchored_at, authority, gen_time, tsa_cert_fingerprint}` — no secrets. |

## How the age proof works

1. `interchange/gix.py` produces a signed RFC 9162 checkpoint over the decision
   log's `record_hash`es: a `(origin, tree_size, root_hash)` tree-head.
2. `scripts/anchor_checkpoint.py` (daily) submits `SHA-256(checkpoint note)` to
   an **RFC 3161 TSA** (freetsa.org) and stores the signed timestamp token,
   bound to that tree-head, in `checkpoint_anchors.jsonl` — **additively**: it
   never touches `record_hash`, the chain, or `verify_evidence_chain`.
3. `interchange/external_anchor.verify_anchor_receipt` verifies the token
   **offline** against the pinned TSA cert (`tsa/`): real CMS-signature check +
   `id-kp-timeStamping` EKU + messageImprint == the digest recomputed from the
   tree-head fields. On success it yields a TSA-attested **upper bound on the
   tree-head's age**, independent of Tex's key.

## Why the second channel (`PUBLISHED_TREE_HEADS.jsonl`) matters

A transparency log's non-equivocation only bites if the tree-heads are
**published where the operator cannot quietly rewrite them**. This file is
committed to git, so:

- **GitHub's commit history is itself a second, independent timestamp** of each
  tree-head (in addition to the TSA's `genTime`).
- Anyone can diff a tree-head they were shown against this public log; a fork or
  back-dated rewrite would have to contradict either the TSA receipt or the
  public git history of this file.

For a stronger channel, mirror this file to an external append-only store (an
S3 bucket with object-lock, a second git remote, or a public endpoint) and
record where in this README. Today it is published via this repository's git
history.

### Bootstrap entry (2026-06-17) — honest labeling

The first committed entry in `checkpoint_anchors.jsonl` / `PUBLISHED_TREE_HEADS.jsonl`
is a **real** freetsa.org timestamp (verify it offline yourself with the
committed pin) over a **demonstration** tree-head: its leaves are
`SHA-256("decision-0")…SHA-256("decision-6")`, placeholders, **not** real
adjudicated decisions. It exists to prove the end-to-end pipeline produced a
genuinely external, offline-verifiable receipt this session — nothing more. It
does **not** assert Tex has seven real anchored decisions. Production points
`--hashes-file` at the live ledger's `record_hash` export, and from then on each
entry anchors the real decision-log tree-head.

## Run it / verify it yourself

```bash
# fully offline demo (mints a throwaway CA, mock TSA, anchor → verify → catch a forgery)
python scripts/verify_it_yourself.py --anchor

# real anchor against freetsa.org (network; gated by env — see the script header)
TEX_EVIDENCE_ANCHOR_ENABLE=1 python scripts/anchor_checkpoint.py --hashes-file <file-of-record-hashes>
```
