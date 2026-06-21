# Profile Memory — frontier survey (retrieved 2026-06-21)

Survey for L2 (per-tenant PROFILE on top of S5 sealed memory + a two-way
confirm/correct loop). Every citation below was **retrieved this session** via web
fetch and is verifiable at the URL given; where a fact is carried from a prior
session's survey rather than re-retrieved, it is labelled `UNVERIFIED-FROM-MEMORY`.
This file is the "frontier is the floor" evidence the constitution requires before
non-trivial novel work.

## TL;DR — the frontier says exactly what Tex already does; L2 fills the one gap

The 2026 literature on long-term agent memory converges on a single thesis:
**security and verifiability cannot be retrofitted at retrieval time — they must be
anchored at WRITE time, with provenance, versioning, and a real forget path.** Tex's
S5 memory already implements the write-anchored, forgettable, content-anchored,
per-tenant store. The frontier's named *open* problem — "validate provenance
**before** write," and "forgetting is the strongest test" — is precisely the gap L2
closes for the *personalization* surface: a profile fact (preference / boundary /
correction) is provenance-validated before it is written, citable after, and
revocable. The novel contribution L2 adds beyond the literature is the **two-way
confirm/correct loop bound to a monotone-lowering verdict**: an operator correction
is a sealed, signed LABEL that can only *tighten* a future tier — never inflate one
— so personalization can never become a fabrication vector.

---

## 1. MemTensor "mnemonic sovereignty" — arXiv:2604.16548

**"A Survey on the Security of Long-Term Memory in LLM Agents: Toward Mnemonic
Sovereignty"** — Zehao Lin, Xixuan Hao, Renyu Fu, Shaobo Cui, Kai Chen, Chunyu Li,
Zhiyu Li, Feiyu Xiong. Retrieved 2026-06-21 from
<https://arxiv.org/abs/2604.16548> and <https://arxiv.org/html/2604.16548v1>.

- **Mnemonic sovereignty** (verbatim): *"a system's verifiable, recoverable
  governance over what may be written, who may read, when updates are authorized,
  and which states may be forgotten."* This is the exact property a per-tenant
  profile must provide — and the name maps onto Tex's existing per-tenant
  write-gate + recall + forget.
- **Memory Lifecycle Framework**: six phases (Write, Store, Retrieve, Execute,
  Share & Propagate, **Forget & Rollback**) × four objectives (Integrity,
  Confidentiality, Availability, Governance). The thesis: *"robust LTM security
  cannot be retrofitted at retrieval or execution time alone, but must be anchored
  in storage-time provenance, versioning, and policy-aware retention from the
  outset."*
- **Governance primitives** Section 11 enumerates (the design checklist L2 is
  measured against):
  1. **Write-gate validation** — pre-consolidation checks before content enters
     memory. *(L2: `ProfileMemory.apply_correction`/`confirm` validate provenance
     — operator present, monotone-lowering transition, well-formed subject —
     BEFORE any write; a bad correction writes nothing.)*
  2. **Provenance tracking** — source + modification metadata. *(L2: every fact
     content-anchors operator, original tier, optional decision_id, kind, time.)*
  3. **Versioning / snapshots** — *(partially; profile facts are immutable +
     content-addressed, so a re-correction is a new id, not a mutation.)*
  4. **Principal-scoped retrieval** — *(L2: strict per-tenant, app-layer.)*
  5. **Compression auditing** — *(N/A; the profile stores discrete labels, no
     summarization.)*
  6. **Conflict detection (evidence vs confidence)** — *(L2: a correction IS a
     human-detected conflict between Tex's spoken tier and reality.)*
  7. **Multi-evidence verification** — *(deferred; corrections cite a single named
     human act, not a corpus.)*
  8. **Audit-retention tiering** — deletable vs audit-mandatory state. *(L2 inherits
     S5's split: the forgettable profile store is deliberately NOT in the
     append-only EvidenceRecorder/SealedFactLedger chains.)*
  9. **Cross-substrate deletion** — verified removal across all stores. *(L2:
     `revoke` removes the profile fact AND (when decision-backed) calls S5's
     `PresenceCalibrationFeed.forget_resolution` to pull the calibration
     contribution — the one cross-substrate edge a correction creates.)*

  > **Honesty note on a name-vs-body discrepancy I actually observed.** The
  > *abstract* names *"five architectural primitives"* of "Verifiable Memory
  > Governance (VMG)"; the *body* (Section 11, in the v1 HTML I fetched) enumerates
  > **nine** governance primitives. I report the nine I read rather than inventing a
  > clean "five." (The nanozk lesson applied to a citation: do not round a source to
  > a tidier number than it states.)

- **The named OPEN problems** — *"shared blind spots across every system
  examined"*: systems lack *"validate provenance before write"* and *"explicit
  source metadata in long-term memory,"* and *"Forgetting is the strongest test of
  mnemonic sovereignty"* and *"remains largely unimplemented."* **These two are
  exactly what L2 ships**: provenance-validated-before-write profile facts, and a
  real per-record `revoke`.

## 2. TierMem — arXiv:2602.17913

**"From Lossy to Verified: A Provenance-Aware Tiered Memory for Agents"** — Qiming
Zhu, Shunian Chen, Rui Yu, Zhehao Wu, Benyou Wang. Retrieved 2026-06-21 from
<https://arxiv.org/abs/2602.17913>.

- **Two-tier hierarchy + a runtime sufficiency router**: a fast summary index by
  default; *Escalate* to an **immutable raw-log store** only when summary evidence
  is insufficient; then **write back verified findings as new summary units linked
  to their raw sources.** Results on LoCoMo: 0.851 acc (vs 0.873 raw-only),
  −54.1% input tokens, −60.7% latency.
- **Why it matters to Tex**: TierMem's escalation discipline is the *same shape* as
  Tex's tier law — answer at the cheap tier (DERIVED estimate) only when sufficient,
  else escalate to the authoritative source (recompute from SEALED rows), else
  ABSTAIN. And "write back verified findings linked to raw sources" is exactly what
  S5 `seal` does (a verdict bound to its `EvidenceRef`s) — and what an L2 *confirm*
  records. The novel inversion L2 adds: in TierMem the router decides sufficiency;
  in Tex the **operator's correction** is a human sufficiency signal that lowers the
  tier ceiling for a subject permanently and revocably.
- **The "write-before-query barrier"** TierMem names (compression decisions made
  before knowing what a query hinges on) is why Tex never compresses a fact into a
  weight or a lossy summary: profile facts are stored discrete and verbatim, and the
  gate recomputes from rows at query time.

## 3. Portable Agent Memory — arXiv:2605.11032 (revocation design input)

**"Portable Agent Memory: A Protocol for Provenance-Verified Memory Transfer Across
Heterogeneous LLM Agents"** — Santhosh Kumar Ravindran (Microsoft). Retrieved
2026-06-21 from <https://arxiv.org/html/2605.11032v1>.

- Crypto: **BLAKE3** content-addressing (entry id = BLAKE3 of canonical JSON with
  the `id` field omitted), **Ed25519** root signing, a **Merkle-DAG** over
  `parent_ids`, and **capability tokens** (signed, scoped — read/write/derive/
  redact/export/rehydrate).
- **Provenance-preserving deletion** (verbatim): *"Redacted entries maintain their
  DAG position with content replaced by typed tokens, enabling recovery by
  authorized parties while satisfying erasure requirements."*
- **Design tension L2 resolves deliberately the OTHER way.** Portable Agent Memory
  redacts-in-place (keeps a recoverable placeholder for audit). Tex's profile
  `revoke` does **wholesale forget-by-avoidance** (S5's discipline): the record is
  *gone*, not a recoverable token. Rationale, stated honestly: a *forgettable*
  per-tenant profile must satisfy erasure as true unrecoverability from the store,
  not "recoverable by authorized parties" — the right-to-be-forgotten reading is
  stronger. The audit trail Portable Agent Memory keeps via placeholders is, in Tex,
  carried by the *separate* append-only governance chain a correction may have fed
  (the human-resolution evidence row), which is not revoked — so "what was decided"
  stays auditable even though "this tenant's private boundary" is fully forgotten.
  We adopt their content-addressing idea but via Tex's existing `sha256` content
  anchor (`tex.presence.memory.records.presence_record_hash`) — **no new crypto
  primitive** (the nanozk rule): we do not introduce BLAKE3 or a Merkle-DAG where a
  recomputable sha256 anchor + the existing `tex.evidence.seal` signer already give
  tamper-evidence + authorship.

## 4. Carried context (not re-retrieved this session)

- arXiv:2410.15267 — "delete from the external retrieval store, not the weights" as
  a forget technique for closed-source models. Cited by S5's design survey; carried
  forward here as the basis for **forget-by-avoidance**. `UNVERIFIED-FROM-MEMORY`
  (S5 retrieved it; I did not re-fetch it this session).
- arXiv:2403.03868 (Jin & Ren, selection-conditional conformal) and Barber et al.
  2023 (conformal beyond exchangeability) — the honest coverage label on the
  calibration feed L2 feeds into. Carried from S5's `calibration.py`;
  `UNVERIFIED-FROM-MEMORY` this session.

## 5. What the survey CHANGED in the L2 design

1. **Provenance-validated-before-write is now a hard write-gate**, not a comment —
   directly answering the survey's named blind spot (§1). A correction with no named
   operator, or a non-lowering tier transition, writes NOTHING.
2. **Revoke is cross-substrate** (profile fact + calibration contribution), matching
   VMG primitive #9 — rather than only deleting the local row.
3. **Wholesale forget over redaction-with-placeholder** is now a *documented,
   deliberate* choice (§3), with the audit-trail responsibility explicitly assigned
   to the separate append-only chain — not an unexamined default.
4. **The monotone-lowering binding is the contribution beyond the frontier.** None of
   the surveyed systems bind a personalization signal to a verdict's *direction of
   travel*. L2's correction can only move a tier toward caution (it is folded with
   `tighten`, never `max`), so "becomes more yours" can never mean "becomes more
   confident than it can prove."
