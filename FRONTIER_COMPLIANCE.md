# TEX FRONTIER COMPLIANCE MAP — MAY 2026

Every regulatory anchor and the Tex module that satisfies it.

> **Last reviewed: 7 May 2026.** Dates and statuses below reflect the
> live state of each statute as of this review. Re-check before
> citing in pitch material — AI policy is moving fast in 2026.

## EU AI Act

| Article | Obligation                                                | Status                       | Tex Module                                              |
|---------|-----------------------------------------------------------|------------------------------|---------------------------------------------------------|
| Art. 26 | Deployer obligations for high-risk AI                     | Applicable from 2 Aug 2026   | `compliance/eu_ai_act/article_26.py`                    |
| Art. 50 | Transparency for AI-generated content                     | Applicable from 2 Aug 2026   | `compliance/eu_ai_act/article_50.py` + `c2pa/`         |
| Art. 17 | QMS / post-market monitoring                              | Applicable from 2 Aug 2026   | `compliance/eu_ai_act/article_17.py`                    |

The Code of Practice on Transparency of AI-Generated Content (operationalising
Art. 50) is on its second draft (3 March 2026). Final Code expected June 2026.

## US Federal

| Reference                                | Status                              | Tex Module                                |
|------------------------------------------|-------------------------------------|-------------------------------------------|
| FTC §5 (15 U.S.C. § 45) — existing AI enforcement | In force; ongoing (Rytr, Air AI, Operation AI Comply) | `compliance/ftc/policy_statement.py` |
| FTC AI policy statement under EO 14365  | **Deadline lapsed 11 Mar 2026; not yet published**     | `compliance/ftc/policy_statement.py` (TODO hook to pin focus areas if/when published) |
| NIST AI RMF                              | Voluntary, in use                   | `compliance/nist/ai_rmf.py`               |
| NIST AI Agent Standards Initiative (Feb 2026) | Active                          | `compliance/nist/agent_standards.py`      |
| NIST FIPS 204 (ML-DSA)                  | Standard published                  | `pqcrypto/ml_dsa.py`                      |
| NIST FIPS 203 (ML-KEM)                  | Standard published                  | `pqcrypto/ml_kem.py`                      |
| NIST FIPS 205 (SLH-DSA)                 | Standard published                  | `pqcrypto/slh_dsa.py`                     |

**FTC policy statement note:** EO 14365 (11 Dec 2025) directed the FTC
Chairman to publish a §5-and-AI policy statement within 90 days. The
deadline was 11 March 2026; **as of May 2026 the statement has not been
published**, per Morgan Lewis's April 2026 enforcement update. The White
House issued a separate National Policy Framework on 20 March 2026 —
legislative recommendations, not the §5 policy statement. FTC continues
to enforce §5 AI cases under existing authority. Tex's substantiation
packet is framed against the existing §5 framework (15 U.S.C. § 45) and
works *today*; do not reference the March 11 2026 statement as if it
exists.

## US State

| Statute                                  | Status                              | Tex Module                                |
|------------------------------------------|-------------------------------------|-------------------------------------------|
| California SB 942 (CAITA), as amended by AB 853 | Operative 2 Aug 2026 (per AB 853, signed 13 Oct 2025) | `compliance/state/california_sb942.py` |
| AB 853 — Large online platforms          | Effective 1 Jan 2027                | `compliance/state/california_ab853_platforms.py` (P1 stub) |
| AB 853 — Capture device manufacturers    | Effective 1 Jan 2028                | `compliance/state/california_ab853_capture.py` (P2 stub) |
| Colorado AI Act (SB 24-205, delayed by SB25B-004) | Effective 30 Jun 2026          | `compliance/state/colorado_ai_act.py`    |
| New York AI Advertising Disclosure       | Effective Jun 2026                  | `compliance/state/new_york_ai_disclosure.py` |

**SB 942 note:** AB 853 (signed 13 October 2025) moved the operative date
from 1 January 2026 to **2 August 2026** to align with the EU AI Act.
As of 7 May 2026 the latent disclosure obligation is **not yet
operative**. Tex emits compliant evidence ahead of the 2 August 2026
enforcement date so customers ship with provenance from day one. AB 853
also added obligations for large online platforms (1 Jan 2027) and
capture device manufacturers (1 Jan 2028) — see the linked stub modules.

## NAIC (Insurance)

| Reference                                | Tex Module                                |
|------------------------------------------|-------------------------------------------|
| NAIC Model Bulletin on AI               | `compliance/naic/model_bulletin.py`      |
| Cyber Insurance AI Rider Documentation  | `compliance/naic/cyber_rider.py`         |
