# TEX_CANONICAL.md is NOT in this repo

**Action required before opening any new thread:** Matthew, save the
"TEX — CANONICAL TRUTH DOCUMENT" (provided to Thread 1 as a chat-context
document attachment) into the repo root as `TEX_CANONICAL.md`.

Every thread prompt in Section 15 of the canonical doc begins with
*"read TEX_CANONICAL.md in the repo root"*. Without that file present
in the repo, future Claude sessions will not find their north star.

The canonical doc was provided as a chat-context document, not as an
uploaded file, when Thread 1 was opened. So this thread could read it,
but could not persist it back to disk without manual save-as.

## Threads completed

- **Thread 1** — domain + secrets cleanup. See `THREAD_1_CHANGELOG.md`.
- **Thread 2** — clean-install test-suite green. See `THREAD_2_CHANGELOG.md`.
- **Thread 3** — multi-tenant authorization. See `THREAD_3_CHANGELOG.md`.
- **Thread 4** — Layer 5 export routes + circular-import fix. See `THREAD_4_CHANGELOG.md`.
- **Thread 5** — C2PA emission + digital-twin wiring. See `THREAD_5_CHANGELOG.md`.
- **Thread 7** — EcosystemEngine integration into production HTTP path. See `THREAD_7_CHANGELOG.md` (May 24, 2026).

Remaining (per Section 14 of the canonical doc): Threads 6, 8, 9.

## Section 11 + Section 17 updates after Thread 7 (May 24, 2026)

For canonical-doc reconciliation in Thread 8, the following updates need
to be made to the in-context canonical doc:

**Section 2 at-a-glance table — Layer 4 row:**
> | **Layer 4** | ✅ Core + ecosystem wired | PDP, 22 specialists, contracts, 6 gateways, MCP, **EcosystemEngine + EcosystemBridge wired into /evaluate behind TEX_ECOSYSTEM=1** | SAFEFLOW + intervention engine still unwired (deferred to Thread 8 / cross-cutting); composition gate (axis → FORBID/SANCTION) Thread 8 |

**Section 11 — "What's BUILT but NOT WIRED into `/v1/guardrail`" subsection, EcosystemEngine paragraph:** strike. Replace with a "Now wired — see Thread 7" entry. The 8-step engine is now invoked via `EcosystemBridge.emit_verdict()` from `EvaluateActionCommand._maybe_apply_ecosystem()`. Axis scores land in `response.scores` under `ecosystem.*` namespace; GAAT level lands as `ecosystem_graduated_level:<value>` in `response.uncertainty_flags`. The 5-layer response schema (`extra="forbid"`) is preserved by this namespace projection.

**Section 11 — Gaps table:** Strike "EcosystemEngine not called from production path (Thread 7)" row. Replace with note that SAFEFLOW remains unwired and the composition gate is Thread 8.

**Section 13 — Layer 4 routes:** `POST /evaluate` and `POST /v1/guardrail` now carry the 7 `ecosystem.*` scores + 1 `ecosystem_graduated_level:*` uncertainty flag when `TEX_ECOSYSTEM=1`.

**Section 17 — Defects:** Defect #12 ("EcosystemEngine never called from production HTTP path") → **RESOLVED in Thread 7**. Move to Resolved section in any next reconciliation.

**Section 19 — Defensible pitch, "after threads" paragraph:** the "eight-step ecosystem governance pipeline evaluates every action..." sentence becomes structurally true today rather than aspirational; the engine is invoked behind a default-off flag.

**Test count:** Section 0 line "3,836 passing tests / 9 failures" is stale at the snapshot date. After all 5 prior threads + Thread 7: 3,478 main + 591 frontier + 20 thread suite = 4,089 passing across all suites, 0 failures.

## Standing-instruction reminder (May 24, 2026)

The user's standing instruction is to ground work in current-as-of-today
SOTA rather than January 2026 training data. Two non-blocking items
surfaced during Thread 7 that Thread 8 should address as part of the doc
reconciliation:

1. **EU AI Act Digital Omnibus provisional agreement (May 7, 2026):**
   Article 50(2) machine-readable AI content marking grace period
   shortened from 6→3 months. New deadline December 2, 2026.
   Review `src/tex/compliance/eu_ai_act/article_50.py` against this.
2. **Section 7 cryptographic specs reconciliation:** verify ML-DSA
   composite signature draft -18 → -19 movement since the May 22
   snapshot; check IETF SCITT draft -22 status. (Both already cited
   correctly in the canonical doc as of May 22, but worth a final
   pre-pitch verification pass.)

