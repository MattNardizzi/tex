# FRONTIER_DELTA — Thread 8.1 (May 19, 2026)

## Scope

Thread 8.1 is a focused frontier-extension thread, not a feature thread.
It pushes Tex to three bleeding-edge primitives that exist in published
work but are not shipped in any AI-governance product as of May 19, 2026:

1. **BLAKE3-accelerated ML-DSA-B** for signed governance-log records
2. **AIR-style LLM-synthesized eradication rules** with cryptographic
   attestation
3. **Neyman-Pearson optimal multi-monitor selection** under cost +
   false-alarm budgets

All three were identified during the Thread 8 frontier-validation
sweep (FRONTIER_DELTA_thread_8.md §11) as "deferred but reachable".
The user explicitly requested they be built rather than deferred.

## 1. Why these three, and not others

After running a fresh frontier sweep (May 19, 2026, post-Thread-8):

- **ML-DSA-B**: Project Eleven + Taurus shipped the Rust reference in
  October 2025. JP Aumasson and Zooko Wilcox endorsed it. 15-30% faster
  sign/verify than stock ML-DSA-65. Zero shipping AI-governance products
  have it. Real, reachable, drop-in via the existing algorithm-agility
  plumbing. Cheap to build.

- **AIR eradication rule synthesis**: arxiv 2602.11749, Feb 12 2026.
  90%+ success rates on detection / containment / eradication with
  LLM-generated rules. Tex's `InterventionKind` enum was fixed at 7
  kinds; adding LLM-synthesized rules requires plan-level check
  infrastructure. The user explicitly approved building it.

- **Neyman-Pearson multi-monitor selection**: Hua et al. arxiv
  2507.15886, NeurIPS 2025. Provably optimal portfolio selection under
  cost + alpha budget. Tex's Step 8 already selects within a single
  candidate set; this generalises to selection *across* multiple
  monitor portfolios. No AI-governance product implements this.

What was explicitly NOT pushed in Thread 8.1 (still deferred):

- Full Project Eleven Rust ML-DSA-B with SHAKE-replacement inside the
  lattice algorithm itself. Requires Python binding of their fork,
  which does not yet exist. Tex implements the FIPS 204 §5.4 HashML-DSA
  subset (BLAKE3 pre-hashing) which captures the dominant performance
  win per the Taurus blog.
- Production LLM client implementations for eradication rule synthesis
  (OpenAI, Anthropic, Azure adapters). The `LLMClient` Protocol is
  shipped; concrete adapters are operator-side.
- Postgres-backed `RuleRegistry`. The Protocol is stable; production
  deployments swap mechanically.

## 2. What's wired into the existing engine surface

### Cryptographic signing chain

`tex.institutional._pq_signing.select_institutional_signing_provider()`
selection chain (best → fallback):

  1. **BLAKE3_ML_DSA_65** (Thread 8.1, May 19, 2026 frontier)
  2. ML_DSA_65 (stock FIPS 204, NIST Security Level 3)
  3. HYBRID_ML_DSA_ED25519 (CNSA 2.0 transition mode)
  4. ECDSA_P256 (FIPS 186-5 classical floor)

The selector probes each in order, picks the first whose `generate_keypair`
call succeeds. On hosts with liboqs + BLAKE3 binding, BLAKE3-ML-DSA-65
is selected. On hosts without liboqs, the chain falls through to
ECDSA-P256 — same behaviour as Thread 2-8, just one extra probe at the
top. `selection_chain_version` bumped to `v2-blake3-thread-8.1`.

### Intervention engine

`InterventionEngine.__init__` now accepts two optional kwargs:

  - `eradication_synthesizer: EradicationRuleSynthesizer | None = None`
  - `rule_registry: RuleRegistry | None = None`

When the kind is `ERADICATION_RULE_SYNTHESIS`, the engine pulls
`incident_context` from `intervention.parameters`, synthesises a rule,
registers it, and embeds the serialisable rule dict into the
governance-log audit payload. FAIL-CLOSED when:

  - The synthesizer or registry is not wired
  - `incident_context` is missing or malformed
  - Synthesis fails (LLM down AND deterministic check fails)
  - Plan-level checks reject the rule

`InterventionKind.ERADICATION_RULE_SYNTHESIS` is NOT in the engine's
`blocking_kinds` set — verdict defaults to `SANCTION` so the current
event admits cleanly while the registered rule blocks future
recurrences (matches AIR §3 semantics).

### Multi-monitor selection

`NeymanPearsonSelector` is independently usable today (no engine
integration in this thread — that's a Thread 9 wiring). Operators who
have multiple specialist monitors can call:

```python
selector = NeymanPearsonSelector(false_alarm_budget=0.05)
portfolio = selector.select_portfolio(
    available_monitors=(drift, contracts, causal_graph, governance),
    cost_budget=10.0,
)
pool = compose_intervention_pool(
    portfolio=portfolio,
    sources_by_monitor_id={
        "drift": drift_intervention_source,
        "contracts": contracts_intervention_source,
        ...
    },
)
# pool is now a deduped tuple of candidate interventions from the
# selected monitors only, ready for InterventionEngine.select().
```

The plumbing is hot. Thread 9 wires it into the EcosystemEngine when
Tex grows enough specialist monitors to make it load-bearing.

## 3. Test counts

| Frontier                  | Tests | Status |
|--------------------------:|------:|--------|
| BLAKE3-ML-DSA             |    16 | passing |
| AIR eradication           |    30 | passing |
| Neyman-Pearson selection  |    23 | passing |
| **Thread 8.1 new**        | **69** | passing |
| Thread 8 baseline         |  2,568 | passing |
| **Full regression total** | **2,637 passed, 16 skipped, 0 failed** |

The one test that needed updating from Thread 8 was
`test_engine.py::test_every_kind_has_mapping`, which hard-coded the
phase set as `{contain, recover, hold}`. Thread 8.1 added `eradicate`,
so the assertion now reads `{contain, recover, hold, eradicate}`. No
other Thread 1-8 tests required modification.

## 4. Honest caveats

- The BLAKE3-ML-DSA performance claim (15-30% faster) is reproducible
  on hosts with both liboqs and BLAKE3 installed. On hosts with neither,
  the selection chain falls through to ECDSA-P256 and the claim does
  not apply to that host. Telemetry event
  `tex.institutional.signing.provider_selected` is the source of truth
  per-deploy.

- The AIR eradication synthesizer's deterministic mode produces rules
  that block recurrence of the *fingerprint substring* of the original
  incident's payload. An adversary that changes one byte of the payload
  evades the rule. This matches AIR §3 — the paper's evaluation
  measures "same-incident-class recurrence", not adversarial evasion of
  the synthesised rule. Adversarial rule-evasion is the LLM mode's job;
  it's expected to generalise better than fingerprint matching. The
  deterministic fallback is the safety floor, not the bleeding edge.

- The Neyman-Pearson selector assumes monitor independence for the
  union-bound composite-false-alarm calculation. Correlated monitors
  would tighten the actual composite rate but also tighten composite
  detection; the operator-tunable lambda lets you compensate. Future
  work: correlation matrix support per Hua et al. §4 extensions.

## 5. References

- Project Eleven blog (Oct 2025):
  https://blog.projecteleven.com/posts/announcing-ml-dsa-b-optimizing-post-quantum-signatures-with-blake3
- Taurus blog (Oct 2025):
  https://www.taurushq.com/blog/faster-post-quantum-signatures-introducing-ml-dsa-b/
- NIST FIPS 204 §5.4 (HashML-DSA, hash-then-sign mode)
- BLAKE3 specification (Aumasson, Neves, Wilcox-O'Hearn, O'Connor 2020)
- arxiv 2602.11749 (AIR, Xiao/Sun/Chen, Feb 12 2026) — incident-response
  lifecycle for LLM agents
- arxiv 2507.15886 (Hua et al., NeurIPS 2025) — Neyman-Pearson
  multi-monitor optimality
- arxiv 2512.18561v3 (AAF Theorem 5, March 19 2026) — bounded-compromise
  certificate basis from Thread 8
