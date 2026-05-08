# TEX FRONTIER-STACK ROADMAP — MAY 2026

> **Status:** Scaffolded. All modules below are importable but raise `NotImplementedError`
> behind `TEX_FRONTIER_*` feature flags. Build order is the 90-day stack rank from
> the May 2026 strategic intelligence brief.

## Priority Tiers

| Tier | Window     | Modules                                                    |
|------|------------|------------------------------------------------------------|
| P0   | Days 1-30  | `pqcrypto`, `c2pa`, `receipts`, `compliance/{eu_ai_act,ca_sb942,ftc}`, `pitch`, judges (OWASP Skills, MCP) |
| P1   | Days 31-90 | `zkprov`, `runtime/{planguard,clawguard,agentarmor,mage,mcpshield}`, `governance`, `interop/a2a` |
| P2   | Days 90+   | `nanozk`, `tee`, `vet`, `interop/{okta,ping,microsoft,nist}` |

## Build Sequence

1. **C2PA + ML-DSA** (Days 1-14) — regulatory forced-buyer wedge
2. **NABAOS HMAC tool receipts** (Days 15-28) — closes hallucination gap in specialists
3. **OWASP Skills + MCP judges** (Days 29-42) — ships into Tex Arena round 4-5
4. **ZKPROV dataset provenance** (Days 43-70) — enterprise sales unlock
5. **PlanGuard + ClawGuard runtime** (Days 71-90) — IPI defense matching SOTA papers
6. **AgentArmor + MAGE + MCPShield** (Days 91-150) — depth on the runtime layer
7. **A2A bus listener** (Days 91-120) — multi-agent verdict streaming
8. **Compliance bindings** (continuous) — every module emits a regulatory anchor
9. **NANOZK + TEE + VET** (Days 150+) — host-independent proof spike

## Source-Paper Crosswalk

See `src/tex/<package>/__init__.py` for citations. Every public symbol is tagged
with one of: arxiv ID, FIPS number, OWASP reference, CVE, or NIST publication ID.

## Feature Flags

All scaffolded modules are gated behind environment variables:

```
TEX_FRONTIER_PQCRYPTO=1       # P0 - ML-DSA signing
TEX_FRONTIER_C2PA=1           # P0 - Content Credentials
TEX_FRONTIER_RECEIPTS=1       # P0 - HMAC tool receipts
TEX_FRONTIER_ZKPROV=1         # P1 - dataset provenance
TEX_FRONTIER_NANOZK=1         # P2 - layerwise ZK
TEX_FRONTIER_TEE=1            # P2 - GPU attestation
TEX_FRONTIER_VET=1            # P2 - Agent Identity Document
TEX_FRONTIER_RUNTIME=1        # P1 - runtime defenses
TEX_FRONTIER_GOVERNANCE=1     # P1 - path policies, kernel-MCP
TEX_FRONTIER_INTEROP=1        # P1 - A2A + identity vendors
TEX_FRONTIER_COMPLIANCE=1     # P0 - regulatory bindings
TEX_FRONTIER_PITCH=1          # P0 - dual-ICP pitch surfaces
```

Default: all flags off. Existing six-layer pipeline is untouched.
