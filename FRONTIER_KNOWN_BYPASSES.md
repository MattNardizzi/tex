# TEX FRONTIER KNOWN BYPASSES — UPDATED MAY 2026

This file extends the existing `var/tex/known_bypasses.md` with new attack
classes documented in May 2026 frontier research. Each entry maps to a Tex
module that addresses it (or marks it as P0/P1/P2 unimplemented).

## New Attack Classes

### LH-001: Long-horizon goal hijack
Cross-turn manipulation that flies under single-turn detectors. Documented in
arxiv 2605.03228 (MAGE, Cisco co-author, May 4 2026).
**Defense:** `runtime/mage` (P1, scaffolded)

### MCP-001: Tool poisoning via metadata
Malicious server modifies tool descriptions to lure agents into unsafe calls.
Documented in MCP Safety Audit (arxiv 2504.03767) and BlueRock 2026 telemetry.
**Defense:** `runtime/mcpshield` + `specialists/mcp_injection_specialist.py` (P0, scaffolded)

### MCP-002: SSRF via tool input
36.7% of public MCP servers vulnerable per BlueRock Feb 2026.
**Defense:** `governance/kernel_mcp` (P1, scaffolded)

### IPI-001: Indirect prompt injection via skill files
Malicious skill files in agent skill registries. Documented in arxiv 2604.11790
(ClawGuard) and the OWASP Agentic Skills Top 10.
**Defense:** `runtime/clawguard` + `specialists/owasp_skills_top10_specialist.py` (P0/P1)

### COM-001: Six commercial detectors evaded at 100%
Documented in arxiv 2504.11168. Affects Azure Prompt Shield, Meta Prompt Guard
class detectors.
**Defense:** `runtime/clawguard` deterministic boundary enforcement (P1)

### HOST-001: Host tampering
Host running the agent can substitute models, alter inputs, or fake outputs.
Documented in arxiv 2512.15892 (VET).
**Defense:** `vet/` Agent Identity Documents + `tee/` attestation (P2)

### MODEL-SUB-001: Cheap-model substitution
Service silently swaps GPT-4 → GPT-3.5, applies aggressive quantization.
Documented in arxiv 2603.18046 (NANOZK).
**Defense:** `nanozk/` layerwise ZK proofs (P2)

### TRAIN-001: Unauthorized training data
Model claims to be trained on certified dataset; actually trained on something else.
Documented in arxiv 2506.20915 (ZKPROV).
**Defense:** `zkprov/` (P1)
