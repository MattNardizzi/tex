# TEX FRONTIER THREAT MODEL — MAY 2026

Maps every scaffolded defense module to its threat reference.

## OWASP Top 10 for Agentic Applications 2026 (ASI)

| ID     | Threat                          | Defense Module(s)                              |
|--------|---------------------------------|------------------------------------------------|
| ASI01  | Agent Goal Hijack               | `runtime/planguard`, `runtime/mage`            |
| ASI02  | Tool Misuse                     | `runtime/clawguard`, `governance/kernel_mcp`   |
| ASI03  | Privilege Compromise            | `governance/path_policy`, `interop/okta`       |
| ASI04  | Resource Overload               | `runtime/mage`                                 |
| ASI05  | Cascading Hallucination         | `receipts`, `runtime/agentarmor`               |
| ASI06  | Intent Breaking                 | `runtime/planguard`                            |
| ASI07  | Misaligned Behavior             | `governance/stpa_specs`                        |
| ASI08  | Repudiation                     | `pqcrypto`, `vet`, `receipts`                  |
| ASI09  | Identity Spoofing               | `vet`, `interop/a2a` (signed agent cards)      |
| ASI10  | Overwhelming Human Oversight    | `governance/path_policy`                       |

## OWASP Agentic Skills Top 10 (separate framework)

Implemented via `specialists/owasp_skills_top10_specialist.py`. Covers the
skill supply-chain attack surface (manifest tampering, permission escalation,
provenance gaps, untrusted skill registries).

## MCP Threat Surface

| CVE / Reference         | Defense Module                       |
|-------------------------|--------------------------------------|
| CVE-2025-49596 (MCP Inspector RCE)  | `runtime/mcpshield`         |
| CVE-2026-22252 (LibreChat)          | `runtime/mcpshield`         |
| CVE-2025-54136 (Cursor)             | `runtime/mcpshield`         |
| CVE-2026-22688 (WeKnora)            | `runtime/mcpshield`         |
| BlueRock 2026: 36.7% MCP servers SSRF-vulnerable | `specialists/mcp_injection_specialist.py` |

## Long-Horizon Attack Defense

`runtime/mage` (arxiv 2605.03228, Cisco co-author, May 4 2026) — shadow memory
analogous to shadow stacks. Targets cross-turn goal manipulation that single-turn
defenses miss.

## Host-Independent Trust

`vet` (arxiv 2512.15892, Oxford) — Agent Identity Documents + Web Proofs +
TEE attestation. Lets insurers/regulators verify Tex output without trusting
the host that ran it.
