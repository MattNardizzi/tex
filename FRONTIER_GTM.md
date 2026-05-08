# TEX DUAL-ICP GTM — MAY 2026

Two doors, same product. Pick the door per prospect.

## Door A: VP Marketing / Head of Brand

**Pitch surface:** `src/tex/pitch/vp_marketing.py`

**Headline:** Your AI-SDR is one hallucinated stat away from an FTC settlement.

**Proof points (all citation-anchored):**
- $24M in 2025-2026 FTC + state AG settlements on AI marketing claims
- 7 enforcement actions, B2B private right of action emerging
- EU AI Act Article 50 enforces August 2, 2026 — machine-readable disclosure required
- California SB 942 already live; NY AI advertising disclosure June 2026
- 31-47% false-positive rate across top 4 intent-data vendors feeding AI-SDRs

**Tex deliverable:** Every AI-generated email carries a C2PA Content Credential
manifest signed with ML-DSA. Insurers and FTC investigators can verify origin
offline.

## Door B: CISO at AI-SDR-using SaaS

**Pitch surface:** `src/tex/pitch/ciso.py`

**Headline:** Your AI stack runs on MCP. 37% of MCP servers are vulnerable.

**Proof points:**
- BlueRock Feb 2026: 36.7% of 7,000+ public MCP servers SSRF-vulnerable
- CVE-2025-49596 (MCP Inspector RCE), CVE-2026-22252 (LibreChat), CVE-2025-54136 (Cursor)
- OWASP Agentic Skills Top 10 documented active exploitation Q1 2026
- Vidar infostealer variants targeting agent skill files (Hudson Rock Feb 2026)
- Microsoft Defender Feb 2026: enterprise security advisory on agent gateways

**Tex deliverable:** Every MCP tool call adjudicated with a signed receipt.
Kernel-level governance gate enforces deny-by-default on sensitive paths,
private IP ranges, and outbound secret patterns.

## Insurer-Verifiable Evidence Packet

`src/tex/pitch/insurer_export.py` produces a single artifact:

- ML-DSA signed audit chain (post-quantum)
- C2PA manifests for outbound AI content
- HMAC tool receipts for every tool call
- ZKPROV proofs binding outputs to authorized training data
- TEE attestation JWTs (when running on H100/Blackwell)
- VET Agent Identity Document + Web Proofs

Verifier cannot tamper, host cannot forge, signer cannot deny.
