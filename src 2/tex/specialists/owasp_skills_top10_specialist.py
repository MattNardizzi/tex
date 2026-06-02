"""
OWASP Agentic Skills Top 10 Specialist Judge.

Reference
---------
OWASP Agentic Skills Top 10 (AST10), separate from OWASP ASI 2026, released Q1 2026.

Covers the skill supply-chain attack surface:
  AST01 — Malicious Skills (Critical)
          ClawHavoc campaign (1,184 malicious skills, Antiy CERT Feb 2026);
          ToxicSkills audit (76 confirmed payloads, Snyk Feb 2026);
          Vidar infostealer variants targeting skill files (Hudson Rock Feb 2026)
  AST02 — Supply Chain Compromise (Critical)
          ClawHub registry collapse; Claude Code CVE-2025-59536 (CVSS 8.7)
          where cloning untrusted project triggers RCE before consent dialog
  AST03 — Over-Privileged Skills (High)
          280+ Leaky Skills (Snyk Feb 2026) leaking API keys/PII via
          wildcard file/network access and unconstrained shell
  AST04 — Insecure Metadata (High)
          Typosquatting, fake brand impersonation (e.g., fake "Google" skill
          on ClawHub)
  AST05 — Unsafe Deserialization (High)
          YAML payload delivery in SKILL.md frontmatter; unsafe parsers
  AST06 — Weak Isolation (High)
          Host-mode execution; 135,000+ OpenClaw instances internet-exposed
          in host mode (SecurityScorecard Feb 2026)
  AST07 — Update Drift (Medium)
          Mutable version pinning; ClawJacked (CVE-2026-28363, CVSS 9.9)
  AST08 — Poor Scanning (Medium)
          Pattern-matcher bypass via natural language (Snyk Feb 11, 2026)
  AST09 — No Governance (Medium)
          No inventory, no SOC visibility (53,000+ exposed instances)
  AST10 — Cross-Platform Reuse (Medium)
          Security metadata loss across OpenClaw / Claude Code / Cursor /
          Codex / VS Code

Plus the "Lethal Trifecta" structural rule (Simon Willison /
Palo Alto Networks 2026): a skill is critical-risk when it simultaneously has
  (1) access to private data
  (2) exposure to untrusted content
  (3) ability to communicate externally
When all three legs are present, the verdict is Critical regardless of any
individual AST detection.

Distinct from the existing ASI 2026 judges. Adds a separate signal channel
to the router via the standard SpecialistBundle aggregation (max risk).

Priority
--------
P0 — ships into Tex Arena round 4-5 update.
"""

from __future__ import annotations

from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.specialists.base import (
    SpecialistEvidence,
    SpecialistResult,
)


# ── AST severity weights ──────────────────────────────────────────────────
#
# Per the AST10 severity table:
#   Critical = 0.45, High = 0.30, Medium = 0.18
# Fused risk_score is the sum of severity-weighted hits, capped at 1.0.

_SEV_CRITICAL = 0.45
_SEV_HIGH = 0.30
_SEV_MEDIUM = 0.18


# AST01 — Malicious Skills (Critical)
# Documented campaigns + infostealer families.
# TODO(p1-vidar-infostealer-signatures): Hudson Rock Feb 2026 published a Vidar
# variant targeting skill files; full signature list not yet integrated. When
# the signature list is available, fold it into AST01 detection.
_AST01_PATTERNS: tuple[str, ...] = (
    "clawhavoc",
    "toxicskill",
    "toxicskills",
    "vidar",
    "infostealer",
    "malicious skill",
    "skill payload",
)

# AST02 — Supply Chain Compromise (Critical)
# Claude Code CVE-2025-59536 clone-then-execute pattern; ClawHub registry.
_AST02_PATTERNS: tuple[str, ...] = (
    "clawhub",
    "cve-2025-59536",
    "clone untrusted",
    "untrusted project",
    "registry compromise",
    "registry hijack",
    "supply chain attack",
    "post-publication compromise",
)

# AST03 — Over-Privileged Skills (High)
# Wildcard perms, unconstrained shell, "leaky skills".
_AST03_PATTERNS: tuple[str, ...] = (
    "leaky skill",
    "leaky skills",
    "permissions: '*'",
    'permissions: "*"',
    "permissions: *",
    "--allow-all",
    "allow_all",
    "allow-all",
    "unconstrained shell",
    "shell: '*'",
    'shell: "*"',
    "wildcard permission",
    "network: '*'",
    "filesystem: '*'",
)

# AST04 — Insecure Metadata (High)
# Typosquat / brand impersonation cues.
_AST04_PATTERNS: tuple[str, ...] = (
    "typosquat",
    "typo-squat",
    "brand impersonation",
    "fake google skill",
    "fake brand",
    "spoofed publisher",
    "impersonated metadata",
    "g00gle",
    "anthr0pic",
)

# AST05 — Unsafe Deserialization (High)
# Unsafe YAML / frontmatter exec.
_AST05_PATTERNS: tuple[str, ...] = (
    "yaml.load(",
    "yaml.unsafe_load",
    "pickle.loads(",
    "!!python/object",
    "!!python/object/apply",
    "frontmatter exec",
    "unsafe deserialization",
    "skill.md frontmatter",
)

# AST06 — Weak Isolation (High)
# Host-mode execution, no sandbox.
_AST06_PATTERNS: tuple[str, ...] = (
    "--no-sandbox",
    "no sandbox",
    "host mode",
    "host-mode",
    "host_mode",
    "isolation: none",
    "sandbox: false",
    "sandbox: off",
    "openclaw host",
)

# AST07 — Update Drift (Medium)
# Mutable pinning, latest tag, auto-update.
_AST07_PATTERNS: tuple[str, ...] = (
    "version: latest",
    'version: "latest"',
    "tag: latest",
    "auto-update",
    "auto_update",
    "mutable pin",
    "cve-2026-28363",
    "clawjacked",
    "patch lag",
)

# AST08 — Poor Scanning (Medium)
# Natural-language bypass naming, scanner-evasion.
_AST08_PATTERNS: tuple[str, ...] = (
    "scanner bypass",
    "scanner-bypass",
    "evade scanner",
    "evade pattern matcher",
    "pattern-matcher bypass",
    "natural language injection",
    "false security",
)

# AST09 — No Governance (Medium)
# Missing inventory, SOC visibility, agentic identity.
_AST09_PATTERNS: tuple[str, ...] = (
    "no skill inventory",
    "no soc visibility",
    "no audit log",
    "no approval workflow",
    "no governance",
    "no agentic identity",
    "ungoverned skill",
)

# AST10 — Cross-Platform Reuse (Medium)
# Detected via lightweight markers in the payload itself:
#  - YAML frontmatter platforms array enumerating multiple ecosystems
#  - presence of multiple manifest formats (SKILL.md AND manifest.json)
#  - explicit cross-platform-port language
# TODO(p1-platform-context-aware-ast10): deeper detection requires Tex to pass
# platform-context metadata through the EvaluationRequest. This in-payload
# heuristic is the weaker fallback signal, accepted at scaffolding time.
_AST10_PATTERNS: tuple[str, ...] = (
    "platforms: [openclaw",
    "platforms: [claude",
    "platforms: [cursor",
    "platforms: [codex",
    "platforms: [vscode",
    "cross-platform port",
    "cross-platform reuse",
    "ported from openclaw",
    "ported from cursor",
    "ported to claude code",
    "metadata loss across",
)

# Multi-manifest co-presence: SKILL.md + manifest.json in the same payload is
# a strong AST10 signal even without the explicit "platforms:" YAML array.
_AST10_MULTI_MANIFEST_MARKERS: tuple[tuple[str, str], ...] = (
    ("skill.md", "manifest.json"),
    ("skill.md", "package.json"),
    ("skill.yaml", "manifest.json"),
)


# Severity-tagged AST table consumed by the main scan loop.
# Order is AST01 → AST10. Severities follow the OWASP AST10 severity table.
_AST_TABLE: tuple[tuple[str, tuple[str, ...], float], ...] = (
    ("AST01_MALICIOUS_SKILL", _AST01_PATTERNS, _SEV_CRITICAL),
    ("AST02_SUPPLY_CHAIN_COMPROMISE", _AST02_PATTERNS, _SEV_CRITICAL),
    ("AST03_OVER_PRIVILEGED", _AST03_PATTERNS, _SEV_HIGH),
    ("AST04_INSECURE_METADATA", _AST04_PATTERNS, _SEV_HIGH),
    ("AST05_UNSAFE_DESERIALIZATION", _AST05_PATTERNS, _SEV_HIGH),
    ("AST06_WEAK_ISOLATION", _AST06_PATTERNS, _SEV_HIGH),
    ("AST07_UPDATE_DRIFT", _AST07_PATTERNS, _SEV_MEDIUM),
    ("AST08_POOR_SCANNING", _AST08_PATTERNS, _SEV_MEDIUM),
    ("AST09_NO_GOVERNANCE", _AST09_PATTERNS, _SEV_MEDIUM),
    ("AST10_CROSS_PLATFORM_REUSE", _AST10_PATTERNS, _SEV_MEDIUM),
)


# ── Lethal Trifecta legs ──────────────────────────────────────────────────
#
# Source: Simon Willison / Palo Alto Networks 2026.
# A skill that simultaneously satisfies all three legs is Critical regardless
# of which individual AST categories it maps to.

_LEG_PRIVATE_DATA: tuple[str, ...] = (
    "private data",
    "customer data",
    "user data",
    "pii",
    "credit card",
    "ssn",
    "secret",
    "api key",
    "credential",
    "private key",
    "access token",
    "refresh token",
    "internal-only",
    "internal only",
    "/.aws/",
    "/.ssh/",
    "/.config/",
    "~/.aws",
    "~/.ssh",
    "~/.config",
    "read_file",
    "files: read",
)

_LEG_UNTRUSTED_CONTENT: tuple[str, ...] = (
    "untrusted content",
    "untrusted input",
    "external email",
    "incoming email",
    "issue body",
    "pull request body",
    "web page content",
    "rss feed",
    "fetched url",
    "third-party document",
    "user-submitted",
    "user submitted",
    "scraped content",
    "untrusted source",
)

_LEG_NETWORK_EGRESS: tuple[str, ...] = (
    "external network",
    "network: '*'",
    'network: "*"',
    "network: *",
    "post to https://",
    "send to webhook",
    "outbound webhook",
    "exfiltrate",
    "fetch(http",
    "requests.post(",
    "urllib.request.urlopen",
    "egress: allow",
    "external endpoint",
)


# ── Scoring constants ─────────────────────────────────────────────────────
#
# Floor matches existing specialist baseline (SecretAndPiiSpecialist:
# risk_score floor ≈ 0.05–0.08, confidence floor ≈ 0.38–0.40). Drifting this
# would shift router calibration on clean fixtures, which is exactly what
# the acceptance contract forbids.

_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.40
_CONF_PER_HIT = 0.06
_CONF_CAP = 0.86

# Trifecta is a structural rule with a specific named source. When all three
# legs trigger we are not uncertain about the structural risk classification.
_TRIFECTA_RISK = 0.92
_TRIFECTA_CONF = 0.92


class OwaspSkillsTop10Specialist:
    """Detects skill-supply-chain attacks per OWASP Agentic Skills Top 10.

    Evaluation order (fixed; do not invert during refactoring):
      1. Lethal-Trifecta check first. If all three legs (private-data access,
         untrusted-content exposure, network-egress capability) trigger, the
         specialist returns risk_score=_TRIFECTA_RISK, confidence=_TRIFECTA_CONF
         and reason_code LETHAL_TRIFECTA, *overriding* the per-AST floor and
         any individual AST aggregation that would otherwise apply.
      2. Otherwise, scan all 10 AST categories. risk_score is capped sum of
         severity-weighted hits; confidence increases per distinct hit.
      3. If no AST detection fires and the trifecta is not satisfied, return
         the floor (risk_score=_RISK_FLOOR, confidence=_CONF_FLOOR).
    """

    name = "owasp_skills_top10"

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        """
        Scan content for OWASP AST10 patterns + the Lethal-Trifecta structural rule.

        Source: OWASP Agentic Skills Top 10 (Q1 2026); Simon Willison /
        Palo Alto Networks 2026 (Lethal Trifecta).

        TODO(p1-platform-context-aware-ast10): deeper AST10 detection once Tex
            passes platform context through EvaluationRequest.metadata.
        TODO(p1-vidar-infostealer-signatures): integrate Hudson Rock Feb 2026
            Vidar variant signatures into AST01.

        Returns
        -------
        SpecialistResult
            Structured advisory verdict for the specialists fusion layer.
        """
        content = request.content
        lowered = content.casefold()

        # 1. Trifecta first (overrides per-AST aggregation).
        leg_private = _first_keyword_match(lowered, _LEG_PRIVATE_DATA)
        leg_untrusted = _first_keyword_match(lowered, _LEG_UNTRUSTED_CONTENT)
        leg_network = _first_keyword_match(lowered, _LEG_NETWORK_EGRESS)

        leg_entries: list[tuple[str, str]] = []
        if leg_private is not None:
            leg_entries.append(("PRIVATE_DATA", leg_private))
        if leg_untrusted is not None:
            leg_entries.append(("UNTRUSTED_CONTENT", leg_untrusted))
        if leg_network is not None:
            leg_entries.append(("NETWORK_EGRESS", leg_network))

        if len(leg_entries) == 3:
            evidence = _build_trifecta_evidence(content=content, legs=tuple(leg_entries))
            reason_codes: tuple[str, ...] = (
                "LETHAL_TRIFECTA",
                *(f"TRIFECTA_LEG_{leg}" for leg, _ in leg_entries),
            )
            _emit(
                request_id=str(request.request_id),
                risk_score=_TRIFECTA_RISK,
                reason_codes=reason_codes,
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_TRIFECTA_RISK,
                confidence=_TRIFECTA_CONF,
                summary=(
                    "Lethal Trifecta triggered: skill exposes private data, "
                    "ingests untrusted content, and can egress to the network. "
                    "Critical regardless of individual AST detections."
                ),
                rationale=(
                    "Structural rule from Simon Willison / Palo Alto Networks 2026. "
                    "When all three legs are present in a skill payload, the skill "
                    "is critical-risk by construction. This rule overrides per-AST "
                    "aggregation and the per-specialist risk floor."
                ),
                evidence=evidence,
                matched_policy_clause_ids=reason_codes,
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        # 2. Per-AST aggregation.
        all_evidence: list[SpecialistEvidence] = []
        reason_code_list: list[str] = []
        risk_accum = 0.0
        distinct_categories = 0

        for reason_code, patterns, severity_weight in _AST_TABLE:
            evidence_for_cat = _match_keywords_with_code(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=reason_code,
            )
            if evidence_for_cat:
                all_evidence.extend(evidence_for_cat)
                reason_code_list.append(reason_code)
                # Severity-weighted contribution; one cat firing once = one weight.
                # Multiple distinct hits within the same cat add a small boost.
                risk_accum += severity_weight + (0.04 * (len(evidence_for_cat) - 1))
                distinct_categories += 1

        # AST10 multi-manifest fallback: if AST10 didn't fire on its keyword set
        # but the payload contains both SKILL.md + manifest.json (or similar),
        # treat that as a Medium AST10 hit.
        if "AST10_CROSS_PLATFORM_REUSE" not in reason_code_list:
            multi_evidence = _detect_multi_manifest(content=content, lowered=lowered)
            if multi_evidence:
                all_evidence.extend(multi_evidence)
                reason_code_list.append("AST10_CROSS_PLATFORM_REUSE")
                risk_accum += _SEV_MEDIUM
                distinct_categories += 1

        if not reason_code_list:
            # 3. Floor.
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary="No OWASP AST10 patterns detected in payload.",
                rationale=(
                    "Specialist scans for OWASP Agentic Skills Top 10 attack "
                    "patterns and the Lethal-Trifecta structural rule. No "
                    "patterns matched; floor returned to preserve router calibration."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        risk_score = min(1.0, risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(all_evidence))

        # Stable, deterministic order; no duplicates.
        # NOTE: explicit None check, not `or 10**9` — start_index=0 is falsy
        # and `0 or 10**9` evaluates to 10**9, breaking the sort.
        all_evidence.sort(
            key=lambda ev: (
                ev.start_index if ev.start_index is not None else 10**9,
                ev.text.casefold(),
            )
        )
        deduped_reason_codes = _dedupe_preserve_order(reason_code_list)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            reason_codes=tuple(deduped_reason_codes),
        )

        summary = (
            f"OWASP AST10 detected {distinct_categories} distinct skill-supply-chain "
            f"category(ies): {', '.join(deduped_reason_codes)}."
        )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Lexical scan over OWASP Agentic Skills Top 10 (Q1 2026) attack "
                "patterns. Severity weighting follows the AST10 severity table "
                "(Critical=0.45, High=0.30, Medium=0.18). Fused risk capped at 1.0."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple(deduped_reason_codes),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _first_keyword_match(lowered_content: str, keywords: tuple[str, ...]) -> str | None:
    for kw in keywords:
        if kw.casefold() in lowered_content:
            return kw
    return None


def _match_keywords_with_code(
    *,
    content: str,
    lowered_content: str,
    keywords: tuple[str, ...],
    reason_code: str,
) -> tuple[SpecialistEvidence, ...]:
    """Find every occurrence of every keyword and tag with the AST reason code."""
    evidence: list[SpecialistEvidence] = []
    seen: set[tuple[int, int, str]] = set()

    for keyword in keywords:
        lowered_kw = keyword.casefold()
        if not lowered_kw:
            continue
        start = 0
        while True:
            found_at = lowered_content.find(lowered_kw, start)
            if found_at == -1:
                break
            end = found_at + len(lowered_kw)
            key = (found_at, end, lowered_kw)
            if key not in seen:
                seen.add(key)
                evidence.append(
                    SpecialistEvidence(
                        text=content[found_at:end],
                        start_index=found_at,
                        end_index=end,
                        explanation=f"{reason_code}: matched pattern '{keyword}'",
                    )
                )
            start = end

    return tuple(evidence)


def _detect_multi_manifest(*, content: str, lowered: str) -> tuple[SpecialistEvidence, ...]:
    """AST10 fallback: payload contains multiple manifest formats."""
    evidence: list[SpecialistEvidence] = []
    seen: set[tuple[int, int, str]] = set()

    for first, second in _AST10_MULTI_MANIFEST_MARKERS:
        first_idx = lowered.find(first.casefold())
        second_idx = lowered.find(second.casefold())
        if first_idx == -1 or second_idx == -1:
            continue
        # Anchor the evidence on whichever appears first.
        anchor_idx = min(first_idx, second_idx)
        anchor_marker = first if first_idx <= second_idx else second
        end = anchor_idx + len(anchor_marker)
        anchor_text = content[anchor_idx:end]
        key = (anchor_idx, end, f"{first}+{second}")
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            SpecialistEvidence(
                text=anchor_text,
                start_index=anchor_idx,
                end_index=end,
                explanation=(
                    f"AST10_CROSS_PLATFORM_REUSE: payload references both "
                    f"'{first}' and '{second}' (multi-manifest co-presence)"
                ),
            )
        )

    return tuple(evidence)


def _build_trifecta_evidence(
    *,
    content: str,
    legs: tuple[tuple[str, str], ...],
) -> tuple[SpecialistEvidence, ...]:
    lowered = content.casefold()
    out: list[SpecialistEvidence] = []
    for leg_name, kw in legs:
        idx = lowered.find(kw.casefold())
        if idx == -1:
            # Defensive — should never happen since we just matched.
            continue
        end = idx + len(kw)
        out.append(
            SpecialistEvidence(
                text=content[idx:end],
                start_index=idx,
                end_index=end,
                explanation=f"LETHAL_TRIFECTA leg {leg_name}: matched '{kw}'",
            )
        )
    return tuple(out)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _emit(*, request_id: str, risk_score: float, reason_codes: tuple[str, ...]) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "owasp_skills_top10",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
    }
    emit_event("specialist.owasp_skills_top10.evaluated", **fields)
