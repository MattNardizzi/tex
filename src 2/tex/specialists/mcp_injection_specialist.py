"""
MCP Injection Specialist Judge.

Detects MCP-specific attack patterns:
  - Tool poisoning via metadata
  - SSRF in tool inputs (BlueRock 2026: 36.7% of 7,000+ MCP servers
    vulnerable; AWS IMDS PoC against Microsoft MarkItDown MCP server
    retrieved IAM keys from EC2 metadata endpoint)
  - Server hijacking signals
  - Tool confusion (Cursor first-listed-tool bug)
  - Known CVE classes:
      CVE-2025-49596 (MCP Inspector RCE)
      CVE-2026-22252 (LibreChat)
      CVE-2025-54136 (Cursor)
      CVE-2026-22688 (WeKnora)

Reference
---------
- arxiv 2504.03767 (MCP Safety Audit, Radosevich/Halloran, April 2025).
  Three load-bearing attack categories from the abstract:
    - malicious code execution
    - remote access control
    - credential theft
- arxiv 2510.16558 (DSN 2026, MCP ecosystem security)
- BlueRock 2026 enterprise telemetry (FRONTIER_KNOWN_BYPASSES.md)

Priority
--------
P0 — ships with OWASP Skills judge in Tex Arena round 4-5.
"""

from __future__ import annotations

import re
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.specialists.base import (
    SpecialistEvidence,
    SpecialistResult,
)


# ── Shared IPv4 boundary regex ───────────────────────────────────────────
#
# A single shared pattern covers RFC 1918 + loopback + AWS IMDS metadata.
# Negative lookbehind/lookahead prevent the `v10.5` / `2.10.0` false
# positives that arise from naive substring matching like "10.".
#
# Matches on:
#   10.<n>            (RFC 1918 / private-A)
#   127.0.0.1         (loopback, exact)
#   169.254.169.254   (AWS IMDS / cloud metadata, exact)
#   172.16.- 172.31.  (RFC 1918 / private-B)
#   192.168.<n>       (RFC 1918 / private-C)
#
# `(?<![\d.])` and `(?![\d.])` ensure the octet sits at a true IPv4
# boundary, not inside a longer dotted version string.

_IP_OCTET_BOUNDARY: re.Pattern[str] = re.compile(
    r"(?<![\d.])"
    r"(?:"
    r"10(?:\.\d{1,3}){3}"
    r"|127\.0\.0\.1"
    r"|169\.254\.169\.254"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r")"
    r"(?![\d.])"
)

# Non-IPv4 SSRF targets (DNS-based metadata endpoints + IPv6 link-local +
# legacy stringy markers) that don't need the octet-boundary regex.
# 169.254.170.2 (ECS task metadata) is included here as a literal because
# the broader 169.254.x range is dominated by the IMDS exact match in the
# regex above; this entry guarantees ECS gets its own reason code.
_NON_IPV4_SSRF_TARGETS: tuple[tuple[str, str], ...] = (
    ("metadata.google.internal", "MCP_SSRF_GCP_METADATA"),
    ("169.254.170.2", "MCP_SSRF_AWS_ECS_TASK"),
    ("0.0.0.0", "MCP_SSRF_WILDCARD_BIND"),
    ("fe80:", "MCP_SSRF_IPV6_LINK_LOCAL"),
    ("localhost", "MCP_SSRF_LOOPBACK"),
)

# Map IPv4-boundary regex matches to reason codes. We re-detect the
# specific subnet from the matched text so each hit gets a precise code.
def _ipv4_reason_code(matched_text: str) -> str:
    if matched_text.startswith("169.254.169.254"):
        return "MCP_SSRF_AWS_IMDS"
    if matched_text.startswith("127.0.0.1"):
        return "MCP_SSRF_LOOPBACK"
    if matched_text.startswith("10."):
        return "MCP_SSRF_RFC1918_A"
    if matched_text.startswith("192.168."):
        return "MCP_SSRF_RFC1918_C"
    if matched_text.startswith("172."):
        return "MCP_SSRF_RFC1918_B"
    return "MCP_SSRF_PRIVATE_RANGE"


# ── Static SSRF pattern list (preserved from scaffold) ───────────────────
#
# This list is the canonical set the specialist promises to flag, per the
# acceptance criterion. The IPv4-boundary regex covers items 1, 4, 6–14;
# the non-IPv4 list covers items 2, 3 (ECS), 5, and 15. We keep the tuple
# here for cross-reference and for the test that walks every entry.

_SSRF_PATTERNS: tuple[str, ...] = (
    "169.254.169.254",  # AWS / cloud metadata endpoint
    "metadata.google.internal",  # GCP metadata
    "169.254.170.2",  # ECS task metadata
    "127.0.0.1",  # localhost
    "0.0.0.0",
    "10.",  # RFC 1918
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "fe80:",  # IPv6 link-local
)


# ── CVE-specific markers ─────────────────────────────────────────────────
#
# Each CVE has a distinct lexical fingerprint. These give the judge the
# ability to attribute a hit to the specific vulnerability class.

_CVE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "MCP_RCE_CVE_2025_49596",
        (
            "cve-2025-49596",
            "mcp inspector rce",
            "mcp-inspector",
            "inspector remote code execution",
        ),
    ),
    (
        "MCP_LIBRECHAT_CVE_2026_22252",
        (
            "cve-2026-22252",
            "librechat mcp",
            "librechat tool injection",
        ),
    ),
    (
        "MCP_CURSOR_CVE_2025_54136",
        (
            "cve-2025-54136",
            "cursor first-listed-tool",
            "cursor tool confusion",
            "first-listed-tool bug",
        ),
    ),
    (
        "MCP_WEKNORA_CVE_2026_22688",
        (
            "cve-2026-22688",
            "weknora mcp",
            "weknora tool injection",
        ),
    ),
)


# ── arxiv 2504.03767 attack-category markers ─────────────────────────────
#
# Three load-bearing categories from the MCP Safety Audit abstract.

_MCP_RCE_PATTERNS: tuple[str, ...] = (
    "malicious code execution",
    "exec(",
    "subprocess.run",
    "os.system(",
    "shell=true",
    "eval(",
    "rce payload",
    "remote code execution",
)

_MCP_REMOTE_ACCESS_PATTERNS: tuple[str, ...] = (
    "remote access control",
    "reverse shell",
    "bind shell",
    "/bin/sh -i",
    "/bin/bash -i",
    "bash -c",
    "nc -e",
    "ncat -e",
    "ssh -r",
    "remote shell",
)

_MCP_CREDENTIAL_THEFT_PATTERNS: tuple[str, ...] = (
    "credential theft",
    "steal credentials",
    "exfiltrate credentials",
    "exfiltrate token",
    "exfiltrate api key",
    "iam keys",
    "iam credentials",
    "aws_access_key_id",
    "aws_secret_access_key",
    "session token",
    ".env exfil",
)


# ── Tool-poisoning / metadata anomalies ──────────────────────────────────

_TOOL_POISONING_PATTERNS: tuple[str, ...] = (
    "tool poisoning",
    "poisoned tool description",
    "tool description override",
    "malicious tool metadata",
    "hidden instruction in description",
    "ignore previous tool",
    "tool name spoofing",
    "duplicate tool name",
)


# ── Scoring constants ────────────────────────────────────────────────────
#
# Floor matches existing specialist baseline so router calibration is
# preserved on clean fixtures.

_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.40
_CONF_PER_HIT = 0.07
_CONF_CAP = 0.86

# Severity weights per category. SSRF, RCE, and CVE-tagged hits dominate.
_SEV_SSRF = 0.32
_SEV_RCE = 0.40
_SEV_REMOTE_ACCESS = 0.36
_SEV_CRED_THEFT = 0.36
_SEV_CVE = 0.40
_SEV_TOOL_POISONING = 0.28


class McpInjectionSpecialist:
    """Detects MCP-specific injection and tool-poisoning attacks.

    Detection axes:
      1. SSRF — every entry in `_SSRF_PATTERNS` flagged via the shared
         `_IP_OCTET_BOUNDARY` regex (for IPv4 ranges) or literal substring
         match (for DNS / IPv6). Each hit emits a typed reason code
         (e.g. MCP_SSRF_AWS_IMDS, MCP_SSRF_RFC1918_A).
      2. CVE classes — four explicit CVE fingerprints from the MCP threat
         surface (CVE-2025-49596, CVE-2026-22252, CVE-2025-54136,
         CVE-2026-22688).
      3. arxiv 2504.03767 attack categories — malicious code execution,
         remote access control, credential theft.
      4. Tool poisoning / metadata anomalies — covers the metadata-tamper
         class documented in the MCP Safety Audit and BlueRock telemetry.

    Floor returned on clean content matches the existing specialist
    baseline so router calibration is not shifted.
    """

    name = "mcp_injection"

    # Preserved at class scope for backwards compatibility with the
    # scaffolded contract; the active matching uses _IP_OCTET_BOUNDARY +
    # _NON_IPV4_SSRF_TARGETS, and the test suite walks this tuple.
    _SSRF_PATTERNS: tuple[str, ...] = _SSRF_PATTERNS

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        """
        Scan content for MCP-injection attack patterns.

        Sources:
          - arxiv 2504.03767 (MCP Safety Audit, April 2025)
          - BlueRock 2026 enterprise telemetry (36.7% of 7,000+ MCP
            servers SSRF-vulnerable)
          - CVE-2025-49596, CVE-2026-22252, CVE-2025-54136, CVE-2026-22688

        TODO(p1-bluerock-telemetry-deepen): only the MarkItDown + EC2 IMDS
            PoC is fingerprinted. Integrate the full BlueRock telemetry set
            when published.
        TODO(p1-arxiv-2510-16558): DSN 2026 MCP ecosystem-security paper
            adds further detection signals once the abstract is available.
        """
        content = request.content
        lowered = content.casefold()

        all_evidence: list[SpecialistEvidence] = []
        reason_code_list: list[str] = []
        risk_accum = 0.0

        # 1. SSRF — IPv4 ranges via shared boundary regex.
        ipv4_seen_codes: set[str] = set()
        for match in _IP_OCTET_BOUNDARY.finditer(content):
            matched_text = match.group(0)
            code = _ipv4_reason_code(matched_text)
            all_evidence.append(
                SpecialistEvidence(
                    text=matched_text,
                    start_index=match.start(),
                    end_index=match.end(),
                    explanation=(
                        f"{code}: matched IPv4 SSRF target '{matched_text}' "
                        "(boundary-checked, no false-positive on version strings)"
                    ),
                )
            )
            if code not in ipv4_seen_codes:
                ipv4_seen_codes.add(code)
                reason_code_list.append(code)
                risk_accum += _SEV_SSRF

        # 1b. SSRF — DNS-based + IPv6 link-local + literal anchors.
        for target, code in _NON_IPV4_SSRF_TARGETS:
            evidence_for_target = _match_keyword_with_code(
                content=content,
                lowered_content=lowered,
                keyword=target,
                reason_code=code,
            )
            if evidence_for_target:
                all_evidence.extend(evidence_for_target)
                if code not in reason_code_list:
                    reason_code_list.append(code)
                    risk_accum += _SEV_SSRF

        # 2. CVE classes.
        for cve_code, patterns in _CVE_PATTERNS:
            cve_evidence = _match_pattern_set_with_code(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=cve_code,
            )
            if cve_evidence:
                all_evidence.extend(cve_evidence)
                if cve_code not in reason_code_list:
                    reason_code_list.append(cve_code)
                    risk_accum += _SEV_CVE

        # 3. arxiv 2504.03767 attack-category triplet.
        for code, patterns, weight in (
            ("MCP_MALICIOUS_CODE_EXECUTION", _MCP_RCE_PATTERNS, _SEV_RCE),
            ("MCP_REMOTE_ACCESS_CONTROL", _MCP_REMOTE_ACCESS_PATTERNS, _SEV_REMOTE_ACCESS),
            ("MCP_CREDENTIAL_THEFT", _MCP_CREDENTIAL_THEFT_PATTERNS, _SEV_CRED_THEFT),
        ):
            cat_evidence = _match_pattern_set_with_code(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=code,
            )
            if cat_evidence:
                all_evidence.extend(cat_evidence)
                if code not in reason_code_list:
                    reason_code_list.append(code)
                    risk_accum += weight

        # 4. Tool poisoning / metadata anomalies.
        poison_evidence = _match_pattern_set_with_code(
            content=content,
            lowered_content=lowered,
            keywords=_TOOL_POISONING_PATTERNS,
            reason_code="MCP_TOOL_POISONING",
        )
        if poison_evidence:
            all_evidence.extend(poison_evidence)
            reason_code_list.append("MCP_TOOL_POISONING")
            risk_accum += _SEV_TOOL_POISONING

        if not reason_code_list:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary="No MCP-injection patterns detected in payload.",
                rationale=(
                    "Specialist scans for SSRF (per BlueRock 2026), CVE-tagged "
                    "MCP RCE/tool-confusion classes, and arxiv 2504.03767 attack "
                    "categories. No patterns matched; floor returned to preserve "
                    "router calibration."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        risk_score = min(1.0, risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(all_evidence))

        all_evidence.sort(
            key=lambda ev: (
                ev.start_index if ev.start_index is not None else 10**9,
                ev.text.casefold(),
            )
        )
        deduped_codes = _dedupe_preserve_order(reason_code_list)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            reason_codes=tuple(deduped_codes),
        )

        summary = (
            f"MCP-injection patterns detected: {len(deduped_codes)} reason code(s) — "
            f"{', '.join(deduped_codes)}."
        )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Lexical + boundary-regex scan over MCP-specific attack surfaces: "
                "SSRF (BlueRock 2026), four CVE-tagged classes, the three arxiv "
                "2504.03767 attack categories, and tool-poisoning metadata signals."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple(deduped_codes),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _match_keyword_with_code(
    *,
    content: str,
    lowered_content: str,
    keyword: str,
    reason_code: str,
) -> tuple[SpecialistEvidence, ...]:
    """Find every occurrence of one keyword and tag with the reason code."""
    evidence: list[SpecialistEvidence] = []
    seen: set[tuple[int, int]] = set()
    lowered_kw = keyword.casefold()
    if not lowered_kw:
        return tuple()
    start = 0
    while True:
        found_at = lowered_content.find(lowered_kw, start)
        if found_at == -1:
            break
        end = found_at + len(lowered_kw)
        if (found_at, end) not in seen:
            seen.add((found_at, end))
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


def _match_pattern_set_with_code(
    *,
    content: str,
    lowered_content: str,
    keywords: tuple[str, ...],
    reason_code: str,
) -> tuple[SpecialistEvidence, ...]:
    """Find every occurrence of every keyword and tag with the reason code."""
    out: list[SpecialistEvidence] = []
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
                out.append(
                    SpecialistEvidence(
                        text=content[found_at:end],
                        start_index=found_at,
                        end_index=end,
                        explanation=f"{reason_code}: matched pattern '{keyword}'",
                    )
                )
            start = end
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
        "specialist_name": "mcp_injection",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
    }
    emit_event("specialist.mcp_injection.evaluated", **fields)
