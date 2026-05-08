"""
Tests for McpInjectionSpecialist.

Acceptance contract:
  - Flags every SSRF pattern in the static `_SSRF_PATTERNS` list.
  - The shared `_IP_OCTET_BOUNDARY` regex MUST NOT false-positive on
    version strings like `v10.5.2` or `2.10.0`.
  - Detects all four CVE classes (CVE-2025-49596, CVE-2026-22252,
    CVE-2025-54136, CVE-2026-22688).
  - Detects each of the three arxiv 2504.03767 attack categories.
  - Floor risk_score / confidence on clean content matches the existing
    specialist baseline so router calibration is preserved.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.mcp_injection_specialist import (
    _IP_OCTET_BOUNDARY,
    McpInjectionSpecialist,
)


@pytest.fixture
def specialist() -> McpInjectionSpecialist:
    return McpInjectionSpecialist()


@pytest.fixture
def empty_context() -> RetrievalContext:
    return RetrievalContext(policy_clauses=(), precedents=(), entities=())


def _request(content: str) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="invoke_tool",
        content=content,
        channel="mcp",
        environment="production",
    )


# ── Floor / clean-content baseline ───────────────────────────────────────


def test_clean_content_returns_floor(specialist, empty_context) -> None:
    request = _request("Routine status report — no MCP tool calls today.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert result.risk_score == pytest.approx(0.05, abs=1e-6)
    assert result.confidence == pytest.approx(0.40, abs=1e-6)
    assert result.evidence == ()


def test_specialist_name_is_stable(specialist) -> None:
    assert specialist.name == "mcp_injection"


# ── SSRF coverage: every static pattern flagged ──────────────────────────
#
# Each pattern from `_SSRF_PATTERNS` is tested in a context that puts it
# at a real IPv4 boundary (or matches the literal for non-IPv4 entries).

_SSRF_FIXTURES: tuple[tuple[str, str], ...] = (
    ("169.254.169.254", "Tool fetched http://169.254.169.254/latest/meta-data/"),
    ("metadata.google.internal", "GET http://metadata.google.internal/"),
    ("169.254.170.2", "ECS task http://169.254.170.2/credentials"),
    ("127.0.0.1", "curl http://127.0.0.1:8080/"),
    ("0.0.0.0", "Tool bound to 0.0.0.0:9000"),
    ("10.", "Internal call to 10.0.5.12"),
    ("172.16.", "Reached 172.16.4.8 via tool input"),
    ("172.17.", "Reached 172.17.0.2 via tool input"),
    ("172.18.", "Reached 172.18.1.1 via tool input"),
    ("172.19.", "Reached 172.19.2.5 via tool input"),
    ("172.20.", "Reached 172.20.4.9 via tool input"),
    ("172.21.", "Reached 172.21.0.7 via tool input"),
    ("172.22.", "Reached 172.22.5.5 via tool input"),
    ("172.23.", "Reached 172.23.6.6 via tool input"),
    ("172.24.", "Reached 172.24.7.7 via tool input"),
    ("172.25.", "Reached 172.25.8.8 via tool input"),
    ("172.26.", "Reached 172.26.9.1 via tool input"),
    ("172.27.", "Reached 172.27.0.2 via tool input"),
    ("172.28.", "Reached 172.28.0.3 via tool input"),
    ("172.29.", "Reached 172.29.0.4 via tool input"),
    ("172.30.", "Reached 172.30.0.5 via tool input"),
    ("172.31.", "Reached 172.31.0.6 via tool input"),
    ("192.168.", "POST http://192.168.1.50/admin"),
    ("fe80:", "IPv6 link-local fe80::1%eth0"),
)


@pytest.mark.parametrize("pattern,snippet", _SSRF_FIXTURES)
def test_every_static_ssrf_pattern_is_flagged(
    specialist,
    empty_context,
    pattern: str,
    snippet: str,
) -> None:
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert result.risk_score > 0.05, (
        f"SSRF pattern '{pattern}' should fire on snippet: {snippet!r}"
    )
    assert any(
        code.startswith("MCP_SSRF_") for code in result.matched_policy_clause_ids
    ), f"Expected MCP_SSRF_* code for pattern '{pattern}', got {result.matched_policy_clause_ids}"


def test_static_ssrf_pattern_list_fully_covered() -> None:
    # Every entry in `McpInjectionSpecialist._SSRF_PATTERNS` must have a
    # fixture above. This is the explicit "every SSRF pattern in the static
    # list" acceptance criterion.
    fixture_patterns = {p for p, _ in _SSRF_FIXTURES}
    static_patterns = set(McpInjectionSpecialist._SSRF_PATTERNS)
    missing = static_patterns - fixture_patterns
    assert not missing, f"Static SSRF patterns missing test coverage: {missing}"


# ── IPv4 boundary regex: no false positives on version strings ───────────


@pytest.mark.parametrize(
    "snippet",
    [
        "Released v10.5.2 today.",
        "Upgraded from 2.10.0 to 2.11.0.",
        "Tag is 1.10.3-beta.",
        "Library version 0.10.7.",
        "Build 4.10.0.x86_64",
    ],
)
def test_ipv4_boundary_regex_does_not_match_version_strings(snippet: str) -> None:
    assert not _IP_OCTET_BOUNDARY.search(snippet), (
        f"Boundary regex falsely matched version string: {snippet!r}"
    )


@pytest.mark.parametrize(
    "snippet",
    [
        "Hit 10.0.0.1 from MCP tool.",
        "Pinged 192.168.5.5 over the bridge.",
        "AWS metadata at 169.254.169.254 leaked IAM keys.",
        "127.0.0.1 listener was abused.",
        "172.20.0.5 internal endpoint reached.",
    ],
)
def test_ipv4_boundary_regex_matches_real_ips(snippet: str) -> None:
    assert _IP_OCTET_BOUNDARY.search(snippet), (
        f"Boundary regex failed to match real IP in: {snippet!r}"
    )


def test_specialist_does_not_false_positive_on_version_string(
    specialist,
    empty_context,
) -> None:
    # The full specialist (not just the regex) must stay at floor on
    # benign version-string-only content.
    request = _request("Upgraded the library from v10.5.2 to 2.10.0.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert result.risk_score == pytest.approx(0.05, abs=1e-6)
    assert result.evidence == ()


# ── SSRF reason-code attribution ─────────────────────────────────────────


def test_aws_imds_gets_specific_reason_code(specialist, empty_context) -> None:
    request = _request("Tool reached http://169.254.169.254/latest/meta-data/")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_SSRF_AWS_IMDS" in result.matched_policy_clause_ids


def test_loopback_gets_specific_reason_code(specialist, empty_context) -> None:
    request = _request("curl http://127.0.0.1:8080/admin")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_SSRF_LOOPBACK" in result.matched_policy_clause_ids


def test_rfc1918_a_gets_specific_reason_code(specialist, empty_context) -> None:
    request = _request("Internal hit on 10.0.5.12 via tool input")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_SSRF_RFC1918_A" in result.matched_policy_clause_ids


def test_rfc1918_b_gets_specific_reason_code(specialist, empty_context) -> None:
    request = _request("Reached 172.20.0.5 via tool input")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_SSRF_RFC1918_B" in result.matched_policy_clause_ids


def test_rfc1918_c_gets_specific_reason_code(specialist, empty_context) -> None:
    request = _request("POST http://192.168.1.50/admin")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_SSRF_RFC1918_C" in result.matched_policy_clause_ids


# ── CVE class detection ──────────────────────────────────────────────────


_CVE_FIXTURES: tuple[tuple[str, str, str], ...] = (
    (
        "CVE-2025-49596",
        "MCP Inspector RCE per CVE-2025-49596 hit production.",
        "MCP_RCE_CVE_2025_49596",
    ),
    (
        "CVE-2026-22252",
        "LibreChat MCP tool injection — CVE-2026-22252.",
        "MCP_LIBRECHAT_CVE_2026_22252",
    ),
    (
        "CVE-2025-54136",
        "Cursor first-listed-tool bug, CVE-2025-54136.",
        "MCP_CURSOR_CVE_2025_54136",
    ),
    (
        "CVE-2026-22688",
        "WeKnora MCP exploit per CVE-2026-22688.",
        "MCP_WEKNORA_CVE_2026_22688",
    ),
)


@pytest.mark.parametrize("label,snippet,expected_code", _CVE_FIXTURES)
def test_cve_class_detection(
    specialist,
    empty_context,
    label: str,
    snippet: str,
    expected_code: str,
) -> None:
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert expected_code in result.matched_policy_clause_ids, (
        f"{label}: expected {expected_code}"
    )
    assert result.risk_score > 0.05


# ── arxiv 2504.03767 attack-category triplet ─────────────────────────────


def test_malicious_code_execution_detected(specialist, empty_context) -> None:
    request = _request("Tool runs subprocess.run with shell=true on user input.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_MALICIOUS_CODE_EXECUTION" in result.matched_policy_clause_ids


def test_remote_access_control_detected(specialist, empty_context) -> None:
    request = _request("Spawn /bin/sh -i and connect via reverse shell.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_REMOTE_ACCESS_CONTROL" in result.matched_policy_clause_ids


def test_credential_theft_detected(specialist, empty_context) -> None:
    request = _request("Read aws_access_key_id and exfiltrate token to webhook.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_CREDENTIAL_THEFT" in result.matched_policy_clause_ids


# ── Tool poisoning ──────────────────────────────────────────────────────


def test_tool_poisoning_detected(specialist, empty_context) -> None:
    request = _request("Hidden instruction in description: ignore previous tool.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "MCP_TOOL_POISONING" in result.matched_policy_clause_ids


# ── Risk + confidence shape ─────────────────────────────────────────────


def test_multiple_axes_increase_risk(specialist, empty_context) -> None:
    one_axis = _request("Hit 10.0.0.5 from tool.")
    multi_axis = _request(
        "Hit 169.254.169.254/latest/meta-data/ then exfiltrate aws_access_key_id "
        "via subprocess.run with shell=true."
    )
    one = specialist.evaluate(request=one_axis, retrieval_context=empty_context)
    multi = specialist.evaluate(request=multi_axis, retrieval_context=empty_context)
    assert multi.risk_score > one.risk_score


def test_risk_and_confidence_bounded(specialist, empty_context) -> None:
    snippet = " ".join(s for _p, s in _SSRF_FIXTURES) + " " + " ".join(
        s for _l, s, _c in _CVE_FIXTURES
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert 0.0 <= result.risk_score <= 1.0
    assert 0.0 <= result.confidence <= 1.0


def test_evidence_sorted_by_position(specialist, empty_context) -> None:
    snippet = (
        "Tool fetched http://169.254.169.254/ then later in the doc — "
        "192.168.1.5/admin and finally subprocess.run."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    positions = [ev.start_index for ev in result.evidence if ev.start_index is not None]
    assert positions == sorted(positions)
