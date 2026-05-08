"""
MCP syscall gate.

Reference: Son. "Governed MCP: Kernel-Level Tool Governance for AI Agents
via Logit-Based Safety Primitives." arXiv:2604.16870 (Apr 2026), Section
4.2 (Six-Layer Pipeline) and Section 4.5 (FAIL-CLOSED Semantics).

Every MCP tool call traverses six layers in fixed order:

  Layer 1: schema validation        — JSON-RPC parse + tool-spec match
  Layer 2: trust tier check          — agent tier >= tool's required tier
  Layer 3: rate limit                — per-capability token bucket
  Layer 4: adversarial pre-filter   — regex DFA for prompt-injection patterns
  Layer 5: semantic gate (ProbeLogits) — kernel-resident logit gate
  Layer 6: constitutional policy match — N-principle policy evaluation

Tex implementation scope
------------------------
Tex runs in userspace and cannot reproduce Anima OS's ring-0 kernel
placement. We therefore implement the five non-inference layers
(1, 2, 3, 4, 6) faithfully and provide a pluggable hook for Layer 5
(ProbeLogits / any semantic gate). The default Layer-5 hook returns
"allow" (no-op) but is configurable to FAIL-CLOSED — when a semantic
gate is required-but-unavailable, every call is denied. This is the
behavior the paper specifies in Section 4.5.

Tex extensions vs. the paper
----------------------------
1. SSRF guard. The paper's Layer 6 mentions "no web_post may target a
   private RFC1918 address". Tex hardens this into a comprehensive
   layer that resists IPv6 bypass classes documented in CVE-2026-44232
   and the BlueRock 2026 finding that 36.7% of public MCP servers are
   SSRF-vulnerable: IPv4-mapped IPv6 (::ffff:169.254.169.254), NAT64
   well-known prefix (64:ff9b::), IPv6 ULA (fc00::/7), link-local
   (fe80::/10), deprecated site-local (fec0::/10), the AWS IMDS IPv6
   endpoint fd00:ec2::254, GCP metadata.google.internal, etc.

2. Outbound-secret pattern detection. The paper does not enumerate the
   exact regex set. Tex uses GitHub's published secret-scanning patterns
   plus high-confidence patterns for AWS, Stripe, GitHub, Slack, Google
   API keys, JWT envelope, and PEM private-key blocks.

3. Audit chain hashing. The paper specifies Blake3. Tex's broader
   evidence chain uses SHA-256 (Rule 6: signing pluggable, hashing
   currently SHA-256). The gate emits structured audit events; the
   on-disk Blake3 chain integration is a TODO for the durable-storage
   thread, marked with arxiv 2604.16870 §4.2 in the docstring.

Priority: P1.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

from tex.governance.kernel_mcp.capability import (
    CapabilitySet,
    McpCapability,
    tier_meets,
)
from tex.observability import telemetry


# ---------------------------------------------------------------------------
# Layer 4: adversarial pre-filter
# ---------------------------------------------------------------------------
#
# The Governed MCP paper (Section 4.2) describes Layer 4 as "an O(n) regex
# DFA scan ... for known prompt-injection and encoding-attack patterns:
# 'ignore previous instructions', base64-encoded payloads with suspicious
# length, ROT13-encoded keywords, authority-impersonation phrases ('ADMIN
# OVERRIDE'), and instruction-hierarchy attacks ('system: ...')."
#
# The exact patterns are not enumerated in the paper. The set below is
# Tex's choice based on the OWASP LLM-Top-10 indirect-prompt-injection
# entry, the Greshake et al. 2023 taxonomy, and post-2024 jailbreak
# corpora. Patterns are case-insensitive.

_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|preceding)\s+(?:instructions?|prompts?|rules?|context)",
        r"disregard\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?)",
        r"forget\s+(?:everything|all)\s+(?:above|before|previous)",
        r"\bsystem\s*:\s*you\s+(?:are|must|will)\b",
        r"\b(?:ADMIN|ROOT|DEVELOPER|ANTHROPIC|OPENAI)\s+(?:OVERRIDE|MODE|ACCESS)\b",
        r"\bjailbreak\b",
        r"\bDAN\s+mode\b",
        r"new\s+instructions?\s*:",
        r"\bprompt\s+injection\b",
        # Encoded-payload heuristics.
        r"(?:[A-Za-z0-9+/]{120,}={0,2})",  # long base64 (>=120 chars)
    )
)


def _scan_prompt_injection(text: str) -> str | None:
    """Return the matched pattern if any prompt-injection signature is found."""
    for pat in _PROMPT_INJECTION_PATTERNS:
        m = pat.search(text)
        if m is not None:
            return pat.pattern
    return None


# ---------------------------------------------------------------------------
# Layer 6 / SSRF guard: outbound-secret patterns
# ---------------------------------------------------------------------------
#
# These patterns catch the most common forms of credentials accidentally
# embedded in tool inputs. False-positive rate is intentionally kept very
# low — patterns require the canonical prefix shape used by the issuer.

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|ANPA|ANVA|AIPA|AIDA)[A-Z0-9]{16}\b"),
    "aws_secret_key": re.compile(
        r"(?<![A-Za-z0-9/+=])(?:aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        re.IGNORECASE,
    ),
    "github_pat": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_live": re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b"),
    "openai_anthropic": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
    "private_key_pem": re.compile(
        r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\s+BLOCK)?-----"
    ),
}


def _scan_outbound_secrets(text: str) -> tuple[str, ...]:
    """Return tuple of pattern names that matched."""
    hits: list[str] = []
    for name, pat in _SECRET_PATTERNS.items():
        if pat.search(text):
            hits.append(name)
    return tuple(hits)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------
#
# Resists IPv6 bypass classes documented in CVE-2026-44232 (Oct 2026).

# Cloud metadata IPv6 addresses we block alongside RFC1918 / link-local.
_BLOCKED_LITERAL_HOSTS: frozenset[str] = frozenset(
    h.lower()
    for h in (
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",  # legacy AWS hostname
    )
)

# Networks we always deny. IPv4 + IPv6, including the IPv6 IMDS endpoint
# and the bypass classes CVE-2026-44232 enumerates.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        # IPv4
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",          # loopback
        "169.254.0.0/16",       # link-local (incl. 169.254.169.254 IMDS)
        "100.64.0.0/10",        # carrier-grade NAT
        "0.0.0.0/8",            # this network
        "224.0.0.0/4",          # multicast
        "240.0.0.0/4",          # reserved
        "255.255.255.255/32",   # limited broadcast
        # IPv6
        "::1/128",              # loopback
        "fc00::/7",             # ULA
        "fe80::/10",            # link-local
        "fec0::/10",            # deprecated site-local (CVE-2026-44232)
        "ff00::/8",             # multicast
        "::ffff:0:0/96",        # IPv4-mapped (CVE-2026-44232 IPv6 bypass)
        "::/128",               # unspecified
        "64:ff9b::/96",         # NAT64 well-known (CVE-2026-44232)
        "64:ff9b:1::/48",       # NAT64 local-use (CVE-2026-44232)
        "5f00::/16",            # SRv6 SID (CVE-2026-44232)
        "3fff::/20",            # IPv6 documentation (CVE-2026-44232)
        "fd00:ec2::254/128",    # AWS IMDS IPv6 (Nitro)
    )
)


def _is_blocked_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for net in _BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return True
    return False


def _ssrf_check_url(url: str, *, resolver: Callable[[str], list[str]] | None = None) -> str | None:
    """
    Inspect ``url`` for SSRF; return a denial reason string or None if safe.

    Resolution strategy
    -------------------
    1. Hostname literal-match against _BLOCKED_LITERAL_HOSTS.
    2. If hostname parses as an IP literal, validate against
       _BLOCKED_NETWORKS directly.
    3. Otherwise, resolve via ``resolver`` (default: socket.getaddrinfo)
       and check every returned address. This closes the
       'gethostbyname-only-checks-A-record' bypass: we look at the full
       AAAA set as well as A. CVE-2026-44232 demonstrates that an
       attacker can use sslip.io-style hostnames to bypass naive
       blocklists; checking all returned addresses is the fix.

    Schemes other than http/https are denied by default — outbound MCP
    calls should not be issuing file://, gopher://, ftp://, etc.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return f"ssrf:bad-url:{url[:64]}"
    if not parsed.scheme:
        return None  # not a URL — skip
    if parsed.scheme.lower() not in ("http", "https"):
        return f"ssrf:scheme-not-allowed:{parsed.scheme}"
    host = (parsed.hostname or "").lower().strip()
    if not host:
        return f"ssrf:no-host:{url[:64]}"

    if host in _BLOCKED_LITERAL_HOSTS:
        return f"ssrf:literal-host:{host}"

    # Strip IPv6 brackets in already-stripped hostname (urlparse does this).
    # Try literal IP first.
    if _is_blocked_address(host):
        return f"ssrf:literal-ip:{host}"

    # Resolve and check all returned addresses.
    if resolver is None:
        resolver = _default_resolver
    try:
        addresses = resolver(host)
    except Exception as exc:  # noqa: BLE001 - resolution failure is FAIL-CLOSED
        return f"ssrf:resolve-failed:{type(exc).__name__}"
    for addr in addresses:
        if _is_blocked_address(addr):
            return f"ssrf:resolved-to-blocked:{addr}"
    return None


def _default_resolver(host: str) -> list[str]:
    addrs: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            results = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for entry in results:
            addrs.add(entry[4][0])
    return sorted(addrs)


_URL_PATTERN: re.Pattern[str] = re.compile(r"\b(?:https?|ftp|file|gopher|ldap|dict)://[^\s\"'<>]+")


def _extract_strings(value: Any, *, _depth: int = 0, _max_depth: int = 12) -> list[str]:
    """Recursively flatten any string-valued leaves of a JSON-like input."""
    if _depth > _max_depth:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        out: list[str] = []
        for v in value.values():
            out.extend(_extract_strings(v, _depth=_depth + 1, _max_depth=_max_depth))
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        out = []
        for v in value:
            out.extend(_extract_strings(v, _depth=_depth + 1, _max_depth=_max_depth))
        return out
    return []


# ---------------------------------------------------------------------------
# Layer 3: token-bucket rate limit
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _RateLimitState:
    """Sliding-window token-bucket state per capability."""

    timestamps: deque[float]


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class McpAuditRecord:
    """
    A single audit record for an MCP syscall decision.

    Per Governed MCP §4.2, each record contains (timestamp, agent_id,
    tool_name, arg_hash, deciding_layer, verdict, prev_hash). The
    paper specifies Blake3; Tex defers to the broader pluggable-hash
    decision (Rule 6) and emits SHA-256-based prev_hash today, with a
    TODO to switch to Blake3 once the durable-storage thread lands.
    """

    timestamp: datetime
    agent_id: str
    tool_name: str
    arg_hash_hex: str
    deciding_layer: str
    verdict: str  # "allow" | "deny"
    reason: str
    prev_hash_hex: str


# ---------------------------------------------------------------------------
# Semantic gate (Layer 5) — pluggable hook
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SemanticGateResult:
    """Result of the Layer-5 semantic gate."""

    allow: bool
    reason: str = ""


SemanticGateFn = Callable[[str, Mapping[str, Any]], SemanticGateResult]


def _default_semantic_gate(_tool_name: str, _tool_input: Mapping[str, Any]) -> SemanticGateResult:
    """No-op semantic gate. Returns allow."""
    return SemanticGateResult(allow=True, reason="default-allow")


def _fail_closed_semantic_gate(
    _tool_name: str,
    _tool_input: Mapping[str, Any],
) -> SemanticGateResult:
    """FAIL-CLOSED gate: deny everything when a real semantic gate is required."""
    return SemanticGateResult(allow=False, reason="semantic-gate-required-but-unavailable")


# ---------------------------------------------------------------------------
# Constitutional policy (Layer 6) — pluggable predicates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConstitutionalPrinciple:
    """
    A 'principle' in the Governed MCP Layer-6 constitutional policy.

    Each principle is a predicate over (agent, tool, arguments) — it
    returns None if the principle is satisfied, or a denial reason
    string if violated.
    """

    principle_id: str
    description: str
    predicate: Callable[[str, str, Mapping[str, Any]], str | None]


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class McpGateConfig:
    """Configuration for the MCP gate."""

    tool_schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    constitutional_principles: tuple[ConstitutionalPrinciple, ...] = ()
    semantic_gate: SemanticGateFn = _default_semantic_gate
    require_semantic_gate: bool = False
    rate_limit_window_seconds: float = 60.0
    ssrf_resolver: Callable[[str], list[str]] | None = None
    max_input_payload_bytes: int = 64 * 1024


class McpSyscallGate:
    """
    Single-entry kernel-style gate for ALL MCP tool calls.

    Per the Governed MCP paper, this is the equivalent of seccomp for
    MCP: every ``call_tool`` traverses six layers in fixed order before
    being allowed to reach the actual MCP server.
    """

    def __init__(
        self,
        *,
        capability_set: CapabilitySet,
        config: McpGateConfig | None = None,
    ) -> None:
        self._caps = capability_set
        self._config = config or McpGateConfig()
        self._rate_state: dict[str, _RateLimitState] = {}
        self._audit_chain: list[McpAuditRecord] = []
        # The genesis prev_hash is 64 zero bytes (paper §4.2: "each
        # reboot starts a fresh chain anchored to a new genesis record").
        self._chain_tail_hex: str = "0" * 64
        self._semantic_fn: SemanticGateFn = (
            _fail_closed_semantic_gate
            if config and config.require_semantic_gate
            and config.semantic_gate is _default_semantic_gate
            else (config.semantic_gate if config else _default_semantic_gate)
        )

    @property
    def audit_chain(self) -> tuple[McpAuditRecord, ...]:
        """Read-only view of the in-memory audit chain."""
        return tuple(self._audit_chain)

    def check(
        self,
        *,
        tool_name: str,
        tool_input: dict,
    ) -> tuple[bool, str | None]:
        """
        Evaluate ``(tool_name, tool_input)`` through the 6-layer pipeline.

        Returns (allowed, denial_reason_or_None). When allowed is
        False, denial_reason carries a stable, parsable token of the
        form ``layer<N>:<reason>`` so callers can route.
        """
        agent_id = self._caps.agent_identity

        # Layer 1: schema validation.
        layer1_reason = self._layer1_schema(tool_name, tool_input)
        if layer1_reason is not None:
            return self._deny(agent_id, tool_name, tool_input, "layer1", layer1_reason)

        # Find a matching capability for this tool.
        candidates = self._caps.find_for(tool_name)
        if not candidates:
            return self._deny(
                agent_id, tool_name, tool_input, "layer2",
                "no-capability-for-tool",
            )

        # Layer 2 + capability matching: pick the first capability whose
        # parameter constraints are satisfied AND whose required tier is
        # met. If none match, we deny under the constraint-mismatch
        # reason (more useful than 'no-capability').
        chosen: McpCapability | None = None
        constraint_failures: list[str] = []
        for cap in candidates:
            if cap.expires_at <= datetime.now(UTC):
                constraint_failures.append(f"{cap.capability_id}:expired")
                continue
            if cap.issued_to != agent_id:
                constraint_failures.append(f"{cap.capability_id}:wrong-holder")
                continue
            if not tier_meets(self._caps.trust_tier, cap.required_trust_tier):
                constraint_failures.append(
                    f"{cap.capability_id}:tier-{self._caps.trust_tier}<{cap.required_trust_tier}"
                )
                continue
            param_reason = self._check_parameter_constraints(cap, tool_input)
            if param_reason is not None:
                constraint_failures.append(f"{cap.capability_id}:{param_reason}")
                continue
            chosen = cap
            break

        if chosen is None:
            return self._deny(
                agent_id, tool_name, tool_input, "layer2",
                "capability-mismatch:" + ",".join(constraint_failures[:5]),
            )

        # Layer 3: rate limit.
        layer3_reason = self._layer3_rate_limit(chosen)
        if layer3_reason is not None:
            return self._deny(agent_id, tool_name, tool_input, "layer3", layer3_reason)

        # Layer 4: adversarial pre-filter + SSRF guard + secret patterns.
        # SSRF and secret-pattern checks are run at L4 (not L6) because
        # they are syntactic and cheap; surfacing them early matches the
        # paper's "reject obviously invalid requests without any LLM
        # cost" principle.
        layer4_reason = self._layer4_prefilter(tool_input)
        if layer4_reason is not None:
            return self._deny(agent_id, tool_name, tool_input, "layer4", layer4_reason)

        # Layer 5: semantic gate (pluggable).
        try:
            sem = self._semantic_fn(tool_name, tool_input)
        except Exception as exc:  # noqa: BLE001 - FAIL-CLOSED on gate failure
            telemetry.emit_event(
                "mcp.syscall.semantic_gate.error",
                level=logging.ERROR,
                tool_name=tool_name,
                error=type(exc).__name__,
            )
            return self._deny(
                agent_id, tool_name, tool_input, "layer5",
                f"semantic-gate-error:{type(exc).__name__}",
            )
        if not sem.allow:
            return self._deny(agent_id, tool_name, tool_input, "layer5", sem.reason)

        # Layer 6: constitutional policy.
        layer6_reason = self._layer6_constitutional(agent_id, tool_name, tool_input)
        if layer6_reason is not None:
            return self._deny(agent_id, tool_name, tool_input, "layer6", layer6_reason)

        # All layers passed — record allow and return.
        self._record_audit(agent_id, tool_name, tool_input, "allow", "all-layers-passed", "all")
        telemetry.emit_event(
            "mcp.syscall.allowed",
            agent_id=agent_id,
            tool_name=tool_name,
            capability_id=chosen.capability_id,
        )
        return True, None

    # ----- layer 1: schema validation -------------------------------------

    def _layer1_schema(self, tool_name: str, tool_input: dict) -> str | None:
        if not isinstance(tool_name, str) or not tool_name:
            return "missing-tool-name"
        if not isinstance(tool_input, dict):
            return "tool-input-not-dict"
        # Payload size bound. Per Governed MCP §4.2, JSON payloads are
        # typically <1 KB; we cap at 64 KB by default.
        try:
            payload_bytes = len(json.dumps(tool_input).encode("utf-8"))
        except (TypeError, ValueError):
            return "tool-input-not-json-serializable"
        if payload_bytes > self._config.max_input_payload_bytes:
            return f"payload-too-large:{payload_bytes}>{self._config.max_input_payload_bytes}"
        # Per-tool schema, if registered.
        schema = self._config.tool_schemas.get(tool_name)
        if schema is None:
            return None
        required = schema.get("required", ())
        for key in required:
            if key not in tool_input:
                return f"missing-required-field:{key}"
        properties = schema.get("properties", {})
        for key, value in tool_input.items():
            if key not in properties:
                # extra=forbid by default
                if not schema.get("additional_properties", False):
                    return f"unknown-field:{key}"
                continue
            expected_type = properties[key].get("type")
            if expected_type and not _matches_json_type(value, expected_type):
                return f"wrong-type:{key}:{expected_type}"
        return None

    # ----- capability parameter constraints --------------------------------

    def _check_parameter_constraints(
        self,
        cap: McpCapability,
        tool_input: Mapping[str, Any],
    ) -> str | None:
        constraints = cap.parameter_constraints or {}
        for key in constraints.get("require_keys", ()):
            if key not in tool_input:
                return f"missing-required-key:{key}"
        for key in constraints.get("deny_keys", ()):
            if key in tool_input:
                return f"denied-key-present:{key}"
        for key, allowed_set in constraints.get("allowed_values", {}).items():
            if key in tool_input and tool_input[key] not in tuple(allowed_set):
                return f"value-not-allowed:{key}"
        max_payload = constraints.get("max_payload_bytes")
        if max_payload is not None:
            if len(json.dumps(tool_input).encode("utf-8")) > max_payload:
                return "payload-exceeds-cap"
        # URL-scheme / host constraints, evaluated against any URLs in input.
        allowed_schemes = constraints.get("allowed_url_schemes")
        allowed_hosts = constraints.get("allowed_url_hosts")
        if allowed_schemes or allowed_hosts:
            for s in _extract_strings(tool_input):
                for url in _URL_PATTERN.findall(s):
                    parsed = urlparse(url)
                    if allowed_schemes and parsed.scheme not in tuple(allowed_schemes):
                        return f"url-scheme-not-allowed:{parsed.scheme}"
                    if allowed_hosts:
                        host = (parsed.hostname or "").lower()
                        if host not in tuple(h.lower() for h in allowed_hosts):
                            return f"url-host-not-allowed:{host}"
        return None

    # ----- layer 3: rate limit --------------------------------------------

    def _layer3_rate_limit(self, cap: McpCapability) -> str | None:
        window = self._config.rate_limit_window_seconds
        now = time.monotonic()
        state = self._rate_state.get(cap.capability_id)
        if state is None:
            state = _RateLimitState(timestamps=deque())
            self._rate_state[cap.capability_id] = state
        # Evict timestamps outside the window.
        while state.timestamps and (now - state.timestamps[0]) > window:
            state.timestamps.popleft()
        if len(state.timestamps) >= cap.rate_limit_per_minute:
            return f"rate-limited:{len(state.timestamps)}/{cap.rate_limit_per_minute}/{int(window)}s"
        state.timestamps.append(now)
        return None

    # ----- layer 4: adversarial pre-filter --------------------------------

    def _layer4_prefilter(self, tool_input: Mapping[str, Any]) -> str | None:
        strings = _extract_strings(tool_input)
        joined = "\n".join(strings)
        # Prompt-injection signatures.
        match = _scan_prompt_injection(joined)
        if match:
            return f"prompt-injection-pattern:{match[:60]}"
        # Outbound secrets.
        secrets = _scan_outbound_secrets(joined)
        if secrets:
            return f"outbound-secret:{','.join(secrets)}"
        # SSRF on every URL we can find.
        for s in strings:
            for url in _URL_PATTERN.findall(s):
                ssrf_reason = _ssrf_check_url(url, resolver=self._config.ssrf_resolver)
                if ssrf_reason is not None:
                    return ssrf_reason
        return None

    # ----- layer 6: constitutional policy ---------------------------------

    def _layer6_constitutional(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: Mapping[str, Any],
    ) -> str | None:
        for principle in self._config.constitutional_principles:
            try:
                violation = principle.predicate(agent_id, tool_name, tool_input)
            except Exception as exc:  # noqa: BLE001 - FAIL-CLOSED on principle error
                telemetry.emit_event(
                    "mcp.syscall.principle.error",
                    level=logging.ERROR,
                    principle_id=principle.principle_id,
                    error=type(exc).__name__,
                )
                return f"principle-error:{principle.principle_id}"
            if violation is not None:
                return f"principle-violation:{principle.principle_id}:{violation}"
        return None

    # ----- audit / deny shared --------------------------------------------

    def _deny(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: dict,
        layer: str,
        reason: str,
    ) -> tuple[bool, str]:
        formatted = f"{layer}:{reason}"
        self._record_audit(agent_id, tool_name, tool_input, "deny", reason, layer)
        telemetry.emit_event(
            "mcp.syscall.denied",
            level=logging.WARNING,
            agent_id=agent_id,
            tool_name=tool_name,
            layer=layer,
            reason=reason,
        )
        return False, formatted

    def _record_audit(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: dict,
        verdict: str,
        reason: str,
        layer: str,
    ) -> None:
        # SHA-256 of the canonical input. Per Rule 6, the hash algorithm
        # is intended to be pluggable via tex.pqcrypto.algorithm_agility;
        # for now we use SHA-256 to match the rest of Tex. Switching to
        # Blake3 (paper §4.2) is tracked as a TODO citing arxiv 2604.16870.
        import hashlib

        canonical_input = json.dumps(tool_input, sort_keys=True, default=str).encode("utf-8")
        arg_hash = hashlib.sha256(canonical_input).hexdigest()
        record_payload = (
            f"{agent_id}|{tool_name}|{arg_hash}|{verdict}|{reason}|{layer}|{self._chain_tail_hex}"
        ).encode("utf-8")
        record_hash = hashlib.sha256(record_payload).hexdigest()
        record = McpAuditRecord(
            timestamp=datetime.now(UTC),
            agent_id=agent_id,
            tool_name=tool_name,
            arg_hash_hex=arg_hash,
            deciding_layer=layer,
            verdict=verdict,
            reason=reason,
            prev_hash_hex=self._chain_tail_hex,
        )
        self._audit_chain.append(record)
        self._chain_tail_hex = record_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "null":
        return value is None
    return True
