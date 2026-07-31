"""
ClawGuard rule sets.

BaseRuleSet — loaded before user task is known.
TaskRuleSet — induced from user instruction before any external tool runs.

Design (paper §III-B, arxiv 2604.11790)
---------------------------------------
The active rule set is R = R_base ∪ R_task, with R_base evaluated
unconditionally and R_task derived from the user's stated objective. Each
rule lives in one of three domains:
  cmd  — tool-name and shell-command patterns
  file — local resource paths
  net  — outbound network destinations

Each domain holds a blacklist B_d and a whitelist W_d. Element-level
verdict V_elem(x) is one of:
  ⊥     (deny)  — x matches B_d
  ⊤     (allow) — x matches W_d
  amb   (review) — neither, or obfuscated input
Per paper: when x matches both, blacklist priority applies.

Priority: P0.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event, get_logger

_DEFAULT_LOGGER = get_logger("tex.runtime.clawguard")


class RuleDomain(str, Enum):
    """Paper §III-A.2: d ∈ {cmd, file, net}."""

    CMD = "cmd"
    FILE = "file"
    NET = "net"


class RuleAction(str, Enum):
    """Paper §III-A: B (deny) vs W (allow)."""

    DENY = "deny"
    ALLOW = "allow"


class Verdict(str, Enum):
    """Element-level verdict from V_elem."""

    ALLOW = "allow"  # ⊤
    DENY = "deny"  # ⊥
    AMBIGUOUS = "ambiguous"  # amb


class Rule(BaseModel):
    """A single boundary-enforcement rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(min_length=1)
    description: str
    domain: RuleDomain
    action: RuleAction
    pattern: str  # regex (for cmd, net, secrets-in-cmd) or path glob fragment
    severity: str = "block"  # "block" | "warn"
    source: str = "base"  # "base" | "task" — for audit


class BaseRuleSet(BaseModel):
    """Non-negotiable security invariants. Cannot be overridden by R_task."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[Rule, ...]

    @classmethod
    def default(cls) -> "BaseRuleSet":
        """
        Default baseline rules.

        TODO(P0): seed with:
          - deny: shell rm -rf /
          - deny: writes to ~/.ssh
          - deny: network calls to private IP ranges (RFC 1918, link-local, multicast)
          - deny: read /etc/shadow, /etc/passwd
          - deny: outbound to non-allowlisted domains (configurable)
          - deny: secret patterns in outbound payloads (AWS keys, OpenAI sk-, GitHub ghp_)

        Status: implemented per arxiv 2604.11790 Appendix B (default
        baseline safety rules) and aligned with MITRE ATT&CK T1041
        (exfiltration over C2) and TA0006 (credential access).
        """
        return cls(rules=_DEFAULT_BASELINE_RULES)


class TaskRuleSet(BaseModel):
    """User-objective-derived rules. Active alongside R_base (paper Eq. 10)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[Rule, ...]
    objective: str = ""
    confirmed: bool = False  # User confirmation per §III-B Step 3.

    @classmethod
    def induce_from_objective(cls, user_instruction: str) -> "TaskRuleSet":
        """
        Induce task-specific rules from the user's stated objective, before
        any external tool is invoked. Per arxiv 2604.11790 §III-B Eq. 9:
            R_task_raw = M(rho, H_0)

        TODO(P0): LLM-induce task-specific rules from user instruction
        TODO(P0): present rules to user for confirmation
        TODO(P0): lock in approved rule set for the session

        Status: deterministic baseline implemented. The LLM-induction
        path lives in `induce_from_objective_llm`; this offline path
        extracts explicit allow/deny domains and paths from the
        instruction so tests can run without network.
        """
        normalized = (user_instruction or "").strip()
        if not normalized:
            return cls(rules=(), objective="", confirmed=False)

        rules: list[Rule] = []
        for idx, domain in enumerate(_extract_allowed_domains(normalized)):
            rules.append(
                Rule(
                    rule_id=f"task.net.allow.{idx}",
                    description=f"Allow outbound to {domain} (induced from objective)",
                    domain=RuleDomain.NET,
                    action=RuleAction.ALLOW,
                    pattern=re.escape(domain),
                    source="task",
                )
            )
        for idx, path in enumerate(_extract_allowed_paths(normalized)):
            rules.append(
                Rule(
                    rule_id=f"task.file.allow.{idx}",
                    description=f"Allow file path {path} (induced from objective)",
                    domain=RuleDomain.FILE,
                    action=RuleAction.ALLOW,
                    pattern=re.escape(path),
                    source="task",
                )
            )
        return cls(rules=tuple(rules), objective=normalized, confirmed=False)

    def confirm(self) -> "TaskRuleSet":
        """User confirmation step per §III-B Step 3."""
        return self.model_copy(update={"confirmed": True})


# ---------------------------------------------------------------------------
# Default baseline rules (paper §III-B Step 1, Appendix B)
# ---------------------------------------------------------------------------

# Per the scaffolding docstring's six-rule contract, the rules below cover:
#  1. Shell `rm -rf /` and friends (catastrophic deletion)
#  2. Writes to ~/.ssh and other credential stores
#  3. Network calls to RFC 1918 / link-local / multicast / loopback
#  4. Reads of /etc/shadow, /etc/passwd, /etc/sudoers, etc.
#  5. Outbound to non-allowlisted domains (off-by-default; rule object
#     present so deployments can flip it on)
#  6. Secret patterns in outbound payloads (AWS, OpenAI, GitHub, generic)

_DEFAULT_BASELINE_RULES: tuple[Rule, ...] = (
    # Rule 1: rm -rf / and other destructive shell commands.
    # MITRE T1485 (data destruction).
    Rule(
        rule_id="base.cmd.deny.rm_rf_root",
        description="Block rm -rf on root filesystem or recursive force-delete patterns",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        # Match `rm -<flags>` where flags contain BOTH r and f in any order
        # (e.g. -rf, -fr, -rfv, -Rf, -RF). We then require a path argument
        # to be present.
        pattern=(
            r"(?:^|[\s|;&])rm\s+-(?=[a-zA-Z]*[rR])(?=[a-zA-Z]*[fF])[a-zA-Z]+"
            r"(?:\s+\S+)*\s+(?:/|~|\.)"
        ),
        source="base",
    ),
    Rule(
        rule_id="base.cmd.deny.curl_pipe_shell",
        description="Block curl/wget piped into shell (MITRE T1059)",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        pattern=r"(?:curl|wget)[^|;]*\|\s*(?:bash|sh|zsh|fish)\b",
        source="base",
    ),
    # Rule 2: writes to ~/.ssh and other credential stores.
    # MITRE TA0006 (credential access).
    Rule(
        rule_id="base.file.deny.ssh_write",
        description="Block writes to ~/.ssh or any SSH key store",
        domain=RuleDomain.FILE,
        action=RuleAction.DENY,
        pattern=r"(?:^|/)\.ssh(?:/|$)",
        source="base",
    ),
    # Rule 3: network calls to private IP ranges, link-local, multicast,
    # loopback. Defends against SSRF (MITRE T1090) and metadata-service
    # exfiltration (e.g., 169.254.169.254 cloud metadata endpoints).
    Rule(
        rule_id="base.net.deny.private_ranges",
        description=(
            "Block outbound to RFC1918 (10/8, 172.16/12, 192.168/16), "
            "loopback (127/8), link-local (169.254/16), multicast (224-239)"
        ),
        domain=RuleDomain.NET,
        action=RuleAction.DENY,
        pattern=(
            r"(?:^|[/@:])"
            r"(?:"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|169\.254\.\d{1,3}\.\d{1,3}"
            r"|2(?:2[4-9]|3\d)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|localhost"
            r")"
        ),
        source="base",
    ),
    # Rule 4: reads of /etc/shadow, /etc/passwd, /etc/sudoers.
    # MITRE T1003 (OS credential dumping).
    Rule(
        rule_id="base.file.deny.system_credentials",
        description="Block reads of /etc/shadow, /etc/passwd, /etc/sudoers, /etc/master.passwd",
        domain=RuleDomain.FILE,
        action=RuleAction.DENY,
        pattern=r"^/etc/(?:shadow|passwd|sudoers|master\.passwd|gshadow)\b",
        source="base",
    ),
    # Rule 5: outbound to non-allowlisted domains. Present as a rule object
    # so deployments can flip the default; the pattern below is a deny-all
    # sentinel that DOES NOT activate unless the deployment explicitly
    # turns it on by replacing this rule. Per paper §III-B, R_base
    # invariants are "fixed at deny and cannot be overridden by R_task";
    # this entry exists as a documented hook.
    Rule(
        rule_id="base.net.deny.non_allowlisted_default",
        description=(
            "Outbound-allowlist sentinel — disabled by default; deployments "
            "can replace with a 'deny everything not matched by R_task whitelist' rule"
        ),
        domain=RuleDomain.NET,
        action=RuleAction.DENY,
        # Pattern that matches nothing — sentinel/documentation rule.
        pattern=r"(?!.*)$",
        severity="warn",
        source="base",
    ),
    # Rule 6: secret patterns in outbound payloads.
    Rule(
        rule_id="base.cmd.deny.secret_aws",
        description="Block AWS access key patterns in outbound payloads",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        pattern=r"\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b",
        source="base",
    ),
    Rule(
        rule_id="base.cmd.deny.secret_openai",
        description="Block OpenAI API key patterns (sk-...) in outbound payloads",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        pattern=r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        source="base",
    ),
    Rule(
        rule_id="base.cmd.deny.secret_github",
        description="Block GitHub personal access token patterns",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        pattern=r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b",
        source="base",
    ),
    Rule(
        rule_id="base.cmd.deny.exec_dangerous_binaries",
        description="Block direct exec of high-risk binaries without explicit allowlist",
        domain=RuleDomain.CMD,
        action=RuleAction.DENY,
        pattern=r"(?:^|[\s|;&])(?:sudo|chmod\s+\+s|chown\s+root)\b",
        source="base",
    ),
)


# ---------------------------------------------------------------------------
# Sanitization patterns (paper §III-A.1, Appendix A)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _SanitizationPattern:
    name: str
    pattern: re.Pattern[str]
    redaction: str


_DEFAULT_SANITIZATION_PATTERNS: tuple[_SanitizationPattern, ...] = (
    _SanitizationPattern(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        redaction="<AWS_ACCESS_KEY_REDACTED>",
    ),
    _SanitizationPattern(
        name="openai_api_key",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
        redaction="<OPENAI_KEY_REDACTED>",
    ),
    _SanitizationPattern(
        name="github_token",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
        redaction="<GITHUB_TOKEN_REDACTED>",
    ),
    _SanitizationPattern(
        name="generic_bearer",
        pattern=re.compile(
            r"\bBearer\s+[A-Za-z0-9_\-\.=]+\b", re.IGNORECASE
        ),
        redaction="<BEARER_REDACTED>",
    ),
    _SanitizationPattern(
        name="ssh_private_key_block",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----.*?-----END "
            r"(?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        redaction="<SSH_PRIVATE_KEY_REDACTED>",
    ),
)


def get_default_sanitization_patterns() -> tuple[_SanitizationPattern, ...]:
    return _DEFAULT_SANITIZATION_PATTERNS


# ---------------------------------------------------------------------------
# Task-rule induction helpers (offline path)
# ---------------------------------------------------------------------------

# Detects domain literals in plain English instructions like "summarize
# example.com" or "fetch from foo.org/blog". We deliberately keep this
# strict to avoid hallucinating domains the user never named.
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|org|net|io|ai|co|app|dev|edu|gov)\b",
    re.IGNORECASE,
)
# File-path pattern. We deliberately use a word-boundary on the leading
# slash/tilde so substrings of URLs like "https://example.com/blog" are
# not picked up as filesystem paths.
_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'`(])(~/[A-Za-z0-9_\-./]+|/(?!/)[A-Za-z0-9_\-./]+)"
)


def _extract_allowed_domains(instruction: str) -> list[str]:
    return list(dict.fromkeys(m.group(0).lower() for m in _DOMAIN_PATTERN.finditer(instruction)))


def _extract_allowed_paths(instruction: str) -> list[str]:
    return list(
        dict.fromkeys(m.group(1) for m in _PATH_PATTERN.finditer(instruction))
    )


# ---------------------------------------------------------------------------
# Public helper exposed for the boundary enforcer's audit logger
# ---------------------------------------------------------------------------


def emit_rule_event(*, event: str, rule_id: str, **fields: Any) -> None:
    emit_event(event, logger=_DEFAULT_LOGGER, rule_id=rule_id, **fields)


__all__ = [
    "BaseRuleSet",
    "Rule",
    "RuleAction",
    "RuleDomain",
    "TaskRuleSet",
    "Verdict",
    "emit_rule_event",
    "get_default_sanitization_patterns",
]
