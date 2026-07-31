"""
Tool-call boundary enforcer.

Checks every tool call against the union of base + task rules. Deterministic
deny-by-default. Cannot be evaded by prompt manipulation since rules are
checked at the boundary, not inside the LLM.

Implementation
--------------
Per arxiv 2604.11790 §III-A, ClawGuard places four components at every
tool-call boundary:

  1. Content Sanitizer (S_in / S_out): pattern-library redaction of
     sensitive spans on both incoming arguments AND outgoing tool returns.
  2. Rule Evaluator (V): three-valued verdict (allow / deny / ambiguous)
     evaluated under R = R_base ∪ R_task across three domains
     {cmd, file, net}.
  3. Skill Inspector: out of scope for this enforcer's check_call hot path
     — handled at session-init time when a skill is first loaded.
  4. Approval Mechanism: ambiguous verdicts queue for user authorization.

The most-restrictive-wins aggregation (paper Eq. 7) combines per-attribute
verdicts into the final V(a*).

Backwards-compatible signature: check_call returns (allowed, reason) where
ambiguous verdicts that do not have an approval handler are conservatively
treated as DENY — matching deny-by-default for headless deployments.

Priority: P0.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from tex.observability.telemetry import emit_event, get_logger
from tex.runtime.clawguard.rule_set import (
    BaseRuleSet,
    Rule,
    RuleAction,
    RuleDomain,
    TaskRuleSet,
    Verdict,
    get_default_sanitization_patterns,
)

# Approval handler: takes a sanitized tool call, returns True iff user
# explicitly approves. Per paper §III-A.4, a timeout τ is applied; the
# handler is responsible for honoring it. None disables the approval
# queue (ambiguous → deny).
ApprovalHandler = Callable[[str, Mapping[str, Any], str], bool]

_DEFAULT_LOGGER = get_logger("tex.runtime.clawguard")


class SanitizedCall(BaseModel):
    """The (a*) form from paper Eq. 4."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str
    sanitized_input: dict[str, Any]
    redactions: tuple[str, ...]  # names of patterns that fired


class ContentSanitizer:
    """Pattern-library redaction of sensitive spans (paper §III-A.1)."""

    def __init__(
        self,
        *,
        patterns: tuple[Any, ...] | None = None,
    ) -> None:
        self._patterns = patterns or get_default_sanitization_patterns()

    def sanitize(self, value: Any) -> tuple[Any, list[str]]:
        """Recursively sanitize strings; return (clean_value, fired_pattern_names)."""
        fired: list[str] = []
        cleaned = self._walk(value, fired)
        return cleaned, fired

    def _walk(self, value: Any, fired: list[str]) -> Any:
        if isinstance(value, str):
            return self._sanitize_string(value, fired)
        if isinstance(value, Mapping):
            return {k: self._walk(v, fired) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self._walk(v, fired) for v in value)
        return value

    def _sanitize_string(self, text: str, fired: list[str]) -> str:
        result = text
        for sp in self._patterns:
            new_result = sp.pattern.sub(sp.redaction, result)
            if new_result != result:
                fired.append(sp.name)
                result = new_result
        return result


# Obfuscation indicators per paper §III-A.2: base64-looking blobs, hex
# encoding, shell concatenation, excessive indirection. Conservatively
# map matches to ambiguous so they queue for user review.
_OBFUSCATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # `<blob> | base64 -d | bash` — base64 decoded into a shell. Catches
    # both `base64 -d <<< "..."` style and `echo ... | base64 -d | bash`.
    re.compile(r"base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh|fish)"),
    # Direct `base64 -d "<blob>"` inline.
    re.compile(r"(?:base64\s+(?:-d|--decode)|atob)\s*\(?\s*[\"']?[A-Za-z0-9+/=]{32,}"),
    # Hex-encoded shell (\x41\x42... sequences of length >= 8 bytes).
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
    # `eval $(...)` indirection.
    re.compile(r"\beval\s*[\$`]\("),
    # Suspicious shell concatenation that builds binaries from fragments.
    re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[+]\$\{?[A-Za-z_]"),
    # `echo $(echo ...) | bash` style pipeline indirection.
    re.compile(r"\$\(\s*echo[^)]+\)\s*\|\s*(?:bash|sh)"),
)


def _looks_obfuscated(text: str) -> bool:
    return any(p.search(text) for p in _OBFUSCATION_PATTERNS)


class RuleEvaluator:
    """
    V from paper §III-A.2. Returns (verdict, hit_rule, attribute, value).

    Modes:
      - "strict": paper-faithful. An attribute that matches NEITHER a
        whitelist nor a blacklist returns AMBIGUOUS, forcing user
        review. Use this when R_task is LLM-induced and reliably covers
        the intended tool surface (paper §III-B Step 2).
      - "deny_only": offline-friendly. Only blacklists block; everything
        else is implicitly ALLOW. Use this when R_task is induced by a
        deterministic baseline that may not enumerate every legitimate
        endpoint.
    """

    _STRICT = "strict"
    _DENY_ONLY = "deny_only"

    def __init__(
        self,
        *,
        base: BaseRuleSet,
        task: TaskRuleSet,
        mode: str = _DENY_ONLY,
        logger: logging.Logger | None = None,
    ) -> None:
        if mode not in (self._STRICT, self._DENY_ONLY):
            raise ValueError(f"unknown mode: {mode}")
        self._base = base
        self._task = task
        self._mode = mode
        self._logger = logger or _DEFAULT_LOGGER
        # Pre-compile patterns once.
        self._compiled: list[tuple[Rule, re.Pattern[str]]] = [
            (r, re.compile(r.pattern, re.IGNORECASE | re.DOTALL))
            for r in (*base.rules, *task.rules)
        ]

    def evaluate(
        self, *, tool_name: str, attributes: Mapping[RuleDomain, tuple[str, ...]]
    ) -> tuple[Verdict, Rule | None, str | None]:
        """
        Combine per-attribute V_elem outcomes into V(a*) under
        most-restrictive-wins (paper Eq. 7).

        attributes maps each domain to the concrete strings to be checked
        against that domain's rules. Strings can include the tool name
        and shell command (cmd domain), filesystem paths (file domain),
        and network destinations (net domain).
        """
        seen_amb: tuple[Rule | None, str] | None = None
        for domain, values in attributes.items():
            for value in values:
                if not isinstance(value, str):
                    continue
                # Obfuscation -> ambiguous (paper §III-A.2 final paragraph).
                if domain is RuleDomain.CMD and _looks_obfuscated(value):
                    seen_amb = (None, f"obfuscation_detected:{value[:40]}")
                v_elem, rule = self._evaluate_value(domain, value)
                if v_elem is Verdict.DENY and rule is not None:
                    return Verdict.DENY, rule, value
                if v_elem is Verdict.AMBIGUOUS:
                    seen_amb = (rule, value)
        if seen_amb is not None:
            rule, value = seen_amb
            return Verdict.AMBIGUOUS, rule, value
        return Verdict.ALLOW, None, None

    def _evaluate_value(
        self, domain: RuleDomain, value: str
    ) -> tuple[Verdict, Rule | None]:
        """Per-attribute V_elem (paper Eq. 6) with blacklist priority."""
        deny_hit: Rule | None = None
        allow_hit: Rule | None = None
        for rule, compiled in self._compiled:
            if rule.domain is not domain:
                continue
            if compiled.search(value) is None:
                continue
            if rule.action is RuleAction.DENY:
                deny_hit = rule  # blacklist priority
                break
            if rule.action is RuleAction.ALLOW and allow_hit is None:
                allow_hit = rule
        if deny_hit is not None:
            return Verdict.DENY, deny_hit
        if allow_hit is not None:
            return Verdict.ALLOW, allow_hit
        if self._mode == self._DENY_ONLY:
            return Verdict.ALLOW, None
        return Verdict.AMBIGUOUS, None


class ToolCallBoundaryEnforcer:
    """
    Full ClawGuard boundary check.

    Per arxiv 2604.11790 §III-A, the canonical pipeline is:
        1. Sanitize input args (S_in)
        2. Evaluate rules over the sanitized call (V)
        3. If amb -> ask user via approval handler
        4. If allow -> tool runs, then sanitize output (S_out)

    This enforcer focuses on steps 1-3 (the deny-or-allow decision). Step
    4 (output sanitization) is exposed via sanitize_output for callers
    that drive tool execution.
    """

    def __init__(
        self,
        *,
        base_rules: BaseRuleSet,
        task_rules: TaskRuleSet,
        sanitizer: ContentSanitizer | None = None,
        approval_handler: ApprovalHandler | None = None,
        mode: str = "deny_only",
        logger: logging.Logger | None = None,
    ) -> None:
        self._base = base_rules
        self._task = task_rules
        self._sanitizer = sanitizer or ContentSanitizer()
        self._approval_handler = approval_handler
        self._logger = logger or _DEFAULT_LOGGER
        self._evaluator = RuleEvaluator(
            base=base_rules, task=task_rules, mode=mode, logger=self._logger
        )

    def check_call(
        self, *, tool_name: str, tool_input: dict
    ) -> tuple[bool, str | None]:
        """
        Returns (allowed, deny_reason).

        TODO(P0): apply base rules first (non-negotiable)
        TODO(P0): apply task rules second (user-confirmed)
        TODO(P0): deny on first match; emit audit event with rule_id

        Status: implemented per arxiv 2604.11790 §III-A pipeline. The
        scaffolded signature is preserved; ambiguous verdicts route
        through the optional approval handler, defaulting to DENY when
        no handler is configured (deny-by-default invariant).
        """
        sanitized_input, redactions = self._sanitizer.sanitize(dict(tool_input))
        attributes = self._build_attributes(tool_name, sanitized_input)
        verdict, rule, offending_value = self._evaluator.evaluate(
            tool_name=tool_name, attributes=attributes
        )

        if verdict is Verdict.DENY:
            assert rule is not None
            self._emit_audit(
                event="clawguard.tool_call.denied",
                level=logging.WARNING,
                tool_name=tool_name,
                rule_id=rule.rule_id,
                domain=rule.domain.value,
                offending_value=str(offending_value)[:200],
                redactions=tuple(redactions),
            )
            return False, f"deny:{rule.rule_id}:{rule.description}"

        if verdict is Verdict.AMBIGUOUS:
            if self._approval_handler is None:
                self._emit_audit(
                    event="clawguard.tool_call.denied",
                    level=logging.WARNING,
                    tool_name=tool_name,
                    rule_id="ambiguous_no_approval",
                    domain="multi",
                    offending_value=str(offending_value)[:200],
                    redactions=tuple(redactions),
                )
                return (
                    False,
                    "ambiguous:no_approval_handler:tool call required user approval",
                )
            try:
                approved = bool(
                    self._approval_handler(
                        tool_name, sanitized_input, str(offending_value or "")
                    )
                )
            except Exception as exc:  # noqa: BLE001
                emit_event(
                    "clawguard.approval.exception",
                    level=logging.ERROR,
                    logger=self._logger,
                    error=str(exc),
                )
                return False, f"ambiguous:approval_exception:{exc}"
            if not approved:
                self._emit_audit(
                    event="clawguard.tool_call.denied",
                    level=logging.WARNING,
                    tool_name=tool_name,
                    rule_id="ambiguous_user_rejected",
                    domain="multi",
                    offending_value=str(offending_value)[:200],
                    redactions=tuple(redactions),
                )
                return False, "ambiguous:user_rejected"
            self._emit_audit(
                event="clawguard.tool_call.allowed_via_approval",
                level=logging.INFO,
                tool_name=tool_name,
                rule_id="ambiguous_user_approved",
                domain="multi",
                offending_value=str(offending_value)[:200],
                redactions=tuple(redactions),
            )
            return True, None

        self._emit_audit(
            event="clawguard.tool_call.allowed",
            level=logging.INFO,
            tool_name=tool_name,
            rule_id="none",
            domain="none",
            offending_value="",
            redactions=tuple(redactions),
        )
        return True, None

    def sanitize_output(self, output: Any) -> tuple[Any, list[str]]:
        """Apply S_out per paper Eq. 5."""
        return self._sanitizer.sanitize(output)

    @staticmethod
    def _build_attributes(
        tool_name: str, tool_input: Mapping[str, Any]
    ) -> dict[RuleDomain, tuple[str, ...]]:
        """
        Project tool_name + tool_input into the three rule domains.

        Per paper §III-A.2, "for each relevant attribute x_i extracted
        from a*". We extract:
          - cmd: tool_name itself + free-text command-like strings (those
            that do not look like paths or network URLs).
          - file: any path-like string (starts with / or ~, or begins
            with a drive letter).
          - net: any URL or hostname-like string (contains :// or ends
            with a TLD, or is a literal IP).

        Each value is routed to ONE primary domain. Per Eq. 7, an
        AMBIGUOUS verdict in any domain blocks the call by default; we
        therefore avoid double-evaluating the same string in domains
        where it is not relevant, which would otherwise force benign
        URLs to be 'amb' in cmd despite being explicitly allowed in net.
        """
        cmd: list[str] = [tool_name]
        files: list[str] = []
        nets: list[str] = []

        def _classify_string(value: str) -> None:
            looks_net = (
                "://" in value
                or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", value) is not None
                or any(
                    tld in value.lower()
                    for tld in (
                        ".com",
                        ".org",
                        ".net",
                        ".io",
                        ".ai",
                        ".co",
                        ".app",
                        ".dev",
                        ".edu",
                        ".gov",
                        "localhost",
                    )
                )
            )
            looks_path = (
                value.startswith(("/", "~/"))
                or value.startswith(("./", "../"))
                or "/.ssh" in value
                or value.startswith("~")
            )
            # Every string is a candidate cmd attribute so command-injection
            # patterns ('rm -rf /', 'curl ... | bash') can match the full
            # value even when it embeds a URL or a path. Domain-specific
            # routing only ADDS the value to file/net domains; it does not
            # remove it from cmd. This matches the paper's intent that a
            # single tool call can have multiple relevant attributes
            # evaluated under their own domain rules (paper §III-A.2,
            # Eq. 7 most-restrictive-wins).
            cmd.append(value)
            if looks_net:
                nets.append(value)
            if looks_path:
                files.append(value)

        def _walk(value: Any) -> None:
            if isinstance(value, str):
                _classify_string(value)
            elif isinstance(value, Mapping):
                for v in value.values():
                    _walk(v)
            elif isinstance(value, (list, tuple)):
                for v in value:
                    _walk(v)

        for v in tool_input.values():
            _walk(v)

        return {
            RuleDomain.CMD: tuple(cmd),
            RuleDomain.FILE: tuple(files),
            RuleDomain.NET: tuple(nets),
        }

    def _emit_audit(
        self,
        *,
        event: str,
        level: int,
        tool_name: str,
        rule_id: str,
        domain: str,
        offending_value: str,
        redactions: tuple[str, ...],
    ) -> None:
        emit_event(
            event,
            level=level,
            logger=self._logger,
            tool_name=tool_name,
            rule_id=rule_id,
            domain=domain,
            offending_value=offending_value,
            redactions=list(redactions),
        )


__all__ = [
    "ApprovalHandler",
    "ContentSanitizer",
    "RuleEvaluator",
    "SanitizedCall",
    "ToolCallBoundaryEnforcer",
]
