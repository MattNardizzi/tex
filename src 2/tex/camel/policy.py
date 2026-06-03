"""
CaMeL tool policy.

Each tool registers its *maximum acceptable capability level* per
argument. A tool call is authorized iff each argument's capability
level is ``<=`` the tool's stated maximum for that position.

Defaults
--------
- A tool with no registered policy is treated as TRUSTED-only: any
  argument with USER or UNTRUSTED capability fails the check. This is
  the fail-closed default required by Tex's PDP contract.
- Policies are append-only and frozen after first ``freeze()`` call,
  which the PDP triggers on startup to prevent runtime tampering.

Source-based gating
-------------------
A tool may additionally enumerate forbidden source labels regardless of
level (e.g. ``"send_email"`` forbidding any argument whose source
includes ``"unverified_email"``). Source matching is exact-string.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tex.camel.capability import CapabilityLevel, CapabilitySet


class ToolPolicy(BaseModel):
    """Per-tool capability requirements."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(min_length=1, max_length=128)
    max_arg_levels: tuple[CapabilityLevel, ...] = Field(default_factory=tuple)
    forbidden_sources: frozenset[str] = Field(default_factory=frozenset)
    description: str | None = Field(default=None, max_length=500)

    def check(self, arg_caps: tuple[CapabilitySet, ...]) -> tuple[bool, str | None]:
        """Return (authorized, reason-if-denied)."""
        if len(arg_caps) != len(self.max_arg_levels):
            return (
                False,
                f"arity mismatch: tool {self.tool_name!r} expects "
                f"{len(self.max_arg_levels)} args, got {len(arg_caps)}",
            )
        for i, (caps, max_level) in enumerate(zip(arg_caps, self.max_arg_levels)):
            if caps.level > max_level:
                return (
                    False,
                    f"arg #{i} of {self.tool_name!r}: level "
                    f"{caps.level.name} exceeds max {max_level.name}",
                )
            forbidden = caps.sources & self.forbidden_sources
            if forbidden:
                return (
                    False,
                    f"arg #{i} of {self.tool_name!r}: source(s) "
                    f"{sorted(forbidden)} are forbidden",
                )
        return True, None


class ToolPolicyRegistry:
    """Mutable until ``freeze``'d; then immutable."""

    __slots__ = ("_policies", "_frozen")

    def __init__(self) -> None:
        self._policies: dict[str, ToolPolicy] = {}
        self._frozen = False

    def register(self, policy: ToolPolicy) -> None:
        if self._frozen:
            raise RuntimeError("ToolPolicyRegistry is frozen")
        if policy.tool_name in self._policies:
            raise ValueError(f"tool {policy.tool_name!r} already registered")
        self._policies[policy.tool_name] = policy

    def freeze(self) -> "ToolPolicyRegistry":
        self._frozen = True
        return self

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def get(self, tool_name: str) -> ToolPolicy | None:
        return self._policies.get(tool_name)

    def policy_for(self, tool_name: str, *, arity: int) -> ToolPolicy:
        """Return the registered policy or a fail-closed default."""
        registered = self._policies.get(tool_name)
        if registered is not None:
            return registered
        # Fail-closed default: TRUSTED-only for every argument
        return ToolPolicy(
            tool_name=tool_name,
            max_arg_levels=tuple(CapabilityLevel.TRUSTED for _ in range(arity)),
            description="auto-generated fail-closed default",
        )


__all__ = ["ToolPolicy", "ToolPolicyRegistry"]
