"""
TexClient - the core HTTP client for the Python SDK.

Pure stdlib (urllib) so that `pip install tex-guardrail` doesn't drag in
requests/httpx and conflict with whatever your agent already uses.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


_DEFAULT_TIMEOUT_SECONDS: float = 5.0
_DEFAULT_BASE_URL: str = "https://api.tex.io"


class TexError(RuntimeError):
    """Base class for all Tex SDK errors."""


class TexAuthError(TexError):
    """Raised when the API key is missing, invalid, or expired."""


class TexBlocked(TexError):
    """
    Raised when Tex returns a FORBID verdict and the caller asked us to
    raise on block via raise_on_forbid=True. The underlying TexVerdict is
    attached as `verdict` for inspection.
    """

    def __init__(self, message: str, verdict: "TexVerdict") -> None:
        super().__init__(message)
        self.verdict = verdict


class Verdict(str, Enum):
    """Tex's three-way verdict."""

    PERMIT = "PERMIT"
    ABSTAIN = "ABSTAIN"
    FORBID = "FORBID"


@dataclass(frozen=True, slots=True)
class TexASIFinding:
    """A single OWASP ASI 2026 finding from a Tex evaluation."""

    short_code: str
    title: str
    severity: float
    confidence: float
    verdict_influence: str
    counterfactual: str | None = None


@dataclass(frozen=True, slots=True)
class TexVerdict:
    """Result of one Tex evaluation."""

    allowed: bool
    verdict: Verdict
    score: float
    confidence: float
    reason: str
    decision_id: str
    request_id: str
    policy_version: str
    asi_findings: tuple[TexASIFinding, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    uncertainty_flags: tuple[str, ...] = field(default_factory=tuple)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_permit(self) -> bool:
        return self.verdict is Verdict.PERMIT

    @property
    def is_abstain(self) -> bool:
        return self.verdict is Verdict.ABSTAIN

    @property
    def is_forbid(self) -> bool:
        return self.verdict is Verdict.FORBID


class TexClient:
    """
    Synchronous client for the Tex guardrail API.

    Parameters
    ----------
    api_key
        Your Tex API key. Sent as `Authorization: Bearer <key>`.
    base_url
        Base URL of the Tex deployment. Defaults to https://api.tex.io.
    timeout_seconds
        Per-request timeout. Defaults to 5 seconds. Tex's p50 is well
        under 200ms; this is the safety net for transient network issues.
    """

    __slots__ = ("_api_key", "_base_url", "_timeout_seconds")

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = _DEFAULT_BASE_URL,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._api_key = api_key.strip() if api_key else None
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = float(timeout_seconds)

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        *,
        content: str | None = None,
        messages: list[dict[str, str]] | None = None,
        prompt: str | None = None,
        response: str | None = None,
        tool_call: dict[str, Any] | None = None,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        policy_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        stage: str = "pre_call",
        raise_on_forbid: bool = False,
    ) -> TexVerdict:
        """
        Evaluate one action through Tex.

        Provide content via any of: `content`, `messages`, `prompt`+`response`,
        or `tool_call`. At least one must be supplied.

        Set `raise_on_forbid=True` to convert a FORBID verdict into a
        raised `TexBlocked` exception, which is convenient inside decorator
        wrappers that want to abort the protected call.
        """
        body: dict[str, Any] = {"stage": stage}
        if content is not None:
            body["content"] = content
        if messages is not None:
            body["messages"] = messages
        if prompt is not None:
            body["prompt"] = prompt
        if response is not None:
            body["response"] = response
        if tool_call is not None:
            body["tool_call"] = tool_call
        if action_type is not None:
            body["action_type"] = action_type
        if channel is not None:
            body["channel"] = channel
        if environment is not None:
            body["environment"] = environment
        if recipient is not None:
            body["recipient"] = recipient
        if policy_id is not None:
            body["policy_id"] = policy_id
        if metadata is not None:
            body["metadata"] = metadata

        raw = self._post("/v1/guardrail", body=body)
        verdict = _parse_verdict(raw)

        if raise_on_forbid and verdict.is_forbid:
            raise TexBlocked(verdict.reason, verdict)

        return verdict

    def evaluate_async(
        self,
        *,
        content: str | None = None,
        messages: list[dict[str, str]] | None = None,
        prompt: str | None = None,
        response: str | None = None,
        tool_call: dict[str, Any] | None = None,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        policy_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        stage: str = "pre_call",
    ) -> dict[str, Any]:
        """
        Submit an action for fire-and-forget async evaluation.

        Returns immediately with a decision_id and poll_url. Evaluation
        runs in the background and lands in Tex's durable evidence chain.

        **Use this only for observability / audit, not for pre-release
        gating.** By the time the result is available, your action has
        already shipped.

        Returns
        -------
        dict
            {"decision_id": "...", "status": "accepted", "poll_url": "..."}
        """
        body: dict[str, Any] = {"stage": stage}
        if content is not None:
            body["content"] = content
        if messages is not None:
            body["messages"] = messages
        if prompt is not None:
            body["prompt"] = prompt
        if response is not None:
            body["response"] = response
        if tool_call is not None:
            body["tool_call"] = tool_call
        if action_type is not None:
            body["action_type"] = action_type
        if channel is not None:
            body["channel"] = channel
        if environment is not None:
            body["environment"] = environment
        if recipient is not None:
            body["recipient"] = recipient
        if policy_id is not None:
            body["policy_id"] = policy_id
        if metadata is not None:
            body["metadata"] = metadata

        return self._post("/v1/guardrail/async", body=body)

    def poll_async(self, decision_id: str) -> dict[str, Any]:
        """Poll the result of a previously-submitted async evaluation.

        Returns a dict with keys: decision_id, status ('pending'|'complete'|
        'failed'), result (None until complete), error, submitted_at,
        completed_at.
        """
        return self._get(f"/v1/guardrail/async/{decision_id}")

    def evaluate_chunk(
        self,
        *,
        session_id: str,
        chunk: str,
        is_final: bool = False,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        policy_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Submit one streaming-content chunk for inline evaluation.

        Use this when your LLM is streaming tokens to a user and you want
        to interrupt mid-stream if the response goes off-policy. Provide
        a stable `session_id` (e.g. a UUID per stream); each chunk appends
        to the cumulative buffer Tex maintains for that session.

        Returns a dict containing the latest verdict for the cumulative
        content. When `verdict == "FORBID"`, drop the rest of your stream
        immediately. When `is_final=True`, the session is finalized and
        the buffer cleared.
        """
        body: dict[str, Any] = {
            "session_id": session_id,
            "chunk": chunk,
            "is_final": is_final,
        }
        if action_type is not None:
            body["action_type"] = action_type
        if channel is not None:
            body["channel"] = channel
        if environment is not None:
            body["environment"] = environment
        if recipient is not None:
            body["recipient"] = recipient
        if policy_id is not None:
            body["policy_id"] = policy_id
        if metadata is not None:
            body["metadata"] = metadata

        return self._post("/v1/guardrail/stream/chunk", body=body)

    def health(self) -> dict[str, Any]:
        """Return the Tex deployment's health info."""
        return self._get("/health")

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _post(self, path: str, *, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers=self._headers(),
        )
        return self._send(req)

    def _get(self, path: str) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        req = urllib.request.Request(url, method="GET", headers=self._headers())
        return self._send(req)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _send(self, req: urllib.request.Request) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                payload = resp.read()
                if not payload:
                    return {}
                return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise TexAuthError(
                    f"Tex authentication failed ({exc.code}): {exc.reason}"
                ) from exc
            try:
                detail = json.loads(exc.read().decode("utf-8"))
            except Exception:
                detail = {"detail": str(exc)}
            raise TexError(
                f"Tex API error ({exc.code}): {detail.get('detail', exc.reason)}"
            ) from exc
        except urllib.error.URLError as exc:
            raise TexError(f"Tex network error: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise TexError(f"Tex returned invalid JSON: {exc}") from exc


def _parse_verdict(raw: dict[str, Any]) -> TexVerdict:
    """Translate the canonical webhook response into a SDK TexVerdict."""
    findings = tuple(
        TexASIFinding(
            short_code=f.get("short_code", ""),
            title=f.get("title", ""),
            severity=float(f.get("severity", 0.0)),
            confidence=float(f.get("confidence", 0.0)),
            verdict_influence=f.get("verdict_influence", "informational"),
            counterfactual=f.get("counterfactual"),
        )
        for f in raw.get("asi_findings", []) or []
    )
    return TexVerdict(
        allowed=bool(raw.get("allowed", False)),
        verdict=Verdict(raw.get("verdict", "ABSTAIN")),
        score=float(raw.get("score", 0.0)),
        confidence=float(raw.get("confidence", 0.0)),
        reason=raw.get("reason", ""),
        decision_id=raw.get("decision_id", ""),
        request_id=raw.get("request_id", ""),
        policy_version=raw.get("policy_version", ""),
        asi_findings=findings,
        reasons=tuple(raw.get("reasons", []) or []),
        uncertainty_flags=tuple(raw.get("uncertainty_flags", []) or []),
        raw=raw,
    )
