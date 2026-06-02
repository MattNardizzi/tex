"""
THE test that decides if this is real (from the thread brief):

    Does Tex say the thing that mattered on the night it mattered, without
    crying wolf the other six nights? Does surprise-driven selection beat
    importance/severity ranking at telling a human what they actually need
    to know?

Scenario: seven nights. Execution FORBID volume is a high-severity
dimension. Six nights are ordinary (~2 FORBIDs). On night seven a real
incident drives 40 FORBIDs. A benign discovery dimension sits on-mean every
night.

  * Surprise selection (ours): warms an accumulating model of normal, so it
    speaks the FORBID line ONLY on night seven.
  * Severity ranking (the industry baseline): ranks by a static severity
    weight, so it speaks the high-severity FORBID line EVERY night —
    crying wolf on the six ordinary ones.

The test asserts surprise has zero false alarms and catches the incident,
while severity floods.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.vigil.dimensions import DimensionReading, ProofRef
from tex.vigil.normal import ModelOfNormal
from tex.vigil.selector import select


# --- a deliberately simple severity baseline (what everyone else builds) ---

# Static severity weights per dimension. FORBID volume is "high severity",
# so a severity ranker surfaces it whenever there is any.
_SEVERITY = {"execution": 0.9, "discovery": 0.2}


@dataclass
class SeverityResult:
    spoke_execution: bool


def severity_baseline(readings: list[DimensionReading], top_k: int = 1) -> SeverityResult:
    """Rank by static severity; speak the top-k that have any volume."""
    scored = [
        (r, _SEVERITY.get(r.key, 0.5) * (1.0 if float(r.slots.get("count", 0) or 0) > 0 else 0.0))
        for r in readings
    ]
    scored = [(r, s) for (r, s) in scored if s > 0.0]
    scored.sort(key=lambda rs: rs[1], reverse=True)
    spoken = {r.key for (r, _) in scored[:top_k]}
    return SeverityResult(spoke_execution="execution" in spoken)


def _night(forbids: int, history: list[float]) -> list[DimensionReading]:
    execution = DimensionReading(
        key="execution",
        kind="gamma",
        observation=(float(forbids), 1.0),
        history=list(history),
        slots={"count": forbids},
        proof=ProofRef(kind="decision", id="d"),
    )
    discovery = DimensionReading(
        key="discovery",
        kind="gamma",
        observation=(2.0, 1.0),
        history=[2, 2, 2, 2],
        slots={"count": 2},
        proof=ProofRef(kind="scan_run", id="r"),
    )
    return [execution, discovery]


def test_surprise_beats_severity_over_seven_nights() -> None:
    # Six ordinary nights (~2 FORBIDs) then one incident night (40).
    volumes = [2, 2, 3, 2, 2, 2, 40]
    model = ModelOfNormal()

    surprise_spoke_execution: list[bool] = []
    severity_spoke_execution: list[bool] = []
    history: list[float] = []

    for forbids in volumes:
        readings = _night(forbids, history)

        sel = select(readings, model)
        surprise_spoke_execution.append(
            any(u.dimension == "execution" for u in sel.utterances)
        )
        severity_spoke_execution.append(severity_baseline(readings).spoke_execution)

        # Accumulating model of normal: tonight becomes part of history.
        history.append(float(forbids))

    incident = [False, False, False, False, False, False, True]

    # Surprise: speaks the execution line exactly on the incident night.
    assert surprise_spoke_execution == incident, surprise_spoke_execution

    # Severity: speaks it every night -> cries wolf on the six ordinary ones.
    assert severity_spoke_execution == [True] * 7, severity_spoke_execution

    # Scored the way the brief frames it.
    surprise_false_alarms = sum(
        1 for spoke, mattered in zip(surprise_spoke_execution, incident) if spoke and not mattered
    )
    severity_false_alarms = sum(
        1 for spoke, mattered in zip(severity_spoke_execution, incident) if spoke and not mattered
    )
    surprise_caught = surprise_spoke_execution[-1]
    severity_caught = severity_spoke_execution[-1]

    assert surprise_false_alarms == 0
    assert severity_false_alarms == 6
    assert surprise_caught and severity_caught  # both catch it; only one floods
