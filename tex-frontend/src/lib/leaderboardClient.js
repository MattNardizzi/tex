// ────────────────────────────────────────────────────────────────────
//  Leaderboard client — talks to the real backend.
// ────────────────────────────────────────────────────────────────────

const LEADERBOARD_BASE = "/api/leaderboard";

export async function fetchLeaderboard(handle = null) {
  const url = handle
    ? `${LEADERBOARD_BASE}?handle=${encodeURIComponent(handle)}`
    : LEADERBOARD_BASE;
  const res = await fetch(url, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`leaderboard fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function submitRound({
  handle,
  decisionId,
  attemptsUsed,
  secondsLeft,
  incidentDifficulty = 2,
  incidentId = null,
}) {
  const res = await fetch(`${LEADERBOARD_BASE}/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      handle,
      decision_id: decisionId,
      attempts_used: attemptsUsed,
      seconds_left: secondsLeft,
      incident_difficulty: incidentDifficulty,
      incident_id: incidentId,
    }),
  });
  // Tolerate 404 (decision expired) and 409 (already submitted) — return null.
  if (res.status === 404 || res.status === 409) {
    return null;
  }
  if (!res.ok) {
    throw new Error(`submit failed: ${res.status}`);
  }
  return res.json();
}
