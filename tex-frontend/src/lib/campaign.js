// ────────────────────────────────────────────────────────────────────
//  Campaign progress + earned badges (localStorage)
//
//  Frontend-only. No backend persistence — clearing cookies wipes
//  badges, which is acceptable for a marketing surface.
// ────────────────────────────────────────────────────────────────────

import { INCIDENTS, ASI_CHAPTERS, incidentsByAsi } from "./incidents.js";

const KEY = "tex.v10.campaign";

function load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return defaultState();
    const parsed = JSON.parse(raw);
    return { ...defaultState(), ...parsed };
  } catch {
    return defaultState();
  }
}

function save(state) {
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    /* quota / private mode — silently degrade */
  }
}

function defaultState() {
  return {
    // map of incidentId → best score
    bestScores: {},
    // map of incidentId → best stealth (0..1)
    bestStealth: {},
    // map of incidentId → first cleared timestamp
    cleared: {},
    // map of ASI code → chapter complete timestamp
    chaptersComplete: {},
    // tracked badges
    badges: [],
  };
}

export function getCampaignState() {
  return load();
}

/**
 * Record a finished round.
 * "Cleared" = intent passed AND verdict !== FORBID (i.e. the player
 * got through, even if escalated). PERMIT counts as clear; FORBID does not.
 */
export function recordCampaignRound(incident, score) {
  const state = load();
  const id = incident.id;

  // Best score / stealth
  if ((score.total || 0) > (state.bestScores[id] || 0)) {
    state.bestScores[id] = score.total;
  }
  if ((score.stealth || 0) > (state.bestStealth[id] || 0)) {
    state.bestStealth[id] = score.stealth;
  }

  // Clear flag
  const cleared =
    !score.forfeit &&
    (score.verdict === "PERMIT" || score.verdict === "ABSTAIN");
  if (cleared && !state.cleared[id]) {
    state.cleared[id] = Date.now();
  }

  // Chapter completion check
  for (const code of (incident.asi || [])) {
    if (state.chaptersComplete[code]) continue;
    const all = incidentsByAsi(code);
    const allCleared = all.every((inc) => state.cleared[inc.id]);
    if (allCleared && all.length > 0) {
      state.chaptersComplete[code] = Date.now();
      const chapter = ASI_CHAPTERS.find((c) => c.code === code);
      if (chapter && !state.badges.includes(`chapter:${code}`)) {
        state.badges.push(`chapter:${code}`);
      }
    }
  }

  // Tier badges
  const tiers = [1, 2, 3];
  for (const tier of tiers) {
    const tierKey = `tier:${tier}`;
    if (state.badges.includes(tierKey)) continue;
    const tierIncidents = INCIDENTS.filter((i) => i.tier === tier);
    const allTierCleared = tierIncidents.every((inc) => state.cleared[inc.id]);
    if (allTierCleared && tierIncidents.length > 0) {
      state.badges.push(tierKey);
    }
  }

  // Stealth master — average stealth >= 0.85 across cleared incidents
  if (!state.badges.includes("stealth_master")) {
    const stealthValues = Object.values(state.bestStealth);
    if (stealthValues.length >= 5) {
      const avg = stealthValues.reduce((a, b) => a + b, 0) / stealthValues.length;
      if (avg >= 0.85) state.badges.push("stealth_master");
    }
  }

  save(state);
  return state;
}

/** Build chapter list with per-chapter progress for the campaign view */
export function chapterStatus() {
  const state = load();
  return ASI_CHAPTERS.map((ch) => {
    const incidents = incidentsByAsi(ch.code);
    const cleared = incidents.filter((i) => state.cleared[i.id]).length;
    const complete = state.chaptersComplete[ch.code];
    return {
      ...ch,
      incidents,
      cleared,
      total: incidents.length,
      complete: Boolean(complete),
      bestScore: incidents.reduce(
        (max, i) => Math.max(max, state.bestScores[i.id] || 0),
        0
      ),
    };
  }).sort((a, b) => a.order - b.order);
}

/** Per-incident status used by the picker */
export function incidentStatus(incidentId) {
  const state = load();
  return {
    bestScore: state.bestScores[incidentId] || 0,
    bestStealth: state.bestStealth[incidentId] || 0,
    cleared: Boolean(state.cleared[incidentId]),
  };
}

export const BADGE_META = {
  "tier:1": {
    label: "Recon",
    description: "Cleared every Tier I incident",
    color: "var(--cyan)",
  },
  "tier:2": {
    label: "Operator",
    description: "Cleared every Tier II incident",
    color: "var(--yellow)",
  },
  "tier:3": {
    label: "Specialist",
    description: "Cleared every Tier III incident",
    color: "var(--pink)",
  },
  stealth_master: {
    label: "Phantom",
    description: "Average stealth ≥ 0.85 across 5+ incidents",
    color: "var(--green)",
  },
};

export function getBadgeMeta(badgeId) {
  if (BADGE_META[badgeId]) return BADGE_META[badgeId];
  if (badgeId.startsWith("chapter:")) {
    const code = badgeId.split(":")[1];
    const ch = ASI_CHAPTERS.find((c) => c.code === code);
    return {
      label: ch ? ch.title : code,
      description: `Cleared every ${code} incident`,
      color: "var(--violet)",
    };
  }
  return { label: badgeId, description: "", color: "var(--ink-dim)" };
}

export function resetCampaign() {
  save(defaultState());
}
