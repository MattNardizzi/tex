import React from "react";

/*
  LayerBreakdown — visualizes Tex's six-layer pipeline on every verdict.

  This is the architecture made visible. No competitor has a six-layer
  specialist-routed pipeline. Engineering leaders see it here and know
  Tex isn't a wrapper around a classifier.

  Reads `router.layer_scores` from the backend response. The backend
  emits scores per layer:
    - deterministic
    - retrieval
    - specialists
    - semantic
    - router (fusion)
    - evidence (always present if chain valid)
*/

const LAYERS = [
  {
    key: "deterministic",
    n: 1,
    name: "Deterministic",
    desc: "Recognizers · regex · rule-based",
    color: "var(--cyan)",
  },
  {
    key: "retrieval",
    n: 2,
    name: "Retrieval",
    desc: "Policy · precedent · entity grounding",
    color: "var(--cyan)",
  },
  {
    key: "specialists",
    n: 3,
    name: "Specialists",
    desc: "Heuristic judges · domain rules",
    color: "var(--cyan)",
  },
  {
    key: "semantic",
    n: 4,
    name: "Semantic",
    desc: "Structured LLM judge · 5 dimensions",
    color: "var(--cyan)",
  },
  {
    key: "router",
    n: 5,
    name: "Router",
    desc: "Fusion · uncertainty · abstention",
    color: "var(--cyan)",
  },
  {
    key: "evidence",
    n: 6,
    name: "Evidence",
    desc: "SHA-256 hash chain · HMAC signed",
    color: "var(--yellow)",
  },
];

export default function LayerBreakdown({ decision }) {
  const layerScores = decision?.router?.layer_scores || {};
  const detBlocked = decision?.deterministic?.blocked;
  const detScore = decision?.deterministic?.score || 0;
  const evidenceValid = decision?.evidence?.chain_valid;

  function scoreFor(key) {
    if (key === "deterministic") return Math.max(detScore, layerScores[key] || 0);
    if (key === "evidence") return evidenceValid ? 1 : 0;
    return Number(layerScores[key]) || 0;
  }

  function firedFor(key) {
    if (key === "deterministic") return Boolean(detBlocked) || detScore > 0.4;
    if (key === "evidence") return Boolean(evidenceValid);
    return scoreFor(key) > 0.35;
  }

  // Identify the primary layer that produced the verdict — the one
  // with the highest signal (excluding evidence which is structural).
  const primary = LAYERS
    .filter((l) => l.key !== "evidence")
    .reduce(
      (acc, l) => {
        const s = scoreFor(l.key);
        return s > acc.s ? { key: l.key, s } : acc;
      },
      { key: null, s: -1 }
    );

  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        marginBottom: 8,
        flexWrap: "wrap",
        gap: 8,
      }}>
        <span className="kicker" style={{ color: "var(--cyan)" }}>
          SIX-LAYER PIPELINE
        </span>
        {primary.key && (
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            DRIVING LAYER · {primary.key.toUpperCase()}
          </span>
        )}
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(6, 1fr)",
        gap: 6,
      }} className="layer-grid">
        {LAYERS.map((l) => {
          const score = scoreFor(l.key);
          const fired = firedFor(l.key);
          const isPrimary = l.key === primary.key;
          const baseColor = l.color;

          return (
            <div
              key={l.key}
              title={`${l.name} — ${l.desc}${score ? ` · score ${score.toFixed(2)}` : ""}`}
              style={{
                padding: "10px 8px",
                border: `1px solid ${
                  isPrimary
                    ? baseColor
                    : fired
                    ? "rgba(95, 240, 255, 0.4)"
                    : "var(--hairline-2)"
                }`,
                borderRadius: 6,
                background: isPrimary
                  ? "rgba(95, 240, 255, 0.10)"
                  : fired
                  ? "rgba(95, 240, 255, 0.04)"
                  : "var(--bg-2)",
                position: "relative",
                minHeight: 78,
              }}
            >
              <div className="mono" style={{
                fontSize: 10,
                color: fired ? baseColor : "var(--ink-faint)",
                fontWeight: 600,
              }}>
                {String(l.n).padStart(2, "0")}
              </div>
              <div className="mono" style={{
                fontSize: 11,
                color: fired ? "var(--ink)" : "var(--ink-faint)",
                fontWeight: 600,
                marginTop: 3,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}>
                {l.name}
              </div>
              <div className="micro" style={{
                fontSize: 9,
                color: "var(--ink-faint)",
                marginTop: 3,
                lineHeight: 1.3,
              }}>
                {l.desc}
              </div>
              <div style={{
                marginTop: 6,
                height: 3,
                background: "rgba(168, 174, 201, 0.1)",
                borderRadius: 2,
                overflow: "hidden",
              }}>
                <div style={{
                  width: `${Math.round(score * 100)}%`,
                  height: "100%",
                  background: fired ? baseColor : "var(--ink-faint)",
                  transition: "width 0.5s ease",
                }} />
              </div>
            </div>
          );
        })}
      </div>

      <style>{`
        @media (max-width: 700px) {
          .layer-grid { grid-template-columns: repeat(3, 1fr) !important; }
        }
      `}</style>
    </div>
  );
}
