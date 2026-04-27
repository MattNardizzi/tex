import React from "react";
import { INCIDENTS, ASI_CHAPTERS, incidentTags } from "../lib/incidents.js";
import { incidentStatus, chapterStatus } from "../lib/campaign.js";

/*
  IncidentPicker — three modes:
    - "campaign"  : grouped by ASI chapter, gated by tier progression
    - "ranked"    : flat list, all incidents, sortable by tier
    - "daily"     : single incident card (handled by DailyTile separately)

  Player taps an incident → calls onPick(incident).
*/

export default function IncidentPicker({ mode = "ranked", onPick }) {
  if (mode === "campaign") return <CampaignView onPick={onPick} />;
  return <RankedView onPick={onPick} />;
}

function CampaignView({ onPick }) {
  const chapters = chapterStatus();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {chapters.map((ch) => (
        <Chapter key={ch.code} chapter={ch} onPick={onPick} />
      ))}
    </div>
  );
}

function Chapter({ chapter, onPick }) {
  const completePct = chapter.total === 0 ? 0 : (chapter.cleared / chapter.total) * 100;
  return (
    <div className="panel" style={{ padding: "18px 20px" }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        gap: 12,
        marginBottom: 14,
        flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <span className="kicker" style={{
            color: chapter.complete ? "var(--green)" : "var(--cyan)",
          }}>
            {chapter.code}
          </span>
          <span className="display" style={{
            fontSize: "clamp(18px, 3vw, 22px)",
            color: chapter.complete ? "var(--green)" : "var(--ink)",
          }}>
            {chapter.title}
          </span>
          {chapter.complete && (
            <span className="micro" style={{ color: "var(--green)" }}>
              ★ CLEARED
            </span>
          )}
        </div>
        <div className="micro" style={{ color: "var(--ink-faint)" }}>
          {chapter.cleared} / {chapter.total} CLEARED
        </div>
      </div>

      {/* Progress bar */}
      <div style={{
        height: 3,
        background: "var(--hairline)",
        borderRadius: 2,
        marginBottom: 14,
        overflow: "hidden",
      }}>
        <div style={{
          height: "100%",
          width: `${completePct}%`,
          background: chapter.complete ? "var(--green)" : "var(--cyan)",
          transition: "width 0.4s ease",
          boxShadow: chapter.complete ? "0 0 10px var(--green-glow)" : "0 0 10px var(--cyan-glow)",
        }} />
      </div>

      {/* Incidents */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {chapter.incidents.map((inc) => (
          <IncidentRow key={inc.id} incident={inc} onPick={onPick} />
        ))}
      </div>
    </div>
  );
}

function RankedView({ onPick }) {
  const sorted = [...INCIDENTS].sort((a, b) => a.tier - b.tier);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {sorted.map((inc) => (
        <IncidentRow key={inc.id} incident={inc} onPick={onPick} expanded />
      ))}
    </div>
  );
}

function IncidentRow({ incident, onPick, expanded = false }) {
  const status = incidentStatus(incident.id);
  const tierColor =
    incident.tier === 1 ? "var(--cyan)" :
    incident.tier === 2 ? "var(--yellow)" :
    "var(--pink)";

  return (
    <button
      onClick={() => onPick(incident)}
      style={{
        textAlign: "left",
        padding: expanded ? "14px 16px" : "10px 14px",
        background: status.cleared ? "rgba(95, 250, 159, 0.04)" : "var(--bg-1)",
        border: status.cleared
          ? "1px solid rgba(95, 250, 159, 0.25)"
          : "1px solid var(--hairline-2)",
        borderRadius: 6,
        display: "grid",
        gridTemplateColumns: "auto 1fr auto",
        gap: 14,
        alignItems: "center",
        transition: "all 0.2s ease",
        cursor: "pointer",
        width: "100%",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = tierColor;
        e.currentTarget.style.background = "var(--bg-2)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = status.cleared
          ? "rgba(95, 250, 159, 0.25)"
          : "var(--hairline-2)";
        e.currentTarget.style.background = status.cleared
          ? "rgba(95, 250, 159, 0.04)"
          : "var(--bg-1)";
      }}
    >
      {/* Tier pips */}
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 1,
        color: tierColor,
        flexShrink: 0,
      }}>
        {[1, 2, 3].map((n) => (
          <span key={n} className={`tier-pip ${n <= incident.tier ? "on" : ""}`} />
        ))}
      </div>

      {/* Name + setup */}
      <div style={{ minWidth: 0 }}>
        <div style={{
          display: "flex",
          alignItems: "baseline",
          gap: 8,
          flexWrap: "wrap",
        }}>
          <span className="display" style={{
            fontSize: expanded ? 17 : 15,
            color: status.cleared ? "var(--green)" : "var(--ink)",
            letterSpacing: "0.04em",
          }}>
            {incident.name}
          </span>
          {incidentTags(incident).slice(0, 2).map((c) => (
            <span key={c} className="micro" style={{
              color: "var(--cyan)",
              padding: "1px 5px",
              border: "1px solid rgba(95, 240, 255, 0.3)",
              borderRadius: 3,
              fontSize: 9,
            }}>
              {c}
            </span>
          ))}
          {status.cleared && (
            <span className="micro" style={{ color: "var(--green)", fontSize: 9 }}>
              ★ CLEARED
            </span>
          )}
        </div>
        {expanded && (
          <div style={{
            color: "var(--ink-dim)",
            fontSize: 12,
            marginTop: 4,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {incident.setup}
          </div>
        )}
      </div>

      {/* Best score (if any) */}
      <div style={{
        textAlign: "right",
        flexShrink: 0,
        minWidth: 60,
      }}>
        {status.bestScore > 0 ? (
          <>
            <div className="mono tabular" style={{
              fontSize: expanded ? 14 : 13,
              color: tierColor,
              fontWeight: 600,
            }}>
              {status.bestScore}
            </div>
            <div className="micro" style={{ color: "var(--ink-faint)", fontSize: 9 }}>
              BEST
            </div>
          </>
        ) : (
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            PLAY →
          </span>
        )}
      </div>
    </button>
  );
}
