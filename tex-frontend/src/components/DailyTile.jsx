import React, { useEffect, useState } from "react";
import {
  todayIncident,
  getDailyState,
  dailyCompleted,
  msUntilMidnight,
  formatCountdown,
} from "../lib/dailyChallenge.js";

/*
  DailyTile — hub feature card.
  - Today's incident (date-seeded)
  - Streak counter
  - Live countdown to next daily
  - "PLAY DAILY" CTA, or "CLEARED" if already completed
*/

export default function DailyTile({ onPlay }) {
  const incident = todayIncident();
  const [state, setState] = useState(() => getDailyState());
  const [countdown, setCountdown] = useState(msUntilMidnight());

  useEffect(() => {
    const t = setInterval(() => {
      setCountdown(msUntilMidnight());
    }, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    setState(getDailyState());
  }, []);

  const completed = Boolean(state.todayResult);
  const tierColor =
    incident.tier === 1 ? "var(--cyan)" :
    incident.tier === 2 ? "var(--yellow)" :
    "var(--pink)";

  return (
    <div className="panel" style={{
      position: "relative",
      padding: "20px 22px",
      overflow: "hidden",
      background: "linear-gradient(135deg, var(--bg-1), rgba(255, 225, 74, 0.04) 100%)",
      borderColor: completed ? "rgba(95, 250, 159, 0.35)" : "rgba(255, 225, 74, 0.3)",
    }}>
      {/* Top row */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        marginBottom: 14,
        gap: 10,
        flexWrap: "wrap",
      }}>
        <div>
          <div className="kicker" style={{ color: "var(--yellow)" }}>
            DAILY CHALLENGE
          </div>
          <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 2 }}>
            ROTATES IN {formatCountdown(countdown)}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div className="display tabular" style={{
            fontSize: 24,
            color: state.streak > 0 ? "var(--yellow)" : "var(--ink-faint)",
            lineHeight: 1,
          }}>
            🔥 {state.streak}
          </div>
          <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
            DAY STREAK
          </div>
        </div>
      </div>

      {/* Incident preview */}
      <div style={{
        padding: "12px 14px",
        background: "var(--bg-2)",
        borderRadius: 6,
        border: "1px solid var(--hairline)",
        marginBottom: 14,
      }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 4,
          flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", gap: 1, color: tierColor }}>
            {[1, 2, 3].map((n) => (
              <span key={n} className={`tier-pip ${n <= incident.tier ? "on" : ""}`} />
            ))}
          </div>
          <span className="display" style={{
            fontSize: 17,
            color: "var(--ink)",
            letterSpacing: "0.04em",
          }}>
            {incident.name.toUpperCase()}
          </span>
          {(incident.asi || []).slice(0, 2).map((c) => (
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
        </div>
        <div style={{ color: "var(--ink-dim)", fontSize: 12, lineHeight: 1.5 }}>
          {incident.goal}
        </div>
      </div>

      {/* CTA */}
      {completed ? (
        <div style={{
          padding: "10px 14px",
          background: "rgba(95, 250, 159, 0.08)",
          border: "1px solid rgba(95, 250, 159, 0.3)",
          borderRadius: 6,
          textAlign: "center",
        }}>
          <div className="kicker" style={{ color: "var(--green)", marginBottom: 4 }}>
            ★ TODAY CLEARED
          </div>
          <div className="mono tabular" style={{ fontSize: 14, color: "var(--ink)" }}>
            {state.todayResult.score} PTS · {state.todayResult.verdict}
          </div>
        </div>
      ) : (
        <button onClick={onPlay} className="btn-primary" style={{
          width: "100%",
          background: "var(--yellow)",
          color: "#1A1500",
        }}>
          PLAY DAILY →
        </button>
      )}
    </div>
  );
}
