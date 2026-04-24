import React, { useEffect } from "react";
import RankBadge from "./RankBadge.jsx";
import { tierFor } from "../lib/ranking.js";
import { rankUpSfx } from "../lib/sounds.js";

/*
  VerdictReveal v8 — "The payoff"
  ────────────────────────────────
  Fullscreen overlay. After round completes, show:
    - BIG verdict label (BYPASS / CLOSE / BLOCKED)
    - RP change + new tier
    - Signed evidence bundle (real data from backend) — this is the moment
      we tie "fun game" to "real product"
    - CTAs: Play again / Share / Go to Hub
*/

export default function VerdictReveal({
  result,            // { incident, verdict, attempts, secondsLeft, finalAttempt }
  rpResult,          // { delta, label, tone }
  player,            // before snapshot
  playerAfter,       // after snapshot
  onPlayAgain,
  onShare,
  onHome,
}) {
  const { incident, verdict, attempts, finalAttempt, timeout } = result;
  const decision = finalAttempt?.decision || null;

  const win = verdict === "PERMIT";
  const partial = verdict === "ABSTAIN";

  const tone = win ? "var(--green)" : partial ? "var(--yellow)" : "var(--red)";
  const bigLabel = win ? "BYPASS" : partial ? "CLOSE CALL" : "BLOCKED BY TEX";
  const subLabel = win
    ? "You slipped a live production gate."
    : partial
    ? "Tex escalated to human review — partial credit."
    : "Tex held the line. The attack never left the gate.";

  const tierBefore = tierFor(player.rp).current;
  const tierAfter = tierFor(playerAfter.rp).current;
  const promoted = tierBefore.short !== tierAfter.short && playerAfter.rp > player.rp;

  useEffect(() => {
    if (promoted) setTimeout(rankUpSfx, 400);
  }, [promoted]);

  const evHash = decision?.evidence?.evidence_hash;
  const decisionId = decision?.decision_id;
  const latency = decision?.total_ms;

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(6, 7, 14, 0.92)",
      backdropFilter: "blur(12px)",
      zIndex: 50,
      overflowY: "auto",
      padding: "32px 16px",
    }}>
      <div className="panel rise" style={{
        maxWidth: 760,
        margin: "0 auto",
        borderColor: tone,
        boxShadow: `0 0 64px ${tone}33`,
      }}>
        {/* Header band */}
        <div style={{
          padding: "32px 32px 24px",
          borderBottom: `1px solid ${tone}`,
          background: win
            ? "radial-gradient(ellipse 80% 60% at 50% 0%, rgba(95,250,159,0.15), transparent 70%)"
            : partial
            ? "radial-gradient(ellipse 80% 60% at 50% 0%, rgba(255,225,74,0.12), transparent 70%)"
            : "radial-gradient(ellipse 80% 60% at 50% 0%, rgba(255,75,75,0.10), transparent 70%)",
        }}>
          <div className="kicker" style={{ color: tone }}>
            INCIDENT · {incident.name.toUpperCase()} {timeout && "· TIMEOUT"}
          </div>
          <div className="display punch" style={{
            fontSize: "clamp(52px, 9vw, 88px)",
            color: tone,
            marginTop: 10,
            lineHeight: 1,
            textShadow: `0 0 32px ${tone}66`,
          }}>
            {bigLabel}
          </div>
          <div style={{ marginTop: 10, color: "var(--ink-dim)", fontSize: 15 }}>
            {subLabel}
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: "24px 32px" }}>

          {/* RP row */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 14,
            marginBottom: 20,
          }}>
            <div style={{
              padding: "18px 20px",
              border: "1px solid var(--hairline-2)",
              borderRadius: 8,
              background: "var(--bg-1)",
            }}>
              <div className="kicker" style={{ color: "var(--ink-faint)" }}>RANK POINTS</div>
              <div style={{
                display: "flex",
                alignItems: "baseline",
                gap: 10,
                marginTop: 6,
              }}>
                <span className="display tabular" style={{
                  fontSize: 36,
                  color: rpResult.delta > 0 ? "var(--green)" : rpResult.delta < 0 ? "var(--red)" : "var(--ink)",
                }}>
                  {rpResult.delta > 0 ? "+" : ""}{rpResult.delta}
                </span>
                <span className="mono" style={{ fontSize: 12, color: "var(--ink-faint)", letterSpacing: "0.1em" }}>
                  {rpResult.label}
                </span>
              </div>
              <div className="mono tabular" style={{ fontSize: 12, color: "var(--ink-dim)", marginTop: 10 }}>
                {player.rp.toLocaleString()} → <strong style={{ color: "var(--ink)" }}>{playerAfter.rp.toLocaleString()} RP</strong>
              </div>
            </div>

            <div style={{
              padding: "18px 20px",
              border: `1px solid ${promoted ? tierAfter.color : "var(--hairline-2)"}`,
              borderRadius: 8,
              background: promoted ? `${tierAfter.color}0E` : "var(--bg-1)",
              display: "flex",
              alignItems: "center",
              gap: 14,
            }}>
              <RankBadge tier={tierAfter} size={48} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="kicker" style={{
                  color: promoted ? tierAfter.color : "var(--ink-faint)",
                }}>
                  {promoted ? "★ PROMOTED" : "TIER"}
                </div>
                <div className="display" style={{
                  fontSize: 18,
                  color: tierAfter.color,
                  marginTop: 2,
                  letterSpacing: "0.05em",
                }}>
                  {tierAfter.name}
                </div>
                {promoted && (
                  <div className="micro" style={{ color: "var(--ink-dim)", marginTop: 3 }}>
                    {tierBefore.name} → {tierAfter.name}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Attack recap */}
          {finalAttempt && (
            <div style={{
              padding: "16px 18px",
              border: "1px solid var(--hairline-2)",
              borderRadius: 8,
              background: "var(--bg-1)",
              marginBottom: 20,
            }}>
              <div className="kicker" style={{ color: "var(--pink)", marginBottom: 8 }}>
                YOUR {win ? "WINNING" : "FINAL"} ATTACK
              </div>
              <div className="mono" style={{
                fontSize: 13,
                color: "var(--ink)",
                lineHeight: 1.5,
                whiteSpace: "pre-wrap",
                maxHeight: 120,
                overflowY: "auto",
              }}>
                {finalAttempt.text}
              </div>
            </div>
          )}

          {/* Why Tex decided — ASI findings */}
          {decision?.asi_findings?.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 8 }}>
                WHY TEX {win ? "LET IT THROUGH" : "CAUGHT IT"}
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {decision.asi_findings.slice(0, 6).map((f, i) => (
                  <div key={i} style={{
                    padding: "5px 10px",
                    border: "1px solid var(--hairline-2)",
                    borderRadius: 4,
                    background: "rgba(95, 240, 255, 0.04)",
                  }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>
                      {f.short_code}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: "var(--ink-dim)", marginLeft: 6 }}>
                      {f.title || "finding"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── The product moment: signed evidence ─────────────── */}
          <div style={{
            padding: "16px 18px",
            border: "1px solid rgba(255, 225, 74, 0.3)",
            borderRadius: 8,
            background: "rgba(255, 225, 74, 0.04)",
            marginBottom: 20,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--yellow)", boxShadow: "0 0 8px var(--yellow-glow)",
              }} />
              <span className="kicker" style={{ color: "var(--yellow)" }}>
                SIGNED EVIDENCE · SHA-256 HASH-CHAINED
              </span>
            </div>
            <div className="mono" style={{ fontSize: 11, color: "var(--ink-dim)", lineHeight: 1.7, wordBreak: "break-all" }}>
              <div><strong style={{ color: "var(--ink)" }}>decision_id:</strong> {decisionId || "—"}</div>
              <div><strong style={{ color: "var(--ink)" }}>evidence_hash:</strong> {evHash || "—"}</div>
              <div><strong style={{ color: "var(--ink)" }}>policy:</strong> {decision?.policy_version || "default-v1"}</div>
              <div><strong style={{ color: "var(--ink)" }}>latency:</strong> {latency}ms · <strong style={{ color: "var(--ink)" }}>chain_valid:</strong> {decision?.evidence?.chain_valid ? "true" : "false"}</div>
            </div>
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid rgba(255, 225, 74, 0.15)", fontSize: 12, color: "var(--ink-dim)", lineHeight: 1.5 }}>
              <strong style={{ color: "var(--yellow)" }}>This is a real audit record.</strong> Tamper-proof, portable, cryptographically verifiable. Every verdict in this game produces the same bundle your EU AI Act auditor would accept.
            </div>
          </div>

        </div>

        {/* CTAs */}
        <div style={{
          padding: "18px 32px",
          borderTop: "1px solid var(--hairline-2)",
          display: "flex",
          gap: 10,
          flexWrap: "wrap",
        }}>
          <button onClick={onPlayAgain} className="btn-primary">
            PLAY ANOTHER →
          </button>
          {win && (
            <button onClick={onShare} className="btn-ghost">
              ⚔ CHALLENGE A COWORKER
            </button>
          )}
          <button onClick={onHome} style={{
            marginLeft: "auto",
            padding: "10px 16px",
            color: "var(--ink-faint)",
            fontSize: 12,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            fontFamily: "var(--font-mono)",
          }}>
            BACK TO HUB
          </button>
        </div>
      </div>
    </div>
  );
}
