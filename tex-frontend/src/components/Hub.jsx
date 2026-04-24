import React from "react";
import RankBadge from "./RankBadge.jsx";
import { tierFor, leaderboardWithPlayer, globalStats } from "../lib/ranking.js";
import { clickSfx } from "../lib/sounds.js";

/*
  Hub v8 — "Ranked · You vs Tex"
  ────────────────────────────────
  One opponent: Tex. One button: PLAY. Ranked ladder with seasons.
  No 7-case grid. No locks. No tutorial.

  Layout:
    Top bar: TEX ARENA · RANKED · season countdown · mute
    Hero: split 60/40
      L: rank + RP bar + PLAY A ROUND + how-it-works micro
      R: Tex portrait, live pip, record (∞–0–3)
    Live stats strip: attempts today / bypasses today / global
    Leaderboard: top 3 + player window
    Footer: product pitch + buyer CTA
*/

export default function Hub({ player, onPlay, onEditHandle, onOpenBuyer, onToggleMute, muted }) {
  const tier = tierFor(player.rp || 0);
  const nextTier = tier.next;
  const rp = player.rp || 0;
  const { list, yourRank, total } = leaderboardWithPlayer(player);
  const stats = globalStats();

  const rpToNext = nextTier ? Math.max(0, nextTier.min - rp) : 0;
  const rpProgress = nextTier
    ? Math.min(100, Math.round(((rp - tier.current.min) / (nextTier.min - tier.current.min)) * 100))
    : 100;

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* ── Top bar ───────────────────────────────────────────────── */}
      <header style={{
        borderBottom: "1px solid var(--hairline-2)",
        padding: "14px 32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "rgba(6, 7, 14, 0.6)",
        backdropFilter: "blur(10px)",
        position: "sticky",
        top: 0,
        zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 8, height: 8, borderRadius: "50%",
            background: "var(--cyan)", boxShadow: "0 0 10px var(--cyan-glow)"
          }} className="pulse" />
          <span className="display" style={{ fontSize: 17, letterSpacing: "0.06em" }}>
            TEX ARENA
          </span>
          <span className="kicker" style={{ color: "var(--cyan)" }}>RANKED</span>
          <span className="micro hide-mobile" style={{ color: "var(--ink-faint)" }}>
            · LIVE · EVERY VERDICT IS REAL
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span className="micro hide-mobile" style={{ color: "var(--ink-faint)" }}>
            SEASON 1 · <span style={{ color: "var(--yellow)" }}>6 DAYS LEFT</span>
          </span>
          <button
            onClick={onToggleMute}
            className="kicker"
            style={{
              color: "var(--ink-dim)",
              padding: "6px 10px",
              border: "1px solid var(--hairline-2)",
              borderRadius: 4,
            }}
            aria-label={muted ? "Unmute" : "Mute"}
          >
            {muted ? "♪ OFF" : "♪ ON"}
          </button>
          <button
            onClick={onOpenBuyer}
            className="kicker"
            style={{ color: "var(--yellow)" }}
          >
            BUILD WITH IT →
          </button>
        </div>
      </header>

      {/* ── Hero ──────────────────────────────────────────────────── */}
      <section style={{
        padding: "56px 32px 24px",
        maxWidth: 1280,
        margin: "0 auto",
        width: "100%",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.3fr) minmax(0, 1fr)",
          gap: 48,
          alignItems: "center",
        }} className="hero-grid">
          {/* LEFT — rank + CTA */}
          <div className="rise">
            <div className="kicker" style={{ color: "var(--pink)", marginBottom: 18 }}>
              ● RED-TEAM CHALLENGE · ONE OPPONENT · ONE GOAL
            </div>

            <h1 className="display" style={{
              fontSize: "clamp(56px, 9vw, 112px)",
              margin: 0,
              lineHeight: 0.92,
            }}>
              <span>CAN YOU</span>
              <br />
              <span className="glow-pink" style={{ color: "var(--pink)" }}>BEAT TEX?</span>
            </h1>

            <p style={{
              marginTop: 20,
              fontSize: 16,
              lineHeight: 1.55,
              color: "var(--ink-dim)",
              maxWidth: 520,
            }}>
              Tex is the content gate for AI agents. You are the red-teamer.
              Write a message that <strong style={{ color: "var(--ink)" }}>slips past him</strong>.
              If Tex returns <span style={{ color: "var(--green)" }}>PERMIT</span>,
              you bypassed a production-grade gate — that's a rank climb,
              a bragging-rights screenshot, and proof you can think like an attacker.
            </p>

            {/* Rank + progress */}
            <div style={{
              marginTop: 28,
              padding: "18px 20px",
              border: `1px solid ${tier.current.color}55`,
              borderRadius: 10,
              background: `linear-gradient(90deg, ${tier.current.color}0E, transparent 70%)`,
              display: "flex",
              alignItems: "center",
              gap: 18,
              maxWidth: 560,
            }}>
              <RankBadge tier={tier.current} size={56} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 4 }}>
                  <button
                    onClick={onEditHandle}
                    className="mono"
                    style={{ fontSize: 14, color: "var(--ink)", fontWeight: 600 }}
                  >
                    @{player.handle || "anonymous"}
                    <span style={{ color: "var(--ink-faint)", marginLeft: 6, fontSize: 11 }}>✎</span>
                  </button>
                  <span className="kicker" style={{ color: tier.current.color }}>
                    {tier.current.name}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span className="mono tabular" style={{ fontSize: 13, color: "var(--ink)" }}>
                    {rp.toLocaleString()} RP
                  </span>
                  {nextTier && (
                    <>
                      <span className="micro" style={{ color: "var(--ink-faint)" }}>
                        → {nextTier.name}
                      </span>
                      <span className="mono tabular" style={{ fontSize: 12, color: "var(--ink-dim)", marginLeft: "auto" }}>
                        {rpToNext} TO GO
                      </span>
                    </>
                  )}
                </div>
                <div style={{
                  marginTop: 6,
                  height: 4,
                  background: "rgba(168, 174, 201, 0.1)",
                  borderRadius: 2,
                  overflow: "hidden",
                }}>
                  <div style={{
                    width: `${rpProgress}%`,
                    height: "100%",
                    background: nextTier
                      ? `linear-gradient(90deg, ${tier.current.color}, ${nextTier.color})`
                      : tier.current.color,
                    transition: "width 0.7s ease",
                  }} />
                </div>
              </div>
            </div>

            {/* CTA */}
            <div style={{ marginTop: 28, display: "flex", gap: 14, flexWrap: "wrap" }}>
              <button onClick={() => { clickSfx(); onPlay(); }} className="btn-big">
                STEP IN THE RING →
              </button>
              <button onClick={onOpenBuyer} className="btn-ghost">
                I'M A BUYER, NOT A PLAYER
              </button>
            </div>

            {/* How-it-works, minimal */}
            <div style={{
              marginTop: 24,
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 12,
              maxWidth: 560,
            }}>
              <HowStep n="01" text="Write one attack" />
              <HowStep n="02" text="Tex adjudicates in < 200ms" />
              <HowStep n="03" text="PERMIT = bypass. Climb ranks." />
            </div>
          </div>

          {/* RIGHT — Tex portrait */}
          <div className="rise-2" style={{
            position: "relative",
            aspectRatio: "4 / 5",
            maxWidth: 420,
            width: "100%",
            justifySelf: "end",
            borderRadius: 10,
            overflow: "hidden",
            border: "1px solid rgba(95, 240, 255, 0.25)",
            background: "linear-gradient(180deg, rgba(6,7,14,0.2), rgba(6,7,14,0.85))",
          }}>
            <div className="scan" />
            <div style={{
              position: "absolute", top: 14, left: 14, zIndex: 2,
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan-glow)",
              }} className="pulse" />
              <span className="kicker" style={{ color: "var(--cyan)" }}>TEX · LIVE</span>
            </div>
            <div style={{ position: "absolute", top: 14, right: 14, zIndex: 2, textAlign: "right" }}>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>RECORD</div>
              <div className="mono tabular" style={{ fontSize: 14, color: "var(--ink)", marginTop: 2 }}>
                {stats.texRecord}
              </div>
            </div>

            <img
              src="/tex/tex-full.png"
              alt="Tex"
              className="float"
              style={{
                position: "absolute",
                inset: 0,
                width: "100%",
                height: "100%",
                objectFit: "cover",
                objectPosition: "center top",
              }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
                e.currentTarget.nextElementSibling.style.display = "flex";
              }}
            />
            <div style={{
              display: "none",
              position: "absolute",
              inset: 0,
              alignItems: "center",
              justifyContent: "center",
              color: "var(--cyan)",
              fontFamily: "var(--font-display)",
              fontSize: 80,
              textShadow: "0 0 40px var(--cyan-glow)",
            }}>
              TEX
            </div>

            <div style={{
              position: "absolute",
              bottom: 0, left: 0, right: 0,
              padding: 20,
              background: "linear-gradient(180deg, transparent, rgba(6,7,14,0.95))",
            }}>
              <div className="micro" style={{ color: "var(--cyan)", opacity: 0.9 }}>THE UNDEFEATED</div>
              <div className="display" style={{ fontSize: 36, marginTop: 2 }}>TEX</div>
              <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
                Content-layer adjudication gate · 200ms · signed evidence
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Live stats strip ──────────────────────────────────────── */}
      <section style={{
        maxWidth: 1280, margin: "0 auto", padding: "20px 32px", width: "100%",
      }} className="rise-3">
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 12,
        }}>
          <Stat label="ATTEMPTS TODAY" value={stats.attemptsToday.toLocaleString()} color="var(--ink)" />
          <Stat label="BYPASSES TODAY" value={stats.bypassesToday} color="var(--pink)" />
          <Stat label="YOUR STREAK" value={player.streak ? `${player.streak}D` : "—"} color="var(--yellow)" />
          <Stat label="YOUR RANK" value={`#${yourRank}`} color={tier.current.color} />
        </div>
      </section>

      {/* ── Leaderboard ───────────────────────────────────────────── */}
      <section style={{ maxWidth: 1280, margin: "0 auto", padding: "28px 32px 40px", width: "100%" }}>
        <div className="panel" style={{ overflow: "hidden" }}>
          <div style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--hairline-2)",
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
          }}>
            <div>
              <div className="kicker" style={{ color: "var(--cyan)" }}>TOP THIS WEEK</div>
              <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 3 }}>
                RESETS SUNDAY · {total.toLocaleString()} PLAYERS
              </div>
            </div>
            <div className="micro" style={{ color: "var(--ink-faint)" }}>
              RANK · HANDLE · TIER · RP
            </div>
          </div>
          <div style={{ padding: 12 }}>
            {list.map((e, i) =>
              e.divider ? (
                <div key={`d-${i}`} style={{
                  textAlign: "center",
                  color: "var(--ink-faint)",
                  padding: "6px 0",
                  letterSpacing: "0.4em",
                }}>· · ·</div>
              ) : (
                <LeaderRow key={`${e.handle}-${e.rank}`} entry={e} />
              )
            )}
          </div>
          <div style={{
            padding: "14px 20px",
            borderTop: "1px solid var(--hairline-2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}>
            <span className="mono" style={{ fontSize: 13, color: "var(--ink-dim)" }}>
              Climb the ranks. Drag your coworkers in.
            </span>
            <button onClick={() => { clickSfx(); onPlay(); }} className="btn-ghost">
              PLAY A ROUND →
            </button>
          </div>
        </div>
      </section>

      {/* ── Footer product pitch ──────────────────────────────────── */}
      <footer style={{
        borderTop: "1px solid var(--hairline-2)",
        padding: "28px 32px",
        maxWidth: 1280,
        margin: "0 auto",
        width: "100%",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr auto",
          gap: 20,
          alignItems: "center",
        }}>
          <div>
            <div className="kicker" style={{ color: "var(--yellow)" }}>THIS IS A REAL PRODUCT</div>
            <div className="display" style={{ fontSize: 22, marginTop: 4 }}>
              EVERYONE LOGS IT. TEX PROVES IT.
            </div>
            <p style={{ marginTop: 6, color: "var(--ink-dim)", fontSize: 14, maxWidth: 680, lineHeight: 1.5 }}>
              Every verdict in this game is signed by a real production API with
              SHA-256 hash-chained evidence. The same bundle your auditor needs for
              the EU AI Act (Aug 2, 2026). Want to run Tex in front of your own agents?
            </p>
          </div>
          <button onClick={onOpenBuyer} className="btn-primary">
            BOOK A 20-MIN WALKTHROUGH
          </button>
        </div>
        <div style={{
          marginTop: 20,
          paddingTop: 16,
          borderTop: "1px solid var(--hairline)",
          display: "flex",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 12,
          color: "var(--ink-faint)",
        }} className="micro">
          <span>BUILT BY VORTEXBLACK · TEXAEGIS.COM</span>
          <span>API LATENCY {"<"} 200MS · SIGNED EVIDENCE · OWASP ASI 2026</span>
        </div>
      </footer>

      <style>{`
        @media (max-width: 900px) {
          .hero-grid { grid-template-columns: 1fr !important; gap: 32px !important; }
          .hero-grid > div:last-child { justify-self: center !important; }
        }
      `}</style>
    </div>
  );
}

function HowStep({ n, text }) {
  return (
    <div style={{
      padding: "12px 14px",
      border: "1px solid var(--hairline-2)",
      borderRadius: 6,
      background: "var(--bg-1)",
    }}>
      <div className="mono" style={{ fontSize: 11, color: "var(--ink-faint)", letterSpacing: "0.1em" }}>{n}</div>
      <div style={{ fontSize: 13, color: "var(--ink)", marginTop: 4, lineHeight: 1.4 }}>{text}</div>
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{
      padding: "14px 16px",
      border: "1px solid var(--hairline-2)",
      borderRadius: 8,
      background: "var(--bg-1)",
    }}>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="display tabular" style={{ fontSize: 26, color, marginTop: 4 }}>{value}</div>
    </div>
  );
}

function LeaderRow({ entry }) {
  const medalColor =
    entry.rank === 1 ? "var(--yellow)" :
    entry.rank === 2 ? "var(--ink-dim)" :
    entry.rank === 3 ? "#D49A5C" : "var(--ink-faint)";

  const bg = entry.isYou ? "rgba(255, 61, 122, 0.07)" :
             entry.rank === 1 ? "rgba(255, 225, 74, 0.05)" : "transparent";
  const border = entry.isYou ? "1px solid rgba(255, 61, 122, 0.35)" :
                 entry.rank === 1 ? "1px solid rgba(255, 225, 74, 0.22)" : "1px solid transparent";

  const t = tierFor(entry.rp).current;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "48px 1fr auto auto",
      gap: 14,
      alignItems: "center",
      padding: "12px 14px",
      background: bg,
      border,
      borderRadius: 6,
      marginBottom: 2,
    }}>
      <span className="mono tabular" style={{ fontSize: 15, fontWeight: 600, color: medalColor }}>
        {entry.rank}
      </span>
      <span style={{ color: "var(--ink)", fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        @{entry.handle}
        {entry.isYou && <span className="micro" style={{ color: "var(--ink-faint)", marginLeft: 8 }}>— YOU</span>}
      </span>
      <span className="kicker" style={{ color: t.color, letterSpacing: "0.08em" }}>
        {t.name}
      </span>
      <span className="mono tabular" style={{ fontSize: 14, fontWeight: 500, color: t.color, minWidth: 64, textAlign: "right" }}>
        {entry.rp.toLocaleString()}
      </span>
    </div>
  );
}
