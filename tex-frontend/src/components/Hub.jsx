import React, { useEffect, useState } from "react";
import RankBadge from "./RankBadge.jsx";
import ComplianceStrip from "./ComplianceStrip.jsx";
import { tierFor, fetchLeaderboardWithPlayer, emptyLeaderboard, globalStats } from "../lib/ranking.js";
import { clickSfx } from "../lib/sounds.js";

/*
  Hub v9 — "OWASP-framed Ranked"
  ───────────────────────────────
  Changes from v8:
    1. Kicker line above headline: "OWASP ASI 2026 ADJUDICATION BENCHMARK"
    2. Top nav adds "FOR ENGINEERING →" + "FOR SECURITY TEAMS →" + ASI link
    3. New section: "TEX × OWASP ASI 2026" + ComplianceStrip
    4. New CTA: "RUN YOUR OWN ATTACK"
    5. Pitch band leads with OWASP positioning, then Aug 2 2026 + signed evidence
*/

export default function Hub({
  player,
  onPlay,
  onEditHandle,
  onOpenBuyer,
  onOpenDevelopers,
  onOpenAsi,
  onOpenRunYourOwn,
  onToggleMute,
  muted,
}) {
  const tier = tierFor(player.rp || 0);
  const nextTier = tier.next;
  const rp = player.rp || 0;
  const isNew = rp === 0 && !player.handle;

  const [board, setBoard] = useState(() => emptyLeaderboard(player));

  useEffect(() => {
    let cancelled = false;
    fetchLeaderboardWithPlayer(player).then((data) => {
      if (!cancelled) setBoard(data);
    });
    return () => { cancelled = true; };
  }, [player.handle, player.rp]);

  const { list, yourRank, total } = board;
  const stats = globalStats();

  const rpToNext = nextTier ? Math.max(0, nextTier.min - rp) : 0;
  const rpProgress = nextTier
    ? Math.min(100, Math.round(((rp - tier.current.min) / (nextTier.min - tier.current.min)) * 100))
    : 100;

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* ── Top bar ─────────────────────────────────────────────── */}
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
        gap: 12,
        flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, minWidth: 0 }}>
          <div style={{
            width: 8, height: 8, borderRadius: "50%",
            background: "var(--cyan)", boxShadow: "0 0 10px var(--cyan-glow)"
          }} className="pulse" />
          <span className="display" style={{ fontSize: 17, letterSpacing: "0.06em" }}>
            TEX ARENA
          </span>
          <span className="kicker" style={{ color: "var(--cyan)" }}>RANKED</span>
          <span className="micro hide-mobile" style={{ color: "var(--ink-faint)" }}>
            · SEASON 1 · <span style={{ color: "var(--yellow)" }}>6 DAYS LEFT</span>
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <button onClick={onOpenAsi} className="micro" style={{
            color: "var(--cyan)", padding: "6px 10px",
            border: "1px solid rgba(95, 240, 255, 0.35)", borderRadius: 4,
          }}>
            OWASP ASI →
          </button>
          <button onClick={onOpenDevelopers} className="micro" style={{
            color: "var(--ink-dim)", padding: "6px 10px",
            border: "1px solid var(--hairline-2)", borderRadius: 4,
          }}>
            FOR ENGINEERING →
          </button>
          <button onClick={onOpenBuyer} className="micro" style={{
            color: "var(--ink-dim)", padding: "6px 10px",
            border: "1px solid var(--hairline-2)", borderRadius: 4,
          }}>
            FOR SECURITY TEAMS →
          </button>
          <button
            onClick={onToggleMute}
            className="micro"
            style={{
              color: "var(--ink-dim)", padding: "6px 10px",
              border: "1px solid var(--hairline-2)", borderRadius: 4,
            }}
            aria-label={muted ? "Unmute" : "Mute"}
          >
            {muted ? "♪ OFF" : "♪ ON"}
          </button>
        </div>
      </header>

      {/* ── Hero ───────────────────────────────────────────────── */}
      <section style={{ padding: "40px 48px 32px", maxWidth: 1440, margin: "0 auto", width: "100%" }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.35fr) minmax(0, 0.85fr)",
          gap: 56,
          alignItems: "start",
        }} className="hero-grid">
          {/* LEFT */}
          <div className="rise">
            <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 14, letterSpacing: "0.18em" }}>
              ⛨ OWASP ASI 2026 · THE PUBLIC ADJUDICATION BENCHMARK
            </div>

            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              padding: "6px 12px",
              border: "1px solid var(--pink)",
              borderRadius: 4,
              background: "rgba(255, 61, 122, 0.06)",
              marginBottom: 22,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--pink)", boxShadow: "0 0 8px var(--pink-glow)",
              }} className="pulse" />
              <span className="kicker" style={{ color: "var(--pink)" }}>
                {stats.bypassesToday === 0
                  ? `NOBODY HAS BEATEN TEX TODAY · ${stats.attemptsToday.toLocaleString()} TRIED`
                  : `${stats.bypassesToday} BYPASSES TODAY · ${stats.attemptsToday.toLocaleString()} ATTEMPTS`}
              </span>
            </div>

            <h1 className="display" style={{
              fontSize: "clamp(64px, 10.5vw, 136px)",
              margin: 0,
              lineHeight: 0.9,
            }}>
              <span>CAN YOU</span>
              <br />
              <span className="glow-pink" style={{ color: "var(--pink)" }}>BEAT TEX?</span>
            </h1>

            <p style={{
              marginTop: 22,
              fontSize: 17,
              lineHeight: 1.55,
              color: "var(--ink-dim)",
              maxWidth: 620,
            }}>
              Tex is the <strong style={{ color: "var(--ink)" }}>OWASP ASI 2026 reference adjudicator</strong> —
              a live production gate that reviews AI agent outputs and returns
              PERMIT, ABSTAIN, or FORBID with cryptographically signed evidence.
              You're the red-teamer. Slip a single message past Tex and you've
              bypassed a real security system.
            </p>

            <div style={{ marginTop: 32, display: "flex", gap: 12, flexWrap: "wrap" }}>
              <button onClick={() => { clickSfx(); onPlay(); }} className="btn-big">
                STEP IN THE RING →
              </button>
              <button onClick={onOpenRunYourOwn} className="btn-ghost" style={{ alignSelf: "center" }}>
                RUN YOUR OWN ATTACK
              </button>
            </div>

            <div style={{
              marginTop: 20,
              display: "flex",
              gap: 18,
              flexWrap: "wrap",
              color: "var(--ink-faint)",
            }} className="micro">
              <span>01 · WRITE ONE ATTACK</span>
              <span style={{ opacity: 0.4 }}>/</span>
              <span>02 · TEX ADJUDICATES IN {"<"} 200MS</span>
              <span style={{ opacity: 0.4 }}>/</span>
              <span style={{ color: "var(--green)" }}>03 · PERMIT = BYPASS</span>
            </div>

            {!isNew && (
              <div style={{
                marginTop: 28,
                padding: "16px 18px",
                border: `1px solid ${tier.current.color}55`,
                borderRadius: 10,
                background: `linear-gradient(90deg, ${tier.current.color}12, transparent 70%)`,
                display: "flex",
                alignItems: "center",
                gap: 16,
                maxWidth: 620,
              }}>
                <RankBadge tier={tier.current} size={52} />
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
            )}

            {isNew && (
              <div style={{
                marginTop: 24,
                fontSize: 13,
                color: "var(--ink-faint)",
                maxWidth: 620,
              }} className="mono">
                New here? Your first attack decides your tier.
              </div>
            )}
          </div>

          {/* RIGHT — Tex portrait */}
          <div className="rise-2" style={{ position: "relative" }}>
            <div style={{
              position: "relative",
              aspectRatio: "4 / 5",
              maxWidth: 460,
              width: "100%",
              borderRadius: 10,
              overflow: "hidden",
              border: "1px solid rgba(95, 240, 255, 0.28)",
              background: "linear-gradient(180deg, rgba(6,7,14,0.2), rgba(6,7,14,0.85))",
              boxShadow: "0 0 48px rgba(95, 240, 255, 0.08)",
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
                <div className="mono tabular" style={{ fontSize: 14, color: "var(--green)", marginTop: 2, fontWeight: 600 }}>
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
                  if (e.currentTarget.nextElementSibling) {
                    e.currentTarget.nextElementSibling.style.display = "flex";
                  }
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
                <div className="micro" style={{ color: "var(--cyan)", opacity: 0.9 }}>OWASP ASI 2026 REFERENCE ADJUDICATOR</div>
                <div className="display" style={{ fontSize: 36, marginTop: 2 }}>TEX</div>
                <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
                  Six-layer pipeline · 200ms · signed evidence
                </div>
              </div>
            </div>

            <div style={{
              marginTop: 16,
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 10,
              maxWidth: 460,
            }}>
              <StatMini label="YOUR STREAK" value={player.streak ? `${player.streak}D` : "—"} color="var(--yellow)" />
              <StatMini label="YOUR RANK" value={isNew ? "—" : `#${yourRank}`} color={tier.current.color} />
            </div>
          </div>
        </div>
      </section>

      {/* ── OWASP / Compliance band ─────────────────────────────── */}
      <section style={{
        padding: "20px 48px",
        borderTop: "1px solid var(--hairline-2)",
        borderBottom: "1px solid var(--hairline-2)",
        background: "var(--bg-1)",
      }}>
        <div style={{
          maxWidth: 1440,
          margin: "0 auto",
          width: "100%",
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) minmax(0, 2fr)",
          gap: 24,
          alignItems: "center",
        }} className="owasp-band-grid">
          <div>
            <div className="kicker" style={{ color: "var(--cyan)" }}>TEX × OWASP ASI 2026</div>
            <div className="display" style={{ fontSize: 18, marginTop: 4, lineHeight: 1.15 }}>
              EVERY VERDICT MAPPED. EVERY FRAMEWORK COVERED.
            </div>
            <button
              onClick={onOpenAsi}
              className="micro"
              style={{
                marginTop: 8,
                color: "var(--cyan)",
                textDecoration: "underline",
              }}
            >
              SEE THE ASI MAPPING →
            </button>
          </div>
          <ComplianceStrip />
        </div>
      </section>

      {/* ── Leaderboard ──────────────────────────────────────────── */}
      <section style={{ maxWidth: 1440, margin: "0 auto", padding: "32px 48px 40px", width: "100%" }} className="rise-3">
        <div className="panel" style={{ overflow: "hidden" }}>
          <div style={{
            padding: "16px 22px",
            borderBottom: "1px solid var(--hairline-2)",
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}>
            <div>
              <div className="kicker" style={{ color: "var(--cyan)" }}>SEASON 1 · LEADERBOARD</div>
              <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 3 }}>
                RESETS SUNDAY · {(total - 1).toLocaleString()} PLAYERS · THRONE VACANT
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
            padding: "14px 22px",
            borderTop: "1px solid var(--hairline-2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}>
            <span className="mono" style={{ fontSize: 13, color: "var(--ink-dim)" }}>
              The throne is yours if you beat Tex. Nobody has.
            </span>
            <button onClick={() => { clickSfx(); onPlay(); }} className="btn-ghost">
              PLAY A ROUND →
            </button>
          </div>
        </div>
      </section>

      {/* ── Product pitch band ─────────────────────────────────── */}
      <section style={{
        borderTop: "1px solid var(--hairline-2)",
        background: "linear-gradient(180deg, transparent, rgba(255, 225, 74, 0.03))",
        padding: "32px 48px",
      }}>
        <div style={{ maxWidth: 1440, margin: "0 auto", width: "100%" }}>
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr auto",
            gap: 24,
            alignItems: "center",
          }} className="pitch-grid">
            <div>
              <div className="kicker" style={{ color: "var(--yellow)" }}>THIS IS A REAL PRODUCT</div>
              <div className="display" style={{ fontSize: 28, marginTop: 6, lineHeight: 1.05 }}>
                EVERYONE LOGS IT.{" "}
                <span className="glow-yellow" style={{ color: "var(--yellow)" }}>TEX PROVES IT.</span>
              </div>
              <p style={{ marginTop: 8, color: "var(--ink-dim)", fontSize: 14, maxWidth: 780, lineHeight: 1.55 }}>
                Every verdict in this game is signed by a real production API
                with SHA-256 hash-chained evidence and OWASP ASI 2026 findings.
                The same tamper-proof bundle your EU AI Act, NIST AI RMF, and
                ISO 42001 auditor will accept on Aug 2, 2026.
              </p>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <button onClick={onOpenDevelopers} className="btn-primary" style={{ background: "var(--cyan)", color: "#001A1F" }}>
                GET API ACCESS
              </button>
              <button onClick={onOpenBuyer} className="btn-ghost">
                BOOK 20-MIN WALKTHROUGH
              </button>
            </div>
          </div>
          <div style={{
            marginTop: 22,
            paddingTop: 16,
            borderTop: "1px solid var(--hairline)",
            display: "flex",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
            color: "var(--ink-faint)",
          }} className="micro">
            <span>BUILT BY VORTEXBLACK · TEXAEGIS.COM</span>
            <span>API LATENCY {"<"} 200MS · SIGNED EVIDENCE · OWASP ASI 2026 · NIST · ISO 42001</span>
          </div>
        </div>
      </section>

      <style>{`
        @media (max-width: 960px) {
          .hero-grid { grid-template-columns: 1fr !important; gap: 32px !important; }
          .hero-grid > div:last-child { justify-self: center !important; max-width: 460px !important; margin: 0 auto; }
          .pitch-grid { grid-template-columns: 1fr !important; }
          .owasp-band-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}

function StatMini({ label, value, color }) {
  return (
    <div style={{
      padding: "12px 14px",
      border: "1px solid var(--hairline-2)",
      borderRadius: 6,
      background: "var(--bg-1)",
    }}>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="display tabular" style={{ fontSize: 22, color, marginTop: 4 }}>{value}</div>
    </div>
  );
}

function LeaderRow({ entry }) {
  if (entry.isThrone) {
    return (
      <div style={{
        display: "grid",
        gridTemplateColumns: "48px 1fr auto auto",
        gap: 14,
        alignItems: "center",
        padding: "16px 14px",
        background: "linear-gradient(90deg, rgba(95,250,159,0.08), rgba(255,225,74,0.04) 70%, transparent)",
        border: "1px dashed rgba(95, 250, 159, 0.45)",
        borderRadius: 6,
        marginBottom: 4,
      }}>
        <span className="display tabular" style={{ fontSize: 20, color: "var(--green)" }}>
          1
        </span>
        <span style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--green)" }}>
          <span className="kicker" style={{ color: "var(--green)" }}>
            ★ THRONE · UNCLAIMED
          </span>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            — YOUR NAME HERE IF YOU BEAT TEX
          </span>
        </span>
        <span className="kicker" style={{ color: "var(--green)", letterSpacing: "0.08em" }}>
          UNDEFEATED
        </span>
        <span className="mono tabular" style={{ fontSize: 14, color: "var(--ink-faint)", minWidth: 64, textAlign: "right" }}>
          —
        </span>
      </div>
    );
  }

  const medalColor =
    entry.rank === 2 ? "var(--yellow)" :
    entry.rank === 3 ? "var(--ink-dim)" :
    entry.rank === 4 ? "#D49A5C" : "var(--ink-faint)";

  const bg = entry.isYou ? "rgba(255, 61, 122, 0.07)" :
             entry.rank === 2 ? "rgba(255, 225, 74, 0.04)" : "transparent";
  const border = entry.isYou ? "1px solid rgba(255, 61, 122, 0.35)" :
                 entry.rank === 2 ? "1px solid rgba(255, 225, 74, 0.22)" : "1px solid transparent";

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
