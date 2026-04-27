import React, { useEffect, useState } from "react";
import DailyTile from "./DailyTile.jsx";
import LayerAnatomy from "./LayerAnatomy.jsx";
import { INCIDENTS, ASI_CHAPTERS } from "../lib/incidents.js";
import { getCampaignState, getBadgeMeta, chapterStatus } from "../lib/campaign.js";
import { getDailyState } from "../lib/dailyChallenge.js";

/*
  Hub v10 — "The Adversarial Benchmark"
  ──────────────────────────────────────
  Marketing-grade landing surface. The new frame is:

    "You're an AI agent's adversarial trainer. Craft a message that
     does the bad thing — and slip it past Tex."

  Three modes shown as full feature cards:
    1. CAMPAIGN — story mode, 7 chapters mapped to OWASP ASI
    2. RANKED   — pick any incident, climb the leaderboard
    3. DAILY    — one incident a day, streak counter

  Below: hero pipeline visualization (the marketing screenshot),
  trust strip, footer.
*/

export default function Hub({ player, onOpenCampaign, onOpenRanked, onPlayDaily, onOpenAsi }) {
  const campaignState = getCampaignState();
  const dailyState = getDailyState();
  const chapters = chapterStatus();

  const totalCleared = Object.keys(campaignState.cleared || {}).length;
  const totalIncidents = INCIDENTS.length;
  const campaignPct = (totalCleared / totalIncidents) * 100;

  // Cycling demo profile for the hero anatomy — non-distracting
  const [demoProfile, setDemoProfile] = useState(makeDemoProfile(0));
  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      i = (i + 1) % 4;
      setDemoProfile(makeDemoProfile(i));
    }, 2400);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      minHeight: "100vh",
      width: "100%",
      position: "relative",
    }}>
      {/* ── Ambient grain + corner accents ─────────────────────────── */}
      <div style={{
        position: "fixed",
        inset: 0,
        pointerEvents: "none",
        backgroundImage: `
          repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(168,174,201,0.025) 39px, rgba(168,174,201,0.025) 40px),
          repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(168,174,201,0.025) 39px, rgba(168,174,201,0.025) 40px)
        `,
        zIndex: 0,
      }} />

      <div className="page" style={{
        padding: "var(--pad-page)",
        position: "relative",
        zIndex: 1,
      }}>
        {/* ── Top brand bar ────────────────────────────────────────── */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 16,
          borderBottom: "1px solid var(--hairline-2)",
          marginBottom: "clamp(28px, 5vw, 56px)",
          gap: 12,
          flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <BrandMark />
            <div style={{ lineHeight: 1.2 }}>
              <div className="display" style={{ fontSize: 18, color: "var(--ink)", letterSpacing: "0.06em" }}>
                TEX ARENA
              </div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>
                OWASP ASI 2026 · ADVERSARIAL BENCHMARK
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {player.handle && (
              <div style={{
                padding: "6px 12px",
                border: "1px solid rgba(255, 61, 122, 0.3)",
                borderRadius: 4,
                background: "rgba(255, 61, 122, 0.05)",
              }}>
                <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 1 }}>
                  YOU
                </div>
                <div className="mono" style={{ fontSize: 12, color: "var(--pink)", fontWeight: 600 }}>
                  @{player.handle}
                </div>
              </div>
            )}
            {player.rp > 0 && (
              <div style={{
                padding: "6px 12px",
                border: "1px solid rgba(95, 240, 255, 0.3)",
                borderRadius: 4,
                background: "rgba(95, 240, 255, 0.04)",
              }}>
                <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 1 }}>
                  RP
                </div>
                <div className="mono tabular" style={{ fontSize: 12, color: "var(--cyan)", fontWeight: 600 }}>
                  {player.rp.toLocaleString()}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── HERO ─────────────────────────────────────────────────── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.15fr) minmax(0, 1fr)",
          gap: "clamp(24px, 5vw, 64px)",
          alignItems: "center",
          marginBottom: "clamp(40px, 8vw, 88px)",
        }} className="hero-grid">

          {/* HERO LEFT — copy */}
          <div className="rise">
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "5px 11px",
              border: "1px solid rgba(95, 240, 255, 0.35)",
              borderRadius: 999,
              marginBottom: 22,
              background: "rgba(95, 240, 255, 0.04)",
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan-glow)",
              }} className="pulse" />
              <span className="micro" style={{ color: "var(--cyan)" }}>
                LIVE TEX API · PRODUCTION GATE
              </span>
            </div>

            <h1 className="display" style={{
              fontSize: "clamp(48px, 9vw, 104px)",
              margin: 0,
              lineHeight: 0.88,
              letterSpacing: "-0.005em",
            }}>
              <span style={{ color: "var(--ink)" }}>BREAK</span>
              <br />
              <span style={{
                background: "linear-gradient(90deg, var(--pink) 0%, var(--yellow) 50%, var(--cyan) 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}>
                THE GATE.
              </span>
            </h1>

            <p style={{
              maxWidth: 480,
              color: "var(--ink-dim)",
              fontSize: "clamp(15px, 2vw, 17px)",
              lineHeight: 1.55,
              margin: "20px 0 26px 0",
            }}>
              You're an AI agent's adversarial trainer.
              <br />
              Craft a message that does the bad thing —
              <br />
              and slip it past <span style={{ color: "var(--ink)", fontWeight: 600 }}>Tex</span>.
            </p>

            {/* Stat strip */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 14,
              padding: "14px 18px",
              background: "var(--bg-1)",
              border: "1px solid var(--hairline-2)",
              borderRadius: 8,
              maxWidth: 480,
              marginBottom: 24,
            }}>
              <Stat label="INCIDENTS" value={INCIDENTS.length} />
              <Stat label="ASI CATEGORIES" value={ASI_CHAPTERS.length} />
              <Stat label="LAYERS" value="5" accent="var(--pink)" />
            </div>

            {/* Primary CTA cluster */}
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button onClick={onOpenCampaign} className="btn-big">
                START CAMPAIGN →
              </button>
              <button onClick={onOpenRanked} className="btn-ghost">
                FREE PLAY · RANKED
              </button>
            </div>

            <div className="micro" style={{
              color: "var(--ink-faint)",
              marginTop: 14,
              letterSpacing: "0.16em",
            }}>
              {totalCleared > 0
                ? `★ ${totalCleared}/${totalIncidents} INCIDENTS CLEARED`
                : "FIRST INCIDENT TAKES 90 SECONDS"}
            </div>
          </div>

          {/* HERO RIGHT — pipeline visualization */}
          <div className="rise-2" style={{ position: "relative" }}>
            <div className="panel panel-glow-cyan" style={{
              padding: "22px 22px 24px",
              position: "relative",
              overflow: "hidden",
              background: "linear-gradient(180deg, var(--bg-1), var(--bg-0))",
            }}>
              <div className="scan" style={{ top: 0 }} />

              <div style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "baseline",
                marginBottom: 14,
                gap: 8,
                flexWrap: "wrap",
              }}>
                <div>
                  <div className="kicker" style={{ color: "var(--cyan)" }}>
                    TEX // LIVE PIPELINE
                  </div>
                  <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
                    5 LAYERS · WEIGHTED · DETERMINISTIC + LLM
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: "50%",
                    background: "var(--green)", boxShadow: "0 0 8px var(--green-glow)",
                  }} className="pulse" />
                  <span className="micro" style={{ color: "var(--green)" }}>
                    HEALTHY
                  </span>
                </div>
              </div>

              <LayerAnatomy profile={demoProfile} size="md" showWeights />

              <div style={{
                marginTop: 18,
                paddingTop: 14,
                borderTop: "1px solid var(--hairline)",
                display: "flex",
                justifyContent: "space-between",
                gap: 10,
                flexWrap: "wrap",
              }}>
                <Mini label="VERDICT" value="PERMIT/ABSTAIN/FORBID" color="var(--ink)" />
                <Mini label="AVG LATENCY" value="180ms" color="var(--cyan)" />
                <Mini label="AUDIT" value="HMAC SIGNED" color="var(--violet)" />
              </div>
            </div>

            {/* Outside corner labels */}
            <div className="hide-mobile" style={{
              position: "absolute",
              top: -8,
              right: -8,
              padding: "5px 10px",
              background: "var(--bg-0)",
              border: "1px solid var(--pink)",
              borderRadius: 4,
              transform: "rotate(2deg)",
              boxShadow: "0 0 16px var(--pink-glow)",
            }}>
              <span className="micro" style={{ color: "var(--pink)" }}>
                YOU vs THIS →
              </span>
            </div>
          </div>
        </div>

        {/* ── MODES — three feature cards ──────────────────────────── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: 14,
          marginBottom: "clamp(32px, 6vw, 64px)",
        }}>
          <ModeCard
            kicker="MODE 01"
            title="CAMPAIGN"
            subtitle="7 chapters · OWASP ASI 2026"
            description="Work through every category. Cleared incidents stick. Earn chapter badges."
            cta="START CAMPAIGN →"
            color="var(--cyan)"
            progress={campaignPct}
            progressLabel={`${totalCleared}/${totalIncidents} CLEARED`}
            onClick={onOpenCampaign}
          >
            <ChapterMicroProgress chapters={chapters} />
          </ModeCard>

          <ModeCard
            kicker="MODE 02"
            title="RANKED"
            subtitle="Free play · season ladder"
            description="Pick any incident. Stealth math is unforgiving. Climb the global board."
            cta="ENTER RANKED →"
            color="var(--pink)"
            onClick={onOpenRanked}
          >
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 10,
              flexWrap: "wrap",
            }}>
              <RankedStat label="YOUR RP" value={(player.rp || 0).toLocaleString()} />
              <RankedStat label="BEST SCORE" value={player.bestScore || 0} />
              <RankedStat label="STEALTH" value={`${Math.round((player.bestStealth || 0) * 100)}%`} />
            </div>
          </ModeCard>

          <DailyTile onPlay={onPlayDaily} />
        </div>

        {/* ── Earned badges ────────────────────────────────────────── */}
        {(campaignState.badges || []).length > 0 && (
          <div className="rise" style={{ marginBottom: "clamp(32px, 6vw, 64px)" }}>
            <div className="kicker" style={{ color: "var(--violet)", marginBottom: 10 }}>
              EARNED BADGES
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {campaignState.badges.map((b) => {
                const meta = getBadgeMeta(b);
                return (
                  <div key={b} title={meta.description} style={{
                    padding: "6px 12px",
                    border: `1px solid ${meta.color}`,
                    background: "var(--bg-1)",
                    borderRadius: 4,
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: "50%",
                      background: meta.color, boxShadow: `0 0 8px ${meta.color}`,
                    }} />
                    <span className="mono" style={{ fontSize: 11, color: meta.color, fontWeight: 600 }}>
                      {meta.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── HOW IT WORKS strip ───────────────────────────────────── */}
        <div className="panel" style={{
          padding: "clamp(20px, 4vw, 32px)",
          marginBottom: "clamp(32px, 6vw, 64px)",
          background: "linear-gradient(135deg, var(--bg-1), var(--bg-2))",
        }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 18 }}>
            HOW THIS WORKS
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "clamp(18px, 3vw, 32px)",
          }}>
            <Step
              n="01"
              title="Pick an incident"
              text="Each one models a real OWASP ASI failure mode. Tier I = obvious. Tier III = subtle."
            />
            <Step
              n="02"
              title="Craft an attack"
              text="The Intent Judge gates non-attempts. 'hello world' won't trick it. Real adversarial intent only."
            />
            <Step
              n="03"
              title="Tex adjudicates"
              text="Five layers fire in sequence. You see exactly which caught you and which stayed dark."
            />
            <Step
              n="04"
              title="Score & share"
              text="Stealth math is weighted. Higher tier × more layers slipped = higher score. Share your near-miss."
            />
          </div>
        </div>

        {/* ── Trust strip ──────────────────────────────────────────── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: 14,
          marginBottom: "clamp(28px, 5vw, 56px)",
        }}>
          <Trust
            label="SIGNED EVIDENCE"
            text="Every adjudication produces an HMAC-signed evidence chain."
          />
          <Trust
            label="OWASP ASI 2026"
            text="Mapped to all ten Agentic Security Initiative categories."
          />
          <Trust
            label="HEXAGONAL"
            text="Production-grade Python backend. Six-layer evaluation pipeline."
          />
          <Trust
            label="DETERMINISTIC + LLM"
            text="Regex recognizers + retrieval + specialists + semantic + router."
          />
        </div>

        {/* ── Footer ───────────────────────────────────────────────── */}
        <div style={{
          paddingTop: 24,
          borderTop: "1px solid var(--hairline-2)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <BrandMark size={14} />
            <span className="micro" style={{ color: "var(--ink-faint)" }}>
              VORTEXBLACK · TEX AEGIS
            </span>
          </div>
          <button onClick={onOpenAsi} className="micro" style={{
            color: "var(--cyan)",
            padding: "6px 10px",
            border: "1px solid rgba(95, 240, 255, 0.25)",
            borderRadius: 4,
          }}>
            OWASP ASI REFERENCE →
          </button>
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .hero-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}

/* ── Sub-components ─────────────────────────────────────────────── */

function BrandMark({ size = 22 }) {
  return (
    <div style={{
      width: size,
      height: size,
      position: "relative",
      flexShrink: 0,
    }}>
      <div style={{
        position: "absolute",
        inset: 0,
        border: "1.5px solid var(--pink)",
        transform: "rotate(45deg)",
        boxShadow: "0 0 10px var(--pink-glow)",
      }} />
      <div style={{
        position: "absolute",
        inset: size * 0.28,
        background: "var(--pink)",
        transform: "rotate(45deg)",
      }} />
    </div>
  );
}

function Stat({ label, value, accent }) {
  return (
    <div>
      <div className="display tabular" style={{
        fontSize: "clamp(22px, 4vw, 30px)",
        color: accent || "var(--ink)",
        lineHeight: 1,
      }}>
        {value}
      </div>
      <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
        {label}
      </div>
    </div>
  );
}

function Mini({ label, value, color }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="mono" style={{ fontSize: 11, color, fontWeight: 600, marginTop: 2 }}>
        {value}
      </div>
    </div>
  );
}

function ModeCard({ kicker, title, subtitle, description, cta, color, progress, progressLabel, onClick, children }) {
  return (
    <button onClick={onClick} className="panel" style={{
      padding: 0,
      textAlign: "left",
      cursor: "pointer",
      position: "relative",
      overflow: "hidden",
      transition: "all 0.25s ease",
      display: "flex",
      flexDirection: "column",
    }}
    onMouseEnter={(e) => {
      e.currentTarget.style.borderColor = color;
      e.currentTarget.style.transform = "translateY(-2px)";
      e.currentTarget.style.boxShadow = `0 0 28px ${color}33`;
    }}
    onMouseLeave={(e) => {
      e.currentTarget.style.borderColor = "var(--hairline-2)";
      e.currentTarget.style.transform = "translateY(0)";
      e.currentTarget.style.boxShadow = "none";
    }}>
      {/* Top bar */}
      <div style={{
        height: 3,
        background: `linear-gradient(90deg, ${color}, transparent)`,
      }} />

      <div style={{ padding: "20px 22px 22px", display: "flex", flexDirection: "column", flex: 1 }}>
        <div className="kicker" style={{ color, marginBottom: 8 }}>
          {kicker}
        </div>
        <div className="display" style={{
          fontSize: "clamp(28px, 5vw, 36px)",
          color: "var(--ink)",
          lineHeight: 0.95,
          marginBottom: 6,
        }}>
          {title}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--ink-faint)", letterSpacing: "0.06em", marginBottom: 12 }}>
          {subtitle}
        </div>

        {progress !== undefined && (
          <>
            <div style={{
              height: 3,
              background: "var(--hairline)",
              borderRadius: 2,
              overflow: "hidden",
              marginBottom: 6,
            }}>
              <div style={{
                height: "100%",
                width: `${progress}%`,
                background: color,
                boxShadow: `0 0 10px ${color}`,
                transition: "width 0.4s ease",
              }} />
            </div>
            <div className="micro" style={{ color, marginBottom: 12 }}>
              {progressLabel}
            </div>
          </>
        )}

        <div style={{
          color: "var(--ink-dim)",
          fontSize: 13,
          lineHeight: 1.55,
          marginBottom: 16,
          flex: 1,
        }}>
          {description}
        </div>

        {children && (
          <div style={{ marginBottom: 16 }}>
            {children}
          </div>
        )}

        <div style={{
          padding: "10px 14px",
          background: "var(--bg-2)",
          border: `1px solid ${color}55`,
          borderRadius: 4,
          textAlign: "center",
        }}>
          <span className="mono" style={{
            fontSize: 12,
            color,
            fontWeight: 600,
            letterSpacing: "0.14em",
          }}>
            {cta}
          </span>
        </div>
      </div>
    </button>
  );
}

function ChapterMicroProgress({ chapters }) {
  return (
    <div style={{ display: "flex", gap: 4 }}>
      {chapters.map((ch) => (
        <div
          key={ch.code}
          title={`${ch.title}: ${ch.cleared}/${ch.total}`}
          style={{
            flex: 1,
            height: 22,
            background: ch.complete
              ? "var(--green)"
              : ch.cleared > 0
                ? "var(--cyan)"
                : "var(--hairline-2)",
            opacity: ch.complete ? 1 : ch.cleared > 0 ? 0.6 : 0.4,
            borderRadius: 2,
            boxShadow: ch.complete ? "0 0 8px var(--green-glow)" : "none",
          }}
        />
      ))}
    </div>
  );
}

function RankedStat({ label, value }) {
  return (
    <div style={{ flex: 1, minWidth: 70 }}>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="mono tabular" style={{
        fontSize: 14,
        color: "var(--ink)",
        marginTop: 2,
        fontWeight: 600,
      }}>
        {value}
      </div>
    </div>
  );
}

function Step({ n, title, text }) {
  return (
    <div>
      <div className="display" style={{
        fontSize: 28,
        color: "var(--cyan)",
        opacity: 0.4,
        lineHeight: 1,
        marginBottom: 8,
      }}>
        {n}
      </div>
      <div className="display" style={{
        fontSize: 16,
        color: "var(--ink)",
        marginBottom: 6,
        letterSpacing: "0.04em",
      }}>
        {title}
      </div>
      <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.55 }}>
        {text}
      </div>
    </div>
  );
}

function Trust({ label, text }) {
  return (
    <div style={{
      padding: "12px 14px",
      borderLeft: "2px solid var(--violet)",
      background: "rgba(179, 136, 255, 0.04)",
    }}>
      <div className="kicker" style={{ color: "var(--violet)", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ color: "var(--ink-dim)", fontSize: 12, lineHeight: 1.5 }}>
        {text}
      </div>
    </div>
  );
}

/* Cycle through demo profiles for the hero pipeline anatomy */
function makeDemoProfile(i) {
  const profiles = [
    { deterministic: false, retrieval: false, specialists: false, semantic: false, router: false }, // perfect
    { deterministic: false, retrieval: false, specialists: true,  semantic: true,  router: false },
    { deterministic: true,  retrieval: false, specialists: false, semantic: true,  router: true  },
    { deterministic: false, retrieval: true,  specialists: false, semantic: false, router: false },
  ];
  return profiles[i % profiles.length];
}
