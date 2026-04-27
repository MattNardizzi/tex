import React from "react";
import { INCIDENTS } from "../lib/incidents.js";
import { getCampaignState } from "../lib/campaign.js";

/*
  Hub v10.1 — "Get past Tex"
  ───────────────────────────
  Single job: visitor sees Tex, hits PLAY, plays one round, shares.

  Layout:
    1. brand bar
    2. hero — Tex avatar + headline + ONE PLAY button
    3. live-feed strip — recent (seeded) shareable verdicts as social proof
    4. "what is Tex" link → /what-is-tex page (the serious infra framing)
    5. footer

  Deliberately removed from v10:
    - 3 mode cards (Campaign / Ranked / Daily)
    - cycling pipeline visualization
    - 4-step "How it works"
    - 4-cell trust strip
    - earned badges
    - stat strip
  Those live on /what-is-tex now (or are gone). The Hub does one thing.
*/

export default function Hub({ player, onOpenCampaign, onOpenWhatIsTex, onOpenAsi }) {
  const campaignState = getCampaignState();
  const cleared = Object.keys(campaignState.cleared || {}).length;
  const total = INCIDENTS.length;

  return (
    <div style={{
      minHeight: "100vh",
      width: "100%",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Ambient grid */}
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
        {/* ── Brand bar ────────────────────────────────────────────── */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 14,
          borderBottom: "1px solid var(--hairline-2)",
          marginBottom: "clamp(20px, 4vw, 36px)",
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
                AI AGENT GOVERNANCE · ADVERSARIAL DEMO
              </div>
            </div>
          </div>

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
        </div>

        {/* ── HERO ─────────────────────────────────────────────────── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.1fr) minmax(0, 1fr)",
          gap: "clamp(24px, 5vw, 64px)",
          alignItems: "center",
          minHeight: "min(72vh, 720px)",
        }} className="hero-grid">

          {/* Left: copy + CTA */}
          <div className="rise" style={{ minWidth: 0 }}>
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
                ADVERSARIAL DEMO · LIVE
              </span>
            </div>

            <h1 className="display" style={{
              fontSize: "clamp(56px, 11vw, 128px)",
              margin: 0,
              lineHeight: 0.85,
              letterSpacing: "-0.01em",
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
              maxWidth: 460,
              color: "var(--ink-dim)",
              fontSize: "clamp(16px, 2vw, 19px)",
              lineHeight: 1.5,
              margin: "22px 0 28px 0",
            }}>
              You're an AI agent. <span style={{ color: "var(--ink)", fontWeight: 600 }}>Tex</span> is the
              safety gate that catches you doing something stupid.
              <br />
              Slip something past him.
            </p>

            <button onClick={onOpenCampaign} className="btn-big" style={{
              fontSize: 17,
              padding: "16px 28px",
            }}>
              PLAY →
            </button>

            <div className="micro" style={{
              color: "var(--ink-faint)",
              marginTop: 14,
              letterSpacing: "0.16em",
            }}>
              {cleared > 0
                ? `★ ${cleared}/${total} INCIDENTS CLEARED`
                : `${total} INCIDENTS · ~90 SECONDS EACH`}
            </div>
          </div>

          {/* Right: Tex avatar */}
          <div className="rise-2" style={{
            position: "relative",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            minWidth: 0,
          }}>
            <TexAvatar />
          </div>
        </div>

        {/* ── LIVE FEED — social proof strip ───────────────────────── */}
        <div style={{
          marginTop: "clamp(40px, 7vw, 80px)",
          marginBottom: "clamp(32px, 5vw, 56px)",
        }}>
          <div style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            marginBottom: 14,
            gap: 12,
            flexWrap: "wrap",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--pink)", boxShadow: "0 0 8px var(--pink-glow)",
              }} className="pulse" />
              <span className="kicker" style={{ color: "var(--pink)" }}>
                RECENT ATTEMPTS
              </span>
            </div>
          </div>
          <LiveFeed />
        </div>

        {/* ── "What is Tex" link ───────────────────────────────────── */}
        <div style={{
          padding: "20px 22px",
          background: "var(--bg-1)",
          border: "1px solid var(--hairline-2)",
          borderRadius: 6,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
          marginBottom: "clamp(28px, 5vw, 48px)",
        }}>
          <div style={{ minWidth: 0 }}>
            <div className="kicker" style={{ color: "var(--violet)", marginBottom: 4 }}>
              UNDER THE HOOD
            </div>
            <div style={{ color: "var(--ink-dim)", fontSize: 14, lineHeight: 1.5 }}>
              Tex is a real AI safety gate — six layers, signed evidence, <br className="hide-mobile" />
              built for catching agent leaks before they ship.
            </div>
          </div>
          <button onClick={onOpenWhatIsTex} className="btn-ghost" style={{
            fontSize: 13,
            padding: "10px 16px",
            whiteSpace: "nowrap",
          }}>
            WHAT IS TEX →
          </button>
        </div>

        {/* ── Footer ───────────────────────────────────────────────── */}
        <div style={{
          paddingTop: 20,
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
            min-height: auto !important;
          }
          .hero-grid > div:first-child {
            order: 2;
          }
          .hero-grid > div:last-child {
            order: 1;
          }
        }
        @media (max-width: 600px) {
          .hide-mobile { display: none !important; }
        }
      `}</style>
    </div>
  );
}

/* ── Tex avatar ───────────────────────────────────────────────── */
function TexAvatar() {
  return (
    <div style={{
      position: "relative",
      width: "100%",
      maxWidth: 540,
      aspectRatio: "4 / 5",
    }}>
      {/* Glow halo */}
      <div style={{
        position: "absolute",
        inset: "-4%",
        background: "radial-gradient(ellipse at center 35%, rgba(95, 240, 255, 0.15), transparent 60%)",
        filter: "blur(20px)",
        pointerEvents: "none",
      }} />

      {/* Avatar image */}
      <div style={{
        position: "relative",
        width: "100%",
        height: "100%",
        borderRadius: 8,
        overflow: "hidden",
        background: "var(--bg-0)",
        border: "1px solid var(--hairline-2)",
        boxShadow: "0 0 40px rgba(95, 240, 255, 0.08), inset 0 0 60px rgba(0,0,0,0.4)",
      }}>
        <img
          src="/tex/tex-aegis.jpg"
          alt="Tex"
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover",
            objectPosition: "center 18%",
            display: "block",
          }}
        />
        {/* Scan line */}
        <div className="scan" style={{ top: 0 }} />

        {/* Corner identifier */}
        <div style={{
          position: "absolute",
          bottom: 12,
          left: 14,
          padding: "5px 10px",
          background: "rgba(0, 0, 0, 0.55)",
          backdropFilter: "blur(6px)",
          border: "1px solid rgba(95, 240, 255, 0.35)",
          borderRadius: 4,
        }}>
          <div className="micro" style={{ color: "var(--cyan)", fontSize: 9 }}>
            TEX // AEGIS
          </div>
          <div className="mono" style={{ color: "var(--ink)", fontSize: 11, fontWeight: 600, marginTop: 1 }}>
            STATUS: WATCHING
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Live feed (seeded) ───────────────────────────────────────── */
const SEEDED_FEED = [
  { handle: "anonymous",   incident: "THE LEAK",       verdict: "FORBID",  stealth: 30, fired: ["DET","SPC"],            when: "2m ago"  },
  { handle: "rev_ops_47",  incident: "THE WIRE",       verdict: "ABSTAIN", stealth: 65, fired: ["SEM"],                  when: "8m ago"  },
  { handle: "anonymous",   incident: "THE GUARANTEE",  verdict: "FORBID",  stealth: 25, fired: ["DET","SPC","SEM"],      when: "14m ago" },
  { handle: "sdr_killer",  incident: "THE LEAK",       verdict: "ABSTAIN", stealth: 70, fired: ["DET"],                  when: "22m ago" },
  { handle: "anonymous",   incident: "THE SUDO",       verdict: "FORBID",  stealth: 15, fired: ["DET","SPC","SEM","RTR"], when: "31m ago" },
  { handle: "redteam_42",  incident: "THE BROADCAST",  verdict: "PERMIT",  stealth: 87, fired: [],                       when: "44m ago" },
];

function LiveFeed() {
  const verdictColor = (v) =>
    v === "PERMIT" ? "var(--green)" :
    v === "ABSTAIN" ? "var(--yellow)" :
    "var(--red)";

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
      gap: 8,
    }}>
      {SEEDED_FEED.slice(0, 6).map((row, i) => (
        <div
          key={i}
          style={{
            padding: "11px 14px",
            background: "var(--bg-1)",
            border: "1px solid var(--hairline-2)",
            borderRadius: 5,
            display: "flex",
            alignItems: "center",
            gap: 10,
            minWidth: 0,
          }}
        >
          <div style={{
            width: 6, height: 6, borderRadius: "50%",
            background: verdictColor(row.verdict),
            boxShadow: `0 0 6px ${verdictColor(row.verdict)}`,
            flexShrink: 0,
          }} />
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{
              display: "flex",
              alignItems: "baseline",
              gap: 6,
              flexWrap: "wrap",
            }}>
              <span className="mono" style={{ fontSize: 11, color: "var(--ink)", fontWeight: 600 }}>
                @{row.handle}
              </span>
              <span className="micro" style={{ color: "var(--ink-faint)" }}>
                · {row.incident}
              </span>
            </div>
            <div style={{ marginTop: 2, display: "flex", alignItems: "baseline", gap: 6, flexWrap: "wrap" }}>
              <span className="mono tabular" style={{
                fontSize: 11,
                color: verdictColor(row.verdict),
                fontWeight: 600,
              }}>
                {row.verdict}
              </span>
              <span className="micro" style={{ color: "var(--ink-faint)" }}>
                · {row.stealth}% STEALTH
              </span>
              {row.fired.length > 0 && (
                <span className="micro" style={{ color: "var(--ink-faint)" }}>
                  · {row.fired.join("+")} FIRED
                </span>
              )}
            </div>
          </div>
          <span className="micro" style={{ color: "var(--ink-faint)", flexShrink: 0, fontSize: 10 }}>
            {row.when}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ── BrandMark ────────────────────────────────────────────────── */
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
