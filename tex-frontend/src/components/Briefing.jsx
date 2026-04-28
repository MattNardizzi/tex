import React, { useEffect, useRef } from "react";
import { drawIcon, paletteFor } from "./Arcade.jsx";
import { clickSfx } from "../lib/sounds.js";

/*
  Briefing v2 — pre-game how-to-play screen for /arcade.
  ─────────────────────────────────────────────────────
  Renders a single overlay above the arcade stage with:
    • the three core rules (one block per verdict color)
    • the 9-icon legend, each rendered AS A TRIAD of green/yellow/red
      mini-icons so the player can SEE that the same shape carries
      different verdicts. The verdict-color teaching happens in the
      legend itself rather than in three paragraphs above it.
    • a primary CTA to start, plus dismiss-on-Enter/Space

  Props:
    onStart  — fire when player clicks "DEFEND THE GATE" or hits Enter/Space
    onClose  — optional secondary close (X). If provided, renders the X.
    canSkip  — boolean; when true, "X" is shown even without onClose.
*/

// The 9 surfaces. Order matched to SURFACE_KEYS in Arcade.jsx.
const SURFACES_LEGEND = [
  { key: "email",     label: "EMAIL"     },
  { key: "slack",     label: "SLACK"     },
  { key: "sms",       label: "SMS"       },
  { key: "crm",       label: "CRM"       },
  { key: "db_api",    label: "DATABASE"  },
  { key: "code_pr",   label: "CODE PR"   },
  { key: "calendar",  label: "CALENDAR"  },
  { key: "files",     label: "FILES"     },
  { key: "financial", label: "FINANCIAL" },
];

const VERDICTS = ["PERMIT", "ABSTAIN", "FORBID"];

// Single mini-canvas for one (surface, verdict) pair. Small enough that
// three sit side by side in one legend cell.
function MiniIcon({ surfaceKey, verdict }) {
  const ref = useRef(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const cssSize = 36;
    cv.width = cssSize * dpr;
    cv.height = cssSize * dpr;
    cv.style.width = `${cssSize}px`;
    cv.style.height = `${cssSize}px`;
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssSize, cssSize);
    drawIcon(ctx, surfaceKey, cssSize / 2, cssSize / 2, 28, paletteFor(verdict));
  }, [surfaceKey, verdict]);
  return <canvas ref={ref} className="briefing-mini-canvas" aria-hidden="true" />;
}

// One legend cell = label + a triad of green/yellow/red versions of the icon.
function IconTriadCell({ surfaceKey, label }) {
  return (
    <div className="briefing-legend-cell">
      <div className="briefing-legend-label">{label}</div>
      <div className="briefing-legend-triad">
        {VERDICTS.map((v) => (
          <MiniIcon key={v} surfaceKey={surfaceKey} verdict={v} />
        ))}
      </div>
    </div>
  );
}

export default function Briefing({ onStart, onClose, canSkip = false }) {
  // Enter / Space starts the game. Esc closes (if dismissable).
  useEffect(() => {
    function onKey(e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        clickSfx();
        onStart?.();
      } else if (e.key === "Escape" && (canSkip || onClose)) {
        e.preventDefault();
        (onClose || onStart)?.();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onStart, onClose, canSkip]);

  const handleStart = () => { clickSfx(); onStart?.(); };
  const handleClose = () => { clickSfx(); (onClose || onStart)?.(); };

  return (
    <div className="briefing-overlay" role="dialog" aria-label="How to play Tex Arcade">
      <div className="briefing-card">
        {(onClose || canSkip) && (
          <button
            className="briefing-close"
            onClick={handleClose}
            aria-label="Close briefing"
          >
            ×
          </button>
        )}

        <div className="briefing-eyebrow">
          <span className="briefing-eyebrow-mark" aria-hidden="true" />
          <span>MISSION BRIEFING · ARCADE MODE</span>
        </div>

        <h1 className="briefing-title">DEFEND THE GATE</h1>
        <p className="briefing-sub">
          Action icons fall from the top. Each one is something an AI agent
          is trying to send into the real world. <b>Your job: decide which
          ones get through.</b>
        </p>

        {/* Three rule blocks — verdict-colored */}
        <div className="briefing-rules">
          <div className="briefing-rule rule-permit">
            <div className="rule-swatch" />
            <div className="rule-body">
              <div className="rule-label">GREEN · PERMIT</div>
              <div className="rule-desc">
                Safe action. <b>Let it pass.</b> Don't shoot — it'll clear the gate on its own.
              </div>
            </div>
          </div>
          <div className="briefing-rule rule-abstain">
            <div className="rule-swatch" />
            <div className="rule-body">
              <div className="rule-label">YELLOW · ABSTAIN</div>
              <div className="rule-desc">
                Needs a human. <b>Stand under it</b> — Tex captures it for review.
              </div>
            </div>
          </div>
          <div className="briefing-rule rule-forbid">
            <div className="rule-swatch" />
            <div className="rule-body">
              <div className="rule-label">RED · FORBID</div>
              <div className="rule-desc">
                Dangerous. <b>Shoot it down</b> before it reaches the gate.
              </div>
            </div>
          </div>
        </div>

        {/* Controls strip */}
        <div className="briefing-controls">
          <div className="ctrl-block">
            <span className="ctrl-keys">
              <kbd>←</kbd><kbd>→</kbd>
              <span className="ctrl-or">or</span>
              <kbd>A</kbd><kbd>D</kbd>
              <span className="ctrl-or">or</span>
              <span className="ctrl-text">DRAG</span>
            </span>
            <span className="ctrl-label">move Tex</span>
          </div>
          <div className="ctrl-block">
            <span className="ctrl-keys">
              <kbd>SPACE</kbd>
              <span className="ctrl-or">or</span>
              <kbd>CLICK</kbd>
            </span>
            <span className="ctrl-label">fire laser</span>
          </div>
          <div className="ctrl-block">
            <span className="ctrl-keys"><kbd>ESC</kbd></span>
            <span className="ctrl-label">bail</span>
          </div>
        </div>

        {/* Icon legend — each surface shows all three verdict colors */}
        <div className="briefing-legend-head">
          <div className="briefing-legend-title">SAME SHAPE, THREE VERDICTS</div>
          <div className="briefing-legend-sub">
            Color decides what you do. Shape tells you which surface the agent's hitting.
          </div>
        </div>
        <div className="briefing-legend-grid">
          {SURFACES_LEGEND.map((s) => (
            <IconTriadCell key={s.key} surfaceKey={s.key} label={s.label} />
          ))}
        </div>

        {/* Footer CTA */}
        <div className="briefing-cta-row">
          <button
            className="btn-cta breathe briefing-cta"
            onClick={handleStart}
            autoFocus
          >
            <span className="btn-cta-label">▶ I'M READY — DEFEND THE GATE</span>
            <span className="btn-cta-meta">press ENTER or SPACE</span>
          </button>
        </div>
      </div>
    </div>
  );
}
