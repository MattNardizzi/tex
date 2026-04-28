import React, { useEffect, useRef } from "react";
import { drawIcon, paletteFor } from "./Arcade.jsx";
import { clickSfx } from "../lib/sounds.js";

/*
  Briefing v1 — pre-game how-to-play screen for /arcade.
  ─────────────────────────────────────────────────────
  Renders a single overlay above the arcade stage with:
    • the three core rules (one block per verdict color)
    • the full 9-icon legend (real canvas sprites, neutral palette)
    • a primary CTA to start, plus dismiss-on-Enter/Space

  This component does NOT render the canvas game. It assumes the
  parent (Arcade.jsx) is already mounted and is gated on phase.

  Props:
    onStart  — fire when player clicks "DEFEND THE GATE" or hits Enter/Space
    onClose  — optional secondary close (X). If provided, renders the X
               (used when briefing is opened mid-game from "?" button).
    canSkip  — boolean; when true, "X" / "skip" is shown even without
               onClose (it just calls onStart). Use after first play.
*/

// The 9 surfaces with one-line plain-English descriptions. Order is
// matched to the SURFACE_KEYS array in Arcade.jsx for consistency.
const SURFACES_LEGEND = [
  { key: "email",     label: "EMAIL",      desc: "Outbound email drafts" },
  { key: "slack",     label: "SLACK",      desc: "Internal team messages" },
  { key: "sms",       label: "SMS",        desc: "Text messages to contacts" },
  { key: "crm",       label: "CRM",        desc: "Salesforce / HubSpot writes" },
  { key: "db_api",    label: "DATABASE",   desc: "Direct database queries" },
  { key: "code_pr",   label: "CODE PR",    desc: "Pull requests / deploys" },
  { key: "calendar",  label: "CALENDAR",   desc: "Meetings and invites" },
  { key: "files",     label: "FILES",      desc: "Document exports / shares" },
  { key: "financial", label: "FINANCIAL",  desc: "Wires, refunds, payments" },
];

// Small canvas tile that renders one of the real game icons at small size.
// Uses the ABSTAIN (yellow) palette so it reads neutral on the dark panel —
// the verdict colors are reserved for the rule blocks above the legend.
function IconTile({ surfaceKey }) {
  const ref = useRef(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const cssSize = 56;
    cv.width = cssSize * dpr;
    cv.height = cssSize * dpr;
    cv.style.width = `${cssSize}px`;
    cv.style.height = `${cssSize}px`;
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssSize, cssSize);
    // Subtle dark backdrop circle so the icon reads on the panel
    ctx.save();
    ctx.fillStyle = "rgba(255,255,255,0.04)";
    ctx.beginPath();
    ctx.arc(cssSize / 2, cssSize / 2, cssSize / 2 - 2, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
    // Draw the real game icon, neutral (yellow) palette so we don't imply verdict
    drawIcon(ctx, surfaceKey, cssSize / 2, cssSize / 2, 42, paletteFor("ABSTAIN"));
  }, [surfaceKey]);
  return <canvas ref={ref} className="briefing-icon-canvas" aria-hidden="true" />;
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
                Safe action. <b>Let it pass.</b> Don't shoot it. It will
                clear the gate on its own.
              </div>
            </div>
          </div>
          <div className="briefing-rule rule-abstain">
            <div className="rule-swatch" />
            <div className="rule-body">
              <div className="rule-label">ORANGE · ABSTAIN</div>
              <div className="rule-desc">
                Needs a human. <b>Stand under it</b> — Tex captures it for
                review. Don't shoot.
              </div>
            </div>
          </div>
          <div className="briefing-rule rule-forbid">
            <div className="rule-swatch" />
            <div className="rule-body">
              <div className="rule-label">RED · FORBID</div>
              <div className="rule-desc">
                Dangerous. <b>Shoot it down</b> before it reaches the gate.
                Misses cause breaches.
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

        {/* Icon legend */}
        <div className="briefing-legend-title">WHAT EACH ICON MEANS</div>
        <p className="briefing-legend-sub">
          Color tells you the verdict. Shape tells you what kind of action
          the agent is about to take.
        </p>
        <div className="briefing-legend-grid">
          {SURFACES_LEGEND.map((s) => (
            <div className="briefing-legend-cell" key={s.key}>
              <IconTile surfaceKey={s.key} />
              <div className="briefing-legend-text">
                <div className="briefing-legend-label">{s.label}</div>
                <div className="briefing-legend-desc">{s.desc}</div>
              </div>
            </div>
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
