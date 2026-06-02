import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './ForesightCard.css';

/* =============================================================
   FORESIGHT CARD — I see what's coming.

   The desktop tells this beat as a horizontal beam: NOW on the
   left, the cone widening to the right, a shadow orb running
   forward along the timeline.

   A portrait phone has no horizontal room for that gesture. So
   on mobile, the same beam rotates 90°. NOW sits at the top of
   the card with the orb. A vertical plumb line drops from the
   orb to the bottom. As it descends, a soft cone widens around
   it — the conformal envelope, opening with time. A ghost orb
   peels off the original and travels down the plumb line: the
   simulation running forward. The original orb has not moved.

   At the base, a mono tag: CONFORMAL · 95%.

   Then the serif sentence resolves:

     "I see what's coming, not just what is."

   Why this works on a phone
   ─────────────────────────
   Time-as-down maps perfectly to thumb gesture. As your eye
   tracks the ghost orb falling, the cone widening is the rate
   of uncertainty growing — visceral, not metaphorical.
   ============================================================= */

const ENTRY_DELAY_MS = 350;
const TIMELINE_DRAW_MS = 1100;
const CONE_OPEN_MS = ENTRY_DELAY_MS + TIMELINE_DRAW_MS + 150;
const SHADOW_START_MS = CONE_OPEN_MS + 250;
const LABEL_MS = SHADOW_START_MS + 1800;
const LINE_REVEAL_MS = LABEL_MS + 500;

export default function ForesightCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-foresight-card${armed ? ' tex-foresight-card--armed' : ''}`}>
      <div className="tex-foresight-card-stage">
        <div className="tex-foresight-card-beam">
          {/* The NOW marker: orb + tiny label. Anchored to the
              top of the beam composition so the SVG below begins
              at the orb's bottom edge. */}
          <div className="tex-foresight-card-now">
            <Orb state="quiet" size="sm" />
            <span className="tex-foresight-card-now-label">NOW</span>
          </div>

          <svg
            className="tex-foresight-card-svg"
            viewBox="0 0 220 280"
            preserveAspectRatio="xMidYMin meet"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="tex-foresight-card-fill" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.22" />
                <stop offset="55%" stopColor="#5B6E84" stopOpacity="0.07" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"    />
              </linearGradient>
              <linearGradient id="tex-foresight-card-stroke" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.5" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"  />
              </linearGradient>
            </defs>

            {/* The plumb line — drops from the orb to the base.
                Draws first, then the cone opens, then the ghost
                orb travels. */}
            <line
              className="tex-foresight-card-timeline"
              x1="110" y1="0"
              x2="110" y2="260"
              stroke="#d8d4cc"
              strokeWidth="1"
            />

            {/* The conformal cone — widens as it descends. The
                lateral spread is 56 of 220 (~25% half-width).
                Two dashed boundary hairlines flank the soft fill. */}
            <path
              className="tex-foresight-card-cone"
              d="M 110 0 L 54 260 L 166 260 Z"
              fill="url(#tex-foresight-card-fill)"
              stroke="none"
            />
            <path
              className="tex-foresight-card-cone-bound"
              d="M 110 0 L 54 260"
              fill="none"
              stroke="url(#tex-foresight-card-stroke)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
            />
            <path
              className="tex-foresight-card-cone-bound"
              d="M 110 0 L 166 260"
              fill="none"
              stroke="url(#tex-foresight-card-stroke)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
            />

            {/* The ghost orb — drops down the plumb line, leaving
                no trail. Inner dot + soft halo. Runs once. */}
            <g className="tex-foresight-card-shadow">
              <circle cx="110" cy="0" r="12" fill="#5B6E84" fillOpacity="0.16" />
              <circle cx="110" cy="0" r="5"  fill="#5B6E84" fillOpacity="0.5"  />
            </g>
          </svg>

          {/* CONFORMAL · 95% — a small mono tag at the base. */}
          <div className="tex-foresight-card-conformal">
            <span className="tex-foresight-card-conformal-rule" />
            <span className="tex-foresight-card-conformal-label">CONFORMAL · 95%</span>
            <span className="tex-foresight-card-conformal-rule" />
          </div>
        </div>

        <p
          className="tex-foresight-card-line"
          style={{ transitionDelay: `${LINE_REVEAL_MS}ms` }}
        >
          I see what&rsquo;s coming, <em>not just what is.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex forks the live ecosystem state at the current moment, simulates
        forward, and reports the projected trajectory with conformal coverage
        guarantees — seeing what's coming, not just what is.
      </p>
    </div>
  );
}
