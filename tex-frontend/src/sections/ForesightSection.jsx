import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './ForesightSection.css';

/* =============================================================
   FORESIGHT — I see what's coming.

   The Observability demonstration. Most competitors say "we
   watch over time" — every SIEM has said that since 2003. Tex
   makes a stronger claim: it doesn't just watch the present, it
   simulates forward.

   The screen: the orb at center-left, breathing. A horizontal
   hairline runs through its center to the right edge of the
   canvas — this is the timeline, the present moment riding it.
   A shadow copy of the orb peels off the original and runs
   ahead along the hairline, dotted. Around it, a soft cone
   opens — the conformal interval, widening with time. The
   original orb has not moved.

   The sentence resolves beneath the composition:

     "I see what's coming, not just what is."

   This is real code in src/tex/systemic/ — digital_twin,
   cascade_predictor, trajectory, _conformal. The screen
   finally shows it.
   ============================================================= */

const ENTRY_DELAY_MS = 350;
const TIMELINE_DRAW_MS = 1100;
const SHADOW_START_MS = ENTRY_DELAY_MS + TIMELINE_DRAW_MS + 200;
const CONE_OPEN_MS = SHADOW_START_MS + 200;
const LABELS_MS = SHADOW_START_MS + 800;
const LINE_REVEAL_MS = SHADOW_START_MS + 2200;

export default function ForesightSection() {
  const sectionRef = useRef(null);
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setArmed(true);
          io.disconnect();
        }
      },
      { threshold: 0.32 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-foresight${armed ? ' tex-foresight--armed' : ''}`}
      id="foresight"
      aria-label="Foresight — Tex simulates what's coming, not just what is"
    >
      <div className="tex-foresight-stage">
        {/* MOBILE COMPOSITION — the beam rotated 90°. On desktop the
            forecast travels left to right along a horizontal timeline.
            On a phone that gesture has nowhere to go; the cone collapses
            and the orb falls off the canvas. Here we draw the same idea
            top-down: NOW at the top with the orb, the conformal envelope
            opening as it descends, the CONFORMAL · 95% label anchored at
            the far end. */}
        <div className="tex-foresight-mobile" aria-hidden="true">
          <div className="tex-foresight-mobile-now">
            <Orb state="quiet" size="sm" />
            <span className="tex-foresight-mobile-now-label">NOW</span>
          </div>

          <svg
            className="tex-foresight-mobile-svg"
            viewBox="0 0 200 280"
            preserveAspectRatio="xMidYMin meet"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="tex-cone-fill-mobile" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.20" />
                <stop offset="60%" stopColor="#5B6E84" stopOpacity="0.07" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"    />
              </linearGradient>
              <linearGradient id="tex-cone-stroke-mobile" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.5" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"  />
              </linearGradient>
            </defs>

            {/* Center hairline timeline. */}
            <line
              className="tex-foresight-mobile-timeline"
              x1="100" y1="0"
              x2="100" y2="260"
              stroke="#d8d4cc"
              strokeWidth="1"
            />

            {/* Conformal cone — widens as it descends. */}
            <path
              className="tex-foresight-mobile-cone"
              d="M 100 0 L 30 260 L 170 260 Z"
              fill="url(#tex-cone-fill-mobile)"
              stroke="none"
            />
            <path
              className="tex-foresight-mobile-cone-bound"
              d="M 100 0 L 30 260"
              fill="none"
              stroke="url(#tex-cone-stroke-mobile)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
            />
            <path
              className="tex-foresight-mobile-cone-bound"
              d="M 100 0 L 170 260"
              fill="none"
              stroke="url(#tex-cone-stroke-mobile)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
            />

            {/* The shadow orb — travels down the timeline. */}
            <g className="tex-foresight-mobile-shadow">
              <circle cx="100" cy="0" r="5" fill="#5B6E84" fillOpacity="0.5" />
              <circle cx="100" cy="0" r="12" fill="#5B6E84" fillOpacity="0.16" />
            </g>
          </svg>

          <div className="tex-foresight-mobile-conformal">
            <span className="tex-foresight-mobile-conformal-rule" />
            <span className="tex-foresight-mobile-conformal-label">CONFORMAL · 95%</span>
          </div>
        </div>

        <div className="tex-foresight-composition">
          <svg
            className="tex-foresight-svg"
            viewBox="0 0 1000 360"
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            <defs>
              {/* Cone gradient — soft from start to far edge. */}
              <linearGradient id="tex-cone-fill" x1="0%" y1="50%" x2="100%" y2="50%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.18" />
                <stop offset="60%" stopColor="#5B6E84" stopOpacity="0.06" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"    />
              </linearGradient>

              <linearGradient id="tex-cone-stroke" x1="0%" y1="50%" x2="100%" y2="50%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.5" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"  />
              </linearGradient>
            </defs>

            {/* The timeline hairline — the present moment, extended forward. */}
            <line
              className="tex-foresight-timeline"
              x1="200" y1="180"
              x2="940" y2="180"
              stroke="#d8d4cc"
              strokeWidth="1"
              style={{
                strokeDasharray: 800,
                strokeDashoffset: armed ? 0 : 800,
                transitionDelay: `${ENTRY_DELAY_MS}ms`,
              }}
            />

            {/* Tick — the present moment marker. */}
            <line
              className="tex-foresight-now"
              x1="200" y1="168"
              x2="200" y2="192"
              stroke="#5e564c"
              strokeWidth="1"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${ENTRY_DELAY_MS}ms`,
              }}
            />

            {/* Conformal cone — the envelope of uncertainty Tex
                projects forward. Fades in once. The traveling
                shadow orb below it is what conveys forward motion
                in time; the cone is the silent envelope around it. */}
            <path
              className="tex-foresight-cone"
              d="M 200 180 L 940 100 L 940 260 Z"
              fill="url(#tex-cone-fill)"
              stroke="none"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${CONE_OPEN_MS}ms`,
              }}
            />

            {/* Cone upper and lower bounds — hairlines. */}
            <path
              className="tex-foresight-cone-bound"
              d="M 200 180 L 940 100"
              fill="none"
              stroke="url(#tex-cone-stroke)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${CONE_OPEN_MS}ms`,
              }}
            />
            <path
              className="tex-foresight-cone-bound"
              d="M 200 180 L 940 260"
              fill="none"
              stroke="url(#tex-cone-stroke)"
              strokeWidth="0.6"
              strokeDasharray="3 4"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${CONE_OPEN_MS}ms`,
              }}
            />
            {/* The shadow orb — runs along the hairline, dotted, leading
                into the future. Drawn as a small circle that translates. */}
            <g
              className="tex-foresight-shadow"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${SHADOW_START_MS}ms`,
              }}
            >
              <circle
                className="tex-foresight-shadow-dot"
                cx="200" cy="180"
                r="5"
                fill="#5B6E84"
                fillOpacity="0.5"
                style={{
                  animationDelay: `${SHADOW_START_MS}ms`,
                }}
              />
              <circle
                className="tex-foresight-shadow-halo"
                cx="200" cy="180"
                r="12"
                fill="#5B6E84"
                fillOpacity="0.16"
                style={{
                  animationDelay: `${SHADOW_START_MS}ms`,
                }}
              />
            </g>

            {/* Tiny labels — present, near, far. */}
            <text
              className="tex-foresight-tick-label tex-foresight-tick-now"
              x="200" y="216"
              textAnchor="middle"
              fontFamily="var(--tex-mono)"
              fontSize="10"
              letterSpacing="0.06em"
              fill="#9b9388"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${LABELS_MS}ms`,
              }}
            >
              NOW
            </text>
            <text
              className="tex-foresight-tick-label tex-foresight-tick-conformal"
              x="940" y="86"
              textAnchor="end"
              fontFamily="var(--tex-mono)"
              fontSize="10"
              letterSpacing="0.06em"
              fill="#9b9388"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${LABELS_MS + 200}ms`,
              }}
            >
              CONFORMAL · 95%
            </text>
          </svg>

          {/* The orb — DOM, breathes on its own. Anchored to the
              left side of the composition where the timeline begins. */}
          <div className="tex-foresight-orb">
            <Orb state="quiet" size="sm" />
          </div>
        </div>

        <p
          className="tex-foresight-line"
          style={{ transitionDelay: `${LINE_REVEAL_MS}ms` }}
        >
          I see what's coming, <em>not just what is.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex forks the live ecosystem state at the current moment, simulates forward,
        and reports the projected trajectory with conformal coverage guarantees —
        seeing what's coming, not just what is.
      </p>
    </section>
  );
}
