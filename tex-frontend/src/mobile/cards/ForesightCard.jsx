import React, { useEffect, useRef, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './ForesightCard.css';

/* =============================================================
   FORESIGHT CARD — I see what's coming.   [MOBILE-NATIVE]

   Desktop: horizontal timeline, shadow orb runs left-to-right.
   Mobile:  the user DRAGS the orb DOWN with their thumb,
            pulling a ghost orb forward in time.

   The composition
   ───────────────
   • The orb at top with "NOW" label.
   • A subtle prompt: "PULL TO SEE." in mono.
   • As the user drags down with their finger, a ghost orb
     peels off the original and falls toward the bottom of
     the card. A conformal cone widens from the original orb
     around the ghost's path. The cone widens with distance —
     uncertainty grows the further you pull.
   • Release: everything snaps back. The user can pull again.
   • At the bottom, CONFORMAL · 95% as the proof of method.

   If the user doesn't interact within 2 seconds of the card
   becoming active, the auto-demo plays the gesture for them.

   Why this works on a phone
   ─────────────────────────
   Touch-drag IS the simulation. The user pulls the future
   out of the device with their hand. A mouse can't do this.
   ============================================================= */

const MAX_PULL = 240;   // px the ghost can travel
const AUTO_DELAY = 2000;

export default function ForesightCard({ isActive }) {
  const [armed, setArmed] = useState(false);
  const [pull, setPull] = useState(0);
  const [interacted, setInteracted] = useState(false);
  const [autoPlaying, setAutoPlaying] = useState(false);
  const startYRef = useRef(null);
  const draggingRef = useRef(false);
  const autoTimerRef = useRef(null);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      setPull(0);
      setInteracted(false);
      setAutoPlaying(false);
      if (autoTimerRef.current) clearTimeout(autoTimerRef.current);
      return;
    }
    const t = setTimeout(() => setArmed(true), 80);

    // Auto-demo if the user does not interact.
    autoTimerRef.current = setTimeout(() => {
      if (!interacted) {
        setAutoPlaying(true);
      }
    }, AUTO_DELAY);

    return () => {
      clearTimeout(t);
      if (autoTimerRef.current) clearTimeout(autoTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive]);

  // Pointer-driven pull. We use pointer events for unified
  // mouse + touch handling. Pulling DOWN (positive deltaY)
  // moves the ghost forward in time.
  const onPointerDown = (e) => {
    setInteracted(true);
    setAutoPlaying(false);
    draggingRef.current = true;
    startYRef.current = e.clientY;
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e) => {
    if (!draggingRef.current) return;
    const delta = Math.max(0, Math.min(MAX_PULL, e.clientY - startYRef.current));
    setPull(delta);
  };
  const onPointerUp = () => {
    draggingRef.current = false;
    // Release: snap back.
    setPull(0);
  };

  // Auto-play sweep: simulate a pull then release.
  useEffect(() => {
    if (!autoPlaying) return;
    let raf;
    const start = performance.now();
    const animate = (now) => {
      const t = (now - start) / 1000;
      // 0–1.4s pull down to ~200px; 1.4–2.4s release back.
      let v = 0;
      if (t < 1.4) v = (t / 1.4) * 200;
      else if (t < 2.4) v = 200 * (1 - (t - 1.4) / 1.0);
      else v = 0;
      setPull(v);
      if (t < 2.6 && autoPlaying) raf = requestAnimationFrame(animate);
      else setAutoPlaying(false);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [autoPlaying]);

  // The ghost's vertical offset and the cone's growth are
  // linked to `pull`. Cone width grows from 0 to ~75% as the
  // user pulls.
  const conePct = Math.min(1, pull / MAX_PULL);

  return (
    <div className={`tex-m-foresight${armed ? ' tex-m-foresight--armed' : ''}`}>
      <div className="tex-m-foresight-stage">
        <div className="tex-m-foresight-now">
          <Orb state="quiet" size="sm" />
          <span className="tex-m-foresight-now-label">NOW</span>
        </div>

        {/* THE PULL FIELD — captures pointer gestures.
            Inside it, the cone and ghost render. */}
        <div
          className="tex-m-foresight-field"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
        >
          <svg
            className="tex-m-foresight-svg"
            viewBox="0 0 240 280"
            preserveAspectRatio="xMidYMin meet"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="tex-m-fs-fill" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%"  stopColor="#5B6E84" stopOpacity="0.28" />
                <stop offset="60%" stopColor="#5B6E84" stopOpacity="0.08" />
                <stop offset="100%" stopColor="#5B6E84" stopOpacity="0"    />
              </linearGradient>
            </defs>

            {/* The plumb hairline — the line of time. */}
            <line
              x1="120" y1="0"
              x2="120" y2="260"
              stroke="#d8d4cc"
              strokeWidth="1"
              strokeDasharray="2 4"
            />

            {/* The conformal cone — its width is conePct-driven.
                Two diagonal lines from (120, 0) to (120 ± width, 260). */}
            <path
              d={`M 120 0 L ${120 - 86 * conePct} 260 L ${120 + 86 * conePct} 260 Z`}
              fill="url(#tex-m-fs-fill)"
              stroke="none"
              style={{ transition: pull === 0 ? 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)' : 'none' }}
            />
            <line
              x1="120" y1="0"
              x2={120 - 86 * conePct} y2="260"
              stroke="#5B6E84"
              strokeOpacity={0.4 * conePct + 0.1}
              strokeWidth="0.6"
              strokeDasharray="3 4"
              style={{ transition: pull === 0 ? 'all 0.4s ease' : 'none' }}
            />
            <line
              x1="120" y1="0"
              x2={120 + 86 * conePct} y2="260"
              stroke="#5B6E84"
              strokeOpacity={0.4 * conePct + 0.1}
              strokeWidth="0.6"
              strokeDasharray="3 4"
              style={{ transition: pull === 0 ? 'all 0.4s ease' : 'none' }}
            />

            {/* The ghost orb — falls with the pull. */}
            <g
              transform={`translate(120, ${Math.min(pull, 240)})`}
              style={{ transition: pull === 0 ? 'transform 0.4s cubic-bezier(0.4, 0, 0.2, 1)' : 'none' }}
            >
              <circle r="14" fill="#5B6E84" fillOpacity={0.14 + conePct * 0.12} />
              <circle r="6"  fill="#5B6E84" fillOpacity={0.5 + conePct * 0.2} />
            </g>
          </svg>

          {/* The prompt label sits beneath the cone, only
              before the user has interacted. */}
          <span
            className={`tex-m-foresight-prompt${interacted ? ' tex-m-foresight-prompt--hide' : ''}`}
          >
            <span className="tex-m-foresight-prompt-arrow">↓</span> PULL TO SEE
          </span>
        </div>

        <div className="tex-m-foresight-conformal">
          <span className="tex-m-foresight-conformal-rule" />
          <span className="tex-m-foresight-conformal-label">CONFORMAL · 95%</span>
          <span className="tex-m-foresight-conformal-rule" />
        </div>

        <p className="tex-m-foresight-line">
          I see what&rsquo;s coming, <em>not just what is.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex forks the live ecosystem state at the current moment, simulates
        forward, and reports the projected trajectory with conformal coverage
        guarantees.
      </p>
    </div>
  );
}
