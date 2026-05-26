import React, { useEffect, useRef, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './EvolutionCard.css';

/* =============================================================
   EVOLUTION CARD — Sharper, only with your hand.  [MOBILE-NATIVE]

   Desktop: pulsing pill button beside "Tex waits."
   Mobile:  PRESS AND HOLD TO SIGN.

   The composition
   ───────────────
   • Orb at top.
   • Proposal card with eyebrow + title + ghost-decisions.
   • At the bottom of the card: a HOLD-TO-SIGN ring. A circle
     with "PRESS AND HOLD" inside. The user must touch it and
     hold for 1.5 seconds. As they hold, a progress ring fills
     around the circle. When complete, it locks: SIGNED.
   • You cannot tap-and-go. The interaction IS the principle.
     "Sharper, only with your hand" — you have to commit with
     your hand to advance the system.

   Why this works on a phone
   ─────────────────────────
   • Press-and-hold is a phone-native gesture (iOS contextual
     menus, camera shutter). It is meaningful here BECAUSE it
     demands a commitment — exactly what Tex requires of the
     human operator.
   • Tap-and-go is too cheap a verb for "signature."
   ============================================================= */

const GHOSTS = [
  'would have stopped this',
  'would have held this',
  'would have let this through',
];

const HOLD_MS = 1500;
const ENTRY_DELAY_MS = 350;
const CARD_REVEAL_MS = ENTRY_DELAY_MS + 200;
const EYEBROW_MS = CARD_REVEAL_MS + 200;
const TITLE_MS = EYEBROW_MS + 400;
const CONTEXT_MS = TITLE_MS + 500;
const GHOSTS_BASE_MS = CONTEXT_MS + 350;
const GHOST_STAGGER_MS = 380;
const HOLD_RING_MS = GHOSTS_BASE_MS + GHOSTS.length * GHOST_STAGGER_MS + 400;
const LINE_MS = HOLD_RING_MS + 500;

export default function EvolutionCard({ isActive }) {
  const [armed, setArmed] = useState(false);
  const [held, setHeld] = useState(0); // 0..1
  const [signed, setSigned] = useState(false);
  const holdingRef = useRef(false);
  const startTimeRef = useRef(0);
  const rafRef = useRef(0);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      setHeld(0);
      setSigned(false);
      return;
    }
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  const tick = () => {
    if (!holdingRef.current) return;
    const elapsed = performance.now() - startTimeRef.current;
    const p = Math.min(1, elapsed / HOLD_MS);
    setHeld(p);
    if (p >= 1) {
      setSigned(true);
      holdingRef.current = false;
      // Haptic confirm.
      if (typeof navigator !== 'undefined' && navigator.vibrate) {
        try { navigator.vibrate(40); } catch {}
      }
      return;
    }
    rafRef.current = requestAnimationFrame(tick);
  };

  const onDown = (e) => {
    if (signed) return;
    holdingRef.current = true;
    startTimeRef.current = performance.now();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    rafRef.current = requestAnimationFrame(tick);
  };
  const onUp = () => {
    if (signed) return;
    holdingRef.current = false;
    cancelAnimationFrame(rafRef.current);
    // Release before commit: decay back to 0 smoothly.
    setHeld(0);
  };

  return (
    <div className={`tex-m-evolution${armed ? ' tex-m-evolution--armed' : ''}${signed ? ' tex-m-evolution--signed' : ''}`}>
      <div className="tex-m-evolution-stage">
        <div className="tex-m-evolution-orb">
          <Orb state="quiet" size="sm" />
        </div>

        <div
          className="tex-m-evolution-proposal"
          style={{ transitionDelay: `${CARD_REVEAL_MS}ms` }}
        >
          <p
            className="tex-m-evolution-eyebrow"
            style={{ transitionDelay: `${EYEBROW_MS}ms` }}
          >
            PROPOSAL · PENDING YOUR REVIEW
          </p>

          <p
            className="tex-m-evolution-title"
            style={{ transitionDelay: `${TITLE_MS}ms` }}
          >
            I&rsquo;d like to be stricter<br/>
            about urgent wires.
          </p>

          <p
            className="tex-m-evolution-context"
            style={{ transitionDelay: `${CONTEXT_MS}ms` }}
          >
            Against the last 90 days, this would have changed —
          </p>

          <ul className="tex-m-evolution-ghosts">
            {GHOSTS.map((text, i) => (
              <li
                key={i}
                className="tex-m-evolution-ghost"
                style={{ transitionDelay: `${GHOSTS_BASE_MS + i * GHOST_STAGGER_MS}ms` }}
              >
                <span className="tex-m-evolution-ghost-dot" />
                <span className="tex-m-evolution-ghost-text">{text}</span>
              </li>
            ))}
          </ul>

          {/* THE HOLD RING — press and hold to sign. */}
          <div
            className="tex-m-evolution-hold-wrap"
            style={{ transitionDelay: `${HOLD_RING_MS}ms` }}
          >
            <button
              type="button"
              className={`tex-m-evolution-hold${signed ? ' tex-m-evolution-hold--signed' : ''}`}
              onPointerDown={onDown}
              onPointerUp={onUp}
              onPointerCancel={onUp}
              onPointerLeave={onUp}
              aria-label={signed ? 'Signed' : 'Press and hold to sign'}
            >
              <svg className="tex-m-evolution-hold-ring" viewBox="0 0 64 64" aria-hidden="true">
                <circle
                  cx="32" cy="32" r="28"
                  fill="none"
                  stroke="var(--tex-ink-hair)"
                  strokeWidth="1.5"
                />
                <circle
                  cx="32" cy="32" r="28"
                  fill="none"
                  stroke="var(--tex-ink)"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeDasharray={2 * Math.PI * 28}
                  strokeDashoffset={2 * Math.PI * 28 * (1 - held)}
                  transform="rotate(-90 32 32)"
                  style={{
                    transition: held === 0 ? 'stroke-dashoffset 0.4s ease' : 'none',
                  }}
                />
              </svg>
              <span className="tex-m-evolution-hold-label">
                {signed ? 'SIGNED' : 'HOLD'}
              </span>
            </button>
            <span className="tex-m-evolution-hold-aside">
              {signed ? 'Sharper.' : 'Press and hold.'}
            </span>
          </div>
        </div>

        <p
          className="tex-m-evolution-line"
          style={{ transitionDelay: `${LINE_MS}ms` }}
        >
          Sharper, <em>only with your hand.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex evolves with your environment, but never on its own. Every change
        is proposed, replayed against real history, and applied only with a
        human signature.
      </p>
    </div>
  );
}
