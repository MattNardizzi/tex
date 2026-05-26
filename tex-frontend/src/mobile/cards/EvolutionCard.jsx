import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './EvolutionCard.css';

/* =============================================================
   EVOLUTION CARD — Sharper, only with your hand.

   The hardest section to get right and the most important to
   the buyer. Every competitor that says "we get smarter" means
   we ship silent updates. Tex does not. Tex proposes, shows
   exactly what would have changed against real history, and
   waits for a human signature. There is no auto-apply codepath
   anywhere in src/tex/learning/ — a regression test enforces it.

   The composition on a phone
   ───────────────────────────
   The orb at the top, breathing. Beneath it, a proposal card
   that fills the phone's width (minus 20px gutter):

     EYEBROW       PROPOSAL · PENDING YOUR REVIEW
     TITLE         I'd like to be stricter about urgent wires.
     CONTEXT       Against the last 90 days, this would have
                   changed —
     GHOSTS        • would have stopped this
                   • would have held this
                   • would have let this through
     ACTIONS       [ Your signature. ]   Tex waits.

   The button pulses faintly. It does not auto-press. Tex
   waits. Below the card, the serif line:

     "Sharper, only with your hand."
   ============================================================= */

const GHOSTS = [
  'would have stopped this',
  'would have held this',
  'would have let this through',
];

const ENTRY_DELAY_MS = 350;
const CARD_REVEAL_MS = ENTRY_DELAY_MS + 200;
const EYEBROW_MS = CARD_REVEAL_MS + 200;
const TITLE_MS = EYEBROW_MS + 400;
const CONTEXT_MS = TITLE_MS + 500;
const GHOSTS_BASE_MS = CONTEXT_MS + 350;
const GHOST_STAGGER_MS = 380;
const BUTTON_MS = GHOSTS_BASE_MS + GHOSTS.length * GHOST_STAGGER_MS + 500;
const LINE_MS = BUTTON_MS + 600;

export default function EvolutionCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-evolution-m${armed ? ' tex-evolution-m--armed' : ''}`}>
      <div className="tex-evolution-m-stage">
        <div className="tex-evolution-m-orb">
          <Orb state="quiet" size="sm" />
        </div>

        <div
          className="tex-evolution-m-proposal"
          style={{ transitionDelay: `${CARD_REVEAL_MS}ms` }}
        >
          <p
            className="tex-evolution-m-eyebrow"
            style={{ transitionDelay: `${EYEBROW_MS}ms` }}
          >
            PROPOSAL · PENDING YOUR REVIEW
          </p>

          <p
            className="tex-evolution-m-title"
            style={{ transitionDelay: `${TITLE_MS}ms` }}
          >
            I&rsquo;d like to be stricter<br/>
            about urgent wires.
          </p>

          <p
            className="tex-evolution-m-context"
            style={{ transitionDelay: `${CONTEXT_MS}ms` }}
          >
            Against the last 90 days, this would have changed —
          </p>

          <ul className="tex-evolution-m-ghosts">
            {GHOSTS.map((text, i) => (
              <li
                key={i}
                className="tex-evolution-m-ghost"
                style={{ transitionDelay: `${GHOSTS_BASE_MS + i * GHOST_STAGGER_MS}ms` }}
              >
                <span className="tex-evolution-m-ghost-dot" aria-hidden="true" />
                <span className="tex-evolution-m-ghost-text">{text}</span>
              </li>
            ))}
          </ul>

          <div
            className="tex-evolution-m-actions"
            style={{ transitionDelay: `${BUTTON_MS}ms` }}
          >
            <button
              type="button"
              className="tex-evolution-m-btn"
              tabIndex={-1}
            >
              <span className="tex-evolution-m-btn-label">Your signature.</span>
              <span className="tex-evolution-m-btn-halo" aria-hidden="true" />
            </button>
            <span className="tex-evolution-m-actions-aside">Tex waits.</span>
          </div>
        </div>

        <p
          className="tex-evolution-m-line"
          style={{ transitionDelay: `${LINE_MS}ms` }}
        >
          Sharper, <em>only with your hand.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex evolves with your environment, but never on its own. Every change
        is proposed, replayed against real history, and applied only with a
        human signature. Sharper, only with your hand.
      </p>
    </div>
  );
}
