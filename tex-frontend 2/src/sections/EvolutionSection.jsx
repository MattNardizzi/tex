import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './EvolutionSection.css';

/* =============================================================
   EVOLUTION — Sharper, only with your hand.

   The hardest section on the page and the most important to
   get right. Every competitor that says "we get smarter" means
   we ship silent updates. Tex does not. Tex proposes, shows
   exactly what would have changed against real history, and
   waits for a human signature. There is no auto-apply codepath
   anywhere in src/tex/learning/ — a regression test enforces it.

   The screen: the orb at left, breathing. A small proposal
   card resolves to its right — a single sentence that names
   the change, followed by three ghost-decisions ("would have
   stopped this," "would have held this," "would have let this
   through") in plain English. Beneath the card, a single
   pulsing button labeled "Your signature." The button does
   not auto-press. Tex waits.

   One serif italic line resolves last:

     "Sharper, only with your hand."
   ============================================================= */

const ENTRY_DELAY_MS = 350;
const CARD_REVEAL_MS = ENTRY_DELAY_MS + 400;
const PROPOSAL_TITLE_MS = CARD_REVEAL_MS + 400;
const GHOSTS_BASE_MS = PROPOSAL_TITLE_MS + 600;
const GHOST_STAGGER_MS = 420;
const BUTTON_REVEAL_MS = GHOSTS_BASE_MS + 3 * GHOST_STAGGER_MS + 600;
const LINE_REVEAL_MS = BUTTON_REVEAL_MS + 800;

const GHOSTS = [
  { from: 'PERMIT',  to: 'FORBID',  text: 'would have stopped this' },
  { from: 'PERMIT',  to: 'ABSTAIN', text: 'would have held this' },
  { from: 'ABSTAIN', to: 'PERMIT',  text: 'would have let this through' },
];

export default function EvolutionSection() {
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
      { threshold: 0.28 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-evolution${armed ? ' tex-evolution--armed' : ''}`}
      id="evolution"
      aria-label="Evolution — Tex proposes, you approve. Sharper only with your hand."
    >
      <div className="tex-evolution-stage">
        <div className="tex-evolution-composition">
          {/* The orb — left side, breathing. */}
          <div className="tex-evolution-orb">
            <Orb state="quiet" size="md" />
          </div>

          {/* The proposal card. */}
          <div
            className="tex-evolution-card"
            style={{ transitionDelay: `${CARD_REVEAL_MS}ms` }}
          >
            <p
              className="tex-evolution-card-eyebrow"
              style={{ transitionDelay: `${CARD_REVEAL_MS + 200}ms` }}
            >
              PROPOSAL · PENDING YOUR REVIEW
            </p>

            <p
              className="tex-evolution-card-title"
              style={{ transitionDelay: `${PROPOSAL_TITLE_MS}ms` }}
            >
              I&rsquo;d like to be stricter
              <br/>
              about urgent wires.
            </p>

            <p
              className="tex-evolution-card-history-label"
              style={{ transitionDelay: `${PROPOSAL_TITLE_MS + 400}ms` }}
            >
              Against the last 90 days, this would have changed —
            </p>

            <ul className="tex-evolution-ghosts" aria-label="What would have changed">
              {GHOSTS.map((g, i) => {
                const delay = GHOSTS_BASE_MS + i * GHOST_STAGGER_MS;
                return (
                  <li
                    key={`ghost-${i}`}
                    className="tex-evolution-ghost"
                    style={{ transitionDelay: `${delay}ms` }}
                  >
                    <span className="tex-evolution-ghost-dot" aria-hidden="true" />
                    <span className="tex-evolution-ghost-text">{g.text}</span>
                  </li>
                );
              })}
            </ul>

            <div
              className="tex-evolution-actions"
              style={{ transitionDelay: `${BUTTON_REVEAL_MS}ms` }}
            >
              <button
                type="button"
                className="tex-evolution-btn"
                tabIndex={-1}
              >
                <span className="tex-evolution-btn-label">Your signature.</span>
                <span className="tex-evolution-btn-halo" aria-hidden="true" />
              </button>
              <span className="tex-evolution-actions-aside">
                Tex waits.
              </span>
            </div>
          </div>
        </div>

        <p
          className="tex-evolution-line"
          style={{ transitionDelay: `${LINE_REVEAL_MS}ms` }}
        >
          Sharper, <em>only with your hand.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex evolves with your environment, but never on its own. Every change
        is proposed, replayed against real history, and applied only with a
        human signature. Sharper, only with your hand.
      </p>
    </section>
  );
}
