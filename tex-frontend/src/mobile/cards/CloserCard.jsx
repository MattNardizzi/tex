import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './CloserCard.css';

/* =============================================================
   CLOSER CARD — The weight is mine now.   [MOBILE-NATIVE]

   Desktop: orb at center, line below, soft footer drifts in.
   Mobile:  the page exhales.

   The composition
   ───────────────
   • The orb takes the FULL SCREEN — much larger than on any
     other card, breathing slowly, the protagonist alone at
     the end of its journey.
   • One line, in serif italic, appears word-by-word:
     "The weight" → "is mine" → "now."
   • A long beat. Then everything fades to soft paper EXCEPT
     the orb — which continues breathing. No footer. The page
     does not end. Tex is still on watch.

   Why this works on a phone
   ─────────────────────────
   • A phone in hand is a small object — when the orb takes
     the full screen, it dominates your field of view. The
     scale of the breath becomes the scale of your attention.
   • Word-by-word reveal works better on a phone than desktop
     because the reader can't pre-scan.
   • Ending on a breathing orb (no footer, no CTA) is a
     mobile-app move, not a marketing-site move. The product
     is the last thing you see.
   ============================================================= */

const ENTRY_DELAY = 400;
const WORD_INTERVAL = 700;
const WORDS = ['The weight', 'is mine', 'now.'];
const LAST_WORD_MS = ENTRY_DELAY + WORDS.length * WORD_INTERVAL;
const SOLITUDE_MS = LAST_WORD_MS + 2400;

export default function CloserCard({ isActive }) {
  const [armed, setArmed] = useState(false);
  const [wordIndex, setWordIndex] = useState(-1);
  const [solitude, setSolitude] = useState(false);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      setWordIndex(-1);
      setSolitude(false);
      return;
    }
    const arm = setTimeout(() => setArmed(true), 80);

    // Reveal words one at a time.
    const wordTimers = WORDS.map((_, i) =>
      setTimeout(() => setWordIndex(i), ENTRY_DELAY + i * WORD_INTERVAL)
    );

    // After the line has held, fade everything except the orb.
    const solitudeTimer = setTimeout(() => setSolitude(true), SOLITUDE_MS);

    return () => {
      clearTimeout(arm);
      wordTimers.forEach(clearTimeout);
      clearTimeout(solitudeTimer);
    };
  }, [isActive]);

  return (
    <div
      className={`tex-m-closer${armed ? ' tex-m-closer--armed' : ''}${solitude ? ' tex-m-closer--solitude' : ''}`}
    >
      {/* The orb takes the screen. Wrapper sized so the orb
          fills the visual center, breathing large. */}
      <div className="tex-m-closer-orb-wrap">
        <Orb state="quiet" size="lg" />
      </div>

      {/* The line — word by word. */}
      <p className="tex-m-closer-line" aria-label="The weight is mine now.">
        {WORDS.map((w, i) => (
          <React.Fragment key={i}>
            <span
              className={`tex-m-closer-word${wordIndex >= i ? ' tex-m-closer-word--shown' : ''}`}
            >
              {w}
            </span>
            {i < WORDS.length - 1 ? <span className="tex-m-closer-gap">&nbsp;</span> : null}
          </React.Fragment>
        ))}
      </p>

      <p className="tex-sr-only">
        Tex on watch. The weight is mine now.
      </p>
    </div>
  );
}
