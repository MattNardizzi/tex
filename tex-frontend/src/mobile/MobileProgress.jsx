import React from 'react';
import './MobileProgress.css';

/* =============================================================
   MobileProgress — eight notches.

   Eight 1px-wide hairlines at the top of the screen, just below
   the safe-area inset. Each notch represents one card in the
   eight-card arc. The current notch is full ink; past notches
   are soft grey (proof you walked through them); future notches
   are barely-visible hairline.

   Tapping a notch jumps to that card. The notch has a generous
   invisible tap target so it works at thumb size.

   This is the only persistent UI chrome in the entire mobile
   experience. Everything else is silence.
   ============================================================= */

export default function MobileProgress({ count, active, onJump }) {
  const notches = Array.from({ length: count }, (_, i) => i);

  return (
    <div className="tex-mobile-progress" aria-hidden="false">
      <div
        className="tex-mobile-progress-row"
        role="tablist"
        aria-label="Progress through the eight beats"
      >
        {notches.map((i) => {
          const state =
            i < active ? 'past' :
            i === active ? 'current' : 'future';
          return (
            <button
              key={i}
              type="button"
              role="tab"
              aria-selected={i === active}
              aria-label={`Beat ${i + 1} of ${count}`}
              className={`tex-mobile-progress-notch tex-mobile-progress-notch--${state}`}
              onClick={() => onJump(i)}
            >
              <span className="tex-mobile-progress-bar" aria-hidden="true" />
            </button>
          );
        })}
      </div>
    </div>
  );
}
