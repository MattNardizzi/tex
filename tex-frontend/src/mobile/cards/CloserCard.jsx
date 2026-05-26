import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './CloserCard.css';

/* =============================================================
   CLOSER CARD — The weight is mine now.

   The last beat. After the user has watched Tex find every
   agent, simulate forward, stop a thing, sign every decision,
   and refuse to change itself without their hand — the page
   exhales.

   The orb at center, breathing. One italic line beneath it.
   A long beat of silence. Then a soft footer at the bottom of
   the world: three small links, the wordmark.
   ============================================================= */

export default function CloserCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-closer-m${armed ? ' tex-closer-m--armed' : ''}`}>
      <div className="tex-closer-m-stage">
        <div className="tex-closer-m-orb">
          <Orb state="quiet" size="md" />
        </div>

        <p className="tex-closer-m-line">
          The weight is mine now.
        </p>
      </div>

      {/* Footer — anchored at the bottom of the card, soft and
          tucked into the safe area. */}
      <footer className="tex-closer-m-foot">
        <div className="tex-closer-m-foot-links">
          <a href="/how-it-works" className="tex-closer-m-foot-link">How it works</a>
          <span className="tex-closer-m-foot-sep" aria-hidden="true">·</span>
          <a href="/evidence" className="tex-closer-m-foot-link">Evidence</a>
          <span className="tex-closer-m-foot-sep" aria-hidden="true">·</span>
          <a href="/company" className="tex-closer-m-foot-link">Company</a>
        </div>
        <p className="tex-closer-m-foot-mark">Tex — VortexBlack</p>
      </footer>
    </div>
  );
}
