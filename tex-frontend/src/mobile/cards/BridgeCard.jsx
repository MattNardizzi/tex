import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './BridgeCard.css';

/* =============================================================
   BRIDGE CARD — Watch.

   The breath between the claim (Card 1) and the demonstrations
   that follow (Cards 3-7). On a phone this card is the test of
   how comfortable the product is with silence.

   The composition is two elements only:

     • The orb, centered on the glass, breathing.
     • One word in serif italic, just below the halo's lower edge.

   Nothing else. No supporting copy, no proof line, no button.
   The user reads the word, holds it for a beat, swipes on.
   ============================================================= */

export default function BridgeCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-bridge-card${armed ? ' tex-bridge-card--armed' : ''}`}>
      <div className="tex-bridge-card-stage">
        <div className="tex-bridge-card-orb">
          <Orb state="quiet" size="lg" />
        </div>
        <p className="tex-bridge-card-word">Watch.</p>
      </div>
    </div>
  );
}
