import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './BridgeCard.css';

/* =============================================================
   BRIDGE CARD — Watch.   [MOBILE-NATIVE COMPOSITION]

   Desktop: orb centered, italic word below. Restful.
   Mobile:  a phone-native dark→light reveal.

   The composition
   ───────────────
   The card begins fully dark ink. A pinprick of light appears
   at center and slowly opens, pushing the dark outward into
   a vignette, until the orb materializes from the dilating
   light. As the dark recedes, the word "Watch." resolves one
   letter at a time in serif italic, soft against the just-
   revealed paper.

   This works on a phone (especially an OLED iPhone) the way
   it could never work on a desktop site — the screen IS the
   eye opening. The viewer feels the device wake up.
   ============================================================= */

export default function BridgeCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      return;
    }
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-m-bridge${armed ? ' tex-m-bridge--armed' : ''}`}>
      {/* The black field that retreats. A circle of paper
          expands from center, pushing the dark to a vignette
          at the screen edges. */}
      <div className="tex-m-bridge-iris" aria-hidden="true" />

      <div className="tex-m-bridge-stage">
        <div className="tex-m-bridge-orb">
          <Orb state="quiet" size="lg" />
        </div>
        <p className="tex-m-bridge-word" aria-label="Watch.">
          <span className="tex-m-bridge-l tex-m-bridge-l--1">W</span>
          <span className="tex-m-bridge-l tex-m-bridge-l--2">a</span>
          <span className="tex-m-bridge-l tex-m-bridge-l--3">t</span>
          <span className="tex-m-bridge-l tex-m-bridge-l--4">c</span>
          <span className="tex-m-bridge-l tex-m-bridge-l--5">h</span>
          <span className="tex-m-bridge-l tex-m-bridge-l--6">.</span>
        </p>
      </div>
    </div>
  );
}
