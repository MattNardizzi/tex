import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './BridgeSection.css';

/* =============================================================
   BRIDGE — Watch.

   The seam between the claim and the demonstrations. After the
   hero's "Absolute.", the user scrolls into a single screen with
   one word in serif italic and the orb breathing above it.

   Tex says one thing here, and means: from here on, I'll show you.

   No button. No supporting copy. The user reads the word, holds
   it for a beat, and scrolls on.
   ============================================================= */

export default function BridgeSection() {
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
      { threshold: 0.35 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-bridge${armed ? ' tex-bridge--armed' : ''}`}
      id="bridge"
      aria-label="From here on, Tex shows you."
    >
      <div className="tex-bridge-stage">
        <div className="tex-bridge-orb">
          <Orb state="quiet" size="lg" />
        </div>

        <p className="tex-bridge-word">Watch.</p>
      </div>
    </section>
  );
}
