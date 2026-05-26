import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './CloserSection.css';

/* =============================================================
   CLOSER — The weight is mine now.

   The last beat. Half the vertical room of the others. After
   the user has watched Tex find every agent, simulate forward,
   stop a thing, sign every decision, and refuse to change
   itself without their hand — the page exhales.

   The orb at center, breathing. One italic line beneath it.
   No button. The page ends.
   ============================================================= */

export default function CloserSection() {
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
      { threshold: 0.4 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-closer${armed ? ' tex-closer--armed' : ''}`}
      id="closer"
      aria-label="The weight is mine now."
    >
      <div className="tex-closer-stage">
        <div className="tex-closer-orb">
          <Orb state="quiet" size="md" />
        </div>

        <p className="tex-closer-line">
          The weight is mine now.
        </p>

        {/* The footer mark — small, at the bottom of the world. */}
        <footer className="tex-closer-foot">
          <a
            href="/how-it-works"
            className="tex-closer-foot-link"
          >
            How it works
          </a>
          <span className="tex-closer-foot-sep" aria-hidden="true">·</span>
          <a
            href="/evidence"
            className="tex-closer-foot-link"
          >
            Evidence
          </a>
          <span className="tex-closer-foot-sep" aria-hidden="true">·</span>
          <a
            href="/company"
            className="tex-closer-foot-link"
          >
            Company
          </a>
          <span className="tex-closer-foot-mark">Tex — VortexBlack</span>
        </footer>
      </div>
    </section>
  );
}
