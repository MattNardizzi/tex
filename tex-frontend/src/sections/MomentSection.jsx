import React, { useEffect, useState, useRef } from 'react';
import Orb from '../components/Orb.jsx';
import GlassWord from '../components/GlassWord.jsx';
import './MomentSection.css';

/* =============================================================
   MOMENT SECTION — screen two

   The hero ends on "Absolute." This section is the proof of that
   claim, shown — not told — as Tex's own behavior.

   Two states, one room:
     - "quiet"  : Orb centered, "All Quiet" beneath it. Resting state.
                  Most of the time, this is what you see.
     - "event"  : Orb drifts left. Beside it, in italic serif,
                  "I stopped something." then "I'd like you to look."
                  A single button: Show me.

   The transition runs on a loop — quiet for a beat, event for a beat,
   back to quiet. The user witnesses the rhythm of the product.
   Nothing changes color. Nothing flashes. The composition does the work.

   Props
   -----
   onShowMe : () => void   — opens the Execution room / demo
   onThanks : () => void   — (reserved; not used in this revision)
   ============================================================= */

const QUIET_HOLD_MS = 4200;
const EVENT_HOLD_MS = 6400;
const TRANSITION_MS = 1400;

export default function MomentSection({
  onShowMe = () => {},
  // onThanks reserved for future use
}) {
  const [phase, setPhase] = useState('quiet'); // 'quiet' | 'event'
  const timerRef = useRef(null);
  const sectionRef = useRef(null);
  const [inView, setInView] = useState(false);

  // Only run the loop when the section is actually on screen — saves cycles
  // and means the first time the user scrolls into it, they see "All Quiet"
  // first, not the middle of a transition.
  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { threshold: 0.35 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!inView) {
      if (timerRef.current) clearTimeout(timerRef.current);
      return;
    }

    const hold = phase === 'quiet' ? QUIET_HOLD_MS : EVENT_HOLD_MS;
    timerRef.current = setTimeout(() => {
      setPhase((p) => (p === 'quiet' ? 'event' : 'quiet'));
    }, hold);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [phase, inView]);

  return (
    <section
      ref={sectionRef}
      className={`tex-moment tex-moment--${phase}`}
      id="moment"
      aria-label="What Tex does, shown rather than described"
    >
      {/* Ambient washes — the same warm light bleeding through the
          corners of the dashboard canvas. Cool on top-right, rose
          on bottom-left. */}
      <div className="tex-moment-wash tex-moment-wash--cool" aria-hidden="true" />
      <div className="tex-moment-wash tex-moment-wash--rose" aria-hidden="true" />

      <div className="tex-moment-stage">
        {/* The orb sits in a track. Its position is driven by the
            phase class on the section root, not inline styles, so
            the transition is owned by CSS and stays smooth. */}
        <div className="tex-moment-orb" aria-hidden="true">
          <Orb state={phase === 'event' ? 'asking' : 'quiet'} size="xl" />
        </div>

        {/* Quiet state — "All Quiet" beneath the orb. */}
        <div className="tex-moment-quiet" aria-hidden={phase !== 'quiet'}>
          <GlassWord
            text="All Quiet"
            fontSize={88}
            letterSpacing={-3.4}
            width={440}
            height={120}
            baseline={88}
          />
        </div>

        {/* Event state — italic serif sentence, then aside, then Show me. */}
        <div className="tex-moment-event" aria-hidden={phase !== 'event'}>
          <p className="tex-moment-line">I stopped something.</p>
          <p className="tex-moment-aside">I&rsquo;d like you to look.</p>
          <div className="tex-moment-actions">
            <button
              type="button"
              className="tex-moment-btn"
              onClick={onShowMe}
              tabIndex={phase === 'event' ? 0 : -1}
            >
              Show me
            </button>
          </div>
        </div>
      </div>

      {/* Visually-hidden caption so the section has meaning for
          screen readers even when the orb is the focal element. */}
      <p className="tex-sr-only">
        Tex rests in a state called All Quiet. When something needs a
        human, it speaks: I stopped something. I'd like you to look.
      </p>
    </section>
  );
}
