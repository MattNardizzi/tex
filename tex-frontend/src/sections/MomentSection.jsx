import React, { useEffect, useState, useRef } from 'react';
import Orb from '../components/Orb.jsx';
import './MomentSection.css';

/* =============================================================
   MOMENT — I stopped one.

   The Execution demonstration. The only section on the page
   where the user can press a button and enter the product. Two
   states, one room.

     quiet   → orb centered, "All Quiet" beneath it. The state
               you land on. Held briefly.
     event   → orb drifts left. Beside it, in italic serif:
               "I stopped one. I'd like you to look." Single
               button: Show me. Terminal state — the section
               does not undo what Tex said.
   ============================================================= */

const QUIET_HOLD_MS = 2000;

export default function MomentSection({ onShowMe = () => {} }) {
  const [phase, setPhase] = useState('quiet');
  const sectionRef = useRef(null);
  const timerRef = useRef(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { threshold: 0.25 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!inView) {
      if (timerRef.current) clearTimeout(timerRef.current);
      return;
    }
    if (phase === 'event') return;

    timerRef.current = setTimeout(() => {
      setPhase('event');
    }, QUIET_HOLD_MS);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [inView, phase]);

  return (
    <section
      ref={sectionRef}
      className={`tex-moment tex-moment--${phase}`}
      id="moment"
      aria-label="Execution — what Tex does, shown rather than described"
    >
      <div className="tex-moment-stage">
        {/* The orb — drifts left on phase change. */}
        <div className="tex-moment-orb" aria-hidden="true">
          <Orb state={phase === 'event' ? 'asking' : 'quiet'} size="xl" />
        </div>

        {/* Quiet state — "All Quiet" beneath the orb. */}
        <div className="tex-moment-quiet" aria-hidden={phase !== 'quiet'}>
          <p className="tex-moment-quiet-word">All quiet.</p>
        </div>

        {/* Event state — italic serif, then aside, then Show me. */}
        <div className="tex-moment-event" aria-hidden={phase !== 'event'}>
          <p className="tex-moment-line">I stopped one.</p>
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

      <p className="tex-sr-only">
        Tex rests in a state called all quiet. When something needs a human,
        it speaks: I stopped one. I'd like you to look.
      </p>
    </section>
  );
}
