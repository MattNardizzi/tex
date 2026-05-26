import React, { useEffect, useRef, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './MomentCard.css';

/* =============================================================
   MOMENT CARD — I stopped one.

   The only card where Tex hands the wheel back. Two phases,
   one room.

     quiet phase  — orb at rest, soft italic underneath:
                    "All quiet." Held briefly.

     event phase  — the orb shifts to its 'asking' posture
                    (a fraction more weight in the halo).
                    The italic line is replaced by:
                    "I stopped one." then "I'd like you to look."
                    A single button: Show me.

   The phase change is the demonstration. Tex is the kind of
   system that mostly waits — and when it speaks, it asks for
   you specifically. Not an alert. A request.
   ============================================================= */

const QUIET_HOLD_MS = 2200;

export default function MomentCard({ isActive, onShowMe }) {
  const [armed, setArmed] = useState(false);
  const [phase, setPhase] = useState('quiet');
  const timerRef = useRef(null);

  useEffect(() => {
    if (!isActive) {
      // Reset to quiet whenever we leave the card so the next
      // visit replays the beat.
      setArmed(false);
      setPhase('quiet');
      if (timerRef.current) clearTimeout(timerRef.current);
      return;
    }
    const armTimer = setTimeout(() => setArmed(true), 80);
    timerRef.current = setTimeout(() => setPhase('event'), QUIET_HOLD_MS);
    return () => {
      clearTimeout(armTimer);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isActive]);

  return (
    <div
      className={`tex-moment-card tex-moment-card--${phase}${armed ? ' tex-moment-card--armed' : ''}`}
    >
      <div className="tex-moment-card-stage">
        <div className="tex-moment-card-orb">
          <Orb state={phase === 'event' ? 'asking' : 'quiet'} size="lg" />
        </div>

        {/* QUIET phase — the soft state Tex spends most of its
            life in. Italic, soft grey, beneath the orb. */}
        <div className="tex-moment-card-quiet" aria-hidden={phase !== 'quiet'}>
          <p className="tex-moment-card-quiet-word">All quiet.</p>
        </div>

        {/* EVENT phase — the moment Tex speaks. Two italic
            lines and the only button on the whole eight-card arc. */}
        <div className="tex-moment-card-event" aria-hidden={phase !== 'event'}>
          <p className="tex-moment-card-line">I stopped one.</p>
          <p className="tex-moment-card-aside">I&rsquo;d like you to look.</p>
          <button
            type="button"
            className="tex-moment-card-btn"
            onClick={onShowMe}
            tabIndex={phase === 'event' ? 0 : -1}
          >
            Show me
          </button>
        </div>
      </div>

      <p className="tex-sr-only">
        Tex rests in a state called all quiet. When something needs a human,
        it speaks: I stopped one. I'd like you to look.
      </p>
    </div>
  );
}
