import React, { useEffect, useRef, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './MomentCard.css';

/* =============================================================
   MOMENT CARD — I stopped one.   [MOBILE-NATIVE]

   Desktop: orb drifts left, copy resolves to its right.
   Mobile:  silence, then THE FLASH.

   The composition
   ───────────────
   • Phase 0 (~1.6s): the orb breathes at center on white
     paper. "All quiet." soft italic below.
   • Phase 1 (the flash): the screen inverts — paper → ink —
     and the orb's halo intensifies. Haptic pulse (where
     supported via navigator.vibrate). Held for 280ms.
   • Phase 2: paper returns. The orb is now in 'asking'
     posture. The line "I stopped one. I'd like you to look."
     resolves. Below it, the only button: Show me.

   Why this works on a phone
   ─────────────────────────
   • Full-screen inversion is a phone-native move — the OLED
     and the held proximity make it visceral.
   • Haptics. A phone can buzz; a desktop cannot.
   • Silence → strike → speak is a rhythm only a personal
     device can earn.
   ============================================================= */

const QUIET_MS = 1600;
const FLASH_MS = 280;

export default function MomentCard({ isActive, onShowMe }) {
  const [armed, setArmed] = useState(false);
  const [phase, setPhase] = useState('quiet'); // quiet → flash → event
  const timersRef = useRef([]);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      setPhase('quiet');
      timersRef.current.forEach(clearTimeout);
      timersRef.current = [];
      return;
    }
    const arm = setTimeout(() => setArmed(true), 80);
    const flash = setTimeout(() => {
      setPhase('flash');
      // Haptic pulse on supported devices.
      if (typeof navigator !== 'undefined' && navigator.vibrate) {
        try { navigator.vibrate([60, 40, 20]); } catch {}
      }
    }, QUIET_MS);
    const event = setTimeout(() => setPhase('event'), QUIET_MS + FLASH_MS);
    timersRef.current = [arm, flash, event];
    return () => timersRef.current.forEach(clearTimeout);
  }, [isActive]);

  return (
    <div
      className={`tex-m-moment tex-m-moment--${phase}${armed ? ' tex-m-moment--armed' : ''}`}
    >
      <div className="tex-m-moment-stage">
        <div className="tex-m-moment-orb">
          <Orb
            state={phase === 'event' ? 'asking' : 'quiet'}
            size="lg"
          />
        </div>

        {/* QUIET copy. */}
        <div className="tex-m-moment-quiet" aria-hidden={phase !== 'quiet'}>
          <p className="tex-m-moment-quiet-word">All quiet.</p>
        </div>

        {/* EVENT copy. */}
        <div className="tex-m-moment-event" aria-hidden={phase !== 'event'}>
          <p className="tex-m-moment-line">I stopped one.</p>
          <p className="tex-m-moment-aside">I&rsquo;d like you to look.</p>
          <button
            type="button"
            className="tex-m-moment-btn"
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
