import React, { useEffect, useState, useRef } from 'react';
import Orb from '../components/Orb.jsx';
import GlassWord from '../components/GlassWord.jsx';
import './MomentSection.css';

/* =============================================================
   MOMENT SECTION — screen two

   The hero ends on "Absolute." This section is the proof of that
   claim, shown — not told — as Tex's own behavior.

   Two states, one room:
     - "quiet"  : Orb centered, "All Quiet" beneath it. The state
                  you land on. Held briefly.
     - "event"  : Orb drifts left. Beside it, in italic serif,
                  "I stopped something." then "I'd like you to look."
                  A single button: Show me. This state is terminal —
                  the section holds here until the user acts or
                  scrolls on. Tex does not undo what it said.

   The transition runs once, when the section enters view. The
   user witnesses Tex notice something, then sees the message hold.
   Nothing loops. Nothing changes color. The composition does the work.

   Props
   -----
   onShowMe : () => void   — opens the Execution room / demo
   ============================================================= */

/* Timing — the first quiet beat is short (~1.8s) so the transition
   feels prompt when the user first scrolls in. After Tex speaks, the
   section holds on "I stopped something" indefinitely. No loop back. */
const QUIET_FIRST_HOLD_MS = 1800;
const QUIET_HOLD_MS = 1800; // currently same; kept named for future tuning

export default function MomentSection({
  onShowMe = () => {},
  // onThanks reserved for future use
}) {
  const [phase, setPhase] = useState('quiet'); // 'quiet' | 'event'
  const [hasFiredFirst, setHasFiredFirst] = useState(false);
  const timerRef = useRef(null);
  const sectionRef = useRef(null);
  const [inView, setInView] = useState(false);

  // Arm the loop as soon as the section starts entering the viewport.
  // 20% is early enough that the first transition feels responsive on
  // a normal scroll, but late enough that we're not animating off-screen.
  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { threshold: 0.2 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!inView) {
      if (timerRef.current) clearTimeout(timerRef.current);
      return;
    }

    // Once Tex has spoken, the section holds on "I stopped something"
    // permanently. The message has weight; we don't undo it. The user
    // either clicks Show me or scrolls on.
    if (phase === 'event') return;

    // First quiet → event uses a shorter hold (~1.8s) so the user
    // sees "All Quiet" land, register, then watch Tex speak.
    const hold = hasFiredFirst ? QUIET_HOLD_MS : QUIET_FIRST_HOLD_MS;

    timerRef.current = setTimeout(() => {
      setHasFiredFirst(true);
      setPhase('event');
    }, hold);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [phase, inView, hasFiredFirst]);

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
