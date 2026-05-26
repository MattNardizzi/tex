import React, { useEffect, useRef, useState, useCallback } from 'react';
import HeroCard from './cards/HeroCard.jsx';
import BridgeCard from './cards/BridgeCard.jsx';
import PresenceCard from './cards/PresenceCard.jsx';
import ForesightCard from './cards/ForesightCard.jsx';
import MomentCard from './cards/MomentCard.jsx';
import EvidenceCard from './cards/EvidenceCard.jsx';
import EvolutionCard from './cards/EvolutionCard.jsx';
import CloserCard from './cards/CloserCard.jsx';
import MobileProgress from './MobileProgress.jsx';
import './MobileApp.css';

/* =============================================================
   MobileApp — the eight-card breath, redesigned for the phone.

   Architecture
   ────────────
   One scroller, eight cards. Each card is exactly 100dvw × 100dvh
   and snaps with CSS scroll-snap. Vertical, not horizontal —
   the thumb's natural gesture, and it sidesteps iOS Safari's
   back-swipe ambiguity. Each card auto-plays its animation only
   when it becomes the active card. Swiping away resets the card
   so coming back replays the breath.

   The eight beats
   ───────────────
     1  Hero       Absolute.
     2  Bridge     Watch.
     3  Presence   I see them all.
     4  Foresight  I see what's coming.
     5  Moment     I stopped one.
     6  Evidence   Every decision, signed.
     7  Evolution  Sharper, only with your hand.
     8  Closer     The weight is mine now.

   Active-card detection
   ─────────────────────
   IntersectionObserver watches the eight cards. Whichever one
   has the most of itself in the viewport wins. A short debounce
   prevents thrashing during the snap animation.

   Progress notches
   ────────────────
   Eight 1px-wide hairlines sit at the top of the screen, under
   the safe-area inset. The current card's notch is full ink;
   past notches are soft grey; future notches are hairline. The
   notches are also tap targets — tap one to jump to that card.

   Accessibility
   ─────────────
   The scroller has role="region" and aria-roledescription="carousel".
   Each card has an aria-label that reads as the sentence Tex says
   on that card. Past + future cards are still focusable so VoiceOver
   can step through them.
   ============================================================= */

const CARD_COUNT = 8;

export default function MobileApp({ navigate }) {
  const scrollerRef = useRef(null);
  const cardRefs = useRef([]);
  const [activeIndex, setActiveIndex] = useState(0);

  // Initialize the refs array once.
  if (cardRefs.current.length !== CARD_COUNT) {
    cardRefs.current = Array.from({ length: CARD_COUNT }, () => null);
  }

  // Detect which card is currently in view. We use IntersectionObserver
  // with multiple thresholds and pick whichever card has the highest
  // ratio. This handles the snap transitions without flicker.
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') return;
    const nodes = cardRefs.current.filter(Boolean);
    if (nodes.length === 0) return;

    let lastBest = -1;
    const ratios = new Array(CARD_COUNT).fill(0);

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          const idx = Number(entry.target.dataset.cardIndex);
          ratios[idx] = entry.intersectionRatio;
        });
        let bestIdx = 0;
        let bestRatio = 0;
        ratios.forEach((r, i) => {
          if (r > bestRatio) {
            bestRatio = r;
            bestIdx = i;
          }
        });
        if (bestIdx !== lastBest && bestRatio > 0.5) {
          lastBest = bestIdx;
          setActiveIndex(bestIdx);
        }
      },
      {
        root: scrollerRef.current,
        threshold: [0.25, 0.5, 0.75, 1.0],
      }
    );

    nodes.forEach((n) => io.observe(n));
    return () => io.disconnect();
  }, []);

  // Programmatic jump (used by progress notch taps).
  const goTo = useCallback((idx) => {
    const target = cardRefs.current[idx];
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  // Card list with the elements they receive.
  const cards = [
    <HeroCard      key="hero"      navigate={navigate}     onAdvance={() => goTo(1)} />,
    <BridgeCard    key="bridge" />,
    <PresenceCard  key="presence" />,
    <ForesightCard key="foresight" />,
    <MomentCard    key="moment"    onShowMe={() => navigate('/execution')} />,
    <EvidenceCard  key="evidence" />,
    <EvolutionCard key="evolution" />,
    <CloserCard    key="closer" />,
  ];

  return (
    <div className="tex-mobile-root">
      <MobileProgress
        count={CARD_COUNT}
        active={activeIndex}
        onJump={goTo}
      />

      <div
        ref={scrollerRef}
        className="tex-mobile-scroller"
        role="region"
        aria-roledescription="carousel"
        aria-label="Tex — eight beats"
      >
        {cards.map((card, i) => (
          <section
            key={i}
            ref={(el) => (cardRefs.current[i] = el)}
            data-card-index={i}
            className="tex-mobile-card-slot"
            aria-roledescription="slide"
            aria-label={`${i + 1} of ${CARD_COUNT}`}
          >
            {React.cloneElement(card, { isActive: i === activeIndex, cardIndex: i })}
          </section>
        ))}
      </div>
    </div>
  );
}
