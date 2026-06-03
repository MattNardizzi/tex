import React from 'react';
import HeroSection from './sections/HeroSection.jsx';
import BridgeSection from './sections/BridgeSection.jsx';
import PresenceSection from './sections/PresenceSection.jsx';
import ForesightSection from './sections/ForesightSection.jsx';
import MomentSection from './sections/MomentSection.jsx';
import EvidenceSection from './sections/EvidenceSection.jsx';
import EvolutionSection from './sections/EvolutionSection.jsx';
import CloserSection from './sections/CloserSection.jsx';
import MobileApp from './mobile/MobileApp.jsx';
import { useIsMobile } from './hooks/useIsMobile.js';
import { openCalendly } from './utils/calendly.js';

/* =============================================================
   Tex — the marketing site, end to end.

   Eight beats. One orb. One voice. One room.

   1  Hero        Absolute.                        the claim
   2  Bridge      Watch.                           the invitation
   3  Presence    I see them all.                  Discovery + Identity
   4  Foresight   I see what's coming.             Observability
   5  Moment      I stopped one.                   Execution
   6  Evidence    Signed. Verifiable without us.   Evidence
   7  Evolution   Sharper, only with your hand.    Learning
   8  Closer      The weight is mine now.          the breath out

   Each section is one sentence Tex would say in that moment,
   and one demonstration of what Tex actually does. The screen
   is the trace of a conversation, not a feature grid.

   ────────────────────────────────────────────────────────────
   Two front-ends, one product.

   On screens ≥ 721px the user gets the desktop scroll — eight
   sections stacked in one long white room, the orb traveling
   from beat to beat. That experience is unchanged from the
   day it shipped.

   On phones the user gets MobileApp — the same eight souls
   redesigned for a piece of glass held at thumb distance.
   Different choreography, different compositions, same product.
   ============================================================= */

export default function App() {
  const isMobile = useIsMobile();

  const navigate = (path) => {
    window.history.pushState({}, '', path);
  };

  if (isMobile) {
    return <MobileApp navigate={navigate} />;
  }

  return (
    <>
      <HeroSection navigate={navigate} />
      <BridgeSection />
      <PresenceSection />
      <ForesightSection />
      <MomentSection onShowMe={openCalendly} />
      <EvidenceSection />
      <EvolutionSection />
      <CloserSection />
    </>
  );
}
