import React, { useState } from 'react';
import HeroSection from './sections/HeroSection.jsx';
import SelfSection from './sections/SelfSection.jsx';
import MomentSection from './sections/MomentSection.jsx';
import LifecycleSection from './sections/LifecycleSection.jsx';
import EvolutionSection from './sections/EvolutionSection.jsx';
import CloserSection from './sections/CloserSection.jsx';
import CalendlyModal from './components/CalendlyModal.jsx';

export default function App() {
  const [trialOpen, setTrialOpen] = useState(false);

  const openTrial = () => setTrialOpen(true);
  const closeTrial = () => setTrialOpen(false);

  const navigate = (path) => {
    window.history.pushState({}, '', path);
  };

  const onMomentShowMe = () => {
    navigate('/execution');
  };

  const onMomentThanks = () => {
    /* quiet acknowledgement — no-op on the marketing page */
  };

  return (
    <>
      <HeroSection openTrial={openTrial} navigate={navigate} />
      <SelfSection />
      <MomentSection onShowMe={onMomentShowMe} onThanks={onMomentThanks} />
      <LifecycleSection />
      <EvolutionSection />
      <CloserSection />
      {trialOpen && <CalendlyModal onClose={closeTrial} />}
    </>
  );
}
