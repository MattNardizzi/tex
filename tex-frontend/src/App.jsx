import React, { useState } from 'react';
import HeroSection from './sections/HeroSection.jsx';
import MomentSection from './sections/MomentSection.jsx';
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
      <MomentSection onShowMe={onMomentShowMe} onThanks={onMomentThanks} />
      {trialOpen && <CalendlyModal onClose={closeTrial} />}
    </>
  );
}
