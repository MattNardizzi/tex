import React, { useState } from 'react';
import HeroSection from './sections/HeroSection.jsx';
import CalendlyModal from './components/CalendlyModal.jsx';

export default function App() {
  const [trialOpen, setTrialOpen] = useState(false);

  const openTrial = () => setTrialOpen(true);
  const closeTrial = () => setTrialOpen(false);

  const navigate = (path) => {
    window.history.pushState({}, '', path);
  };

  return (
    <>
      <HeroSection openTrial={openTrial} navigate={navigate} />
      {trialOpen && <CalendlyModal onClose={closeTrial} />}
    </>
  );
}
