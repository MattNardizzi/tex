import React, { useEffect } from 'react';
import './CalendlyModal.css';

const CALENDLY_URL = 'https://calendly.com/matthew-vortexblack/tex-intro';

export default function CalendlyModal({ onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [onClose]);

  return (
    <div
      className="tex-modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Schedule a conversation with Tex"
    >
      <div
        className="tex-modal-frame"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          className="tex-modal-close"
          onClick={onClose}
          aria-label="Close"
        >
          ×
        </button>
        <iframe
          src={CALENDLY_URL}
          title="Schedule a conversation with Tex"
          frameBorder="0"
          className="tex-modal-iframe"
        />
      </div>
    </div>
  );
}
