import React, { useEffect, useState } from 'react';
import './HeroCard.css';

/* =============================================================
   HERO CARD — Absolute.   [MOBILE-NATIVE COMPOSITION]

   The desktop hero gives "Absolute." a tidy glass treatment
   that fits inside a 900px canvas. On a phone, that idea is
   wrong. The point of the word "Absolute." is that nothing
   exceeds it. So on a phone, the word EXCEEDS the screen.

   The composition
   ───────────────
   • The word is set ENORMOUS — wider than the viewport — in
     outline-only serif italic. The reader sees only "bsolut".
     The 'A' and the period are off-screen on either side.
     That truncation IS the design. The word is too big to
     contain — which is what "Absolute." means.
   • Beneath, a hairline tally of three small mono beats:
     EVERY AGENT · EVERY ACTION · EVERY STAGE.
   • A soft italic aside resolves last.
   • The brand mark and Sign-in sit at the top edge, small.
   • The word VERY slowly drifts left-to-right and back across
     the screen — slow enough you don't see it move, but if
     you look back in 4 seconds the 'A' has rotated into view
     and the period out. The word is alive.
   ============================================================= */

export default function HeroCard({ isActive, navigate, onAdvance }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-m-hero${armed ? ' tex-m-hero--armed' : ''}`}>
      <header className="tex-m-hero-top">
        <a
          href="/"
          className="tex-m-hero-brand"
          onClick={(e) => { e.preventDefault(); navigate && navigate('/'); }}
          aria-label="Tex — home"
        >
          <span className="tex-m-hero-mark">T</span>
          <span className="tex-m-hero-name">Tex</span>
        </a>
        <a
          href="/sign-in"
          className="tex-m-hero-signin"
          onClick={(e) => { e.preventDefault(); navigate && navigate('/sign-in'); }}
        >
          Sign in
        </a>
      </header>

      {/* THE WORD. Set massive. The word IS the screen.
          The drift is achieved via a wrapper that animates
          transform: translateX so the visible portion changes
          slowly over time, revealing different letters. */}
      <div className="tex-m-hero-word-wrap" aria-label="Absolute.">
        <div className="tex-m-hero-word">Absolute.</div>
      </div>

      {/* THREE BEATS — mono, hairline. Each one a fact. */}
      <div className="tex-m-hero-beats">
        <span className="tex-m-hero-beat tex-m-hero-beat--1">EVERY AGENT</span>
        <span className="tex-m-hero-beat-sep">·</span>
        <span className="tex-m-hero-beat tex-m-hero-beat--2">EVERY ACTION</span>
        <span className="tex-m-hero-beat-sep">·</span>
        <span className="tex-m-hero-beat tex-m-hero-beat--3">EVERY STAGE</span>
      </div>

      <p className="tex-m-hero-aside">
        Tex is the only system <em>that governs all of it.</em>
      </p>

      {/* SWIPE CUE — small, the only invitation. */}
      <button
        type="button"
        className="tex-m-hero-cue"
        onClick={onAdvance}
        aria-label="Continue"
      >
        <span className="tex-m-hero-cue-rule" />
        <span className="tex-m-hero-cue-label">SWIPE</span>
      </button>
    </div>
  );
}
