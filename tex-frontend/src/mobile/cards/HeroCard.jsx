import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './HeroCard.css';

/* =============================================================
   HERO CARD — Absolute.

   The very first card of the eight-card breath. Three things
   resolve in three seconds:

     1. Tex is here.          (the small breathing orb, top-left
                               beside the wordmark)
     2. Absolute.             (the glass word, dominating the
                               upper half of the phone)
     3. The promise.          (three serif beats below, one breath
                               apart, naming the scope)

   No primary button. The small arrow at the bottom is the only
   invitation — tap or swipe up.

   Why this composition, not the desktop's
   ────────────────────────────────────────
   The desktop hero packs a 900×240 SVG glass word horizontally
   across a vast canvas. That ratio dies at portrait phone width:
   the word becomes a sliver. So mobile gets its OWN composition.
   The glass word is sized as a vertical block — wide enough to
   reach the safe-area edges, tall enough to dominate the screen.
   Letter spacing is retuned (-0.04em instead of the desktop's
   -11 SVG units) so the word reads as one carved letterform at
   thumb distance, not as eight separated characters.
   ============================================================= */

export default function HeroCard({ isActive, navigate, onAdvance }) {
  const [armed, setArmed] = useState(false);

  // The hero is the first card the user lands on — we arm it
  // immediately the first time it becomes active. We do not
  // re-arm on every activation; the hero plays once.
  useEffect(() => {
    if (!isActive) return;
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-hero-card${armed ? ' tex-hero-card--armed' : ''}`}>
      {/* TOP-LEFT MARK — the breathing presence beside the word.
          The orb here is xs so it reads as a sigil, not the
          protagonist (that's coming on card 2). */}
      <header className="tex-hero-card-top">
        <a
          href="/"
          className="tex-hero-card-brand"
          onClick={(e) => {
            e.preventDefault();
            navigate && navigate('/');
          }}
          aria-label="Tex — home"
        >
          <span className="tex-hero-card-brand-mark">T</span>
          <span className="tex-hero-card-brand-word">Tex</span>
        </a>
        <a
          href="/sign-in"
          className="tex-hero-card-signin"
          onClick={(e) => {
            e.preventDefault();
            navigate && navigate('/sign-in');
          }}
        >
          Sign in
        </a>
      </header>

      {/* THE STAGE — glass word, then promise lines. */}
      <div className="tex-hero-card-stage">
        <h1 className="tex-hero-card-word" aria-label="Absolute.">
          <svg
            className="tex-hero-card-glass"
            viewBox="0 0 720 240"
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            <defs>
              {/* The glass body — top highlight, mid silver, base
                  graphite. Same color story as the desktop hero
                  so the word reads as the same word, just resized
                  for the phone. */}
              <linearGradient id="tex-hero-card-body" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"   stopColor="#F4F6FA" stopOpacity="0.98" />
                <stop offset="28%"  stopColor="#C8D2DE" stopOpacity="0.92" />
                <stop offset="58%"  stopColor="#5B6E84" stopOpacity="0.95" />
                <stop offset="100%" stopColor="#1D2733" stopOpacity="1"    />
              </linearGradient>
              <linearGradient id="tex-hero-card-rim" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"  stopColor="#FFFFFF" stopOpacity="0.85" />
                <stop offset="14%" stopColor="#FFFFFF" stopOpacity="0"    />
                <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0"   />
              </linearGradient>
              <radialGradient id="tex-hero-card-floor" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#0E1620" stopOpacity="0.10" />
                <stop offset="60%"  stopColor="#0E1620" stopOpacity="0.04" />
                <stop offset="100%" stopColor="#0E1620" stopOpacity="0"    />
              </radialGradient>
              <mask id="tex-hero-card-mask">
                <text
                  x="360" y="178"
                  textAnchor="middle"
                  fontFamily="var(--tex-serif)"
                  fontSize="158"
                  fontWeight="400"
                  letterSpacing="-7"
                  fill="#FFFFFF"
                >Absolute.</text>
              </mask>
            </defs>

            {/* Soft floor shadow. */}
            <ellipse cx="360" cy="206" rx="220" ry="10" fill="url(#tex-hero-card-floor)" />

            {/* The word body. */}
            <text
              x="360" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="158"
              fontWeight="400"
              letterSpacing="-7"
              fill="url(#tex-hero-card-body)"
            >Absolute.</text>

            {/* Top highlight rim. */}
            <text
              x="360" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="158"
              fontWeight="400"
              letterSpacing="-7"
              fill="url(#tex-hero-card-rim)"
            >Absolute.</text>

            {/* Hairline outline so the word reads even when the
                glass body falls toward the paper at the bottom. */}
            <text
              x="360" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="158"
              fontWeight="400"
              letterSpacing="-7"
              fill="none"
              stroke="#5B6E84"
              strokeOpacity="0.32"
              strokeWidth="0.5"
            >Absolute.</text>

            {/* The light sweep — a single pass across the word
                every few seconds, like a reflection off a polished
                surface. Constrained to the word's mask so it
                doesn't leak onto the paper. */}
            <g mask="url(#tex-hero-card-mask)">
              <rect
                className="tex-hero-card-sweep"
                x="-200" y="0"
                width="200" height="240"
                fill="#E6F0FF"
                opacity="0.85"
              />
            </g>
          </svg>
        </h1>

        <p className="tex-hero-card-line">
          <span className="tex-hero-card-beat tex-hero-card-beat--1">Every agent.</span>{' '}
          <span className="tex-hero-card-beat tex-hero-card-beat--2">Every action.</span>{' '}
          <span className="tex-hero-card-beat tex-hero-card-beat--3">Every stage of its life.</span>
        </p>

        <p className="tex-hero-card-aside">
          Tex is the only system that governs all of it.
        </p>
      </div>

      {/* BOTTOM CUE — the only invitation. Soft floating chevron. */}
      <button
        type="button"
        className="tex-hero-card-cue"
        onClick={onAdvance}
        aria-label="Continue"
      >
        <svg width="14" height="22" viewBox="0 0 14 22" fill="none" aria-hidden="true">
          <path
            d="M7 1 V 19 M 1 13 L 7 19 L 13 13"
            stroke="currentColor"
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>
    </div>
  );
}
