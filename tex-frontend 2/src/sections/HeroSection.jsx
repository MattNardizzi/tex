import React, { useEffect, useState } from 'react';
import { openCalendly } from '../utils/calendly.js';
import './HeroSection.css';

/* =============================================================
   HERO — Absolute.

   The one screen the user sees first. Three things must happen
   in three seconds:

     1. Tex is here.       (the breathing dot, top of frame)
     2. Absolute.          (the glass word)
     3. The promise.       (every agent, every action, every stage)

   No primary button. The arrow at the bottom of the frame is the
   only invitation. The page itself is the demonstration.
   ============================================================= */

export default function HeroSection({ navigate }) {
  const [armed, setArmed] = useState(false);

  // Arm the arrival as soon as the page is ready. Single beat,
  // no scroll dependency — the hero is the first thing.
  useEffect(() => {
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, []);

  return (
    <section
      className={`tex-hero${armed ? ' tex-hero--armed' : ''}`}
      id="top"
      aria-label="Tex"
    >
      {/* TOP BAR — three objects only. Logo. Presence. Show me. */}
      <header className="tex-topbar">
        <a
          href="/"
          className="tex-brand"
          onClick={(e) => {
            e.preventDefault();
            navigate('/');
          }}
          aria-label="Tex — home"
        >
          <span className="tex-brand-mark">T</span>
          <span className="tex-brand-word">
            <span className="tex-brand-word-name">Tex</span>
            <span className="tex-brand-word-by"> by VortexBlack</span>
          </span>
        </a>

        <a
          href="#book"
          className="tex-signin"
          onClick={(e) => {
            e.preventDefault();
            openCalendly();
          }}
        >
          Show me
        </a>
      </header>

      {/* STAGE — the word, then the line. */}
      <div className="tex-hero-stage">
        <h1
          className="tex-hero-word"
          aria-label="Absolute."
        >
          <svg
            className="tex-hero-glass"
            viewBox="0 0 900 240"
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="tex-glass-body" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"   stopColor="#F4F6FA" stopOpacity="0.98" />
                <stop offset="28%"  stopColor="#C8D2DE" stopOpacity="0.92" />
                <stop offset="58%"  stopColor="#5B6E84" stopOpacity="0.95" />
                <stop offset="100%" stopColor="#1D2733" stopOpacity="1"    />
              </linearGradient>

              <linearGradient id="tex-glass-rim" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"  stopColor="#FFFFFF" stopOpacity="0.85" />
                <stop offset="14%" stopColor="#FFFFFF" stopOpacity="0"    />
                <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0"   />
              </linearGradient>

              <radialGradient id="tex-word-floor" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#0E1620" stopOpacity="0.10" />
                <stop offset="60%"  stopColor="#0E1620" stopOpacity="0.04" />
                <stop offset="100%" stopColor="#0E1620" stopOpacity="0"    />
              </radialGradient>

              <mask id="tex-glass-mask">
                <text
                  x="450" y="178"
                  textAnchor="middle"
                  fontFamily="var(--tex-serif)"
                  fontSize="186"
                  fontWeight="400"
                  letterSpacing="-11"
                  fill="#FFFFFF"
                >Absolute.</text>
              </mask>
            </defs>

            <ellipse cx="450" cy="210" rx="320" ry="14" fill="url(#tex-word-floor)" />

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="url(#tex-glass-body)"
            >Absolute.</text>

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="url(#tex-glass-rim)"
            >Absolute.</text>

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="none"
              stroke="#5B6E84"
              strokeOpacity="0.32"
              strokeWidth="0.6"
            >Absolute.</text>

            <g mask="url(#tex-glass-mask)">
              <rect
                className="tex-glass-sweep-rect"
                x="-200" y="0"
                width="280" height="240"
                fill="#E6F0FF"
                opacity="0.85"
              />
            </g>
          </svg>
        </h1>

        <p className="tex-hero-line">
          <span className="tex-beat tex-beat--1">Every agent.</span>{' '}
          <span className="tex-beat tex-beat--2">Every action.</span>{' '}
          <span className="tex-beat tex-beat--3">Every stage of its life.</span>
        </p>

        <p className="tex-hero-aside">
          Tex is the only system that governs all of it.
        </p>
      </div>

      {/* SCROLL CUE — the only invitation. */}
      <a
        href="#bridge"
        className="tex-scroll-cue"
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
      </a>
    </section>
  );
}
