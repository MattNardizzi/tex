import React from 'react';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — Tex

   Top bar:   T mark + "Tex"      •Tex is here
              How it works · Evidence · Company · Sign in

   Stage:
       Tex.
       [ figure, emerging from the page ]
       Every agent. Every action. Every stage of its life.
       Tex is the only system that governs all of it.
       [ Show me ]
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="tex-hero" id="top">
      {/* TOP BAR ------------------------------------------------ */}
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
          <span className="tex-brand-word">Tex</span>
        </a>

        <div className="tex-presence" role="status" aria-live="polite">
          <span className="tex-presence-dot">
            <span className="tex-presence-dot-core" />
          </span>
          <span className="tex-presence-label">Tex is here</span>
        </div>

        <nav className="tex-nav">
          <a
            href="/how-it-works"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/how-it-works');
            }}
          >
            How it works
          </a>
          <a
            href="/evidence"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/evidence');
            }}
          >
            Evidence
          </a>
          <a
            href="/company"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/company');
            }}
          >
            Company
          </a>
          <a
            href="/sign-in"
            className="tex-nav-link tex-nav-link--strong"
            onClick={(e) => {
              e.preventDefault();
              navigate('/sign-in');
            }}
          >
            Sign in
          </a>
        </nav>
      </header>

      {/* STAGE -------------------------------------------------- */}
      <div className="tex-stage">
        <h1 className="tex-hero-name tex-arrive tex-arrive--name">Tex.</h1>

        <figure className="tex-figure tex-arrive tex-arrive--figure">
          <div className="tex-figure-halo" aria-hidden="true" />
          <picture>
            <source media="(min-width: 720px)" srcSet="/tex-avatar.webp" />
            <img
              src="/tex-avatar-sm.webp"
              alt="Tex"
              className="tex-figure-img"
              draggable="false"
            />
          </picture>
          <span className="tex-eye tex-eye--l" aria-hidden="true" />
          <span className="tex-eye tex-eye--r" aria-hidden="true" />
        </figure>

        <p className="tex-hero-line tex-arrive tex-arrive--line">
          <span className="tex-beat tex-beat--1">Every agent.</span>{' '}
          <span className="tex-beat tex-beat--2">Every action.</span>{' '}
          <span className="tex-beat tex-beat--3">Every stage of its life.</span>
        </p>

        <p className="tex-hero-aside tex-arrive tex-arrive--aside">
          Tex is the only system that governs all of it.
        </p>

        <div className="tex-hero-actions tex-arrive tex-arrive--button">
          <button
            type="button"
            className="tex-btn tex-btn--primary"
            onClick={openTrial}
          >
            Show me
          </button>
        </div>
      </div>
    </section>
  );
}
