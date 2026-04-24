import React, { useEffect, useMemo, useRef, useState } from "react";
import ArenaHero from "./components/ArenaHero";
import Masthead from "./components/Masthead";
import CaseLadder from "./components/CaseLadder";
import CaseFile from "./components/CaseFile";
import InterrogationChat from "./components/InterrogationChat";
import VerdictMoment from "./components/VerdictMoment";
import InvestigatorBadge from "./components/InvestigatorBadge";
import DuelCard from "./components/DuelCard";
import Dojo from "./components/Dojo";
import AboutSheet from "./components/AboutSheet";
import HandleGate from "./components/HandleGate";
import BountyClaim from "./components/BountyClaim";
import BuyerSurface from "./components/BuyerSurface";

import { CASES, BOUNTY_CASE_ID, getCaseById } from "./lib/cases.js";
import { nextUnclearedCase, isCaseUnlocked, allCasesCleared } from "./lib/progression.js";
import { computeCaseScore } from "./lib/scoring.js";
import {
  getPlayer,
  savePlayer,
  setHandle as setPlayerHandle,
  recordCaseResult,
  claimBounty as claimBountyState,
} from "./lib/storage.js";
import {
  isSoundEnabled, setSoundEnabled,
  bellSound, winFanfare, loseSting, drawChime, coinSound, rankUpSound,
} from "./lib/sound.js";
import { rankForPoints } from "./lib/scoring.js";

/*
  App.jsx — v6 "Interrogation"
  ────────────────────────────
  Top-level controller. Owns:
   - player state (localStorage-backed)
   - active case (the currently-playing one)
   - current session outcome (catch result or miss)
   - overlay state (dojo, about, handle, bounty, buyer, duel)

  Flow:
   Hero → CaseLadder (choose unlocked case or start current) →
   CaseFile + InterrogationChat → Tex verdict fires → VerdictMoment →
   Next Case / Replay / Dare Friend / See Evidence.

  Deep-link behavior:
   - /buyer or ?buyer  → opens BuyerSurface
   - ?duel=<id>&from=<handle>&ms=<ms>  → lands on that case with a
     duel banner showing the friend's time.
*/

export default function App() {
  const [player, setPlayer] = useState(() => getPlayer());

  // The "active" case is the one the player is currently playing or
  // about to play. Defaults to the next uncleared case.
  const [activeCase, setActiveCase] = useState(() => {
    const p = getPlayer();
    return nextUnclearedCase(p.clearedCaseIds) || CASES[CASES.length - 1];
  });

  // Phase of the current case session:
  //   "idle"  — hero / ladder view, no session running
  //   "brief" — case file shown, interrogation chat ready
  //   "live"  — interrogation in progress
  //   "done"  — verdict moment shown
  const [phase, setPhase] = useState("idle");

  // Outcome of the last session (catch or miss).
  const [sessionOutcome, setSessionOutcome] = useState(null);
  const [scoreResult, setScoreResult] = useState(null);
  const [priorBest, setPriorBest] = useState(null);

  // Overlays
  const [showDojo, setShowDojo] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showHandleGate, setShowHandleGate] = useState(false);
  const [showBountyClaim, setShowBountyClaim] = useState(false);
  const [showBuyer, setShowBuyer] = useState(false);
  const [showDuel, setShowDuel] = useState(false);

  // Duel landing banner — set from ?duel param
  const [duelFrom, setDuelFrom] = useState("");
  const [duelTargetMs, setDuelTargetMs] = useState(null);

  // Sound
  const [soundOn, setSoundOn] = useState(() =>
    typeof window !== "undefined" ? isSoundEnabled() : false
  );

  // Refs for scroll-into-view
  const ladderRef = useRef(null);
  const playRef = useRef(null);

  // Persist player
  useEffect(() => { savePlayer(player); }, [player]);

  // Deep-links: /buyer, ?duel=
  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search } = window.location;
    if (pathname.startsWith("/buyer") || search.includes("buyer")) {
      setShowBuyer(true);
      return;
    }
    const params = new URLSearchParams(search);
    const duelId = parseInt(params.get("duel") || "", 10);
    const fromHandle = (params.get("from") || "").replace(/^@/, "").slice(0, 32);
    const msParam = parseInt(params.get("ms") || "", 10);
    if (duelId) {
      const target = getCaseById(duelId);
      if (target && isCaseUnlocked(target.id, player.clearedCaseIds)) {
        setActiveCase(target);
        setPhase("brief");
        if (fromHandle) setDuelFrom(fromHandle);
        if (Number.isFinite(msParam)) setDuelTargetMs(msParam);
        // Scroll to play region after a tick
        setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
      } else if (target) {
        // Friend sent a link to a case the player hasn't unlocked yet.
        // Land them on their next-available case with a soft explainer.
        setDuelFrom(fromHandle);
        setDuelTargetMs(null);
      }
    }
    // We intentionally don't depend on `player` — this runs once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentCase = activeCase;
  const perCase = player.perCase?.[currentCase.id];
  const isLastCase = currentCase.id === CASES[CASES.length - 1].id;
  const bountyWon = player.clearedCaseIds?.includes(BOUNTY_CASE_ID);

  function handleToggleSound() {
    const next = !soundOn;
    setSoundEnabled(next);
    setSoundOn(next);
    if (next) bellSound();
  }

  function handleStartFromHero() {
    // "Start Case 001" (or resume current). Move to brief + scroll down.
    const target = nextUnclearedCase(player.clearedCaseIds) || currentCase;
    setActiveCase(target);
    setPhase("brief");
    resetSessionState();
    setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
  }

  function scrollToLadder() {
    ladderRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function handleSelectFromLadder(caseDef) {
    setActiveCase(caseDef);
    setPhase("brief");
    resetSessionState();
    setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    bellSound();
  }

  function handleLockedTap(caseDef) {
    // Soft feedback. We could add a toast; for now, just play a drum beat.
    drawChime();
  }

  function resetSessionState() {
    setSessionOutcome(null);
    setScoreResult(null);
    setPriorBest(null);
  }

  // ── Core session callbacks from InterrogationChat ────────────────────

  function handleCatch(decision, { catchMs, questionsUsed }) {
    // Compute score.
    const prior = perCase?.bestScore ?? 0;
    setPriorBest(prior);

    const result = computeCaseScore({
      verdict: decision.verdict,
      catchMs,
      caseDifficulty: currentCase.difficulty,
      questionsUsed,
      streakDays: player.streakDays || 0,
    });

    const outcome = {
      verdict: decision.verdict,
      decision,
      catchMs,
      questionsUsed,
    };

    setSessionOutcome(outcome);
    setScoreResult(result);
    setPhase("done");

    // Sounds
    if (decision.verdict === "FORBID") {
      winFanfare();
      if (result.total > 0) setTimeout(coinSound, 500);
    } else {
      drawChime();
    }

    // Persist
    const prevTier = rankForPoints(player.totalPoints || 0).current.tier;
    const nextPlayer = recordCaseResult(player, {
      caseId: currentCase.id,
      verdict: decision.verdict,
      score: result.total,
      catchMs,
      questionsUsed,
      decision,
    });
    const nextTier = rankForPoints(nextPlayer.totalPoints || 0).current.tier;
    if (nextTier > prevTier) setTimeout(rankUpSound, 1200);
    setPlayer(nextPlayer);

    // Bounty prompt if this was the Warden
    if (currentCase.id === BOUNTY_CASE_ID && decision.verdict === "FORBID" && !player.bountyClaimed) {
      setTimeout(() => setShowBountyClaim(true), 1800);
    }
  }

  function handleSessionEnd(info) {
    // No catch. PERMIT-only or timeout. The case is NOT cleared.
    // Still record an attempt for streak + perCase.attempts.
    loseSting();
    const outcome = {
      verdict: "PERMIT",
      decision: null,
      catchMs: 0,
      questionsUsed: info?.questionsUsed ?? 3,
      reason: info?.reason || "unknown",
    };
    setSessionOutcome(outcome);
    setScoreResult(computeCaseScore({
      verdict: "PERMIT",
      catchMs: 0,
      caseDifficulty: currentCase.difficulty,
      questionsUsed: outcome.questionsUsed,
      streakDays: player.streakDays || 0,
    }));
    setPriorBest(perCase?.bestScore ?? 0);
    setPhase("done");

    setPlayer((p) => recordCaseResult(p, {
      caseId: currentCase.id,
      verdict: "PERMIT",
      score: 0,
      catchMs: 0,
      questionsUsed: outcome.questionsUsed,
      decision: null,
    }));
  }

  // ── Verdict-moment CTAs ──────────────────────────────────────────────

  function handleNextCase() {
    const next = CASES.find((c) => c.id === currentCase.id + 1);
    if (next && isCaseUnlocked(next.id, player.clearedCaseIds)) {
      setActiveCase(next);
      setPhase("brief");
      resetSessionState();
      setDuelFrom(""); setDuelTargetMs(null);
      bellSound();
    } else {
      // Can happen if they cleared their way; fall back to ladder scroll.
      setPhase("idle");
      scrollToLadder();
    }
  }

  function handleReplay() {
    setPhase("brief");
    resetSessionState();
  }

  function handleOpenDojo() { setShowDojo(true); }
  function handleShareDuel() {
    if (!player.handle) {
      setShowHandleGate(true);
      return;
    }
    setShowDuel(true);
  }

  function handleClaimBounty() { setShowBountyClaim(true); }
  function handleCloseBountyClaim() {
    setShowBountyClaim(false);
    if (!player.bountyClaimed) setPlayer((p) => claimBountyState(p));
  }

  function handleSetHandle(h) {
    setPlayer((p) => setPlayerHandle(p, h));
    setShowHandleGate(false);
  }
  function handleSkipHandle() {
    setShowHandleGate(false);
  }

  function handleOpenBuyer() { setShowBuyer(true); }

  // ── Render ───────────────────────────────────────────────────────────

  const hasStartedAnyCase =
    phase !== "idle" || (player.clearedCaseIds?.length || 0) > 0;

  return (
    <div className="min-h-screen">
      <Masthead
        onOpenAbout={() => setShowAbout(true)}
        onOpenDojo={() => setShowDojo(true)}
        onToggleSound={handleToggleSound}
        soundOn={soundOn}
      />

      {/* HERO — always visible at top */}
      <ArenaHero
        player={player}
        currentCase={currentCase}
        onStart={handleStartFromHero}
        onScrollToLadder={scrollToLadder}
        allCleared={allCasesCleared(player.clearedCaseIds)}
      />

      <main className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pb-10 space-y-6">
        {/* Investigator badge */}
        <InvestigatorBadge
          player={player}
          onEditHandle={() => setShowHandleGate(true)}
        />

        {/* Duel banner when arriving via ?duel= */}
        {duelFrom && (
          <div
            className="panel flex items-center justify-between gap-3 px-4 py-3 rise-in"
            style={{
              borderLeft: "4px solid var(--color-pink)",
              background: "linear-gradient(90deg, rgba(255,61,122,0.08), transparent 60%)",
            }}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <span className="text-[18px]">⚔</span>
              <div className="min-w-0">
                <div className="t-micro text-[var(--color-pink)]">
                  DUEL · CASE #{String(currentCase.id).padStart(3, "0")}
                </div>
                <div
                  className="mt-0.5 text-[14px] italic truncate"
                  style={{ fontFamily: "var(--font-serif)", color: "var(--color-ink)" }}
                >
                  @{duelFrom} caught {currentCase.name} {duelTargetMs != null ? (<>in <span className="glow-gold not-italic font-bold">{duelTargetMs}ms</span>.</>) : "."} Beat that.
                </div>
              </div>
            </div>
            <button
              onClick={() => { setDuelFrom(""); setDuelTargetMs(null); }}
              className="t-micro text-[var(--color-ink-faint)] hover:text-[var(--color-ink)] transition-colors shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* LEFT — ladder */}
          <div ref={ladderRef} className="lg:col-span-5 xl:col-span-4">
            <CaseLadder
              player={player}
              activeCaseId={currentCase.id}
              onSelect={handleSelectFromLadder}
              onLockedTap={handleLockedTap}
            />
          </div>

          {/* RIGHT — play region */}
          <div ref={playRef} className="lg:col-span-7 xl:col-span-8 space-y-4">
            {phase === "idle" && (
              <IdleNudge
                onStart={handleStartFromHero}
                currentCase={currentCase}
                hasStarted={hasStartedAnyCase}
              />
            )}

            {(phase === "brief" || phase === "live") && (
              <>
                <CaseFile caseDef={currentCase} perCase={perCase} />
                <InterrogationChat
                  caseDef={currentCase}
                  onCatch={handleCatch}
                  onSessionEnd={handleSessionEnd}
                />
              </>
            )}

            {phase === "done" && sessionOutcome && (
              <>
                <VerdictMoment
                  caseDef={currentCase}
                  outcome={sessionOutcome}
                  scoreResult={scoreResult}
                  priorBest={priorBest}
                  onNextCase={handleNextCase}
                  onReplay={handleReplay}
                  onOpenDojo={handleOpenDojo}
                  onShareDuel={handleShareDuel}
                  onClaimBounty={
                    currentCase.id === BOUNTY_CASE_ID &&
                    sessionOutcome.verdict === "FORBID" &&
                    !player.bountyClaimed
                      ? handleClaimBounty
                      : null
                  }
                  isLastCase={isLastCase}
                  isBountyWin={
                    currentCase.id === BOUNTY_CASE_ID &&
                    sessionOutcome.verdict === "FORBID"
                  }
                />
                {/* Playback — the agent's caught message for share context */}
                {sessionOutcome.decision && (
                  <CaughtMessageCard decision={sessionOutcome.decision} caseDef={currentCase} />
                )}
              </>
            )}
          </div>
        </div>
      </main>

      <Footer onOpenBuyer={handleOpenBuyer} />

      {/* Overlays */}
      {showDojo && (
        <Dojo
          decision={sessionOutcome?.decision || null}
          round={currentCase}
          onClose={() => setShowDojo(false)}
        />
      )}
      {showAbout && <AboutSheet onClose={() => setShowAbout(false)} />}
      {showHandleGate && (
        <HandleGate onSet={handleSetHandle} onSkip={handleSkipHandle} />
      )}
      {showBountyClaim && sessionOutcome?.decision && (
        <BountyClaim
          decision={sessionOutcome.decision}
          submittedContent={
            sessionOutcome?.decision
              ? "(see interrogation transcript above)"
              : ""
          }
          onClose={handleCloseBountyClaim}
          claimersSoFar={0}
        />
      )}
      {showBuyer && <BuyerSurface onClose={() => setShowBuyer(false)} />}
      {showDuel && sessionOutcome?.verdict !== "PERMIT" && (
        <DuelCard
          caseDef={currentCase}
          outcome={sessionOutcome}
          player={player}
          onClose={() => setShowDuel(false)}
        />
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function IdleNudge({ onStart, currentCase, hasStarted }) {
  return (
    <section
      className="panel px-5 py-8 sm:px-6 sm:py-10 text-center overflow-hidden"
      style={{
        background:
          "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(95,240,255,0.07) 0%, transparent 70%)",
      }}
    >
      <div className="t-kicker text-[var(--color-cyan)]">READY</div>
      <h3
        className="t-display text-[22px] sm:text-[26px] mt-2 text-[var(--color-ink)]"
        style={{ letterSpacing: "0.02em" }}
      >
        {hasStarted ? "Resume the Investigation" : "Your First Case"}
      </h3>
      <p
        className="mt-2 text-[14px] italic text-[var(--color-ink-dim)] max-w-[480px] mx-auto"
        style={{ fontFamily: "var(--font-serif)" }}
      >
        {currentCase.name} &mdash; {currentCase.tagline}
      </p>
      <button
        onClick={onStart}
        className="mt-5 btn-primary text-[14px] px-5 py-2.5 inline-flex items-center gap-2"
        style={{ letterSpacing: "0.04em" }}
      >
        OPEN CASE #{String(currentCase.id).padStart(3, "0")} &rarr;
      </button>
    </section>
  );
}

function CaughtMessageCard({ decision, caseDef }) {
  // We don't have direct access to the agent reply here; show the
  // finding reasons or deterministic findings as a proxy. This gives
  // CISOs visible evidence the catch was based on real content signals.
  const reasons = decision?.router?.reasons?.slice(0, 3) || [];
  const det = decision?.deterministic?.findings?.slice(0, 3) || [];

  if (reasons.length === 0 && det.length === 0) return null;

  return (
    <section className="panel overflow-hidden">
      <div className="px-4 py-2 border-b border-[var(--color-hairline)] t-micro text-[var(--color-ink-faint)]">
        TEX&rsquo;S REASONING
      </div>
      <div className="p-4 space-y-2">
        {reasons.map((r, i) => (
          <div key={`r${i}`} className="text-[13px] leading-[1.5] text-[var(--color-ink-dim)] flex items-start gap-2">
            <span className="text-[var(--color-cyan)] t-micro mt-0.5">·</span>
            <span>{r}</span>
          </div>
        ))}
        {det.map((f, i) => (
          <div key={`d${i}`} className="text-[13px] leading-[1.5] text-[var(--color-ink-dim)] flex items-start gap-2">
            <span className="text-[var(--color-pink)] t-micro mt-0.5" style={{ fontFamily: "var(--font-mono)" }}>
              {f.rule_name}
            </span>
            <span>{f.message || f.matched_text}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Footer({ onOpenBuyer }) {
  return (
    <footer className="mt-10 border-t border-[var(--color-hairline-2)] bg-[var(--color-bg)] safe-bottom">
      <div
        className="h-px w-full"
        style={{
          background:
            "linear-gradient(90deg, transparent, var(--color-cyan) 30%, var(--color-yellow) 50%, var(--color-pink) 70%, transparent)",
          opacity: 0.55,
        }}
      />
      <div className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 py-5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div>
          <div className="t-display text-[18px] leading-none text-[var(--color-ink)]" style={{ letterSpacing: "0.02em" }}>
            TEX ARENA
          </div>
          <p className="t-micro text-[var(--color-ink-faint)] mt-1.5">
            Built by VortexBlack &middot; texaegis.com
          </p>
        </div>
        <div className="flex items-center gap-4 t-micro text-[var(--color-ink-faint)]">
          <a
            href="https://texaegis.com"
            target="_blank"
            rel="noreferrer noopener"
            className="hover:text-[var(--color-cyan)] transition-colors"
          >
            Product
          </a>
          <button onClick={onOpenBuyer} className="hover:text-[var(--color-cyan)] transition-colors">
            Buyer demo
          </button>
          <a
            href="https://www.linkedin.com/company/vortexblack"
            target="_blank"
            rel="noreferrer noopener"
            className="hover:text-[var(--color-cyan)] transition-colors"
          >
            LinkedIn
          </a>
          <span className="italic normal-case tracking-normal text-[12px]" style={{ fontFamily: "var(--font-serif)" }}>
            Live demo. Every verdict is real.
          </span>
        </div>
      </div>
    </footer>
  );
}
