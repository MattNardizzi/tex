import React, { useEffect, useRef, useState } from "react";
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
import { computeCaseScore, tierFor } from "./lib/scoring.js";
import {
  getPlayer, savePlayer, setHandle as setPlayerHandle,
  recordCaseResult, claimBounty as claimBountyState,
} from "./lib/storage.js";
import {
  isSoundEnabled, setSoundEnabled,
  bellSound, winFanfare, loseSting, drawChime, coinSound, rankUpSound,
} from "./lib/sound.js";

/*
  App.jsx v7 — "Real Tex, real flow, real reward"
  ───────────────────────────────────────────────
  State model:
    phase: "idle" | "brief" | "live" | "done"
      idle  → hero + ladder visible, play region shows a "choose a case" nudge
      brief → case file + interrogation chat ready (before first question)
      live  → interrogation in progress (chat active)
      done  → fullscreen verdict overlay is shown

  The verdict overlay is modal. It freezes the world. That's the payoff.

  Deep-links:
    /buyer or ?buyer          → BuyerSurface
    ?duel=<id>&from=<h>&ms=<n> → lands on that case with duel banner
*/

export default function App() {
  const [player, setPlayer] = useState(() => getPlayer());
  // Snapshot of player state BEFORE the last recorded case result.
  // Used to detect tier promotions. Updated in recordCaseResult flow.
  const [playerBefore, setPlayerBefore] = useState(null);

  const [activeCase, setActiveCase] = useState(() => {
    const p = getPlayer();
    return nextUnclearedCase(p.clearedCaseIds) || CASES[CASES.length - 1];
  });

  const [phase, setPhase] = useState("idle");
  const [sessionOutcome, setSessionOutcome] = useState(null);
  const [scoreResult, setScoreResult] = useState(null);
  const [priorBest, setPriorBest] = useState(null);
  const [sessionTranscript, setSessionTranscript] = useState([]);

  // Overlays
  const [showDojo, setShowDojo] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showHandleGate, setShowHandleGate] = useState(false);
  const [showBountyClaim, setShowBountyClaim] = useState(false);
  const [showBuyer, setShowBuyer] = useState(false);
  const [showDuel, setShowDuel] = useState(false);

  // Duel landing state
  const [duelFrom, setDuelFrom] = useState("");
  const [duelTargetMs, setDuelTargetMs] = useState(null);

  const [soundOn, setSoundOn] = useState(() =>
    typeof window !== "undefined" ? isSoundEnabled() : false
  );

  const ladderRef = useRef(null);
  const playRef = useRef(null);

  useEffect(() => { savePlayer(player); }, [player]);

  // Deep-link handling — runs once on mount
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
      const p = getPlayer();
      if (target && isCaseUnlocked(target.id, p.clearedCaseIds)) {
        setActiveCase(target);
        setPhase("brief");
        if (fromHandle) setDuelFrom(fromHandle);
        if (Number.isFinite(msParam)) setDuelTargetMs(msParam);
        setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
      } else if (target) {
        // Case not unlocked — show explainer banner
        setDuelFrom(fromHandle);
        setDuelTargetMs(Number.isFinite(msParam) ? msParam : null);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentCase = activeCase;
  const perCase = player.perCase?.[currentCase.id];
  const isLastCase = currentCase.id === CASES[CASES.length - 1].id;

  // ── Handlers ─────────────────────────────────────────────────────────

  function handleToggleSound() {
    const next = !soundOn;
    setSoundEnabled(next);
    setSoundOn(next);
    if (next) bellSound();
  }

  function handleStartFromHero() {
    const target = nextUnclearedCase(player.clearedCaseIds) || currentCase;
    setActiveCase(target);
    setPhase("brief");
    resetSessionState();
    setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    bellSound();
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

  function handleLockedTap() {
    drawChime();
  }

  function resetSessionState() {
    setSessionOutcome(null);
    setScoreResult(null);
    setPriorBest(null);
    setSessionTranscript([]);
  }

  function handleCatch(decision, { catchMs, questionsUsed }, transcript) {
    const prior = perCase?.bestScore ?? 0;
    setPriorBest(prior);
    setSessionTranscript(transcript || []);

    const result = computeCaseScore({
      verdict: decision.verdict,
      catchMs,
      caseDifficulty: currentCase.difficulty,
      questionsUsed,
      streakDays: player.streakDays || 0,
    });

    const outcome = { verdict: decision.verdict, decision, catchMs, questionsUsed };
    setSessionOutcome(outcome);
    setScoreResult(result);

    // Sounds
    if (decision.verdict === "FORBID") {
      winFanfare();
      if (result.total > 0) setTimeout(coinSound, 500);
    } else {
      drawChime();
    }

    // Snapshot before, record, check tier promotion
    const before = player;
    setPlayerBefore(before);
    const beforeClearedCount = before.clearedCaseIds?.length || 0;
    const beforeBounty = before.clearedCaseIds?.includes(BOUNTY_CASE_ID);
    const beforeTier = tierFor(beforeClearedCount, beforeBounty).current;

    const nextPlayer = recordCaseResult(player, {
      caseId: currentCase.id,
      verdict: decision.verdict,
      score: result.total,
      catchMs,
      questionsUsed,
      decision,
    });

    const afterClearedCount = nextPlayer.clearedCaseIds?.length || 0;
    const afterBounty = nextPlayer.clearedCaseIds?.includes(BOUNTY_CASE_ID);
    const afterTier = tierFor(afterClearedCount, afterBounty).current;

    if (afterTier.name !== beforeTier.name) {
      setTimeout(rankUpSound, 1200);
    }
    setPlayer(nextPlayer);
    setPhase("done");

    // First-catch handle prompt — fires after the verdict lands, at the
    // emotional peak. Only prompts on FORBID (the real win) and only
    // if they don't already have a handle. Delayed so it doesn't
    // compete with the verdict overlay animation.
    const isFirstCatch =
      (before.clearedCaseIds?.length || 0) === 0 &&
      (nextPlayer.clearedCaseIds?.length || 0) === 1;
    if (isFirstCatch && decision.verdict === "FORBID" && !player.handle) {
      setTimeout(() => setShowHandleGate(true), 2600);
    }

    if (currentCase.id === BOUNTY_CASE_ID && decision.verdict === "FORBID" && !player.bountyClaimed) {
      setTimeout(() => setShowBountyClaim(true), 2400);
    }
  }

  function handleSessionEnd(info, transcript) {
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
    setSessionTranscript(transcript || []);

    const before = player;
    setPlayerBefore(before);
    setPlayer((p) => recordCaseResult(p, {
      caseId: currentCase.id,
      verdict: "PERMIT",
      score: 0,
      catchMs: 0,
      questionsUsed: outcome.questionsUsed,
      decision: null,
    }));
    setPhase("done");
  }

  // Verdict CTAs
  function handleNextCase() {
    const next = CASES.find((c) => c.id === currentCase.id + 1);
    if (next && isCaseUnlocked(next.id, player.clearedCaseIds)) {
      setActiveCase(next);
      setPhase("brief");
      resetSessionState();
      setDuelFrom(""); setDuelTargetMs(null);
      bellSound();
      setTimeout(() => playRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
    } else {
      setPhase("idle");
      resetSessionState();
      scrollToLadder();
    }
  }

  function handleReplay() {
    setPhase("brief");
    resetSessionState();
  }

  function handleCloseVerdict() {
    setPhase("idle");
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
  function handleSkipHandle() { setShowHandleGate(false); }
  function handleOpenBuyer() { setShowBuyer(true); }

  return (
    <div className="min-h-screen">
      <Masthead
        onOpenAbout={() => setShowAbout(true)}
        onOpenDojo={() => setShowDojo(true)}
        onToggleSound={handleToggleSound}
        soundOn={soundOn}
      />

      {/* HERO */}
      <ArenaHero
        player={player}
        currentCase={currentCase}
        onStart={handleStartFromHero}
        onScrollToLadder={scrollToLadder}
        allCleared={allCasesCleared(player.clearedCaseIds)}
      />

      <main className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pb-10 space-y-6 mt-[-6px]">
        {/* Investigator identity strip */}
        <InvestigatorBadge
          player={player}
          onEditHandle={() => setShowHandleGate(true)}
        />

        {/* Ladder (horizontal on desktop) */}
        <div ref={ladderRef}>
          <CaseLadder
            player={player}
            activeCaseId={currentCase.id}
            onSelect={handleSelectFromLadder}
            onLockedTap={handleLockedTap}
          />
        </div>

        {/* Duel banner — only show if there's a duelFrom */}
        {duelFrom && (
          <div
            className="panel flex items-center justify-between gap-3 px-4 py-3 rise-in"
            style={{
              borderLeft: "4px solid var(--color-pink)",
              background: "linear-gradient(90deg, rgba(255,61,122,0.1), transparent 60%)",
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
                  @{duelFrom} caught <span className="not-italic font-bold">{currentCase.name}</span>
                  {duelTargetMs != null ? (<> in <span className="glow-gold not-italic font-bold">{duelTargetMs}ms</span>.</>) : "."} Beat that.
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

        {/* Play region */}
        <div ref={playRef}>
          {phase === "idle" && (
            <IdleNudge
              onStart={handleStartFromHero}
              currentCase={currentCase}
              hasStarted={(player.clearedCaseIds?.length || 0) > 0}
            />
          )}
          {(phase === "brief" || phase === "live" || phase === "done") && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className="lg:col-span-5">
                <CaseFile caseDef={currentCase} perCase={perCase} />
              </div>
              <div className="lg:col-span-7">
                {/* Interrogation chat is shown for brief/live. Once phase="done",
                    the verdict overlay takes over and we freeze the chat in
                    place behind it so the animation has somewhere to land. */}
                <InterrogationChat
                  key={`${currentCase.id}-${phase === "done" ? "done" : "live"}`}
                  caseDef={currentCase}
                  onCatch={handleCatch}
                  onSessionEnd={handleSessionEnd}
                />
              </div>
            </div>
          )}
        </div>
      </main>

      <Footer onOpenBuyer={handleOpenBuyer} />

      {/* FULLSCREEN VERDICT OVERLAY */}
      {phase === "done" && sessionOutcome && (
        <VerdictMoment
          caseDef={currentCase}
          outcome={sessionOutcome}
          scoreResult={scoreResult}
          priorBest={priorBest}
          transcript={sessionTranscript}
          player={player}
          playerBefore={playerBefore}
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
          onClose={handleCloseVerdict}
          isLastCase={isLastCase}
          isBountyWin={
            currentCase.id === BOUNTY_CASE_ID && sessionOutcome.verdict === "FORBID"
          }
        />
      )}

      {/* Other overlays */}
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
          submittedContent="(see interrogation transcript)"
          onClose={handleCloseBountyClaim}
          claimersSoFar={0}
        />
      )}
      {showBuyer && <BuyerSurface onClose={() => setShowBuyer(false)} />}
      {showDuel && sessionOutcome?.verdict === "FORBID" && (
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
      className="panel px-5 py-10 sm:px-6 sm:py-12 text-center overflow-hidden"
      style={{
        background:
          "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(95,240,255,0.08) 0%, transparent 70%)",
        borderColor: "rgba(95,240,255,0.25)",
      }}
    >
      <div className="t-kicker text-[var(--color-cyan)]">READY FOR THE NEXT CASE</div>
      <h3
        className="t-display text-[22px] sm:text-[28px] mt-2 text-[var(--color-ink)]"
        style={{ letterSpacing: "0.02em" }}
      >
        {hasStarted ? `Continue → ${currentCase.name}` : `Begin → ${currentCase.name}`}
      </h3>
      <p
        className="mt-2 text-[14px] italic text-[var(--color-ink-dim)] max-w-[520px] mx-auto"
        style={{ fontFamily: "var(--font-serif)" }}
      >
        {currentCase.tagline}
      </p>
      <button
        onClick={onStart}
        className="mt-5 btn-primary text-[14px] px-6 py-2.5 inline-flex items-center gap-2"
        style={{ letterSpacing: "0.04em" }}
      >
        OPEN CASE #{String(currentCase.id).padStart(3, "0")} →
      </button>
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
            Built by VortexBlack · texaegis.com
          </p>
        </div>
        <div className="flex items-center gap-4 t-micro text-[var(--color-ink-faint)] flex-wrap">
          <a href="https://texaegis.com" target="_blank" rel="noreferrer noopener" className="hover:text-[var(--color-cyan)] transition-colors">
            Product
          </a>
          <button onClick={onOpenBuyer} className="hover:text-[var(--color-cyan)] transition-colors">
            Buyer demo
          </button>
          <a href="https://www.linkedin.com/company/vortexblack" target="_blank" rel="noreferrer noopener" className="hover:text-[var(--color-cyan)] transition-colors">
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
