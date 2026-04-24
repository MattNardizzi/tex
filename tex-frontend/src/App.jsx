import React, { useEffect, useRef, useState } from "react";
import ArenaHero from "./components/ArenaHero";
import Masthead from "./components/Masthead";
import RoundSelector from "./components/RoundSelector";
import BriefCard from "./components/BriefCard";
import AttackComposer from "./components/AttackComposer";
import TexThinking from "./components/TexThinking";
import VerdictReveal from "./components/VerdictReveal";
import FighterCard from "./components/FighterCard";
import ShareCard from "./components/ShareCard";
import Dojo from "./components/Dojo";
import AboutSheet from "./components/AboutSheet";
import HandleGate from "./components/HandleGate";
import HowToPlayOverlay from "./components/HowToPlayOverlay";
import BountyClaim from "./components/BountyClaim";
import BuyerSurface from "./components/BuyerSurface";

import {
  ROUNDS,
  computeRoundPoints,
  BOUNTY_ROUND_ID,
} from "./lib/rounds";
import { submitAttack } from "./lib/apiClient";
import {
  getPlayer,
  savePlayer,
  recordFightResult,
  claimBounty as claimBountyState,
  rankForPoints,
} from "./lib/storage";
import {
  isSoundEnabled,
  setSoundEnabled,
  bellSound,
  punchSound,
  winFanfare,
  loseSting,
  drawChime,
  coinSound,
  rankUpSound,
} from "./lib/sound";

const HOW_TO_KEY = "tex-arena/how-to-seen/v4";

export default function App() {
  const [player, setPlayer] = useState(() => getPlayer());
  const [currentRound, setCurrentRound] = useState(ROUNDS[0]);
  const [attackText, setAttackText] = useState("");
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [decision, setDecision] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [pointsEarned, setPointsEarned] = useState(0);

  const [priorBestScore, setPriorBestScore] = useState(null);

  const [soundOn, setSoundOn] = useState(() =>
    typeof window !== "undefined" ? isSoundEnabled() : false
  );

  const [showDojo, setShowDojo] = useState(false);
  const [showShare, setShowShare] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showHandleGate, setShowHandleGate] = useState(false);
  const [showBuyerSurface, setShowBuyerSurface] = useState(false);
  const [showHowTo, setShowHowTo] = useState(() => {
    try {
      return typeof window !== "undefined" && !localStorage.getItem(HOW_TO_KEY);
    } catch {
      return true;
    }
  });
  const [showBountyClaim, setShowBountyClaim] = useState(false);
  const [duelFrom, setDuelFrom] = useState(""); // @handle who challenged this session, empty if not a duel landing

  const activeRunRef = useRef(0);
  const verdictRef = useRef(null);
  const composerRef = useRef(null);
  const arenaRef = useRef(null);

  useEffect(() => {
    savePlayer(player);
  }, [player]);

  // Deep-link: /buyer or ?buyer opens the buyer surface directly, so
  // LinkedIn posts can point CISOs straight into the technical demo
  // without forcing them through the arena.
  //
  // ?duel=<roundId>&from=<handle>  is the peer-challenge link emitted
  // by ShareCard. We land the recipient straight on the round their
  // friend played, with a small banner saying who challenged them.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search } = window.location;
    if (pathname.startsWith("/buyer") || search.includes("buyer")) {
      setShowBuyerSurface(true);
      return;
    }
    const params = new URLSearchParams(search);
    const duelId = parseInt(params.get("duel") || "", 10);
    const fromHandle = (params.get("from") || "").replace(/^@/, "").slice(0, 32);
    if (duelId) {
      const targetRound = ROUNDS.find((r) => r.id === duelId);
      if (targetRound) {
        setCurrentRound(targetRound);
        if (fromHandle) setDuelFrom(fromHandle);
      }
    }
  }, []);

  const isLastRound = currentRound.id === ROUNDS[ROUNDS.length - 1].id;

  function handleToggleSound() {
    const next = !soundOn;
    setSoundEnabled(next);
    setSoundOn(next);
    if (next) bellSound();
  }

  function dismissHowTo() {
    try { localStorage.setItem(HOW_TO_KEY, "1"); } catch {}
    setShowHowTo(false);
    if (!player.handle && player.attackCount === 0) {
      setShowHandleGate(true);
    }
  }

  function handleStartPlaying() {
    dismissHowTo();
    setTimeout(() => {
      if (arenaRef.current) {
        arenaRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 100);
  }

  function handleOpenBuyerSurface() {
    setShowBuyerSurface(true);
  }

  function handleSelectRound(round) {
    if (round.id === currentRound.id && decision) return;
    bellSound();
    setCurrentRound(round);
    setAttackText("");
    setDecision(null);
    setPointsEarned(0);
    setErrorMessage("");
    setPriorBestScore(null);
    setTimeout(() => {
      if (window.innerWidth < 1024 && composerRef.current) {
        composerRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 120);
  }

  function handleNextRound() {
    const idx = ROUNDS.findIndex((r) => r.id === currentRound.id);
    const next = ROUNDS[Math.min(idx + 1, ROUNDS.length - 1)];
    handleSelectRound(next);
  }

  async function handleSubmit() {
    if (!attackText.trim() || isEvaluating) return;

    const runId = Date.now();
    activeRunRef.current = runId;
    setIsEvaluating(true);
    setDecision(null);
    setPointsEarned(0);
    setErrorMessage("");
    punchSound();

    const prior = player.perRound?.[currentRound.id]?.bestScore ?? 0;
    setPriorBestScore(prior);

    const minimumThinkingMs = 2000;
    const t0 = performance.now();

    try {
      const result = await submitAttack({ round: currentRound, content: attackText });

      const elapsed = performance.now() - t0;
      const wait = Math.max(0, minimumThinkingMs - elapsed);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));

      if (activeRunRef.current !== runId) return;

      setDecision(result);

      const points = computeRoundPoints(result.verdict, currentRound);
      setPointsEarned(points);

      if (result.verdict === "PERMIT") {
        winFanfare();
        if (points > 0) setTimeout(coinSound, 600);
      } else if (result.verdict === "FORBID") {
        loseSting();
      } else {
        drawChime();
      }

      const prevRank = rankForPoints(player.totalPoints).current.tier;
      const nextPlayer = recordFightResult(player, {
        roundId: currentRound.id,
        verdict: result.verdict,
        points,
        decision: result,
      });
      const newRank = rankForPoints(nextPlayer.totalPoints).current.tier;
      if (newRank > prevRank) {
        setTimeout(rankUpSound, 1400);
      }
      setPlayer(nextPlayer);

      if (
        result.verdict === "PERMIT" &&
        currentRound.id === BOUNTY_ROUND_ID &&
        !player.bountyClaimed
      ) {
        setTimeout(() => setShowBountyClaim(true), 1800);
      }

      setTimeout(() => {
        if (verdictRef.current) {
          verdictRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 160);
    } catch (err) {
      if (activeRunRef.current !== runId) return;
      setErrorMessage(
        err instanceof Error ? err.message : "Something went wrong talking to Tex."
      );
    } finally {
      if (activeRunRef.current === runId) setIsEvaluating(false);
    }
  }

  function handleTryAgain() {
    setAttackText("");
    setDecision(null);
    setPointsEarned(0);
    setErrorMessage("");
    setTimeout(() => {
      if (composerRef.current)
        composerRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 80);
  }

  function handleReset() {
    setAttackText("");
    setDecision(null);
    setPointsEarned(0);
    setErrorMessage("");
  }

  function handleSetHandle(handle) {
    setPlayer((p) => ({ ...p, handle }));
    setShowHandleGate(false);
  }

  function handleSkipHandle() {
    setShowHandleGate(false);
  }

  function handleClaimBounty() {
    setShowBountyClaim(true);
  }

  function handleCloseBountyClaim() {
    setShowBountyClaim(false);
    setPlayer((p) => claimBountyState(p));
  }

  const currentRecord = player.perRound?.[currentRound.id] || null;
  const totalAttempts = player.attackCount;
  const asiFindingsCount = player.asiFindingsCount || 0;
  const asiCategoriesSeenCount = (player.asiCategoriesSeen || []).length;

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-ink)] relative">
      {/* HERO */}
      <ArenaHero
        onStartPlaying={handleStartPlaying}
        onOpenBuyerSurface={handleOpenBuyerSurface}
        onToggleSound={handleToggleSound}
        soundOn={soundOn}
        onAbout={() => setShowAbout(true)}
        totalAttempts={totalAttempts}
        asiFindingsCount={asiFindingsCount}
        asiCategoriesSeenCount={asiCategoriesSeenCount}
        bountyClaimed={player.bountyClaimed}
        claimersSoFar={0}
      />

      {/* Masthead nav */}
      <Masthead
        onOpenAbout={() => setShowAbout(true)}
        onOpenDojo={() => setShowDojo(true)}
        onToggleSound={handleToggleSound}
        soundOn={soundOn}
      />

      {/* ARENA */}
      <div ref={arenaRef} className="bg-[var(--color-bg)] pt-5 pb-10">
        <div className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12">
          <div className="mb-4">
            <FighterCard
              player={player}
              onEditHandle={() => setShowHandleGate(true)}
            />
          </div>

          {duelFrom && (
            <div
              className="mb-4 panel flex items-center justify-between gap-2 px-4 py-3 rise-in"
              style={{
                borderColor: "var(--color-pink)",
                boxShadow: "0 0 0 1px var(--color-pink), 0 0 24px rgba(255, 61, 122, 0.2)",
              }}
            >
              <div className="flex items-center gap-3">
                <span className="text-[18px]">⚔</span>
                <div>
                  <div className="t-micro text-[var(--color-pink)]">
                    Duel · Round {currentRound.id}
                  </div>
                  <div
                    className="mt-0.5 text-[14px] italic"
                    style={{ fontFamily: "var(--font-serif)", color: "var(--color-ink)" }}
                  >
                    @{duelFrom} challenged you on <span className="font-bold not-italic">{currentRound.name}</span>. Beat their score.
                  </div>
                </div>
              </div>
              <button
                onClick={() => setDuelFrom("")}
                className="t-micro text-[var(--color-ink-faint)] hover:text-[var(--color-ink)] transition-colors"
                aria-label="Dismiss duel banner"
              >
                Dismiss
              </button>
            </div>
          )}
        </div>

        <RoundSelector
          rounds={ROUNDS}
          currentRound={currentRound}
          roundsWon={player.roundsWon}
          perRound={player.perRound}
          onSelect={handleSelectRound}
        />

        <main className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 py-6">
          {errorMessage && (
            <div
              className="mb-4 panel border-l-4 px-4 py-3 flex items-start gap-3"
              style={{ borderLeftColor: "var(--color-red)" }}
            >
              <span className="t-micro text-[var(--color-red)] pt-0.5 flex-shrink-0">
                Error
              </span>
              <p className="text-[13px] leading-[1.5] text-[var(--color-ink)]">
                {errorMessage}
              </p>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-5">
            {/* Brief — left */}
            <div className="lg:col-span-5 xl:col-span-4">
              <BriefCard round={currentRound} record={currentRecord} />
            </div>

            {/* Composer / Thinking / Verdict — right */}
            <div
              ref={composerRef}
              className="lg:col-span-7 xl:col-span-8 space-y-4"
            >
              {!isEvaluating && !decision && (
                <AttackComposer
                  round={currentRound}
                  value={attackText}
                  onChange={setAttackText}
                  onSubmit={handleSubmit}
                  onReset={handleReset}
                  isEvaluating={isEvaluating}
                  disabled={false}
                />
              )}

              {isEvaluating && <TexThinking visible={isEvaluating} />}

              {decision && !isEvaluating && (
                <div ref={verdictRef} className="space-y-4">
                  <VerdictReveal
                    decision={decision}
                    round={currentRound}
                    pointsEarned={pointsEarned}
                    personalBest={priorBestScore}
                    onShare={() => setShowShare(true)}
                    onNextRound={handleNextRound}
                    onOpenDojo={() => setShowDojo(true)}
                    onTryAgain={handleTryAgain}
                    onClaimBounty={handleClaimBounty}
                    isLastRound={isLastRound}
                  />

                  <ContentEchoCard content={attackText} />

                  {/* Rematch strip */}
                  <div className="panel flex items-center justify-between gap-2 px-4 py-3">
                    <div>
                      <div className="t-micro text-[var(--color-ink-faint)]">
                        Not satisfied?
                      </div>
                      <div
                        className="mt-0.5 text-[14px] italic"
                        style={{
                          fontFamily: "var(--font-serif)",
                          color: "var(--color-ink)",
                        }}
                      >
                        Rewrite your strike and throw again.
                      </div>
                    </div>
                    <button
                      onClick={handleTryAgain}
                      className="btn-ghost"
                      style={{
                        borderColor: "var(--color-pink)",
                        color: "var(--color-pink)",
                      }}
                    >
                      Rematch
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </main>

        <Footer onOpenBuyerSurface={handleOpenBuyerSurface} />
      </div>

      {/* Overlays */}
      {showHowTo && <HowToPlayOverlay onDismiss={dismissHowTo} />}
      {showDojo && (
        <Dojo
          decision={decision}
          round={currentRound}
          onClose={() => setShowDojo(false)}
        />
      )}
      {showShare && decision && (
        <ShareCard
          decision={decision}
          round={currentRound}
          player={player}
          onClose={() => setShowShare(false)}
        />
      )}
      {showAbout && <AboutSheet onClose={() => setShowAbout(false)} />}
      {showHandleGate && (
        <HandleGate onSet={handleSetHandle} onSkip={handleSkipHandle} />
      )}
      {showBountyClaim && decision && (
        <BountyClaim
          decision={decision}
          submittedContent={attackText}
          onClose={handleCloseBountyClaim}
          claimersSoFar={0}
        />
      )}
      {showBuyerSurface && (
        <BuyerSurface onClose={() => setShowBuyerSurface(false)} />
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function ContentEchoCard({ content }) {
  if (!content) return null;
  return (
    <section className="panel overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--color-hairline)]">
        <span className="t-micro text-[var(--color-ink-faint)]">Your strike</span>
        <span className="t-micro text-[var(--color-ink-faint)]">
          {content.length} chars
        </span>
      </div>
      <pre
        className="p-4 font-mono text-[12px] leading-[1.65] text-[var(--color-ink)] whitespace-pre-wrap break-words"
        style={{ fontFamily: "var(--font-mono)" }}
      >
        {content}
      </pre>
    </section>
  );
}

function Footer({ onOpenBuyerSurface }) {
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
          <div
            className="t-display text-[18px] leading-none text-[var(--color-ink)]"
            style={{ letterSpacing: "0.02em" }}
          >
            TEX ARENA
          </div>
          <p className="t-micro text-[var(--color-ink-faint)] mt-1.5">
            Built by VortexBlack · texaegis.com
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
          <button
            onClick={onOpenBuyerSurface}
            className="hover:text-[var(--color-cyan)] transition-colors"
          >
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
          <span className="text-[var(--color-ink-faint)] opacity-50">·</span>
          <span
            className="italic normal-case tracking-normal text-[12px] text-[var(--color-ink-faint)]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            Live demo. Every verdict is real.
          </span>
        </div>
      </div>
    </footer>
  );
}
