import React, { useRef } from "react";
import { Check, Flame, ChevronRight, Coins } from "lucide-react";

/*
  ROUND SELECTOR — v3
  Fight card row. 7 opponents. Horizontal scroll on narrow viewports.
  The R7 bounty tile is gold-bordered with a persistent gold ribbon.
  Scroll fade on the right + a "See all 7 →" affordance label.
*/

export default function RoundSelector({ rounds, currentRound, roundsWon, perRound, onSelect }) {
  const scrollRef = useRef(null);

  function scrollRight() {
    if (scrollRef.current) {
      scrollRef.current.scrollBy({ left: 240, behavior: "smooth" });
    }
  }

  return (
    <nav className="relative bg-[var(--color-bg)] pt-5 pb-4 border-b border-[var(--color-hairline-2)]">
      <div className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12">
        <div className="flex items-end justify-between mb-3">
          <div>
            <div className="t-micro text-[var(--color-ink-faint)] mb-1">Tonight's Fight Card</div>
            <div className="t-display text-[20px] sm:text-[22px] text-[var(--color-ink)] leading-none">
              7 Opponents · Rising Difficulty
            </div>
          </div>
          <button
            onClick={scrollRight}
            className="t-micro text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors inline-flex items-center gap-1 lg:hidden"
          >
            Swipe <ChevronRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      <div className="scroll-fade-right">
        <div
          ref={scrollRef}
          className="mx-auto max-w-[1400px] flex items-stretch gap-3 overflow-x-auto no-scrollbar snap-x snap-mandatory px-5 sm:px-8 lg:px-12"
          style={{ paddingRight: "112px", paddingTop: "10px", paddingBottom: "4px" }}
        >
          {rounds.map((round) => {
            const isActive = currentRound.id === round.id;
            const isWon = roundsWon.includes(round.id);
            const record = perRound?.[round.id] || null;
            return (
              <OpponentTile
                key={round.id}
                round={round}
                isActive={isActive}
                isWon={isWon}
                record={record}
                onSelect={() => onSelect(round)}
              />
            );
          })}
        </div>
      </div>
    </nav>
  );
}

function OpponentTile({ round, isActive, isWon, record, onSelect }) {
  const isBounty = Boolean(round.isBounty);

  return (
    <button
      onClick={onSelect}
      className={`tile ${isActive ? "tile-active" : ""} ${isBounty ? "tile-bounty" : ""} relative flex-shrink-0 snap-start w-[200px] sm:w-[216px] text-left`}
    >
      {/* Bounty ribbon — persistent, not tiny badge */}
      {isBounty && (
        <div
          className="absolute -top-[10px] left-3 right-3 h-[20px] flex items-center justify-center"
          style={{
            background: "linear-gradient(180deg, #ffe14a 0%, #d4b820 100%)",
            color: "#120a00",
            fontFamily: "var(--font-mono)",
            fontSize: "9px",
            fontWeight: 700,
            letterSpacing: "0.22em",
            textTransform: "uppercase",
            boxShadow: "0 4px 16px rgba(255, 225, 74, 0.35)",
          }}
        >
          ★ HALL OF FAME · UNCLAIMED ★
        </div>
      )}

      {isWon && (
        <div
          className="absolute top-2 right-2 z-10 w-5 h-5 flex items-center justify-center"
          style={{
            background: "var(--color-permit)",
            boxShadow: "0 0 10px rgba(59, 224, 130, 0.5)",
            borderRadius: "2px",
          }}
        >
          <Check className="w-3 h-3 text-[var(--color-bg)]" strokeWidth={3.5} />
        </div>
      )}

      <div className="p-3 pt-4">
        {/* Round num + difficulty */}
        <div className="flex items-center justify-between mb-2">
          <span
            className="t-micro"
            style={{
              color: isBounty
                ? "var(--color-gold)"
                : isActive
                ? "var(--color-pink)"
                : "var(--color-ink-faint)",
            }}
          >
            Round&nbsp;{round.id}
          </span>
          <DifficultyFlames
            score={round.difficultyScore}
            color={isBounty ? "var(--color-gold)" : "var(--color-pink)"}
          />
        </div>

        {/* Opponent name */}
        <div
          className="t-display text-[18px] sm:text-[19px] leading-[0.95] text-[var(--color-ink)] mt-1"
          style={{ letterSpacing: "0.01em" }}
        >
          {round.name.replace("The ", "").toUpperCase()}
        </div>
        <div
          className="font-[var(--font-accent)] italic text-[12px] leading-tight text-[var(--color-ink-faint)] mt-1 h-[28px] overflow-hidden"
        >
          {round.tagline}
        </div>

        {/* Record */}
        <div className="mt-3 pt-3 border-t border-[var(--color-hairline)]">
          {record ? (
            <RecordRow record={record} />
          ) : (
            <div className="flex items-center justify-between">
              <span className="t-micro text-[var(--color-ink-faint)]">
                {isBounty ? "Bounty" : "First fight"}
              </span>
              {isBounty && (
                <Coins className="w-3 h-3" style={{ color: "var(--color-gold)" }} />
              )}
            </div>
          )}
        </div>
      </div>
    </button>
  );
}

function RecordRow({ record }) {
  const { attempts, wins, losses, draws, bestScore } = record;
  return (
    <div>
      <div className="flex items-center gap-2 font-mono text-[10px] text-[var(--color-ink-dim)] mb-1">
        <span>
          <span style={{ color: "var(--color-permit)" }}>{wins}</span>W
        </span>
        <span>
          <span className="text-[var(--color-red)]">{losses}</span>L
        </span>
        <span>
          <span className="text-[var(--color-gold)]">{draws}</span>D
        </span>
        <span className="ml-auto text-[var(--color-ink-faint)]">×{attempts}</span>
      </div>
      <div>
        <div className="flex items-baseline justify-between text-[9px] font-mono uppercase tracking-[0.18em] text-[var(--color-ink-faint)]">
          <span>Closest</span>
          <span>{Math.round(bestScore * 100)}%</span>
        </div>
        <div className="h-[3px] bg-[var(--color-hairline)] mt-1 relative">
          <div
            className="absolute inset-y-0 left-0 bg-[var(--color-cyan)] transition-all duration-500"
            style={{
              width: `${Math.round(bestScore * 100)}%`,
              boxShadow: "0 0 4px rgba(95, 240, 255, 0.5)",
            }}
          />
        </div>
      </div>
    </div>
  );
}

function DifficultyFlames({ score, color }) {
  const active = Math.min(7, score);
  return (
    <div className="flex items-center gap-[1px]">
      {Array.from({ length: 7 }).map((_, i) => (
        <Flame
          key={i}
          className="w-[9px] h-[9px]"
          strokeWidth={2.5}
          style={{
            color: i < active ? color : "rgba(255,255,255,0.12)",
            fill: i < active ? color : "none",
          }}
        />
      ))}
    </div>
  );
}
