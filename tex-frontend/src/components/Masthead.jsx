import React from "react";
import { Volume2, VolumeX, BookOpen, Info } from "lucide-react";

export default function Masthead({ onOpenAbout, onOpenDojo, onToggleSound, soundOn }) {
  return (
    <div className="panel-hairline relative">
      <div className="relative mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span
            className="t-display text-[16px] sm:text-[18px] tracking-[0.02em] text-[var(--color-ink)]"
          >
            TEX&nbsp;ARENA
          </span>
          <span className="t-micro text-[var(--color-ink-faint)] hidden sm:inline">
            · Live demo · Every verdict is real
          </span>
        </div>

        <div className="flex items-center gap-1 sm:gap-2">
          <button
            onClick={onOpenDojo}
            className="inline-flex items-center gap-1.5 px-2 py-1 t-micro text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
          >
            <BookOpen className="w-3 h-3" />
            <span className="hidden sm:inline">Dojo</span>
          </button>
          <button
            onClick={onOpenAbout}
            className="inline-flex items-center gap-1.5 px-2 py-1 t-micro text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
          >
            <Info className="w-3 h-3" />
            <span className="hidden sm:inline">What is Tex?</span>
          </button>
          <a
            href="https://texaegis.com"
            target="_blank"
            rel="noreferrer noopener"
            className="t-micro text-[var(--color-gold)] hover:text-[var(--color-gold-soft)] transition-all px-2 py-1"
          >
            Build with it →
          </a>
          <button
            onClick={onToggleSound}
            className="p-1.5 border border-[var(--color-hairline-2)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] hover:border-[var(--color-ink-dim)] transition-colors rounded-sm"
            aria-label={soundOn ? "Mute" : "Enable sound"}
          >
            {soundOn ? <Volume2 className="w-3 h-3" /> : <VolumeX className="w-3 h-3" />}
          </button>
        </div>
      </div>
    </div>
  );
}
