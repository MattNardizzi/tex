import './Orb.css';

/* =============================================================
   Orb — the breathing presence.

   The protagonist of every section. Five layers — outer atmosphere,
   mid halo, hairline ring, inner halo, core. All on a 4.2s breath
   cycle. The orb is the only soft object in the room; everything
   else is hard-edged so the softness reads as intentional.

   States:
     quiet   — at rest. Slow, even breath.
     asking  — slightly weighted. The same blue-gray, never red.
     proof   — held very still, used in the Evidence section where
               the chain is doing the talking.

   Sizes:
     xs (96px) — for inline use beside text
     sm (140px)
     md (220px)
     lg (320px)
     xl (440px) — the hero / moment surface
   ============================================================= */

export default function Orb({ state = 'quiet', size = 'lg' }) {
  return (
    <div
      className={`tex-orb tex-orb--${state} tex-orb--${size}`}
      aria-hidden="true"
    >
      <div className="tex-orb-halo-outer" />
      <div className="tex-orb-halo-mid" />
      <div className="tex-orb-ring" />
      <div className="tex-orb-halo-inner" />
      <div className="tex-orb-core" />
    </div>
  );
}
