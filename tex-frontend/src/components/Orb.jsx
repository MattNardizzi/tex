import './Orb.css';

/**
 * Orb — the breathing presence at the center of Tex.
 *
 * Lifted directly from the product dashboard so the marketing site and the
 * product share one surface. The same component renders in both places.
 *
 * Two states:
 *   - "quiet"  : centered, slow rhythm. Nothing needs you.
 *   - "asking" : the orb is now slightly slower; positioning is the caller's job.
 *
 * Color in both states is the same cool blue-gray. We never panic-flash to red
 * or amber on the surface — the composition tells the user something changed,
 * not the temperature of the room.
 */
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
