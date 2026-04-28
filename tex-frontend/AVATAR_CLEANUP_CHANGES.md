# AVATAR_CLEANUP_CHANGES.md — remove white frame + pink/blue hex

Two visual elements removed from the Hub Tex avatar:
1. The faded white rectangle behind/around him (was a rim-light effect
   that read as a visible frame).
2. The pink/blue hexagon overlay floating on his forehead (asset was
   misaligned and competed with his cyan eye-scan animation).

## Files

MODIFIED
- `src/components/Hub.jsx`
  - Removed `<div className="t-hex"><THexSvg title="" /></div>` from
    the HubAvatar render. THexSvg export is still defined and exported
    in case other components reuse it.

- `src/index.css`
  - Disabled the `.hub-avatar .avatar-frame::before` pseudo-element by
    setting `content: none`. Was painting a 10% white radial gradient
    in the upper-right corner via `mix-blend-mode: screen`, which read
    as a faded box around Tex. The rule shell is kept so a future
    rim-light tweak can drop in cleanly.

## What stays
- `.avatar-glow` cyan halo behind Tex (the warm atmospheric pool).
- `.eye-scan` horizontal cyan beam sweeping across his eyes — this is
  doing the "AI processing" job the hex overlay was duplicating.
- Parallax tilt on cursor move (frameRef still wires the transform).

## Build verification

  npm install
  npx vite build

Result: 27 modules, 307KB JS / 76KB CSS, gzipped 93KB / 15KB.
~-1.7KB raw vs prior build (THexSvg branch tree-shaken).
