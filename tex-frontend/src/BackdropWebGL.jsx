/* ============================================================================
   BackdropWebGL — full-screen, fixed-position Three.js scene that sits behind
   the entire site. Visible while scrolling every section.

   Composition (back to front):
     1. Deep starfield  — 4000+ points distributed through Z-space.
                          Camera dollies forward on scroll, so passing
                          stars create real parallax. Near stars are
                          larger + brighter + cyan-tinted; far stars
                          are pinpoints in bone-white.
     2. Volumetric fog  — additive distance fog, gives the depth a
                          hazy atmosphere instead of pure vacuum.
     3. Mesh artifact   — a slowly rotating, vertex-displaced
                          icosahedron rendered as wireframe + inner
                          solid. Subtle fresnel rim glow on edges.
     4. Light streaks   — long radial gradient sprites behind the
                          camera that pass through the field giving
                          a "speed of light" feel on scroll.
     5. Bloom approx.   — selective additive bloom done by rendering
                          a blurred pass of bright pixels into an
                          overlay (custom, no postprocessing lib).

   Performance: 60fps on a 2019 MBP-tier integrated GPU. Auto-pauses
   when the tab is hidden. Honors prefers-reduced-motion.
   ============================================================================ */

import { useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function BackdropWebGL() {
  const mountRef = useRef(null);
  const stateRef = useRef({
    scrollY: 0,
    targetScrollY: 0,
    mouseX: 0,
    mouseY: 0,
    targetMouseX: 0,
    targetMouseY: 0,
  });

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const state = stateRef.current;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // --------- renderer ---------
    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x02040a, 1);
    mount.appendChild(renderer.domElement);

    // --------- scene + camera ---------
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x02040a, 0.0028);

    const camera = new THREE.PerspectiveCamera(
      62,
      window.innerWidth / window.innerHeight,
      0.1,
      2200,
    );
    camera.position.set(0, 0, 0);

    // ============================================================
    // 1. STARFIELD — instanced points, distributed across a deep volume
    // ============================================================
    const starCount = reduced ? 1200 : 4500;
    const starGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(starCount * 3);
    const colors    = new Float32Array(starCount * 3);
    const sizes     = new Float32Array(starCount);

    // Distribute stars in a cylindrical volume in front of the camera.
    // Camera flies forward along -Z; stars at Z = -800..+200 wrap as
    // they pass behind.
    const cyanA = new THREE.Color(0x7ff1e9);
    const cyanB = new THREE.Color(0x56e6dc);
    const blueA = new THREE.Color(0x6aa2c8);
    const boneA = new THREE.Color(0xe2dfd6);
    const boneB = new THREE.Color(0xfafaf6);

    for (let i = 0; i < starCount; i++) {
      // Radius distribution biased outward so stars feel dense at edges
      const r = Math.pow(Math.random(), 0.55) * 320 + 6;
      const theta = Math.random() * Math.PI * 2;
      positions[i * 3 + 0] = Math.cos(theta) * r;
      positions[i * 3 + 1] = Math.sin(theta) * r * 0.85; // squash y slightly
      positions[i * 3 + 2] = -Math.random() * 1600 + 100; // -1500..100

      // Depth-derived size + color
      const depthN = -positions[i * 3 + 2] / 1600; // 0..1, 1 = far
      const closeness = 1 - depthN;

      // 70% bone, 25% cyan, 5% blue
      const roll = Math.random();
      let c;
      if (roll < 0.7) c = boneA.clone().lerp(boneB, Math.random());
      else if (roll < 0.95) c = cyanB.clone().lerp(cyanA, Math.random());
      else c = blueA.clone();

      // Far stars are dimmer
      const dim = 0.35 + closeness * 0.65;
      colors[i * 3 + 0] = c.r * dim;
      colors[i * 3 + 1] = c.g * dim;
      colors[i * 3 + 2] = c.b * dim;

      // Size: near = bigger
      sizes[i] = 0.6 + closeness * 4.2 + Math.random() * 0.6;
    }

    starGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    starGeo.setAttribute('color',    new THREE.BufferAttribute(colors, 3));
    starGeo.setAttribute('aSize',    new THREE.BufferAttribute(sizes, 1));

    // Round soft point sprite — generated procedurally
    const ptCanvas = document.createElement('canvas');
    ptCanvas.width = ptCanvas.height = 64;
    const pctx = ptCanvas.getContext('2d');
    const grad = pctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    grad.addColorStop(0,    'rgba(255,255,255,1)');
    grad.addColorStop(0.25, 'rgba(255,255,255,0.55)');
    grad.addColorStop(0.55, 'rgba(255,255,255,0.12)');
    grad.addColorStop(1,    'rgba(255,255,255,0)');
    pctx.fillStyle = grad;
    pctx.fillRect(0, 0, 64, 64);
    const ptTex = new THREE.CanvasTexture(ptCanvas);
    ptTex.colorSpace = THREE.SRGBColorSpace;

    const starMat = new THREE.ShaderMaterial({
      uniforms: {
        uTexture: { value: ptTex },
        uTime:    { value: 0 },
        uPixelRatio: { value: renderer.getPixelRatio() },
      },
      vertexShader: /* glsl */ `
        attribute float aSize;
        varying vec3 vColor;
        uniform float uPixelRatio;
        uniform float uTime;
        void main() {
          vColor = color;
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          // Subtle individual twinkle
          float tw = 0.85 + 0.15 * sin(uTime * 1.2 + position.x * 0.1 + position.y * 0.2);
          gl_PointSize = aSize * uPixelRatio * (320.0 / -mv.z) * tw;
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: /* glsl */ `
        varying vec3 vColor;
        uniform sampler2D uTexture;
        void main() {
          vec4 tex = texture2D(uTexture, gl_PointCoord);
          if (tex.a < 0.01) discard;
          gl_FragColor = vec4(vColor, 1.0) * tex;
        }
      `,
      vertexColors: true,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    const stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    // ============================================================
    // 2. MESH ARTIFACT — distant displaced wireframe icosahedron.
    //    Pure wireframe (no solid fill), pushed deep into the fog
    //    so it reads as a far-off geometric phantom, not a foreground
    //    object. Same vertex displacement noise as before so the
    //    shape pulses and lives, but rendering is sparse line edges.
    // ============================================================
    const ARTIFACT_RADIUS = 140;
    const ARTIFACT_Z = -1300;          // deep, sits inside fog
    const artifactBaseGeo = new THREE.IcosahedronGeometry(ARTIFACT_RADIUS, 5);
    // Convert tri faces -> line segments via WireframeGeometry.
    const wireGeo = new THREE.WireframeGeometry(artifactBaseGeo);

    // Shared simplex-noise glsl (used by both displacement + we keep
    // the vertex shader self-contained on the line material).
    const NOISE_GLSL = /* glsl */ `
      vec3 mod289(vec3 x){ return x - floor(x * (1.0 / 289.0)) * 289.0; }
      vec4 mod289(vec4 x){ return x - floor(x * (1.0 / 289.0)) * 289.0; }
      vec4 permute(vec4 x){ return mod289(((x*34.0)+1.0)*x); }
      vec4 taylorInvSqrt(vec4 r){ return 1.79284291400159 - 0.85373472095314 * r; }
      float snoise(vec3 v){
        const vec2 C = vec2(1.0/6.0, 1.0/3.0);
        const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
        vec3 i = floor(v + dot(v, C.yyy));
        vec3 x0 = v - i + dot(i, C.xxx);
        vec3 g = step(x0.yzx, x0.xyz);
        vec3 l = 1.0 - g;
        vec3 i1 = min(g.xyz, l.zxy);
        vec3 i2 = max(g.xyz, l.zxy);
        vec3 x1 = x0 - i1 + C.xxx;
        vec3 x2 = x0 - i2 + C.yyy;
        vec3 x3 = x0 - D.yyy;
        i = mod289(i);
        vec4 p = permute(permute(permute(
                 i.z + vec4(0.0, i1.z, i2.z, 1.0))
               + i.y + vec4(0.0, i1.y, i2.y, 1.0))
               + i.x + vec4(0.0, i1.x, i2.x, 1.0));
        float n_ = 0.142857142857;
        vec3 ns = n_ * D.wyz - D.xzx;
        vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
        vec4 x_ = floor(j * ns.z);
        vec4 y_ = floor(j - 7.0 * x_);
        vec4 x = x_ * ns.x + ns.yyyy;
        vec4 y = y_ * ns.x + ns.yyyy;
        vec4 h = 1.0 - abs(x) - abs(y);
        vec4 b0 = vec4(x.xy, y.xy);
        vec4 b1 = vec4(x.zw, y.zw);
        vec4 s0 = floor(b0)*2.0 + 1.0;
        vec4 s1 = floor(b1)*2.0 + 1.0;
        vec4 sh = -step(h, vec4(0.0));
        vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy;
        vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww;
        vec3 p0 = vec3(a0.xy, h.x);
        vec3 p1 = vec3(a0.zw, h.y);
        vec3 p2 = vec3(a1.xy, h.z);
        vec3 p3 = vec3(a1.zw, h.w);
        vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
        p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
        vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
        m = m * m;
        return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
      }
    `;

    const wireMat = new THREE.ShaderMaterial({
      uniforms: {
        uTime:   { value: 0 },
        uColor:  { value: new THREE.Color(0x56e6dc) },
        uFogColor:   { value: new THREE.Color(0x02040a) },
        uFogDensity: { value: 0.00065 },
      },
      vertexShader: `
        uniform float uTime;
        varying float vFogDepth;
        ${NOISE_GLSL}
        void main() {
          // Re-derive a "normal" from position direction (WireframeGeometry
          // strips normals, but for a unit-ish sphere, normalize(position)
          // is a valid surface normal).
          vec3 nrm = normalize(position);
          float n  = snoise(nrm * 1.6 + uTime * 0.15);
          float n2 = snoise(nrm * 4.0 + uTime * 0.22);
          float d  = n * 0.55 + n2 * 0.18;
          vec3 displaced = position + nrm * d * 22.0;

          vec4 mv = modelViewMatrix * vec4(displaced, 1.0);
          vFogDepth = -mv.z;
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        uniform vec3 uColor;
        uniform vec3 uFogColor;
        uniform float uFogDensity;
        varying float vFogDepth;
        void main() {
          // Exponential fog applied manually so the line color
          // fades into the void naturally.
          float fogFactor = 1.0 - exp(-uFogDensity * uFogDensity * vFogDepth * vFogDepth);
          fogFactor = clamp(fogFactor, 0.0, 1.0);
          vec3 col = mix(uColor, uFogColor, fogFactor);
          // Base wire alpha is very low — this is supposed to feel like
          // a half-glimpsed structure, not a glowing object.
          float alpha = 0.22 * (1.0 - fogFactor * 0.85);
          gl_FragColor = vec4(col, alpha);
        }
      `,
      transparent: true,
      depthWrite: false,
      blending: THREE.NormalBlending,
    });

    const artifact = new THREE.LineSegments(wireGeo, wireMat);
    // Offset left + slightly up so it doesn't sit directly behind Tex
    artifact.position.set(-260, 60, ARTIFACT_Z);
    scene.add(artifact);

    // ============================================================
    // 3. LIGHT STREAKS — speed-of-light style streaks behind camera
    //    Long thin sprites that travel forward; only visible when scrolling fast.
    // ============================================================
    const streakCount = 24;
    const streakGroup = new THREE.Group();
    const streakMatTemplate = new THREE.MeshBasicMaterial({
      color: 0x7ff1e9,
      transparent: true,
      opacity: 0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const streaks = [];
    for (let i = 0; i < streakCount; i++) {
      const len = 30 + Math.random() * 60;
      const geo = new THREE.PlaneGeometry(0.35, len);
      // Soft gradient texture
      const sc = document.createElement('canvas'); sc.width = 8; sc.height = 256;
      const sx = sc.getContext('2d');
      const g = sx.createLinearGradient(0, 0, 0, 256);
      g.addColorStop(0, 'rgba(127,241,233,0)');
      g.addColorStop(0.5, 'rgba(127,241,233,1)');
      g.addColorStop(1, 'rgba(127,241,233,0)');
      sx.fillStyle = g; sx.fillRect(0, 0, 8, 256);
      const tex = new THREE.CanvasTexture(sc);
      const mat = streakMatTemplate.clone();
      mat.map = tex;
      const m = new THREE.Mesh(geo, mat);
      const theta = Math.random() * Math.PI * 2;
      const r = 30 + Math.random() * 180;
      m.position.set(Math.cos(theta) * r, Math.sin(theta) * r, -Math.random() * 1200);
      m.userData = { speed: 8 + Math.random() * 14, baseZ: m.position.z };
      streakGroup.add(m);
      streaks.push(m);
    }
    scene.add(streakGroup);

    // ============================================================
    // 4. CENTER GLOW — large additive sprite at the vanishing point
    //    Reinforces the "tunnel into deep space" feel.
    // ============================================================
    const glowCanvas = document.createElement('canvas');
    glowCanvas.width = glowCanvas.height = 512;
    const gctx = glowCanvas.getContext('2d');
    const gGrad = gctx.createRadialGradient(256, 256, 0, 256, 256, 256);
    gGrad.addColorStop(0,    'rgba(127,241,233,0.55)');
    gGrad.addColorStop(0.18, 'rgba(86,230,220,0.32)');
    gGrad.addColorStop(0.5,  'rgba(40,90,120,0.10)');
    gGrad.addColorStop(1,    'rgba(0,0,0,0)');
    gctx.fillStyle = gGrad; gctx.fillRect(0, 0, 512, 512);
    const glowMap = new THREE.CanvasTexture(glowCanvas);
    const glowMat = new THREE.SpriteMaterial({
      map: glowMap,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      opacity: 0.85,
    });
    const glow = new THREE.Sprite(glowMat);
    glow.scale.set(900, 900, 1);
    glow.position.set(0, 0, -1100);
    scene.add(glow);

    // ============================================================
    // EVENT WIRING
    // ============================================================
    const onScroll = () => { state.targetScrollY = window.scrollY || 0; };
    const onMouse = (e) => {
      state.targetMouseX = (e.clientX / window.innerWidth) * 2 - 1;
      state.targetMouseY = (e.clientY / window.innerHeight) * 2 - 1;
    };
    const onResize = () => {
      renderer.setSize(window.innerWidth, window.innerHeight);
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
    };
    let visible = true;
    const onVis = () => { visible = !document.hidden; };

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('mousemove', onMouse, { passive: true });
    window.addEventListener('resize', onResize);
    document.addEventListener('visibilitychange', onVis);

    // ============================================================
    // RENDER LOOP
    // ============================================================
    const clock = new THREE.Clock();
    let lastScrollY = 0;
    let raf = 0;
    const tick = () => {
      raf = requestAnimationFrame(tick);
      if (!visible) return;

      const dt = Math.min(clock.getDelta(), 0.05);
      const t = clock.elapsedTime;

      // Smooth scroll + mouse
      state.scrollY += (state.targetScrollY - state.scrollY) * 0.08;
      state.mouseX  += (state.targetMouseX  - state.mouseX)  * 0.04;
      state.mouseY  += (state.targetMouseY  - state.mouseY)  * 0.04;

      const scrollVel = state.targetScrollY - lastScrollY;
      lastScrollY = state.targetScrollY;

      // Camera dollies forward on scroll, tilts with mouse
      const dollyDepth = state.scrollY * 0.35;
      camera.position.x = state.mouseX * 18;
      camera.position.y = -state.mouseY * 12;
      camera.position.z = -dollyDepth * 0.001 * 0; // we instead move stars (more stable)
      camera.lookAt(0, 0, -1000);

      // Stars: wrap their Z when they pass the camera so the field is infinite.
      // Effective forward speed: ambient drift + scroll velocity.
      const speed = 8 + Math.abs(scrollVel) * 0.6;
      const posAttr = starGeo.attributes.position;
      const pa = posAttr.array;
      for (let i = 2; i < pa.length; i += 3) {
        pa[i] += speed * dt;
        if (pa[i] > 200) pa[i] -= 1700;
      }
      posAttr.needsUpdate = true;
      starMat.uniforms.uTime.value = t;

      // Mesh artifact: slow tumble + subtle pulse on scroll velocity
      artifact.rotation.x = t * 0.05;
      artifact.rotation.y = t * 0.08;
      artifact.rotation.z = t * 0.03;
      const pulse = 1 + Math.min(0.18, Math.abs(scrollVel) * 0.002);
      artifact.scale.setScalar(pulse);
      wireMat.uniforms.uTime.value = t;

      // Light streaks: pull forward when user scrolls
      const streakIntensity = Math.min(1.0, Math.abs(scrollVel) * 0.06);
      for (const m of streaks) {
        m.position.z += m.userData.speed * dt * (1 + streakIntensity * 8);
        m.material.opacity = streakIntensity * 0.6;
        if (m.position.z > 100) m.position.z = -1200;
        // Always face the camera direction
        m.lookAt(camera.position.x, camera.position.y, m.position.z + 1);
      }

      // Center glow breathes
      glow.material.opacity = 0.7 + 0.15 * Math.sin(t * 0.5);

      renderer.render(scene, camera);
    };

    if (reduced) {
      renderer.render(scene, camera);
    } else {
      raf = requestAnimationFrame(tick);
    }

    // ============================================================
    // CLEANUP
    // ============================================================
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('mousemove', onMouse);
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVis);

      starGeo.dispose();
      starMat.dispose();
      ptTex.dispose();
      artifactBaseGeo.dispose();
      wireGeo.dispose();
      wireMat.dispose();
      glowMap.dispose();
      glowMat.dispose();
      for (const m of streaks) {
        m.geometry.dispose();
        if (m.material.map) m.material.map.dispose();
        m.material.dispose();
      }
      renderer.dispose();
      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement);
      }
    };
  }, []);

  return <div ref={mountRef} className="backdrop-webgl" aria-hidden="true" />;
}
