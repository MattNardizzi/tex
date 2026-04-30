import * as THREE from 'three';

/**
 * TexField — a continuous WebGL judgment field.
 *
 * Concept:
 *   The screen is the AI surface of an enterprise. Hundreds of agents float
 *   in volumetric space. They emit actions outward. An invisible spherical
 *   membrane of judgment surrounds them; every action passes through it.
 *   PERMIT actions stream outward in cyan. ABSTAIN actions are tagged and
 *   held mid-flight in amber. FORBID actions detonate at the membrane in
 *   red, scattering, and become evidence on a chronological hash chain
 *   woven beneath the field.
 *
 *   Tex himself is the central presence — a flat backplate inside the
 *   membrane, his chest emblem the heartbeat. He does not narrate. He
 *   adjudicates.
 */

const VERDICTS = ['permit', 'permit', 'permit', 'permit', 'permit', 'permit', 'abstain', 'abstain', 'forbid'];

const ACTION_TEMPLATES = [
  { kind: 'email.send',         color: 0x00d9ff },
  { kind: 'slack.dm',           color: 0x00d9ff },
  { kind: 'slack.post',         color: 0x00d9ff },
  { kind: 'postgres.update',    color: 0x9aa3b2 },
  { kind: 'postgres.delete',    color: 0xff4757 },
  { kind: 'mongo.write',        color: 0x9aa3b2 },
  { kind: 'salesforce.update',  color: 0x9aa3b2 },
  { kind: 'stripe.refund',      color: 0xffb547 },
  { kind: 'stripe.charge',      color: 0xffb547 },
  { kind: 'github.push',        color: 0x9aa3b2 },
  { kind: 'github.merge',       color: 0x9aa3b2 },
  { kind: 'shell.exec',         color: 0xff4757 },
  { kind: 'file.delete',        color: 0xff4757 },
  { kind: 'mcp.tool_call',      color: 0x00d9ff },
  { kind: 'calendar.invite',    color: 0x00d9ff },
  { kind: 'docs.share',         color: 0x9aa3b2 },
  { kind: 'http.post',          color: 0x9aa3b2 },
  { kind: 's3.put',             color: 0x9aa3b2 },
  { kind: 'iam.grant',          color: 0xff4757 },
  { kind: 'twilio.sms',         color: 0x00d9ff },
];

const VERDICT_COLORS = {
  permit:  new THREE.Color(0x5fffc4),
  abstain: new THREE.Color(0xffb547),
  forbid:  new THREE.Color(0xff4757),
};

export class TexField {
  constructor(container, { texImageUrl, onReceipt }) {
    this.container = container;
    this.texImageUrl = texImageUrl;
    this.onReceipt = onReceipt || (() => {});

    this.clock = new THREE.Clock();
    this.elapsed = 0;
    this.isDestroyed = false;
    this.actionsInFlight = [];
    this.detonations = [];
    this.chainNodes = [];
    this.spawnAccumulator = 0;
    this.spawnRate = 2.8;  // actions per second on average

    this._initScene();
    this._initAgents();
    this._initMembrane();
    this._initTexBackplate();
    this._initHashChain();
    this._initStarfield();

    this.handleResize = this.handleResize.bind(this);
    window.addEventListener('resize', this.handleResize);
    this.handleResize();

    // Warm-start: pre-populate the field with 14 in-flight actions and a
    // partial hash chain so the very first visible frame is already alive.
    // Without this, the buyer would see 5-10 seconds of empty space before
    // the first action reaches the membrane.
    this._warmStart();

    this._raf = this._raf.bind(this);
    this._frameId = requestAnimationFrame(this._raf);
  }

  _warmStart() {
    // Seed in-flight actions at random progress points, and stamp some
    // hash-chain nodes so the visual lower band is already growing.
    for (let i = 0; i < 14; i++) {
      this._spawnAction();
      const a = this.actionsInFlight[this.actionsInFlight.length - 1];
      // Random progress between 0.2 and 0.85 — some near-membrane, some mid-flight
      a.progress = 0.2 + Math.random() * 0.65;
      // Advance trail to current point
      const pos = new THREE.Vector3().lerpVectors(a.origin, a.target, a.progress);
      a.head.position.copy(pos);
      for (let j = 0; j < 24; j++) {
        a.trailPositions[j * 3 + 0] = pos.x;
        a.trailPositions[j * 3 + 1] = pos.y;
        a.trailPositions[j * 3 + 2] = pos.z;
      }
      a.trail.geometry.attributes.position.needsUpdate = true;
    }
    // Pre-populate hash chain with a smattering of past decisions
    for (let i = 0; i < 22; i++) {
      const v = Math.random() < 0.7 ? 'permit' : (Math.random() < 0.5 ? 'abstain' : 'forbid');
      this._addChainNode(v);
    }
  }

  _initScene() {
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;

    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x000000, 0.012);

    this.camera = new THREE.PerspectiveCamera(42, w / h, 0.1, 800);
    this.camera.position.set(0, 0.6, 38);
    this.camera.lookAt(0, 0, 0);

    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(w, h);
    this.renderer.setClearColor(0x000000, 0);
    this.container.appendChild(this.renderer.domElement);

    // Subtle ambient + a soft cyan key for the membrane sphere
    this.scene.add(new THREE.AmbientLight(0xffffff, 0.45));
    const key = new THREE.DirectionalLight(0x00d9ff, 0.35);
    key.position.set(8, 10, 14);
    this.scene.add(key);
  }

  _initStarfield() {
    // Distant ambient particle field for depth
    const count = 1400;
    const positions = new Float32Array(count * 3);
    const sizes = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      const r = 90 + Math.random() * 220;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3 + 0] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi) - 60;
      sizes[i] = Math.random() * 0.6 + 0.2;
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('size', new THREE.BufferAttribute(sizes, 1));

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      uniforms: {
        uTime: { value: 0 },
      },
      vertexShader: /* glsl */ `
        attribute float size;
        varying float vAlpha;
        uniform float uTime;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = size * (300.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
          float t = sin(uTime * 0.6 + position.x * 0.12 + position.y * 0.07) * 0.5 + 0.5;
          vAlpha = 0.18 + t * 0.22;
        }
      `,
      fragmentShader: /* glsl */ `
        varying float vAlpha;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float a = smoothstep(0.5, 0.0, d) * vAlpha;
          gl_FragColor = vec4(0.6, 0.85, 1.0, a);
        }
      `,
    });

    this.starfield = new THREE.Points(geom, mat);
    this.scene.add(this.starfield);
  }

  _initAgents() {
    // Agents: ~260 points in a roughly spherical cloud, biased away from the
    // center so Tex's silhouette stays clean. Each agent has its own pulse
    // phase, base color, and fixed position.
    const count = 260;
    this.agentCount = count;
    const positions = new Float32Array(count * 3);
    const phases = new Float32Array(count);
    const sizes = new Float32Array(count);
    const colors = new Float32Array(count * 3);

    this.agentData = [];

    for (let i = 0; i < count; i++) {
      // Spherical shell with a hollow inner core (so Tex backplate is visible)
      const r = 7 + Math.random() * 10;
      const theta = Math.random() * Math.PI * 2;
      // Bias points away from front-center cone (where the Tex image is)
      // by rejection-sampling phi
      let phi;
      let attempts = 0;
      do {
        phi = Math.acos(2 * Math.random() - 1);
        attempts++;
        if (attempts > 6) break;
      } while (
        // reject points that fall in front of center within a narrow cone
        Math.abs(Math.cos(phi)) > 0.65 &&
        Math.sin(phi) * Math.cos(theta) > -0.25 &&
        Math.sin(phi) * Math.cos(theta) < 0.25 &&
        r < 9.5
      );

      const x = r * Math.sin(phi) * Math.cos(theta);
      const y = r * Math.sin(phi) * Math.sin(theta) * 0.8; // squish vertically
      const z = r * Math.cos(phi) * 0.7;

      positions[i * 3 + 0] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;
      phases[i] = Math.random() * Math.PI * 2;
      sizes[i] = 0.6 + Math.random() * 1.4;

      // Cool palette: cyan-leaning, with occasional warm outliers
      const tint = Math.random();
      if (tint > 0.92) {
        colors[i * 3 + 0] = 1.0; colors[i * 3 + 1] = 0.71; colors[i * 3 + 2] = 0.28;
      } else if (tint > 0.85) {
        colors[i * 3 + 0] = 1.0; colors[i * 3 + 1] = 0.28; colors[i * 3 + 2] = 0.34;
      } else {
        colors[i * 3 + 0] = 0.0;
        colors[i * 3 + 1] = 0.85;
        colors[i * 3 + 2] = 1.0;
      }

      this.agentData.push({
        position: new THREE.Vector3(x, y, z),
        nextEmit: 0,
      });
    }

    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('phase', new THREE.BufferAttribute(phases, 1));
    geom.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1));
    geom.setAttribute('aColor', new THREE.BufferAttribute(colors, 3));

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        uTime: { value: 0 },
      },
      vertexShader: /* glsl */ `
        attribute float phase;
        attribute float aSize;
        attribute vec3 aColor;
        varying float vAlpha;
        varying vec3 vColor;
        uniform float uTime;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          float pulse = 0.5 + 0.5 * sin(uTime * 1.4 + phase);
          float size = aSize * (1.0 + pulse * 0.6);
          gl_PointSize = size * (340.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
          vAlpha = 0.55 + pulse * 0.45;
          vColor = aColor;
        }
      `,
      fragmentShader: /* glsl */ `
        varying float vAlpha;
        varying vec3 vColor;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float core = smoothstep(0.5, 0.0, d);
          float halo = smoothstep(0.5, 0.15, d) * 0.5;
          float a = (core * 0.9 + halo) * vAlpha;
          gl_FragColor = vec4(vColor, a);
        }
      `,
    });

    this.agents = new THREE.Points(geom, mat);
    this.scene.add(this.agents);
  }

  _initMembrane() {
    // Translucent spherical shell — the judgment field. Rendered as a fresnel
    // shader so it's nearly invisible head-on but bright at grazing angles.
    // It also receives ripples when actions detonate against it.
    const radius = 22;
    this.membraneRadius = radius;
    const geom = new THREE.SphereGeometry(radius, 96, 64);

    this.membraneUniforms = {
      uTime: { value: 0 },
      uRippleCount: { value: 0 },
      uRipples: { value: Array.from({ length: 8 }, () => new THREE.Vector4(0, 0, 0, 0)) },
      uColors: { value: Array.from({ length: 8 }, () => new THREE.Vector3(0, 0.85, 1)) },
    };

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      side: THREE.BackSide,
      uniforms: this.membraneUniforms,
      vertexShader: /* glsl */ `
        varying vec3 vNormal;
        varying vec3 vWorldPos;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          vec4 wp = modelMatrix * vec4(position, 1.0);
          vWorldPos = wp.xyz;
          gl_Position = projectionMatrix * viewMatrix * wp;
        }
      `,
      fragmentShader: /* glsl */ `
        varying vec3 vNormal;
        varying vec3 vWorldPos;
        uniform float uTime;
        uniform int uRippleCount;
        uniform vec4 uRipples[8];   // xyz = epicenter, w = age (seconds)
        uniform vec3 uColors[8];

        void main() {
          // Fresnel: invisible head-on, glowing at grazing
          vec3 vd = normalize(cameraPosition - vWorldPos);
          float fr = 1.0 - max(dot(vNormal, vd), 0.0);
          fr = pow(fr, 2.4);

          vec3 base = vec3(0.0, 0.8, 1.0) * fr * 0.35;

          // Subtle scrolling lattice
          float lat = sin(vWorldPos.y * 0.6 + uTime * 0.4)
                    * sin(vWorldPos.x * 0.6 - uTime * 0.3);
          base += vec3(0.0, 0.55, 0.85) * lat * 0.06 * fr;

          // Ripples — each is a glowing ring radiating from its epicenter
          for (int i = 0; i < 8; i++) {
            if (i >= uRippleCount) break;
            vec4 r = uRipples[i];
            float age = r.w;
            if (age < 0.0 || age > 1.6) continue;
            float dist = distance(vWorldPos, r.xyz);
            float radius = age * 9.0;
            float ring = exp(-pow((dist - radius) * 0.85, 2.0));
            float fade = 1.0 - smoothstep(0.0, 1.6, age);
            base += uColors[i] * ring * fade * 1.1;
          }

          gl_FragColor = vec4(base, fr * 0.85);
        }
      `,
    });

    this.membrane = new THREE.Mesh(geom, mat);
    this.scene.add(this.membrane);
  }

  _initTexBackplate() {
    // Tex is rendered as a textured plane behind the agent cloud, sized to
    // command center stage. We use a custom shader so the chest emblem
    // pulses subtly with the field heartbeat.
    const loader = new THREE.TextureLoader();
    this.texPlaneReady = false;
    loader.load(this.texImageUrl, (texture) => {
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.minFilter = THREE.LinearFilter;
      texture.magFilter = THREE.LinearFilter;

      // Aspect-correct plane
      const aspect = texture.image.width / texture.image.height;
      const height = 14;
      const width = height * aspect;
      const geom = new THREE.PlaneGeometry(width, height, 1, 1);

      this.texUniforms = {
        uMap: { value: texture },
        uTime: { value: 0 },
        uPulse: { value: 0 },
      };

      const mat = new THREE.ShaderMaterial({
        transparent: true,
        depthWrite: false,
        depthTest: true,
        uniforms: this.texUniforms,
        vertexShader: /* glsl */ `
          varying vec2 vUv;
          void main() {
            vUv = uv;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `,
        fragmentShader: /* glsl */ `
          uniform sampler2D uMap;
          uniform float uTime;
          uniform float uPulse;
          varying vec2 vUv;
          void main() {
            vec4 c = texture2D(uMap, vUv);
            // Emblem pulse: gentle cyan lift on the chest hexagon
            float chestY = smoothstep(0.34, 0.40, vUv.y) * smoothstep(0.46, 0.40, vUv.y);
            float chestX = smoothstep(0.45, 0.50, vUv.x) * smoothstep(0.55, 0.50, vUv.x);
            float emblemMask = chestY * chestX;
            float beat = 0.5 + 0.5 * sin(uTime * 1.6);
            vec3 lift = vec3(0.0, 0.85, 1.0) * (emblemMask * (0.4 + beat * 0.6) + uPulse * 0.35);
            c.rgb = c.rgb + lift * 0.5;
            // Slight overall luminance boost so Tex reads as luminous, not dim
            c.rgb *= 1.06;
            // Soft fade only at the very outer 8% of edges
            float vig = smoothstep(0.0, 0.08, min(vUv.x, 1.0 - vUv.x))
                      * smoothstep(0.0, 0.06, min(vUv.y, 1.0 - vUv.y));
            c.rgb *= 0.84 + 0.16 * vig;
            gl_FragColor = vec4(c.rgb, c.a);
          }
        `,
      });

      this.texPlane = new THREE.Mesh(geom, mat);
      // Pull Tex up and slightly back so headline sits below him cleanly
      this.texPlane.position.set(0, 2.4, -3.5);
      this.scene.add(this.texPlane);
      this.texPlaneReady = true;
    });
  }

  _initHashChain() {
    // A growing horizontal chain at the lower portion of the membrane.
    // Each detonation/pass-through stamps a new node onto it.
    this.chainGroup = new THREE.Group();
    this.chainGroup.position.set(0, -16, 0);
    this.scene.add(this.chainGroup);

    // Backbone line
    const lineGeom = new THREE.BufferGeometry();
    const linePositions = new Float32Array(2 * 3);
    linePositions[0] = -28; linePositions[1] = 0; linePositions[2] = 0;
    linePositions[3] = 28;  linePositions[4] = 0; linePositions[5] = 0;
    lineGeom.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x00d9ff,
      transparent: true,
      opacity: 0.18,
    });
    this.chainGroup.add(new THREE.Line(lineGeom, lineMat));

    // Pre-allocate node sprites (additive points)
    this.chainCapacity = 64;
    const np = new Float32Array(this.chainCapacity * 3);
    const nc = new Float32Array(this.chainCapacity * 3);
    const ns = new Float32Array(this.chainCapacity);
    for (let i = 0; i < this.chainCapacity; i++) {
      np[i * 3 + 0] = 1000; // hide off-screen until used
      np[i * 3 + 1] = 0;
      np[i * 3 + 2] = 0;
      nc[i * 3 + 0] = 0; nc[i * 3 + 1] = 0.85; nc[i * 3 + 2] = 1.0;
      ns[i] = 1.0;
    }
    const ngeom = new THREE.BufferGeometry();
    ngeom.setAttribute('position', new THREE.BufferAttribute(np, 3));
    ngeom.setAttribute('aColor', new THREE.BufferAttribute(nc, 3));
    ngeom.setAttribute('aSize', new THREE.BufferAttribute(ns, 1));

    const nmat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uTime: { value: 0 } },
      vertexShader: /* glsl */ `
        attribute vec3 aColor;
        attribute float aSize;
        varying vec3 vColor;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = aSize * (240.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
          vColor = aColor;
        }
      `,
      fragmentShader: /* glsl */ `
        varying vec3 vColor;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float core = smoothstep(0.5, 0.0, d);
          gl_FragColor = vec4(vColor, core * 0.95);
        }
      `,
    });

    this.chainPoints = new THREE.Points(ngeom, nmat);
    this.chainGroup.add(this.chainPoints);
    this.chainCursor = 0;
  }

  // ─────────────── Action lifecycle ───────────────

  _spawnAction() {
    const agent = this.agentData[Math.floor(Math.random() * this.agentData.length)];
    const template = ACTION_TEMPLATES[Math.floor(Math.random() * ACTION_TEMPLATES.length)];

    // Bias verdict by action kind: shell.exec, postgres.delete, file.delete,
    // iam.grant lean toward FORBID; refunds and charges lean ABSTAIN.
    let verdict;
    if (['shell.exec', 'postgres.delete', 'file.delete', 'iam.grant'].includes(template.kind)) {
      verdict = Math.random() < 0.7 ? 'forbid' : (Math.random() < 0.5 ? 'abstain' : 'permit');
    } else if (['stripe.refund', 'stripe.charge', 'docs.share'].includes(template.kind)) {
      verdict = Math.random() < 0.45 ? 'abstain' : (Math.random() < 0.85 ? 'permit' : 'forbid');
    } else {
      verdict = VERDICTS[Math.floor(Math.random() * VERDICTS.length)];
    }

    // Direction: outward from agent
    const origin = agent.position.clone();
    const dir = origin.clone().normalize();
    if (dir.lengthSq() < 0.01) dir.set(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5).normalize();

    // Membrane intersection point
    const target = dir.clone().multiplyScalar(this.membraneRadius);

    // Geometry: a streak (line + leading head sprite). Use a small sphere for the head and a Line2-style for the trail.
    const headGeom = new THREE.SphereGeometry(0.18, 12, 12);
    const headMat = new THREE.MeshBasicMaterial({
      color: VERDICT_COLORS[verdict],
      transparent: true,
      opacity: 0.95,
    });
    const head = new THREE.Mesh(headGeom, headMat);
    head.position.copy(origin);
    this.scene.add(head);

    // Trail: a thin line from origin, growing toward head
    const trailMaxPoints = 24;
    const trailPositions = new Float32Array(trailMaxPoints * 3);
    for (let i = 0; i < trailMaxPoints; i++) {
      trailPositions[i * 3 + 0] = origin.x;
      trailPositions[i * 3 + 1] = origin.y;
      trailPositions[i * 3 + 2] = origin.z;
    }
    const trailGeom = new THREE.BufferGeometry();
    trailGeom.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
    const trailMat = new THREE.LineBasicMaterial({
      color: VERDICT_COLORS[verdict],
      transparent: true,
      opacity: 0.55,
    });
    const trail = new THREE.Line(trailGeom, trailMat);
    this.scene.add(trail);

    const action = {
      origin,
      target,
      progress: 0,
      duration: 1.0 + Math.random() * 0.7,
      verdict,
      kind: template.kind,
      head,
      trail,
      trailPositions,
      trailIndex: 0,
      reachedMembrane: false,
      postMembraneTime: 0,
      done: false,
      // For ABSTAIN: pause near membrane
      abstainTagged: false,
    };

    this.actionsInFlight.push(action);
  }

  _detonate(action) {
    const epicenter = action.target.clone();
    // Add ripple to membrane
    const idx = Math.min(this.detonations.length, 7);
    if (this.membraneUniforms.uRippleCount.value < 8) {
      this.membraneUniforms.uRippleCount.value = Math.min(8, this.membraneUniforms.uRippleCount.value + 1);
    }
    // Shift older ripples down
    if (this.detonations.length >= 8) this.detonations.shift();
    this.detonations.push({ epicenter, age: 0, color: VERDICT_COLORS[action.verdict] });
    this._refreshMembraneUniforms();

    // Particle burst for FORBID detonations
    if (action.verdict === 'forbid') {
      this._burst(epicenter, VERDICT_COLORS.forbid, 36);
    } else if (action.verdict === 'abstain') {
      this._burst(epicenter, VERDICT_COLORS.abstain, 14);
    } else {
      this._burst(epicenter, VERDICT_COLORS.permit, 10);
    }

    // Add hash chain node
    this._addChainNode(action.verdict);

    // Receipt
    const hash = randomHash();
    const agentId = randomAgentId();
    this.onReceipt({
      hash,
      kind: action.kind,
      agent: agentId,
      verdict: action.verdict,
      ms: (1.2 + Math.random() * 3.4).toFixed(1),
    });

    // Pulse Tex's emblem on FORBID
    if (action.verdict === 'forbid' && this.texUniforms) {
      this.texUniforms.uPulse.value = 1.0;
    }
  }

  _refreshMembraneUniforms() {
    for (let i = 0; i < this.detonations.length; i++) {
      const d = this.detonations[i];
      this.membraneUniforms.uRipples.value[i].set(d.epicenter.x, d.epicenter.y, d.epicenter.z, d.age);
      this.membraneUniforms.uColors.value[i].set(d.color.r, d.color.g, d.color.b);
    }
  }

  _burst(position, color, count) {
    const positions = new Float32Array(count * 3);
    const velocities = [];
    for (let i = 0; i < count; i++) {
      positions[i * 3 + 0] = position.x;
      positions[i * 3 + 1] = position.y;
      positions[i * 3 + 2] = position.z;
      const dir = new THREE.Vector3(
        Math.random() - 0.5,
        Math.random() - 0.5,
        Math.random() - 0.5,
      ).normalize().multiplyScalar(2 + Math.random() * 4);
      velocities.push(dir);
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const mat = new THREE.PointsMaterial({
      color,
      size: 0.45,
      transparent: true,
      opacity: 1.0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    });
    const points = new THREE.Points(geom, mat);
    this.scene.add(points);

    this.bursts = this.bursts || [];
    this.bursts.push({ points, velocities, age: 0, life: 0.9 });
  }

  _addChainNode(verdict) {
    const slot = this.chainCursor % this.chainCapacity;
    const x = -26 + (this.chainCursor % 40) * 1.3;
    const y = (this.chainCursor % 2 === 0) ? 0.0 : -0.4;
    const pos = this.chainPoints.geometry.attributes.position;
    const col = this.chainPoints.geometry.attributes.aColor;
    const siz = this.chainPoints.geometry.attributes.aSize;
    pos.array[slot * 3 + 0] = x;
    pos.array[slot * 3 + 1] = y;
    pos.array[slot * 3 + 2] = 0;
    const c = VERDICT_COLORS[verdict];
    col.array[slot * 3 + 0] = c.r;
    col.array[slot * 3 + 1] = c.g;
    col.array[slot * 3 + 2] = c.b;
    siz.array[slot] = verdict === 'forbid' ? 2.2 : 1.4;
    pos.needsUpdate = true;
    col.needsUpdate = true;
    siz.needsUpdate = true;
    this.chainCursor++;
  }

  // ─────────────── Frame loop ───────────────

  _raf() {
    if (this.isDestroyed) return;
    const dt = Math.min(this.clock.getDelta(), 0.05);
    this._frameTick(dt);
    this._frameId = requestAnimationFrame(this._raf);
  }

  _frameTick(dt) {
    if (this.isDestroyed) return;
    this.elapsed += dt;
    this._frameCount = (this._frameCount || 0) + 1;

    // Spawn new actions over time
    this.spawnAccumulator += dt;
    const spawnInterval = 1.0 / this.spawnRate;
    while (this.spawnAccumulator >= spawnInterval) {
      this.spawnAccumulator -= spawnInterval;
      this._spawnAction();
      // Slowly accelerate spawn rate up to a steady cruise
      if (this.spawnRate < 4.6) this.spawnRate += 0.012;
    }

    // Update agents/membrane shaders
    if (this.agents) this.agents.material.uniforms.uTime.value = this.elapsed;
    if (this.starfield) this.starfield.material.uniforms.uTime.value = this.elapsed;
    if (this.membraneUniforms) {
      this.membraneUniforms.uTime.value = this.elapsed;
      // Age existing ripples
      for (let i = 0; i < this.detonations.length; i++) {
        this.detonations[i].age += dt;
      }
      // Drop expired
      while (this.detonations.length && this.detonations[0].age > 1.6) {
        this.detonations.shift();
      }
      this.membraneUniforms.uRippleCount.value = this.detonations.length;
      this._refreshMembraneUniforms();
    }
    if (this.texUniforms) {
      this.texUniforms.uTime.value = this.elapsed;
      // Decay pulse
      this.texUniforms.uPulse.value = Math.max(0, this.texUniforms.uPulse.value - dt * 2.4);
    }

    // Update actions
    for (let i = this.actionsInFlight.length - 1; i >= 0; i--) {
      const a = this.actionsInFlight[i];
      if (!a.reachedMembrane) {
        a.progress = Math.min(1, a.progress + dt / a.duration);
        // Slight curve via lerp + bow
        const p = a.progress;
        const bow = Math.sin(p * Math.PI) * 1.2;
        const pos = new THREE.Vector3().lerpVectors(a.origin, a.target, p);
        // Add a small perpendicular bow
        const perp = new THREE.Vector3().crossVectors(
          a.target.clone().sub(a.origin),
          new THREE.Vector3(0, 1, 0)
        ).normalize().multiplyScalar(bow);
        pos.add(perp);
        a.head.position.copy(pos);

        // Update trail
        a.trailPositions[a.trailIndex * 3 + 0] = pos.x;
        a.trailPositions[a.trailIndex * 3 + 1] = pos.y;
        a.trailPositions[a.trailIndex * 3 + 2] = pos.z;
        a.trailIndex = (a.trailIndex + 1) % 24;
        // Fill the rest from current position so we don't see uninitialized verts
        for (let j = 0; j < 24; j++) {
          if (j === a.trailIndex) continue;
        }
        a.trail.geometry.attributes.position.needsUpdate = true;

        if (a.progress >= 1) {
          a.reachedMembrane = true;
          this._detonate(a);
        }
      } else {
        a.postMembraneTime += dt;
        // PERMIT: continue outward fading; ABSTAIN: pause then fade; FORBID: immediate fade
        if (a.verdict === 'permit') {
          a.head.position.add(a.target.clone().normalize().multiplyScalar(dt * 6));
          a.head.material.opacity = Math.max(0, a.head.material.opacity - dt * 1.4);
          a.trail.material.opacity = Math.max(0, a.trail.material.opacity - dt * 1.4);
        } else {
          a.head.material.opacity = Math.max(0, a.head.material.opacity - dt * 2.0);
          a.trail.material.opacity = Math.max(0, a.trail.material.opacity - dt * 2.0);
        }
        if (a.head.material.opacity <= 0.01) {
          this.scene.remove(a.head);
          this.scene.remove(a.trail);
          a.head.geometry.dispose();
          a.head.material.dispose();
          a.trail.geometry.dispose();
          a.trail.material.dispose();
          a.done = true;
        }
      }
      if (a.done) this.actionsInFlight.splice(i, 1);
    }

    // Update bursts
    if (this.bursts) {
      for (let i = this.bursts.length - 1; i >= 0; i--) {
        const b = this.bursts[i];
        b.age += dt;
        const arr = b.points.geometry.attributes.position.array;
        for (let j = 0; j < b.velocities.length; j++) {
          arr[j * 3 + 0] += b.velocities[j].x * dt;
          arr[j * 3 + 1] += b.velocities[j].y * dt;
          arr[j * 3 + 2] += b.velocities[j].z * dt;
          b.velocities[j].multiplyScalar(0.92);
        }
        b.points.geometry.attributes.position.needsUpdate = true;
        b.points.material.opacity = Math.max(0, 1.0 - b.age / b.life);
        if (b.age >= b.life) {
          this.scene.remove(b.points);
          b.points.geometry.dispose();
          b.points.material.dispose();
          this.bursts.splice(i, 1);
        }
      }
    }

    // Slow camera drift for parallax
    const t = this.elapsed;
    this.camera.position.x = Math.sin(t * 0.08) * 1.4;
    this.camera.position.y = 0.6 + Math.sin(t * 0.12) * 0.6;
    this.camera.lookAt(0, -0.4, 0);

    this.renderer.render(this.scene, this.camera);
  }

  handleResize() {
    if (!this.container) return;
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;
    this.renderer.setSize(w, h);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  destroy() {
    this.isDestroyed = true;
    cancelAnimationFrame(this._frameId);
    window.removeEventListener('resize', this.handleResize);
    if (this.renderer) {
      this.renderer.dispose();
      if (this.renderer.domElement && this.renderer.domElement.parentNode) {
        this.renderer.domElement.parentNode.removeChild(this.renderer.domElement);
      }
    }
  }
}

// ─────────────── Helpers ───────────────

function randomHash() {
  const hex = '0123456789abcdef';
  let s = '0x';
  for (let i = 0; i < 8; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}

const AGENT_PREFIXES = [
  'artisan-sdr', '11x-ada', 'aisdr-prospect', 'glean-research', 'cursor-agent',
  'claude-code', 'copilot-codex', 'lang-react', 'crew-ops', 'ada-support',
  'fin-bot', 'intercom-fin', 'zapier-bot', 'mcp-tool', 'deepscribe',
  'ops-runbook', 'sec-triage', 'data-eng', 'pricing-bot', 'rev-ops',
];

function randomAgentId() {
  const p = AGENT_PREFIXES[Math.floor(Math.random() * AGENT_PREFIXES.length)];
  const n = String(Math.floor(Math.random() * 99) + 1).padStart(2, '0');
  return `${p}-${n}`;
}
