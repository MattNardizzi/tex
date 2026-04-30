import * as THREE from 'three';

/**
 * TexField — the texaegis.com judgment field.
 *
 * The page renders a continuous, legible visualization of Tex catching
 * AI agent actions. The buyer must understand what they're seeing in
 * under 5 seconds without reading the legend.
 *
 * Composition:
 *
 *   1. AGENTS (the cloud of dim cyan dots) — every dot is an AI agent
 *      registered with Tex. They float in a 3D shell. Slow pulse.
 *
 *   2. AMBIENT ACTIONS (faint streaks) — subtle background flow that
 *      establishes "things are happening all the time." No labels.
 *      No detonation rings. Pure texture, never the focal event.
 *
 *   3. HERO ACTION (one at a time, every ~3.5s) — a single labeled
 *      action travels from an agent toward Tex. As it crosses the
 *      field, three brief inline tags appear in sequence:
 *        04 EVALUATION
 *        05 ENFORCEMENT  →  with verdict text (PERMIT / ABSTAIN / FORBID)
 *        06 EVIDENCE     →  with hash
 *      The verdict text persists ~1.4s so the eye can read it.
 *
 *   4. TEX (the avatar) — rendered last, full color, on top. He is the
 *      authority. His chest emblem flares when a hero action resolves.
 *
 *   5. MEMBRANE (the field shell) — extremely subtle. Detonations are
 *      brief 0.5s flashes sized to the action, not auroras. Most
 *      buyers won't consciously notice the membrane. That's correct —
 *      it's there for atmosphere, not narrative.
 *
 *   6. HASH CHAIN (bottom band) — a growing line of stamped decisions.
 *      Each hero action adds a new node visibly.
 */

const VERDICT_COLORS = {
  permit:  new THREE.Color(0x5fffc4),
  abstain: new THREE.Color(0xffb547),
  forbid:  new THREE.Color(0xff4757),
};

const ACTION_TEMPLATES = [
  { kind: 'slack.post',          tend: 'permit'  },
  { kind: 'slack.dm',            tend: 'permit'  },
  { kind: 'email.send',          tend: 'permit'  },
  { kind: 'salesforce.update',   tend: 'permit'  },
  { kind: 'github.merge',        tend: 'permit'  },
  { kind: 'mcp.tool_call',       tend: 'permit'  },
  { kind: 'calendar.invite',     tend: 'permit'  },
  { kind: 'twilio.sms',          tend: 'permit'  },
  { kind: 'http.post',           tend: 'permit'  },
  { kind: 's3.put',              tend: 'permit'  },
  { kind: 'mongo.write',         tend: 'permit'  },

  { kind: 'stripe.refund',       tend: 'abstain' },
  { kind: 'stripe.charge',       tend: 'abstain' },
  { kind: 'docs.share',          tend: 'abstain' },
  { kind: 'github.push',         tend: 'abstain' },

  { kind: 'postgres.delete',     tend: 'forbid'  },
  { kind: 'shell.exec',          tend: 'forbid'  },
  { kind: 'file.delete',         tend: 'forbid'  },
  { kind: 'iam.grant',           tend: 'forbid'  },
];

const AGENT_PREFIXES = [
  'artisan-sdr', '11x-ada', 'aisdr-prospect', 'glean-research',
  'cursor-agent', 'claude-code', 'copilot-codex', 'lang-react',
  'crew-ops', 'ada-support', 'fin-bot', 'intercom-fin', 'zapier-bot',
  'mcp-tool', 'ops-runbook', 'sec-triage', 'data-eng', 'pricing-bot',
  'rev-ops', 'deepscribe',
];

const HERO_VERDICT_MIX = [
  'permit', 'permit', 'permit', 'permit',
  'abstain', 'abstain',
  'forbid', 'forbid',
];

export class TexField {
  constructor(container, { texImageUrl, onReceipt, onHeroEvent }) {
    this.container = container;
    this.texImageUrl = texImageUrl;
    this.onReceipt = onReceipt || (() => {});
    this.onHeroEvent = onHeroEvent || (() => {});

    this.clock = new THREE.Clock();
    this.elapsed = 0;
    this.isDestroyed = false;

    this.ambientActions = [];
    this.heroAction = null;
    this.heroCooldown = 0.4;        // first hero appears fast so buyer sees the narrative right away
    this.detonations = [];
    this.bursts = [];

    this.ambientSpawnAccumulator = 0;
    this.ambientSpawnRate = 5.0;

    this._initScene();
    this._initStarfield();
    this._initAgents();
    this._initMembrane();
    this._initHashChain();
    this._initTexBackplate();

    this.handleResize = this.handleResize.bind(this);
    window.addEventListener('resize', this.handleResize);
    this.handleResize();

    this._warmStartChain();

    this._raf = this._raf.bind(this);
    this._frameId = requestAnimationFrame(this._raf);
  }

  _initScene() {
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;

    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x000000, 0.014);

    this.camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 800);
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

    this.scene.add(new THREE.AmbientLight(0xffffff, 0.5));
  }

  _initStarfield() {
    const count = 1100;
    const positions = new Float32Array(count * 3);
    const sizes = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      const r = 80 + Math.random() * 220;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3 + 0] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi) - 60;
      sizes[i] = Math.random() * 0.5 + 0.15;
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('size', new THREE.BufferAttribute(sizes, 1));

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      uniforms: { uTime: { value: 0 } },
      vertexShader: /* glsl */ `
        attribute float size;
        varying float vAlpha;
        uniform float uTime;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = size * (300.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
          float t = sin(uTime * 0.6 + position.x * 0.12 + position.y * 0.07) * 0.5 + 0.5;
          vAlpha = 0.10 + t * 0.14;
        }
      `,
      fragmentShader: /* glsl */ `
        varying float vAlpha;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float a = smoothstep(0.5, 0.0, d) * vAlpha;
          gl_FragColor = vec4(0.55, 0.8, 1.0, a);
        }
      `,
    });

    this.starfield = new THREE.Points(geom, mat);
    this.scene.add(this.starfield);
  }

  _initAgents() {
    const count = 220;
    this.agentCount = count;
    const positions = new Float32Array(count * 3);
    const phases = new Float32Array(count);
    const sizes = new Float32Array(count);

    this.agentData = [];

    for (let i = 0; i < count; i++) {
      const r = 9 + Math.random() * 11;
      const theta = Math.random() * Math.PI * 2;
      let phi;
      let attempts = 0;
      do {
        phi = Math.acos(2 * Math.random() - 1);
        attempts++;
        if (attempts > 6) break;
      } while (
        Math.abs(Math.cos(phi)) > 0.55 &&
        Math.sin(phi) * Math.cos(theta) > -0.30 &&
        Math.sin(phi) * Math.cos(theta) < 0.30 &&
        r < 11.5
      );

      const x = r * Math.sin(phi) * Math.cos(theta);
      const y = r * Math.sin(phi) * Math.sin(theta) * 0.85;
      const z = r * Math.cos(phi) * 0.7;

      positions[i * 3 + 0] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;
      phases[i] = Math.random() * Math.PI * 2;
      sizes[i] = 0.55 + Math.random() * 0.95;

      this.agentData.push({
        position: new THREE.Vector3(x, y, z),
        agentId: this._randomAgentId(),
      });
    }

    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('phase', new THREE.BufferAttribute(phases, 1));
    geom.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1));

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uTime: { value: 0 } },
      vertexShader: /* glsl */ `
        attribute float phase;
        attribute float aSize;
        varying float vAlpha;
        uniform float uTime;
        void main() {
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          float pulse = 0.5 + 0.5 * sin(uTime * 1.2 + phase);
          float size = aSize * (1.0 + pulse * 0.4);
          gl_PointSize = size * (320.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
          vAlpha = 0.45 + pulse * 0.35;
        }
      `,
      fragmentShader: /* glsl */ `
        varying float vAlpha;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float core = smoothstep(0.5, 0.0, d);
          float halo = smoothstep(0.5, 0.18, d) * 0.4;
          float a = (core * 0.85 + halo) * vAlpha;
          gl_FragColor = vec4(0.0, 0.78, 0.95, a);
        }
      `,
    });

    this.agents = new THREE.Points(geom, mat);
    this.scene.add(this.agents);
  }

  _initMembrane() {
    const radius = 21;
    this.membraneRadius = radius;
    const geom = new THREE.SphereGeometry(radius, 96, 64);

    this.membraneUniforms = {
      uTime: { value: 0 },
      uRippleCount: { value: 0 },
      uRipples: { value: Array.from({ length: 6 }, () => new THREE.Vector4(0, 0, 0, 0)) },
      uColors: { value: Array.from({ length: 6 }, () => new THREE.Vector3(0, 0.85, 1)) },
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
        uniform vec4 uRipples[6];
        uniform vec3 uColors[6];

        void main() {
          vec3 vd = normalize(cameraPosition - vWorldPos);
          float fr = 1.0 - max(dot(vNormal, vd), 0.0);
          fr = pow(fr, 3.5);

          vec3 base = vec3(0.0, 0.55, 0.85) * fr * 0.16;

          // Brief, small ripples — quick flashes, not auroras
          for (int i = 0; i < 6; i++) {
            if (i >= uRippleCount) break;
            vec4 r = uRipples[i];
            float age = r.w;
            if (age < 0.0 || age > 0.6) continue;
            float dist = distance(vWorldPos, r.xyz);
            float radius = age * 4.5;
            float ring = exp(-pow((dist - radius) * 1.6, 2.0));
            float fade = 1.0 - smoothstep(0.0, 0.6, age);
            base += uColors[i] * ring * fade * 0.9;
          }

          gl_FragColor = vec4(base, fr * 0.45);
        }
      `,
    });

    this.membrane = new THREE.Mesh(geom, mat);
    this.scene.add(this.membrane);
  }

  _initTexBackplate() {
    const loader = new THREE.TextureLoader();
    loader.load(this.texImageUrl, (texture) => {
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.minFilter = THREE.LinearFilter;
      texture.magFilter = THREE.LinearFilter;

      const aspect = texture.image.width / texture.image.height;
      const height = 13;
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
        depthTest: false,
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
            float chestY = smoothstep(0.34, 0.40, vUv.y) * smoothstep(0.46, 0.40, vUv.y);
            float chestX = smoothstep(0.45, 0.50, vUv.x) * smoothstep(0.55, 0.50, vUv.x);
            float emblemMask = chestY * chestX;
            float beat = 0.5 + 0.5 * sin(uTime * 1.4);
            vec3 lift = vec3(0.0, 0.85, 1.0) * (emblemMask * (0.45 + beat * 0.55) + uPulse * 0.5);
            c.rgb = c.rgb + lift * 0.55;
            c.rgb *= 1.04;
            gl_FragColor = vec4(c.rgb, c.a);
          }
        `,
      });

      this.texPlane = new THREE.Mesh(geom, mat);
      this.texPlane.renderOrder = 100;
      this.texPlane.position.set(0, 3.2, 0);
      this.scene.add(this.texPlane);
      this.texPlaneReady = true;
    });
  }

  _initHashChain() {
    this.chainGroup = new THREE.Group();
    this.chainGroup.position.set(0, -15.5, 0);
    this.scene.add(this.chainGroup);

    const lineGeom = new THREE.BufferGeometry();
    const linePositions = new Float32Array(2 * 3);
    linePositions[0] = -26; linePositions[1] = 0; linePositions[2] = 0;
    linePositions[3] = 26;  linePositions[4] = 0; linePositions[5] = 0;
    lineGeom.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x00d9ff,
      transparent: true,
      opacity: 0.20,
    });
    this.chainGroup.add(new THREE.Line(lineGeom, lineMat));

    this.chainCapacity = 64;
    const np = new Float32Array(this.chainCapacity * 3);
    const nc = new Float32Array(this.chainCapacity * 3);
    const ns = new Float32Array(this.chainCapacity);
    for (let i = 0; i < this.chainCapacity; i++) {
      np[i * 3 + 0] = 1000;
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
          gl_PointSize = aSize * (260.0 / -mv.z);
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
          gl_FragColor = vec4(vColor, core);
        }
      `,
    });

    this.chainPoints = new THREE.Points(ngeom, nmat);
    this.chainGroup.add(this.chainPoints);
    this.chainCursor = 0;
  }

  _warmStartChain() {
    for (let i = 0; i < 24; i++) {
      const v = Math.random() < 0.78 ? 'permit' : (Math.random() < 0.55 ? 'abstain' : 'forbid');
      this._addChainNode(v);
    }
  }

  // ─────────────── Ambient stream ───────────────

  _spawnAmbientAction() {
    const agent = this.agentData[Math.floor(Math.random() * this.agentData.length)];
    const origin = agent.position.clone();
    const dir = origin.clone().normalize();
    if (dir.lengthSq() < 0.01) dir.set(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5).normalize();
    const target = dir.clone().multiplyScalar(this.membraneRadius);

    const headGeom = new THREE.SphereGeometry(0.06, 8, 8);
    const headMat = new THREE.MeshBasicMaterial({
      color: 0x6acfff,
      transparent: true,
      opacity: 0.45,
    });
    const head = new THREE.Mesh(headGeom, headMat);
    head.position.copy(origin);
    this.scene.add(head);

    const trailMaxPoints = 12;
    const trailPositions = new Float32Array(trailMaxPoints * 3);
    for (let i = 0; i < trailMaxPoints; i++) {
      trailPositions[i * 3 + 0] = origin.x;
      trailPositions[i * 3 + 1] = origin.y;
      trailPositions[i * 3 + 2] = origin.z;
    }
    const trailGeom = new THREE.BufferGeometry();
    trailGeom.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
    const trailMat = new THREE.LineBasicMaterial({
      color: 0x6acfff,
      transparent: true,
      opacity: 0.18,
    });
    const trail = new THREE.Line(trailGeom, trailMat);
    this.scene.add(trail);

    this.ambientActions.push({
      origin, target,
      progress: 0,
      duration: 0.9 + Math.random() * 0.5,
      head, trail, trailPositions,
      done: false,
      reachedMembrane: false,
      postFade: 0,
    });
  }

  _updateAmbient(dt) {
    for (let i = this.ambientActions.length - 1; i >= 0; i--) {
      const a = this.ambientActions[i];
      if (!a.reachedMembrane) {
        a.progress = Math.min(1, a.progress + dt / a.duration);
        const pos = new THREE.Vector3().lerpVectors(a.origin, a.target, a.progress);
        a.head.position.copy(pos);
        const len = a.trailPositions.length / 3;
        for (let j = len - 1; j > 0; j--) {
          a.trailPositions[j * 3 + 0] = a.trailPositions[(j - 1) * 3 + 0];
          a.trailPositions[j * 3 + 1] = a.trailPositions[(j - 1) * 3 + 1];
          a.trailPositions[j * 3 + 2] = a.trailPositions[(j - 1) * 3 + 2];
        }
        a.trailPositions[0] = pos.x;
        a.trailPositions[1] = pos.y;
        a.trailPositions[2] = pos.z;
        a.trail.geometry.attributes.position.needsUpdate = true;

        if (a.progress >= 1) {
          a.reachedMembrane = true;
          this._addRipple(a.target, new THREE.Color(0x33b8e8), 0.5);
        }
      } else {
        a.postFade += dt;
        a.head.material.opacity = Math.max(0, a.head.material.opacity - dt * 1.8);
        a.trail.material.opacity = Math.max(0, a.trail.material.opacity - dt * 1.8);
        if (a.head.material.opacity <= 0.02) {
          this.scene.remove(a.head);
          this.scene.remove(a.trail);
          a.head.geometry.dispose();
          a.head.material.dispose();
          a.trail.geometry.dispose();
          a.trail.material.dispose();
          a.done = true;
        }
      }
      if (a.done) this.ambientActions.splice(i, 1);
    }
  }

  // ─────────────── Hero stream ───────────────

  _spawnHeroAction() {
    let agent;
    let attempts = 0;
    do {
      agent = this.agentData[Math.floor(Math.random() * this.agentData.length)];
      attempts++;
    } while (
      attempts < 20 &&
      (agent.position.z < -2 || Math.abs(agent.position.x) < 5 || agent.position.y < -3)
    );

    const tmpl = ACTION_TEMPLATES[Math.floor(Math.random() * ACTION_TEMPLATES.length)];

    let verdict;
    const r = Math.random();
    if (tmpl.tend === 'forbid') {
      verdict = r < 0.65 ? 'forbid' : (r < 0.85 ? 'abstain' : 'permit');
    } else if (tmpl.tend === 'abstain') {
      verdict = r < 0.55 ? 'abstain' : (r < 0.85 ? 'permit' : 'forbid');
    } else {
      verdict = r < 0.85 ? 'permit' : (r < 0.95 ? 'abstain' : 'forbid');
    }
    if (Math.random() < 0.25) verdict = HERO_VERDICT_MIX[Math.floor(Math.random() * HERO_VERDICT_MIX.length)];

    const origin = agent.position.clone();
    // Hero target: Tex's chest emblem position (Tex plane is at y=3.2)
    const target = new THREE.Vector3(0, 2.4, 0);

    const headGeom = new THREE.SphereGeometry(0.22, 16, 16);
    const headMat = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 1.0,
    });
    const head = new THREE.Mesh(headGeom, headMat);
    head.position.copy(origin);
    head.renderOrder = 50;
    this.scene.add(head);

    const haloGeom = new THREE.SphereGeometry(0.5, 16, 16);
    const haloMat = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.35,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const halo = new THREE.Mesh(haloGeom, haloMat);
    halo.position.copy(origin);
    halo.renderOrder = 49;
    this.scene.add(halo);

    const trailMax = 30;
    const trailPositions = new Float32Array(trailMax * 3);
    for (let i = 0; i < trailMax; i++) {
      trailPositions[i * 3 + 0] = origin.x;
      trailPositions[i * 3 + 1] = origin.y;
      trailPositions[i * 3 + 2] = origin.z;
    }
    const trailGeom = new THREE.BufferGeometry();
    trailGeom.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
    const trailMat = new THREE.LineBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.85,
    });
    const trail = new THREE.Line(trailGeom, trailMat);
    this.scene.add(trail);

    const hash = this._randomHash();

    this.heroAction = {
      origin, target, verdict,
      kind: tmpl.kind,
      agent: agent.agentId,
      hash,
      head, halo, trail, trailPositions,
      phase: 'travel',
      phaseTime: 0,
      progress: 0,
      duration: 1.6,
      done: false,
    };

    this.onHeroEvent({
      type: 'spawn',
      kind: tmpl.kind,
      agent: agent.agentId,
      verdict,
      hash,
      origin: this._project(origin),
    });
  }

  _updateHero(dt) {
    if (!this.heroAction) {
      this.heroCooldown -= dt;
      if (this.heroCooldown <= 0) {
        this._spawnHeroAction();
        this.heroCooldown = 3.4 + Math.random() * 0.8;
      }
      return;
    }

    const h = this.heroAction;
    h.phaseTime += dt;

    if (h.phase === 'travel') {
      h.progress = Math.min(1, h.progress + dt / h.duration);
      const e = h.progress < 0.5
        ? 2 * h.progress * h.progress
        : 1 - Math.pow(-2 * h.progress + 2, 2) / 2;
      const pos = new THREE.Vector3().lerpVectors(h.origin, h.target, e);
      h.head.position.copy(pos);
      h.halo.position.copy(pos);

      const len = h.trailPositions.length / 3;
      for (let j = len - 1; j > 0; j--) {
        h.trailPositions[j * 3 + 0] = h.trailPositions[(j - 1) * 3 + 0];
        h.trailPositions[j * 3 + 1] = h.trailPositions[(j - 1) * 3 + 1];
        h.trailPositions[j * 3 + 2] = h.trailPositions[(j - 1) * 3 + 2];
      }
      h.trailPositions[0] = pos.x;
      h.trailPositions[1] = pos.y;
      h.trailPositions[2] = pos.z;
      h.trail.geometry.attributes.position.needsUpdate = true;

      this.onHeroEvent({ type: 'travel', screen: this._project(pos) });

      if (h.progress >= 1) {
        h.phase = 'evaluate';
        h.phaseTime = 0;
        if (this.texUniforms) this.texUniforms.uPulse.value = 0.7;
        this.onHeroEvent({ type: 'evaluate', screen: this._project(h.target) });
      }
    }

    else if (h.phase === 'evaluate') {
      const t = h.phaseTime / 0.7;
      const s = 1 + Math.sin(t * Math.PI) * 0.5;
      h.head.scale.setScalar(s);
      h.halo.scale.setScalar(s);
      this.onHeroEvent({ type: 'evaluate-tick', screen: this._project(h.target) });
      if (h.phaseTime >= 0.7) {
        h.phase = 'verdict';
        h.phaseTime = 0;
        const c = VERDICT_COLORS[h.verdict];
        h.head.material.color.copy(c);
        h.halo.material.color.copy(c);
        h.trail.material.color.copy(c);
        this._addRipple(h.target, c, 0.6);
        if (h.verdict === 'forbid') this._burst(h.target, c, 28, 4.5);
        else if (h.verdict === 'abstain') this._burst(h.target, c, 12, 2.0);
        if (this.texUniforms) {
          this.texUniforms.uPulse.value = h.verdict === 'forbid' ? 1.0 : 0.55;
        }
        this.onHeroEvent({
          type: 'verdict',
          verdict: h.verdict,
          screen: this._project(h.target),
        });
      }
    }

    else if (h.phase === 'verdict') {
      if (h.verdict === 'permit') {
        const past = h.target.clone().add(new THREE.Vector3(0, 0, 8).multiplyScalar(h.phaseTime / 1.4));
        h.head.position.copy(past);
        h.halo.position.copy(past);
        h.head.material.opacity = Math.max(0, 1 - h.phaseTime / 1.4);
        h.halo.material.opacity = Math.max(0, 0.35 - h.phaseTime / 1.4 * 0.35);
      } else if (h.verdict === 'abstain') {
        const bob = Math.sin(h.phaseTime * 4) * 0.12;
        h.head.position.set(h.target.x, h.target.y + bob, h.target.z);
        h.halo.position.copy(h.head.position);
        h.head.material.opacity = Math.max(0, 1 - h.phaseTime / 1.4 * 0.85);
        h.halo.material.opacity = Math.max(0, 0.35 - h.phaseTime / 1.4 * 0.30);
      } else {
        const k = Math.max(0, 1 - h.phaseTime / 0.6);
        h.head.scale.setScalar(k);
        h.halo.scale.setScalar(k * 1.8);
        h.head.material.opacity = k;
        h.halo.material.opacity = k * 0.4;
      }

      this.onHeroEvent({ type: 'verdict-tick', screen: this._project(h.target) });

      if (h.phaseTime >= 1.4) {
        h.phase = 'evidence';
        h.phaseTime = 0;
        this._addChainNode(h.verdict);
        const chainPos = new THREE.Vector3(0, -15.5, 0);
        this.onHeroEvent({
          type: 'evidence',
          hash: h.hash,
          screen: this._project(chainPos),
        });
        this.onReceipt({
          hash: h.hash,
          kind: h.kind,
          agent: h.agent,
          verdict: h.verdict,
          ms: (1.2 + Math.random() * 3.0).toFixed(1),
        });
      }
    }

    else if (h.phase === 'evidence') {
      h.trail.material.opacity = Math.max(0, h.trail.material.opacity - dt * 0.8);
      if (h.phaseTime >= 1.0) {
        this.scene.remove(h.head);
        this.scene.remove(h.halo);
        this.scene.remove(h.trail);
        h.head.geometry.dispose();
        h.head.material.dispose();
        h.halo.geometry.dispose();
        h.halo.material.dispose();
        h.trail.geometry.dispose();
        h.trail.material.dispose();
        this.heroAction = null;
        this.onHeroEvent({ type: 'end' });
      }
    }
  }

  _addRipple(epicenter, color, lifeSeconds) {
    if (this.detonations.length >= 6) this.detonations.shift();
    this.detonations.push({
      epicenter: epicenter.clone(),
      age: 0,
      life: lifeSeconds,
      color,
    });
    this._refreshMembraneUniforms();
  }

  _refreshMembraneUniforms() {
    const u = this.membraneUniforms;
    for (let i = 0; i < this.detonations.length; i++) {
      const d = this.detonations[i];
      u.uRipples.value[i].set(d.epicenter.x, d.epicenter.y, d.epicenter.z, d.age);
      u.uColors.value[i].set(d.color.r, d.color.g, d.color.b);
    }
    u.uRippleCount.value = this.detonations.length;
  }

  _burst(position, color, count, speedScale) {
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
      ).normalize().multiplyScalar(speedScale * (0.6 + Math.random() * 0.7));
      velocities.push(dir);
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const mat = new THREE.PointsMaterial({
      color,
      size: 0.32,
      transparent: true,
      opacity: 1.0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    });
    const points = new THREE.Points(geom, mat);
    points.renderOrder = 60;
    this.scene.add(points);
    this.bursts.push({ points, velocities, age: 0, life: 0.8 });
  }

  _addChainNode(verdict) {
    const slot = this.chainCursor % this.chainCapacity;
    const x = -24 + (this.chainCursor % 48) * 1.05;
    const y = (this.chainCursor % 2 === 0) ? 0.0 : -0.35;
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
    siz.array[slot] = verdict === 'forbid' ? 2.0 : 1.3;
    pos.needsUpdate = true;
    col.needsUpdate = true;
    siz.needsUpdate = true;
    this.chainCursor++;
  }

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

    this.ambientSpawnAccumulator += dt;
    const interval = 1.0 / this.ambientSpawnRate;
    while (this.ambientSpawnAccumulator >= interval) {
      this.ambientSpawnAccumulator -= interval;
      this._spawnAmbientAction();
    }
    this._updateAmbient(dt);

    this._updateHero(dt);

    if (this.starfield) this.starfield.material.uniforms.uTime.value = this.elapsed;
    if (this.agents) this.agents.material.uniforms.uTime.value = this.elapsed;
    if (this.membraneUniforms) {
      this.membraneUniforms.uTime.value = this.elapsed;
      for (let i = 0; i < this.detonations.length; i++) {
        this.detonations[i].age += dt;
      }
      while (this.detonations.length && this.detonations[0].age > this.detonations[0].life) {
        this.detonations.shift();
      }
      this._refreshMembraneUniforms();
    }
    if (this.texUniforms) {
      this.texUniforms.uTime.value = this.elapsed;
      this.texUniforms.uPulse.value = Math.max(0, this.texUniforms.uPulse.value - dt * 1.4);
    }

    for (let i = this.bursts.length - 1; i >= 0; i--) {
      const b = this.bursts[i];
      b.age += dt;
      const arr = b.points.geometry.attributes.position.array;
      for (let j = 0; j < b.velocities.length; j++) {
        arr[j * 3 + 0] += b.velocities[j].x * dt;
        arr[j * 3 + 1] += b.velocities[j].y * dt;
        arr[j * 3 + 2] += b.velocities[j].z * dt;
        b.velocities[j].multiplyScalar(0.93);
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

    const t = this.elapsed;
    this.camera.position.x = Math.sin(t * 0.06) * 0.7;
    this.camera.position.y = 0.6 + Math.sin(t * 0.10) * 0.35;
    this.camera.lookAt(0, 0.4, 0);

    this.renderer.render(this.scene, this.camera);
  }

  _project(vec3) {
    const v = vec3.clone().project(this.camera);
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;
    return {
      x: (v.x * 0.5 + 0.5) * w,
      y: (-v.y * 0.5 + 0.5) * h,
      z: v.z,
    };
  }

  _randomHash() {
    const hex = '0123456789abcdef';
    let s = '0x';
    for (let i = 0; i < 8; i++) s += hex[Math.floor(Math.random() * 16)];
    return s;
  }

  _randomAgentId() {
    const p = AGENT_PREFIXES[Math.floor(Math.random() * AGENT_PREFIXES.length)];
    const n = String(Math.floor(Math.random() * 99) + 1).padStart(2, '0');
    return `${p}-${n}`;
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
