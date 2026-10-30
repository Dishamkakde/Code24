import React, { useEffect, useRef } from 'react';

const CARDS_DATA = [
  { id: "home", original: 70411, distilled: 6140, saved: 64271, pct: "91% less", url: "kessler.co/" },
  { id: "price", original: 41208, distilled: 4960, saved: 36248, pct: "88% less", url: "kessler.co/pricing" },
  { id: "case", original: 98432, distilled: 6300, saved: 92132, pct: "94% less", url: "kessler.co/cases/atlas-rail" },
  { id: "vision", original: 55870, distilled: 8215, saved: 47655, pct: "85% less", url: "kessler.co/vision" },
  { id: "alloy", original: 63904, distilled: 5512, saved: 58392, pct: "91% less", url: "kessler.co/products/k-alloy-7" },
  { id: "journal", original: 47316, distilled: 7602, saved: 39714, pct: "84% less", url: "kessler.co/journal" }
];

const TOTAL_CARDS = CARDS_DATA.length;

function hash(x: number, y: number, seed: number): number {
  let h = ((x * 374761393 + y * 668265263 + seed * 962590211) ^ 0x5bf03635) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
}

function mod(n: number, m: number): number {
  return ((n % m) + m) % m;
}

function clamp(val: number, min: number, max: number): number {
  return Math.min(Math.max(val, min), max);
}

export function App() {
  const beltRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const badgeNumRef = useRef<HTMLSpanElement | null>(null);
  const badgePctRef = useRef<HTMLSpanElement | null>(null);

  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);
  const codeRefs = useRef<(HTMLDivElement | null)[]>([]);

  useEffect(() => {
    const beltEl = beltRef.current;
    const canvas = canvasRef.current;
    if (!beltEl || !canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let cw = 0;
    let ch = 0;
    let gap = 0;
    let span = 0;
    let period = 0;
    let Lx = window.innerWidth / 2;
    let dpr = 1;
    let beltWidth = 0;
    let beltHeight = 0;

    let off = 0;
    let vel = 0;
    let hover = 0;
    let isHovered = false;
    let isDragging = false;
    let lastX = 0;
    let lastTime = 0;

    let currentTokens = 48193;
    let targetTokens = 48193;
    let lastActiveIndex = -1;

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function updateGeometry() {
      if (!beltEl || !canvas || !ctx) return;
      const beltRect = beltEl.getBoundingClientRect();
      beltWidth = beltRect.width;
      beltHeight = beltRect.height;
      Lx = window.innerWidth / 2;

      const firstCard = cardRefs.current[0];
      if (firstCard) {
        const rect = firstCard.getBoundingClientRect();
        cw = rect.width;
        ch = rect.height;
      } else {
        cw = window.innerWidth * 0.46;
        ch = window.innerHeight * 0.52;
      }

      const rootStyles = getComputedStyle(document.documentElement);
      const gapVal = rootStyles.getPropertyValue("--gap").trim();
      if (gapVal.endsWith("vw")) {
        gap = (parseFloat(gapVal) / 100) * window.innerWidth;
      } else if (gapVal.endsWith("px")) {
        gap = parseFloat(gapVal);
      } else {
        gap = window.innerWidth * 0.0475;
      }

      span = cw + gap;
      period = span * TOTAL_CARDS;

      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = beltWidth * dpr;
      canvas.height = beltHeight * dpr;
      ctx.resetTransform();
      ctx.scale(dpr, dpr);
    }

    updateGeometry();
    off = window.innerWidth / 2 - 0.62 * cw;
    vel = prefersReducedMotion ? 0 : -0.075 * window.innerWidth;

    const onResize = () => updateGeometry();
    window.addEventListener("resize", onResize);

    const onPointerEnter = () => { isHovered = true; };
    const onPointerLeave = () => { isHovered = false; };

    const onPointerDown = (e: PointerEvent) => {
      beltEl.setPointerCapture(e.pointerId);
      isDragging = true;
      lastX = e.clientX;
      lastTime = performance.now();
      beltEl.classList.add("grabbing");
    };

    const onPointerMove = (e: PointerEvent) => {
      if (!isDragging) return;
      const now = performance.now();
      const dtMs = Math.max(8, now - lastTime);
      const dx = e.clientX - lastX;

      off += dx;
      vel = (dx / dtMs) * 1000 * 0.8 + vel * 0.2;

      lastX = e.clientX;
      lastTime = now;
    };

    const onPointerEnd = (e: PointerEvent) => {
      if (!isDragging) return;
      isDragging = false;
      beltEl.classList.remove("grabbing");
      try {
        beltEl.releasePointerCapture(e.pointerId);
      } catch (_) {}
    };

    const onWheel = (e: WheelEvent) => {
      if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
        e.preventDefault();
        vel += -e.deltaX * 6;
      }
    };

    beltEl.addEventListener("pointerenter", onPointerEnter);
    beltEl.addEventListener("pointerleave", onPointerLeave);
    beltEl.addEventListener("pointerdown", onPointerDown);
    beltEl.addEventListener("pointermove", onPointerMove);
    beltEl.addEventListener("pointerup", onPointerEnd);
    beltEl.addEventListener("pointercancel", onPointerEnd);
    beltEl.addEventListener("wheel", onWheel, { passive: false });

    // Sparks
    interface Spark {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      life: number;
      decay: number;
    }
    const sparks: Spark[] = [];

    function updateSparks(dt: number) {
      if (!ctx) return;
      if (Math.random() < 0.6) {
        sparks.push({
          x: Lx + (Math.random() - 0.2) * 6,
          y: 70 + Math.random() * ch,
          vx: 8 + Math.random() * 28,
          vy: (Math.random() - 0.5) * 20 - 15,
          size: 1 + Math.random() * 2,
          life: 1.0,
          decay: 1.2 + Math.random() * 1.6
        });
      }

      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx * dt;
        s.y += s.vy * dt;
        s.life -= s.decay * dt;
        if (s.life <= 0) {
          sparks.splice(i, 1);
        } else {
          ctx.fillStyle = `rgba(255, 122, 60, ${(s.life * 0.85).toFixed(2)})`;
          ctx.fillRect(s.x, s.y, s.size, s.size);
        }
      }
    }

    function drawFx(activeCards: { index: number; x: number; cut: number }[]) {
      if (!ctx) return;
      ctx.clearRect(0, 0, beltWidth, beltHeight);

      for (let idx = 0; idx < activeCards.length; idx++) {
        const item = activeCards[idx];
        const x = item.x;
        const cut = item.cut;
        const i = item.index;

        if (cut <= 0 || x + cw <= Lx) continue;

        const cardY = 70;

        // 1. Haze
        const hazeWidth = Math.min(150, x + cw - Lx);
        if (hazeWidth > 0) {
          const grad = ctx.createLinearGradient(Lx, 0, Lx + 150, 0);
          grad.addColorStop(0, "rgba(255, 96, 40, 0.42)");
          grad.addColorStop(1, "rgba(255, 96, 40, 0)");
          ctx.fillStyle = grad;
          ctx.fillRect(Lx, cardY, hazeWidth, ch);
        }

        // 2. Dithered particles fixed to card surface
        const R = 0.3 * cw;
        const startGx = Math.max(0, Math.floor(cut / 3));
        const endGx = Math.min(Math.floor(cw / 3), Math.floor((cut + R) / 3));
        const rows = Math.floor(ch / 3);

        ctx.fillStyle = "#FF5A1F";

        for (let gx = startGx; gx <= endGx; gx++) {
          const sx = x + gx * 3;
          const d = sx - Lx;
          if (d < 0) continue;

          const p = Math.pow(Math.max(0, 1 - d / R), 1.7);
          if (p <= 0.001) continue;

          for (let row = -5; row < rows + 5; row++) {
            const isInside = (row >= 0 && row < rows);
            const thresh = p * (isInside ? 0.92 : 0.35);

            if (hash(gx, row, i) < thresh) {
              ctx.fillRect(sx, cardY + row * 3, 2.5, 2.5);
            }
          }
        }
      }
    }

    let animId = 0;
    let prevTimestamp = performance.now();

    function tick(now: number) {
      const dt = Math.min(0.1, (now - prevTimestamp) / 1000);
      prevTimestamp = now;

      const autoSpeed = prefersReducedMotion ? 0 : -0.075 * window.innerWidth;
      const targetHover = isHovered ? 1 : 0;
      hover += (targetHover - hover) * Math.min(1, 4 * dt);
      const targetSpeed = autoSpeed * (1 - 0.65 * hover);

      if (!isDragging) {
        vel += (targetSpeed - vel) * (1 - Math.exp(-2.2 * dt));
        off += vel * dt;
      }

      const activeCards: { index: number; x: number; cut: number }[] = [];
      let crossingCard: typeof CARDS_DATA[0] | null = null;
      let crossingCardIndex = -1;
      let crossingCut = 0;

      for (let i = 0; i < TOTAL_CARDS; i++) {
        const x = mod(off + i * span + span, period) - span;
        const cut = clamp(Lx - x, 0, cw);

        const card = cardRefs.current[i];
        const code = codeRefs.current[i];

        if (card) {
          card.style.transform = `translate3d(${x.toFixed(2)}px, 0, 0)`;

          if (cut > 0) {
            const maskCut = cut + 26;
            card.style.clipPath = `inset(0 0 0 ${cut.toFixed(2)}px round 0 1.6vw 1.6vw 0)`;
            (card.style as any).webkitClipPath = `inset(0 0 0 ${cut.toFixed(2)}px round 0 1.6vw 1.6vw 0)`;
            (card.style as any).maskImage = `linear-gradient(90deg, transparent ${cut.toFixed(2)}px, #000 ${maskCut.toFixed(2)}px)`;
            (card.style as any).webkitMaskImage = `linear-gradient(90deg, transparent ${cut.toFixed(2)}px, #000 ${maskCut.toFixed(2)}px)`;
          } else {
            card.style.clipPath = "none";
            (card.style as any).webkitClipPath = "none";
            (card.style as any).maskImage = "none";
            (card.style as any).webkitMaskImage = "none";
          }
        }

        if (code) {
          code.style.transform = `translate3d(${x.toFixed(2)}px, 0, 0)`;
          code.style.clipPath = `inset(0 ${(cw - cut).toFixed(2)}px 0 0)`;
          (code.style as any).webkitClipPath = `inset(0 ${(cw - cut).toFixed(2)}px 0 0)`;
          code.style.visibility = cut > 0 ? "visible" : "hidden";
        }

        if (cut > 0 && cut < cw) {
          crossingCard = CARDS_DATA[i];
          crossingCardIndex = i;
          crossingCut = cut;
        }

        if (cut > 0 && x + cw > Lx) {
          activeCards.push({ index: i, x, cut });
        }
      }

      drawFx(activeCards);
      if (activeCards.length > 0) {
        updateSparks(dt);
      }

      if (crossingCard) {
        const progress = crossingCut / cw;
        targetTokens = Math.round((crossingCard.original - crossingCard.distilled) * progress);

        if (crossingCardIndex !== lastActiveIndex) {
          lastActiveIndex = crossingCardIndex;
          currentTokens = targetTokens;
          if (badgePctRef.current) {
            badgePctRef.current.textContent = `${Math.round((crossingCard.saved / crossingCard.original) * 100)}% less`;
          }
        } else {
          currentTokens += (targetTokens - currentTokens) * Math.min(1, dt * 14);
        }

        if (badgeNumRef.current) {
          badgeNumRef.current.textContent = "\u2212" + Math.round(currentTokens).toLocaleString("en-US");
        }
      }

      animId = requestAnimationFrame(tick);
    }

    animId = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
      beltEl.removeEventListener("pointerenter", onPointerEnter);
      beltEl.removeEventListener("pointerleave", onPointerLeave);
      beltEl.removeEventListener("pointerdown", onPointerDown);
      beltEl.removeEventListener("pointermove", onPointerMove);
      beltEl.removeEventListener("pointerup", onPointerEnd);
      beltEl.removeEventListener("pointercancel", onPointerEnd);
      beltEl.removeEventListener("wheel", onWheel);
    };
  }, []);

  return (
    <div className="stage">
      {/* Top Navigation */}
      <nav className="top-nav">
        <a href="#" className="brand-logo">
          <svg viewBox="0 0 19 23" fill="none">
            <path d="M9.5 1C9.5 1 2 10.5 2 15.5C2 19.6421 5.35786 22 9.5 22C13.6421 22 17 19.6421 17 15.5C17 10.5 9.5 1 9.5 1Z" fill="currentColor"/>
            <path d="M5.5 16C5.5 13 7.5 10.5 9.5 9.5" stroke="var(--bg)" strokeWidth="1.7" strokeLinecap="round"/>
          </svg>
          <span className="brand-name">Distill</span>
        </a>

        <div className="nav-links">
          <a href="#product" className="nav-link">
            Product
            <svg viewBox="0 0 8 5" fill="none"><path d="M1 1L4 4L7 1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </a>
          <a href="#use-cases" className="nav-link">
            Use cases
            <svg viewBox="0 0 8 5" fill="none"><path d="M1 1L4 4L7 1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </a>
          <a href="#resources" className="nav-link">
            Resources
            <svg viewBox="0 0 8 5" fill="none"><path d="M1 1L4 4L7 1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </a>
          <a href="#pricing" className="nav-link">Pricing</a>
        </div>

        <div className="nav-right">
          <a href="#signin" className="nav-signin">Sign in</a>
          <a href="#trial" className="btn-trial">Start a free trial</a>
          <a href="#demo" className="btn-demo">Book a demo</a>
        </div>
      </nav>

      {/* Hero Copy */}
      <header className="hero-grid">
        <div className="hero-left">
          <div className="hero-eyebrow">AI READABILITY</div>
          <h1 className="hero-headline">
            Built for people.
            <em>Read by machines.</em>
          </h1>
        </div>
        <div className="hero-right">
          <p className="hero-paragraph">
            Distill detects AI agents at the edge and serves them a clean, token&#8209;light version of every page, without changing a pixel of what people see.
          </p>
          <a href="#explore" className="hero-button">Explore Distill</a>
        </div>
      </header>

      {/* Scanner Line */}
      <div className="scan" id="scanner">
        <i className="scan-core"></i>
        <b className="scan-halo"></b>
      </div>

      {/* Floating Counter Badge */}
      <div className="badge" id="badge">
        <span className="badge-label">Token reduction</span>
        <div className="badge-pill">
          <span className="badge-number" ref={badgeNumRef}>&#8722;48,193</span>
          <span className="badge-percent" ref={badgePctRef}>91% less</span>
        </div>
      </div>

      {/* The Conveyor Belt */}
      <div className="belt" ref={beltRef}>
        {/* Code Layer */}
        <div className="codes">
          {/* Code 1 (home) */}
          <div className="code-shell" ref={el => { codeRefs.current[0] = el; }}>
            <div className="code-html">
{`<h1>Kessler — Advanced materials</h1>
<p>
  Advanced materials for a stronger
  tomorrow. Ceramic-matrix alloys made
  with desert sand and solar heat.
</p>
<h2>At a glance</h2>
<ul>
  <li>Strength: 200x steel by weight</li>
  <li>Emissions: 87% lower</li>
  <li>Plants: Nevada, Atacama, Oman</li>
  <li>Founded: 2019</li>
</ul>
<h2>Products</h2>
<ul>
  <li>K-Alloy 7 — structural</li>
  <li>Basalt fibre — tensile</li>
  <li>Ceramic matrix — thermal</li>
</ul>
<a href="/demo">Book a demo</a>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 6,140 tokens -->
<!-- original: 70,411 tokens -->
<!-- kessler.co/ -->`}
            </div>
          </div>

          {/* Code 2 (price) */}
          <div className="code-shell" ref={el => { codeRefs.current[1] = el; }}>
            <div className="code-html">
{`<h1>Kessler — Pricing</h1>
<p>
  Three plans for every scale of
  production. Start small, scale to
  full foundry output.
</p>
<h2>Pilot — $299 / mo</h2>
<ul>
  <li>Sample batches: 4 / mo</li>
  <li>Alloy grades: 2</li>
  <li>Support: email</li>
</ul>
<h2>Industrial — $2,400 / mo</h2>
<ul>
  <li>Tonnage: up to 40 t / mo</li>
  <li>Alloy grades: all</li>
  <li>Certification: ISO 9001</li>
  <li>Support: dedicated engineer</li>
</ul>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 4,960 tokens -->
<!-- original: 41,208 tokens -->
<!-- kessler.co/pricing -->`}
            </div>
          </div>

          {/* Code 3 (case) */}
          <div className="code-shell" ref={el => { codeRefs.current[2] = el; }}>
            <div className="code-html">
{`<h1>Case study: Atlas Rail</h1>
<p>
  How Atlas Rail cut track weight by
  a third in eighteen months.
</p>
<h2>The challenge</h2>
<p>
  1,200 km of desert line, rails
  warping above 50 °C every summer.
</p>
<h2>The result</h2>
<ul>
  <li>34% lighter track sections</li>
  <li>3.4x longer service life</li>
  <li>0 unplanned closures in 2025</li>
</ul>
<p>
  We stopped losing summers.
  — Head of Infrastructure
</p>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 6,300 tokens -->
<!-- original: 98,432 tokens -->
<!-- kessler.co/cases/atlas-rail -->`}
            </div>
          </div>

          {/* Code 4 (vision) */}
          <div className="code-shell" ref={el => { codeRefs.current[3] = el; }}>
            <div className="code-html">
{`<article>
  <h1>The Kessler vision</h1>
  <p>
    Materials that outlast the people
    who made them.
  </p>
  <p>
    We build where the sun is
    strongest and the sand is free:
    three plants, one closed loop.
  </p>
  <h2>Principles</h2>
  <ol>
    <li>Heat from the sun, not gas</li>
    <li>Sand in, scrap back in</li>
    <li>Publish every number</li>
  </ol>
</article>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 8,215 tokens -->
<!-- original: 55,870 tokens -->
<!-- kessler.co/vision -->`}
            </div>
          </div>

          {/* Code 5 (alloy) */}
          <div className="code-shell" ref={el => { codeRefs.current[4] = el; }}>
            <div className="code-html">
{`<h1>K-Alloy 7</h1>
<p>The carbon-negative alloy.</p>
<h2>Specification</h2>
<ul>
  <li>Tensile strength: 1,940 MPa</li>
  <li>Density: 2.9 g/cm³</li>
  <li>Max service temp: 1,150 °C</li>
  <li>CO₂: −0.4 kg per kg made</li>
</ul>
<h2>Uses</h2>
<ul>
  <li>Rail, bridges, turbine housings</li>
</ul>
<a href="/k-alloy-7.pdf">Datasheet</a>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 5,512 tokens -->
<!-- original: 63,904 tokens -->
<!-- kessler.co/products/k-alloy-7 -->`}
            </div>
          </div>

          {/* Code 6 (journal) */}
          <div className="code-shell" ref={el => { codeRefs.current[5] = el; }}>
            <div className="code-html">
{`<h1>Kessler Journal</h1>
<p>Field notes from the flats.</p>
<article>
  <h2>Mining nothing but light</h2>
  <time>2026-03-14</time>
</article>
<article>
  <h2>Atacama, year one</h2>
  <time>2026-02-02</time>
</article>
<article>
  <h2>Why we melt sand at noon</h2>
  <time>2026-01-09</time>
</article>`}
            </div>
            <div className="code-meta">
{`<!-- distilled: 7,602 tokens -->
<!-- original: 47,316 tokens -->
<!-- kessler.co/journal -->`}
            </div>
          </div>
        </div>

        {/* Cards Layer */}
        <div className="cards">
          {/* Card 1: Home */}
          <div className="card-shell card-home" ref={el => { cardRefs.current[0] = el; }}>
            <div className="k-nav">
              <div className="k-logo">
                <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                  <polygon points="4,38 20,6 36,38" fill="none"/>
                  <polygon points="18,38 34,14 50,38" fill="none"/>
                </svg>
                <span className="k-brand">Kessler</span>
              </div>
              <div className="k-menu">
                <span className="k-menu-item k-menu-pill">PRODUCTS</span>
                <span className="k-menu-item">IMPACT</span>
                <span className="k-menu-item">ABOUT</span>
              </div>
            </div>
            <div className="home-stats">
              <div className="stat-unit">
                <span className="stat-num">200x</span>
                <span className="stat-lbl">stronger</span>
              </div>
              <div className="home-divider"></div>
              <div className="stat-unit">
                <span className="stat-num">87%</span>
                <span className="stat-lbl">lower emissions</span>
              </div>
            </div>
            <div className="home-tagline">Advanced materials for a stronger tomorrow.</div>
          </div>

          {/* Card 2: Price */}
          <div className="card-shell card-price" ref={el => { cardRefs.current[1] = el; }}>
            <div className="k-nav">
              <div className="k-logo">
                <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                  <polygon points="4,38 20,6 36,38" fill="none"/>
                  <polygon points="18,38 34,14 50,38" fill="none"/>
                </svg>
                <span className="k-brand">Kessler</span>
              </div>
              <div className="k-menu">
                <span className="k-menu-item">PRODUCTS</span>
                <span className="k-menu-item k-menu-pill">PRICING</span>
                <span className="k-menu-item">CONTACT</span>
              </div>
            </div>
            <div className="price-big"><span className="price-curr">$</span>2,400</div>
            <div className="price-sub">PER MONTH · INDUSTRIAL</div>
            <div className="price-plans">
              <div className="plan-row"><span className="plan-name">Pilot</span><span>$299</span></div>
              <div className="plan-row"><span className="plan-name">Industrial</span><span>$2,400</span></div>
              <div className="plan-row"><span className="plan-name">Foundry</span><span>Custom</span></div>
            </div>
            <a href="#pilot" className="price-cta">Start a pilot</a>
          </div>

          {/* Card 3: Case Study */}
          <div className="card-shell card-case" ref={el => { cardRefs.current[2] = el; }}>
            <div className="card-case-bg"></div>
            <div className="card-case-veil"></div>
            <div className="card-case-content">
              <div className="k-nav">
                <div className="k-logo">
                  <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                    <polygon points="4,38 20,6 36,38" fill="none"/>
                    <polygon points="18,38 34,14 50,38" fill="none"/>
                  </svg>
                  <span className="k-brand">Kessler</span>
                </div>
                <div className="k-menu">
                  <span className="k-menu-item">PRODUCTS</span>
                  <span className="k-menu-item k-menu-pill">IMPACT</span>
                  <span className="k-menu-item">ABOUT</span>
                </div>
              </div>
              <div className="case-kicker">CASE STUDY · ATLAS RAIL</div>
              <h2 className="case-title">How Atlas Rail cut track weight by a third in eighteen months</h2>
              <div className="case-stats">
                <div className="c-stat">
                  <span className="c-num">34%</span>
                  <span className="c-lbl">lighter track</span>
                </div>
                <div className="c-stat">
                  <span className="c-num">3.4x</span>
                  <span className="c-lbl">service life</span>
                </div>
                <div className="c-stat">
                  <span className="c-num">0</span>
                  <span className="c-lbl">unplanned closures</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 4: Vision */}
          <div className="card-shell card-vision" ref={el => { cardRefs.current[3] = el; }}>
            <div className="k-nav">
              <div className="k-logo">
                <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                  <polygon points="4,38 20,6 36,38" fill="none"/>
                  <polygon points="18,38 34,14 50,38" fill="none"/>
                </svg>
                <span className="k-brand">Kessler</span>
              </div>
              <div className="k-menu">
                <span className="k-menu-item">PRODUCTS</span>
                <span className="k-menu-item k-menu-pill">VISION</span>
                <span className="k-menu-item">ABOUT</span>
              </div>
            </div>
            <div className="vision-tiles">
              <div className="tile-img tile-foundry"></div>
              <div className="tile-img tile-mesa"></div>
              <div className="tile-quote">
                The Kessler vision: <em>materials that outlast the people who made them.</em>
              </div>
            </div>
            <div className="vision-footer">
              <span>How Kessler pours alloy<br/>at the edge of the desert</span>
              <span>Manifesto · 6 min</span>
            </div>
          </div>

          {/* Card 5: Alloy */}
          <div className="card-shell card-alloy" ref={el => { cardRefs.current[4] = el; }}>
            <div className="card-alloy-bg"></div>
            <div className="card-alloy-veil"></div>
            <div className="card-alloy-content">
              <div className="k-nav">
                <div className="k-logo">
                  <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                    <polygon points="4,38 20,6 36,38" fill="none"/>
                    <polygon points="18,38 34,14 50,38" fill="none"/>
                  </svg>
                  <span className="k-brand">Kessler</span>
                </div>
                <div className="k-menu">
                  <span className="k-menu-item k-menu-pill">PRODUCTS</span>
                  <span className="k-menu-item">IMPACT</span>
                  <span className="k-menu-item">ABOUT</span>
                </div>
              </div>
              <div className="alloy-headline">
                The carbon&#8209;negative
                <em>alloy.</em>
              </div>
              <div className="alloy-specs">
                <div className="spec-row"><span>Product</span><span>K-Alloy 7</span></div>
                <div className="spec-row"><span>Tensile</span><span>1,940 MPa</span></div>
                <div className="spec-row"><span>Datasheet</span><span>PDF ↗</span></div>
              </div>
            </div>
          </div>

          {/* Card 6: Journal */}
          <div className="card-shell card-journal" ref={el => { cardRefs.current[5] = el; }}>
            <div className="k-nav">
              <div className="k-logo">
                <svg viewBox="0 0 54 42" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" strokeLinecap="round">
                  <polygon points="4,38 20,6 36,38" fill="none"/>
                  <polygon points="18,38 34,14 50,38" fill="none"/>
                </svg>
                <span className="k-brand">Kessler</span>
              </div>
              <div className="k-menu">
                <span className="k-menu-item">PRODUCTS</span>
                <span className="k-menu-item k-menu-pill">JOURNAL</span>
                <span className="k-menu-item">ABOUT</span>
              </div>
            </div>
            <div className="journal-header">
              <h2 className="journal-title">
                Journal
                <em>field notes from the flats</em>
              </h2>
            </div>
            <div className="journal-posts">
              <div className="j-post">
                <div className="post-thumb" style={{ backgroundImage: "url('https://d2ol7oe51mr4n9.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/7b6ad638-89ec-4dec-be74-d36fbff3ea53.webp')" }}></div>
                <div className="post-kicker">FIELD NOTES</div>
                <div className="post-heading">Mining nothing but light on the salt flats</div>
              </div>
              <div className="j-post">
                <div className="post-thumb" style={{ backgroundImage: "url('https://d2ol7oe51mr4n9.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/62b0d7c1-3eb7-44bd-9b19-57b975fb250f.webp')" }}></div>
                <div className="post-kicker">PLANTS</div>
                <div className="post-heading">Atacama, year one</div>
              </div>
              <div className="j-post">
                <div className="post-thumb" style={{ backgroundImage: "url('https://d2ol7oe51mr4n9.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/0e201fcd-ffc0-46a0-bd06-faa07bf0e84b.webp')" }}></div>
                <div className="post-kicker">PROCESS</div>
                <div className="post-heading">Why we melt sand at noon</div>
              </div>
            </div>
          </div>
        </div>

        {/* FX Canvas */}
        <canvas className="fx" ref={canvasRef}></canvas>
      </div>
    </div>
  );
}
export default App;
