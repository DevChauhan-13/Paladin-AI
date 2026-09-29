/**
 * BotBlox Preloader & Hero Dynamics Engine
 * Recreates the exact negative-space dot-matrix mascot assembly,
 * authentic radar shimmer, percentage counter, and Space Grotesk text reveals.
 */

function initPreloader() {
  const overlay = document.getElementById('preloaderOverlay');
  const canvas = document.getElementById('preloaderCanvas');
  const counter = document.getElementById('preloaderCounter');
  const heroSection = document.querySelector('.section-hero');
  const heroVideo = document.getElementById('heroVideoMain');

  if (!canvas || !overlay || typeof MATRIX_ACTIVE_DOTS === 'undefined') {
    if (heroSection) heroSection.classList.add('is-revealed');
    if (heroVideo) heroVideo.play().catch(() => {});
    return;
  }

  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  // Exact matrix geometry: 42 rows x 45 cols
  const cols = typeof MATRIX_COLS !== 'undefined' ? MATRIX_COLS : 45;
  const rows = typeof MATRIX_ROWS !== 'undefined' ? MATRIX_ROWS : 42;

  // Responsive canvas sizing
  const displayW = 440;
  const displayH = Math.round(displayW * (rows / cols));
  canvas.width = displayW * dpr;
  canvas.height = displayH * dpr;
  ctx.scale(dpr, dpr);

  const stepX = displayW / cols;
  const stepY = displayH / rows;
  const dotRadius = Math.min(stepX, stepY) * 0.38; // crisp dot diameter

  const centerX = displayW / 2;
  const centerY = displayH / 2;

  // Initialize particle for every active dot in the matrix
  const particles = MATRIX_ACTIVE_DOTS.map(([r, c], i) => {
    const targetX = (c + 0.5) * stepX;
    const targetY = (r + 0.5) * stepY;

    // Start scattered outward around center
    const angle = (i / MATRIX_ACTIVE_DOTS.length) * Math.PI * 8 + (i % 7);
    const dist = 70 + (i % 120) * 1.5 + Math.random() * 40;
    const originX = centerX + Math.cos(angle) * dist;
    const originY = centerY + Math.sin(angle) * dist;

    return {
      originX,
      originY,
      targetX,
      targetY,
      x: originX,
      y: originY,
      seed: Math.random() * 100,
      flickerOffset: Math.random() * 10
    };
  });

  let progress = 0;
  const startTime = performance.now();
  const duration = 2800; // ~2.8s authentic loading experience

  function render(now) {
    const elapsed = now - startTime;
    progress = Math.min(100, Math.floor((elapsed / duration) * 100));

    if (counter) {
      counter.textContent = `${progress}%`;
    }

    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, displayW, displayH);

    // Easing curve: scatter drifts then pulls sharply into negative space grid
    const t = Math.min(1, Math.max(0, (progress - 12) / 76));
    const easeT = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;

    const isNearEnd = progress >= 92;

    // Draw all particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];

      // Organic drift that dampens as particles assemble
      const floatAmp = (1 - easeT) * 10;
      const floatX = Math.sin(now * 0.003 + p.seed) * floatAmp;
      const floatY = Math.cos(now * 0.003 + p.seed) * floatAmp;

      p.x = p.originX + (p.targetX - p.originX) * easeT + floatX;
      p.y = p.originY + (p.targetY - p.originY) * easeT + floatY;

      // Realistic radar/phosphor shimmer
      let opacity = 1.0;
      if (!isNearEnd && (i % 17 === 0 || i % 23 === 0)) {
        const shimmer = Math.sin(now * 0.008 + p.flickerOffset);
        opacity = shimmer > 0.3 ? 0.35 : 0.85;
      }

      ctx.fillStyle = opacity === 1.0 ? '#ffffff' : `rgba(255, 255, 255, ${opacity})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, dotRadius, 0, Math.PI * 2);
      ctx.fill();
    }

    if (progress < 100) {
      requestAnimationFrame(render);
    } else {
      // Complete! Pause briefly at 100% so user sees the crisp robot mascot, then reveal hero
      setTimeout(() => {
        overlay.classList.add('is-loaded');
        if (heroSection) {
          heroSection.classList.add('is-revealed');
        }
        if (heroVideo) {
          heroVideo.play().catch(() => {});
        }
      }, 350);
    }
  }

  requestAnimationFrame(render);
}

document.addEventListener('DOMContentLoaded', () => {
  initPreloader();
});
