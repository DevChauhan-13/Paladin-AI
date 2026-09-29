/**
 * BotBlox Website JavaScript Interactions
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Mobile Menu Toggle
  const mobileToggle = document.querySelector('.mobile-toggle');
  const mainNav = document.querySelector('.main-nav');

  if (mobileToggle && mainNav) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = mainNav.classList.toggle('is-open');
      mobileToggle.setAttribute('aria-expanded', isOpen);
      document.body.style.overflow = isOpen ? 'hidden' : '';
    });
  }

  // 2. Active Link Highlighting
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-link, .dropdown-link');
  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href && (currentPath.endsWith(href) || (href === 'index.html' && currentPath.endsWith('/')))) {
      link.classList.add('is-active');
      const parentNavItem = link.closest('.nav-item');
      if (parentNavItem) parentNavItem.classList.add('active');
    }
  });

  // 3. Scroll Reveal Animations
  const revealElements = document.querySelectorAll('.reveal-on-scroll');
  if ('IntersectionObserver' in window) {
    const revealObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.1
    });

    revealElements.forEach(el => revealObserver.observe(el));
  } else {
    revealElements.forEach(el => el.classList.add('is-visible'));
  }

  // 4. Header Background On Scroll
  const siteHeader = document.querySelector('.site-header');
  if (siteHeader) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 40) {
        siteHeader.style.background = 'rgba(16, 20, 26, 0.95)';
        siteHeader.style.borderColor = 'rgba(255, 255, 255, 0.18)';
        siteHeader.style.boxShadow = '0 12px 36px rgba(0, 0, 0, 0.65)';
      } else {
        siteHeader.style.background = 'rgba(22, 26, 32, 0.88)';
        siteHeader.style.borderColor = 'rgba(255, 255, 255, 0.12)';
        siteHeader.style.boxShadow = '0 10px 30px rgba(0, 0, 0, 0.5)';
      }
    });
  }

  // 5. Interactive Quote / Contact Modal or Notification
  const quoteButtons = document.querySelectorAll('[data-action="quote"]');
  quoteButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      if (window.location.pathname.includes('contact.html')) return;
      window.location.href = 'contact.html#quote';
    });
  });

  // 6. Newsletter Form Feedback
  const newsletterForm = document.querySelector('.newsletter-form');
  if (newsletterForm) {
    newsletterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = newsletterForm.querySelector('.newsletter-input');
      if (input && input.value) {
        input.value = '';
        input.placeholder = 'Subscribed successfully!';
        setTimeout(() => {
          input.placeholder = 'Email';
        }, 3000);
      }
    });
  }

  // 7. Interactive Category Tabs on Products Page
  const filterPills = document.querySelectorAll('[data-filter]');
  const productCards = document.querySelectorAll('[data-category]');
  if (filterPills.length > 0 && productCards.length > 0) {
    filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        filterPills.forEach(p => p.classList.remove('btn-primary'));
        filterPills.forEach(p => p.classList.add('btn-secondary'));
        pill.classList.remove('btn-secondary');
        pill.classList.add('btn-primary');

        const filter = pill.getAttribute('data-filter');
        productCards.forEach(card => {
          if (filter === 'all' || card.getAttribute('data-category') === filter) {
            card.style.display = 'flex';
          } else {
            card.style.display = 'none';
          }
        });
      });
    });
  }

  // 8. Mission Section Scroll-Driven Character Illumination
  const initMissionScrollAnimation = () => {
    const heading = document.getElementById('missionHeading');
    if (!heading) return;

    const lineElements = heading.querySelectorAll('.mission-line');
    let allChars = [];

    if (lineElements.length > 0) {
      lineElements.forEach(lineEl => {
        const text = lineEl.textContent.trim();
        lineEl.innerHTML = '';
        const words = text.split(/\s+/);

        words.forEach((word, wIdx) => {
          const wordSpan = document.createElement('span');
          wordSpan.className = 'mission-word';

          for (let i = 0; i < word.length; i++) {
            const charSpan = document.createElement('span');
            charSpan.className = 'mission-char';
            charSpan.textContent = word[i];
            wordSpan.appendChild(charSpan);
            allChars.push(charSpan);
          }
          lineEl.appendChild(wordSpan);

          if (wIdx < words.length - 1) {
            lineEl.appendChild(document.createTextNode(' '));
          }
        });
      });
    }

    const updateIllumination = () => {
      if (!allChars.length) return;
      const rect = heading.getBoundingClientRect();
      const windowHeight = window.innerHeight;

      // Start illuminating when heading enters lower viewport (85% from top)
      // Fully illuminate when heading reaches center-upper viewport (35% from top)
      const startThreshold = windowHeight * 0.85;
      const endThreshold = windowHeight * 0.35;

      let progress = (startThreshold - rect.top) / (startThreshold - endThreshold);
      progress = Math.max(0, Math.min(1, progress));

      const totalChars = allChars.length;
      const illuminatedPos = progress * totalChars;
      const fullIndex = Math.floor(illuminatedPos);
      const fraction = illuminatedPos - fullIndex;

      for (let i = 0; i < totalChars; i++) {
        const charEl = allChars[i];
        if (i < fullIndex) {
          charEl.style.color = '#ffffff';
          charEl.style.opacity = '1';
          charEl.style.textShadow = '0 0 12px rgba(255, 255, 255, 0.25)';
        } else if (i === fullIndex && progress < 1) {
          const alpha = 0.18 + fraction * 0.82;
          const op = 0.25 + fraction * 0.75;
          charEl.style.color = `rgba(255, 255, 255, ${alpha.toFixed(3)})`;
          charEl.style.opacity = op.toFixed(3);
          charEl.style.textShadow = fraction > 0.4 ? '0 0 8px rgba(255, 255, 255, 0.2)' : 'none';
        } else {
          charEl.style.color = 'rgba(255, 255, 255, 0.18)';
          charEl.style.opacity = '0.25';
          charEl.style.textShadow = 'none';
        }
      }
    };

    let ticking = false;
    const onScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          updateIllumination();
          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    updateIllumination();
  };

  initMissionScrollAnimation();

  // 9. Mission SwitchCore Video Playback Assurance
  const missionVideo = document.querySelector('.mission-video');
  if (missionVideo) {
    missionVideo.play().catch(() => {
      window.addEventListener('scroll', () => {
        missionVideo.play().catch(() => {});
      }, { once: true });
    });
  }

  // 10. Theme Management: White Theme (video replica) vs Dark Theme
  const isSubpage = !window.location.pathname.endsWith('index.html') &&
                    window.location.pathname !== '/' &&
                    !window.location.pathname.endsWith('/sih/') &&
                    !window.location.pathname.endsWith('/sih');

  const savedTheme = localStorage.getItem('botblox_theme');
  // Secondary pages default to the white theme as requested; landing page defaults to dark
  const activeTheme = savedTheme ? savedTheme : (isSubpage ? 'light' : 'dark');

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.classList.toggle('theme-light', theme === 'light');
    document.body.classList.toggle('theme-dark', theme === 'dark');

    const toggleBtns = document.querySelectorAll('.theme-toggle-btn');
    toggleBtns.forEach(btn => {
      const textEl = btn.querySelector('.theme-toggle-text');
      const indEl = btn.querySelector('.theme-toggle-indicator');
      if (textEl) {
        textEl.textContent = theme === 'light' ? 'WHITE' : 'DARK';
      }
      if (indEl) {
        indEl.style.background = theme === 'light' ? '#d50f3b' : '#2ecc71';
        indEl.style.boxShadow = theme === 'light' ? '0 0 6px #d50f3b' : '0 0 6px #2ecc71';
      }
    });
  }

  applyTheme(activeTheme);

  // Toggle button click listener
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.theme-toggle-btn');
    if (btn) {
      const current = document.documentElement.getAttribute('data-theme') || (isSubpage ? 'light' : 'dark');
      const next = current === 'light' ? 'dark' : 'light';
      localStorage.setItem('botblox_theme', next);
      applyTheme(next);
    }
  });
});

