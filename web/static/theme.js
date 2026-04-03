/**
 * theme.js — Selector de tema claro / oscuro / sistema
 * Email Malware Detector v1.2.4
 *
 * Uso: incluir este script en todos los templates ANTES de </body>
 * El tema se persiste en localStorage (respuesta inmediata) y se
 * sincroniza con el servidor vía /api/theme para que sea consistente
 * entre dispositivos y sesiones.
 */
(function () {
  'use strict';

  // ── Paletas ────────────────────────────────────────────────────────────────
  const THEMES = {
    dark: {
      '--bg-body':      '#0f172a',
      '--bg-nav':       '#1e293b',
      '--bg-card':      '#1e293b',
      '--bg-inner':     '#0f172a',
      '--bg-input':     '#0f172a',
      '--border':       '#334155',
      '--border-nav':   '#3b82f6',
      '--text-primary': '#e2e8f0',
      '--text-muted':   '#94a3b8',
      '--text-faint':   '#64748b',
      '--accent':       '#3b82f6',
      '--accent-hover': '#2563eb',
      '--danger':       '#ef4444',
      '--success':      '#22c55e',
      '--warning':      '#eab308',
      '--shadow':       'rgba(0,0,0,0.4)',
    },
    light: {
      '--bg-body':      '#f1f5f9',
      '--bg-nav':       '#ffffff',
      '--bg-card':      '#ffffff',
      '--bg-inner':     '#f8fafc',
      '--bg-input':     '#f8fafc',
      '--border':       '#cbd5e1',
      '--border-nav':   '#3b82f6',
      '--text-primary': '#0f172a',
      '--text-muted':   '#475569',
      '--text-faint':   '#64748b',
      '--accent':       '#2563eb',
      '--accent-hover': '#1d4ed8',
      '--danger':       '#dc2626',
      '--success':      '#16a34a',
      '--warning':      '#ca8a04',
      '--shadow':       'rgba(0,0,0,0.08)',
    },
  };

  // ── Detectar preferencia del sistema ──────────────────────────────────────
  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  // ── Aplicar variables CSS al :root ────────────────────────────────────────
  function applyPalette(palette) {
    const root = document.documentElement;
    Object.entries(palette).forEach(([k, v]) => root.style.setProperty(k, v));
  }

  function applyTheme(theme) {
    const resolved = theme === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : theme;
    applyPalette(THEMES[resolved] || THEMES.dark);
    document.documentElement.setAttribute('data-theme', resolved);
  }

  // ── Inicialización: aplicar el tema guardado ANTES de que se pinte la página
  function init() {
    const saved = localStorage.getItem('emd_theme') || 'dark';
    applyTheme(saved);

    // Reaccionar a cambios del sistema si el tema es 'system'
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (localStorage.getItem('emd_theme') === 'system') applyTheme('system');
      });
    }
  }

  // ── Cambiar tema desde el botón de la navbar ──────────────────────────────
  function setTheme(theme) {
    localStorage.setItem('emd_theme', theme);
    applyTheme(theme);
    updateToggleUI(theme);
    // Persistir en servidor de forma asíncrona (no bloqueante)
    fetch('/api/theme', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme }),
    }).catch(() => {});
  }

  // ── UI del selector ───────────────────────────────────────────────────────
  function updateToggleUI(theme) {
    const btns = document.querySelectorAll('.theme-btn');
    btns.forEach(b => {
      b.classList.toggle('active', b.dataset.theme === theme);
    });
  }

  function buildToggle() {
    const saved = localStorage.getItem('emd_theme') || 'dark';
    const wrap = document.createElement('div');
    wrap.className = 'theme-toggle';
    wrap.title = 'Cambiar tema';
    wrap.innerHTML = [
      { key: 'light',  icon: '☀️',  label: 'Claro'   },
      { key: 'system', icon: '💻',  label: 'Sistema' },
      { key: 'dark',   icon: '🌙',  label: 'Oscuro'  },
    ].map(({ key, icon, label }) =>
      `<button class="theme-btn${saved === key ? ' active' : ''}" data-theme="${key}" title="${label}" onclick="EMDTheme.set('${key}')">${icon}</button>`
    ).join('');
    return wrap;
  }

  // ── Inyectar el toggle en la navbar (.nav-right) ──────────────────────────
  function injectToggle() {
    const navRight = document.querySelector('.nav-right');
    if (!navRight) return;
    if (navRight.querySelector('.theme-toggle')) return; // ya existe
    navRight.insertBefore(buildToggle(), navRight.firstChild);
  }

  // ── CSS del toggle (inyectado una sola vez) ───────────────────────────────
  function injectStyles() {
    if (document.getElementById('emd-theme-styles')) return;
    const s = document.createElement('style');
    s.id = 'emd-theme-styles';
    s.textContent = `
      /* ── Variables aplicadas a body y elementos clave ── */
      body {
        background: var(--bg-body, #0f172a) !important;
        color:      var(--text-primary, #e2e8f0) !important;
      }
      nav {
        background:   var(--bg-nav, #1e293b) !important;
        border-color: var(--border-nav, #3b82f6) !important;
      }
      .section, .card {
        background: var(--bg-card, #1e293b) !important;
      }
      .stat-card, .model-card, .meta-item, .detail-item,
      .feedback-banner, .feedback-bar, .ensemble-banner,
      .result-card, .log-box, .locked-msg, .step {
        background: var(--bg-inner, #0f172a) !important;
      }
      .modal { background: var(--bg-card, #1e293b) !important; }
      .modal-header { background: var(--bg-card, #1e293b) !important; }
      input, select, textarea {
        background: var(--bg-input, #0f172a) !important;
        color:      var(--text-primary, #e2e8f0) !important;
        border-color: var(--border, #334155) !important;
      }
      nav a.nav-link { color: var(--text-muted, #94a3b8) !important; }
      nav a.nav-link:hover { color: var(--text-primary, #e2e8f0) !important; }
      nav a.nav-link.active { color: var(--accent, #3b82f6) !important; }
      .nav-brand span { color: var(--accent, #3b82f6) !important; }
      nav a.nav-logout { color: var(--danger, #ef4444) !important; }
      td, th { border-color: var(--border, #334155) !important; }
      tr:hover td { background: var(--bg-inner, #0f172a) !important; }

      /* ── Selector de tema ── */
      .theme-toggle {
        display: flex;
        align-items: center;
        gap: 2px;
        background: var(--bg-inner, #0f172a);
        border: 1px solid var(--border, #334155);
        border-radius: 20px;
        padding: 3px 5px;
      }
      .theme-btn {
        background: none;
        border: none;
        border-radius: 50%;
        width: 28px;
        height: 28px;
        cursor: pointer;
        font-size: 0.9em;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0.45;
        transition: opacity 0.2s, background 0.2s;
      }
      .theme-btn:hover  { opacity: 0.85; }
      .theme-btn.active {
        opacity: 1;
        background: var(--accent, #3b82f6);
        box-shadow: 0 0 0 2px var(--accent, #3b82f6);
      }
    `;
    document.head.appendChild(s);
  }

  // ── Ejecutar cuanto antes ─────────────────────────────────────────────────
  init();
  injectStyles();

  // Inyectar el toggle cuando el DOM esté listo
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectToggle);
  } else {
    injectToggle();
  }

  // ── API pública ───────────────────────────────────────────────────────────
  window.EMDTheme = { set: setTheme, apply: applyTheme };
})();
