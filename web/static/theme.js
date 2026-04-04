/**
 * theme.js — Selector de tema claro / oscuro / sistema
 * Email Malware Detector v1.2.11
 *
 * Cubre todos los selectores de todos los templates.
 * Un único archivo controla el aspecto visual completo de la aplicación.
 */
(function () {
  'use strict';

  // ── Paletas ────────────────────────────────────────────────────────────────
  const THEMES = {
    dark: {
      '--bg-body':             '#0f172a',
      '--bg-nav':              '#1e293b',
      '--bg-card':             '#1e293b',
      '--bg-inner':            '#0f172a',
      '--bg-input':            '#0f172a',
      '--bg-input-alt':        '#0a1020',
      '--bg-hover':            'rgba(59,130,246,0.08)',
      '--bg-overlay':          'rgba(0,0,0,0.75)',
      '--border':              '#334155',
      '--border-alt':          '#283548',
      '--border-input':        '#2d3f55',
      '--border-nav':          '#3b82f6',
      '--text-primary':        '#e2e8f0',
      '--text-muted':          '#94a3b8',
      '--text-faint':          '#64748b',
      '--text-code':           '#7dd3fc',
      '--accent':              '#3b82f6',
      '--accent-hover':        '#2563eb',
      '--danger':              '#ef4444',
      '--danger-text':         '#f87171',
      '--success':             '#22c55e',
      '--success-text':        '#86efac',
      '--warning':             '#eab308',
      '--warning-text':        '#fbbf24',
      '--shadow':              'rgba(0,0,0,0.4)',
      '--badge-admin-bg':      '#92400e',
      '--badge-admin-fg':      '#fcd34d',
      '--section-admin-bg':    '#1a1200',
      '--section-admin-border':'#4c3000',
      '--placeholder':         '#3d5068',
      '--toggle-bg':           '#1a2535',
      '--toggle-knob':         '#64748b',
      '--save-bar-bg':         '#0f172a',
      '--save-bar-border':     '#1e293b',
    },
    light: {
      '--bg-body':             '#f1f5f9',
      '--bg-nav':              '#ffffff',
      '--bg-card':             '#ffffff',
      '--bg-inner':            '#f8fafc',
      '--bg-input':            '#f8fafc',
      '--bg-input-alt':        '#f1f5f9',
      '--bg-hover':            'rgba(59,130,246,0.06)',
      '--bg-overlay':          'rgba(0,0,0,0.5)',
      '--border':              '#cbd5e1',
      '--border-alt':          '#e2e8f0',
      '--border-input':        '#cbd5e1',
      '--border-nav':          '#3b82f6',
      '--text-primary':        '#0f172a',
      '--text-muted':          '#475569',
      '--text-faint':          '#64748b',
      '--text-code':           '#0369a1',
      '--accent':              '#2563eb',
      '--accent-hover':        '#1d4ed8',
      '--danger':              '#dc2626',
      '--danger-text':         '#b91c1c',
      '--success':             '#16a34a',
      '--success-text':        '#15803d',
      '--warning':             '#ca8a04',
      '--warning-text':        '#a16207',
      '--shadow':              'rgba(0,0,0,0.08)',
      '--badge-admin-bg':      '#fef3c7',
      '--badge-admin-fg':      '#92400e',
      '--section-admin-bg':    '#fffbeb',
      '--section-admin-border':'#fde68a',
      '--placeholder':         '#94a3b8',
      '--toggle-bg':           '#e2e8f0',
      '--toggle-knob':         '#94a3b8',
      '--save-bar-bg':         '#f8fafc',
      '--save-bar-border':     '#e2e8f0',
    },
  };

  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function applyPalette(palette) {
    const root = document.documentElement;
    Object.entries(palette).forEach(([k, v]) => root.style.setProperty(k, v));
  }

  function applyTheme(theme) {
    const resolved = theme === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : theme;
    applyPalette(THEMES[resolved] || THEMES.dark);
    document.documentElement.setAttribute('data-theme', resolved);
  }

  function init() {
    const saved = localStorage.getItem('emd_theme') || 'dark';
    applyTheme(saved);
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (localStorage.getItem('emd_theme') === 'system') applyTheme('system');
      });
    }
  }

  function setTheme(theme) {
    localStorage.setItem('emd_theme', theme);
    applyTheme(theme);
    updateToggleUI(theme);
    fetch('/api/theme', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme }),
    }).catch(() => {});
  }

  function updateToggleUI(theme) {
    document.querySelectorAll('.theme-btn').forEach(b => {
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

  function injectToggle() {
    const navRight = document.querySelector('.nav-right');
    if (!navRight) return;
    if (navRight.querySelector('.theme-toggle')) return;
    navRight.insertBefore(buildToggle(), navRight.firstChild);
  }

  function injectStyles() {
    if (document.getElementById('emd-theme-styles')) return;
    const s = document.createElement('style');
    s.id = 'emd-theme-styles';
    s.textContent = `

      /* ══ BASE ══════════════════════════════════════════════════════════════ */
      body {
        background: var(--bg-body) !important;
        color:      var(--text-primary) !important;
      }

      /* ══ NAVEGACIÓN ════════════════════════════════════════════════════════ */
      nav {
        background:   var(--bg-nav) !important;
        border-color: var(--border-nav) !important;
      }
      .nav-brand, nav .nav-brand {
        border-color: var(--border) !important;
        color: var(--text-primary) !important;
      }
      .nav-brand span    { color: var(--accent) !important; }
      nav a.nav-link     { color: var(--text-muted) !important; }
      nav a.nav-link:hover {
        color:      var(--text-primary) !important;
        background: var(--bg-hover) !important;
      }
      nav a.nav-link.active { color: var(--accent) !important; }
      nav a.nav-logout      { color: var(--danger) !important; }
      .nav-user             { color: var(--text-faint) !important; }

      /* ══ CARDS Y SECCIONES ═════════════════════════════════════════════════ */
      .card, .section {
        background:   var(--bg-card) !important;
        border-color: var(--border-alt) !important;
      }
      .card-header          { border-color: var(--border) !important; }
      .card-header h2,
      .card-header-left h2  { color: var(--text-primary) !important; }
      .card-header p,
      .card-header-left p   { color: var(--text-faint) !important; }

      /* ══ ELEMENTOS INTERNOS ════════════════════════════════════════════════ */
      .stat-card, .model-card, .meta-item, .detail-item,
      .feedback-banner, .feedback-bar, .ensemble-banner,
      .result-card, .locked-msg, .step,
      .sub-card, .default-select,
      .upload-zone, .url-list {
        background:   var(--bg-inner) !important;
        border-color: var(--border) !important;
        color:        var(--text-primary) !important;
      }
      /* version-box necesita mayor especificidad para ganar al style del template */
      .card .version-box, .version-grid .version-box, .version-box {
        background:   var(--bg-inner) !important;
        border-color: var(--border) !important;
        color:        var(--text-primary) !important;
      }
      .log-box {
        color:        var(--text-muted) !important;
        border-color: var(--border) !important;
      }
      .log-box.success { border-color: var(--success) !important; }
      .log-box.error   { border-color: var(--danger) !important; }

      /* ══ MODALES ═══════════════════════════════════════════════════════════ */
      .modal, .modal-header {
        background: var(--bg-card) !important;
        color:      var(--text-primary) !important;
      }
      .modal-overlay { background: var(--bg-overlay) !important; }
      .modal-close   { color: var(--text-muted) !important; }

      /* ══ FORMULARIOS ═══════════════════════════════════════════════════════ */
      input, select, textarea {
        background:   var(--bg-input) !important;
        color:        var(--text-primary) !important;
        border-color: var(--border-input) !important;
      }
      input::placeholder,
      textarea::placeholder { color: var(--placeholder) !important; }
      input:focus, select:focus, textarea:focus {
        border-color: var(--accent) !important;
        outline: none !important;
      }
      label { color: var(--text-muted) !important; }

      /* ══ TABLAS ════════════════════════════════════════════════════════════ */
      td, th      { border-color: var(--border) !important; color: var(--text-primary) !important; }
      th          { color: var(--text-faint) !important; }
      tr:hover td { background: var(--bg-inner) !important; }

      /* ══ BOTONES SECUNDARIOS ═══════════════════════════════════════════════ */
      .btn-secondary {
        background:   var(--bg-inner) !important;
        color:        var(--text-muted) !important;
        border-color: var(--border-input) !important;
      }
      .btn-secondary:hover {
        color:        var(--text-primary) !important;
        border-color: var(--text-faint) !important;
        background:   var(--bg-card) !important;
      }
      .btn-ghost {
        background:   transparent !important;
        color:        var(--text-muted) !important;
        border-color: var(--border) !important;
      }
      .btn-ghost:hover {
        color:        var(--text-primary) !important;
        border-color: var(--text-faint) !important;
      }

      /* ══ BADGES ════════════════════════════════════════════════════════════ */
      .badge-status.ok, .badge-ok {
        background: rgba(34,197,94,0.12) !important;
        color:      var(--success) !important;
      }
      .badge-status.missing, .badge-error {
        background: rgba(239,68,68,0.12) !important;
        color:      var(--danger) !important;
      }
      .badge-status.warn {
        background: rgba(234,179,8,0.12) !important;
        color:      var(--warning) !important;
      }
      .badge-status.info, .badge-loading {
        background: rgba(59,130,246,0.12) !important;
        color:      var(--accent) !important;
      }
      .badge-update {
        background: rgba(245,158,11,0.15) !important;
        color:      var(--warning) !important;
      }
      .admin-badge {
        background: var(--badge-admin-bg) !important;
        color:      var(--badge-admin-fg) !important;
      }
      .cat-badge {
        background:   var(--bg-card) !important;
        color:        var(--text-muted) !important;
        border-color: var(--border) !important;
      }

      /* ══ SECTION ADMIN ═════════════════════════════════════════════════════ */
      .section-admin {
        background:   var(--section-admin-bg) !important;
        border-color: var(--section-admin-border) !important;
      }
      .section-admin .card-header {
        border-color: var(--section-admin-border) !important;
      }

      /* ══ VERSION BOX ═══════════════════════════════════════════════════════ */
      .version-box            { border-left-color: var(--border) !important; }
      .version-box.remote     { border-left-color: var(--success) !important; }
      .version-box.has-update { border-left-color: var(--warning) !important; }
      .version-box .label,
      .version-box .date      { color: var(--text-faint) !important; }
      .version-box .number    { color: var(--text-primary) !important; }
      .changelog {
        background:   var(--bg-inner) !important;
        color:        var(--text-muted) !important;
        border-color: var(--accent) !important;
      }

      /* ══ RESULT BANNER ═════════════════════════════════════════════════════ */
      .result-banner.success {
        background:   rgba(34,197,94,0.1) !important;
        border-color: var(--success) !important;
        color:        var(--success-text) !important;
      }
      .result-banner.error {
        background:   rgba(239,68,68,0.1) !important;
        border-color: var(--danger) !important;
        color:        var(--danger-text) !important;
      }

      /* ══ TEST RESULTS ══════════════════════════════════════════════════════ */
      .test-result.ok {
        background:   rgba(34,197,94,0.1) !important;
        color:        var(--success) !important;
        border-color: rgba(34,197,94,0.25) !important;
      }
      .test-result.error {
        background:   rgba(239,68,68,0.1) !important;
        color:        var(--danger-text) !important;
        border-color: rgba(239,68,68,0.25) !important;
      }
      .test-result.loading {
        background:   rgba(59,130,246,0.1) !important;
        color:        var(--accent) !important;
        border-color: rgba(59,130,246,0.25) !important;
      }
      .test-result.warning {
        background:   rgba(234,179,8,0.1) !important;
        color:        var(--warning-text) !important;
        border-color: rgba(234,179,8,0.25) !important;
      }

      /* ══ TEXTOS ESPECÍFICOS ════════════════════════════════════════════════ */
      .page-header h1  { color: var(--text-primary) !important; }
      .page-header p,
      .subtitle,
      .stat-label,
      .meta-label,
      .mc-label,
      .eb-txt          { color: var(--text-faint) !important; }
      .stat-number,
      .meta-value,
      .mc-name,
      .eb-num          { color: var(--text-primary) !important; }
      code.small-code  { color: var(--text-code) !important; }
      hr.divider       { border-color: var(--border) !important; }
      .info-item small { color: var(--text-faint) !important; }
      .info-item strong{ color: var(--text-primary) !important; }
      .mc-auc, .mc-cv  { color: var(--text-muted) !important; }
      .mc-err          { color: var(--danger-text) !important; }
      .step-num        { color: var(--text-faint) !important; }
      .status-text     { color: var(--text-muted) !important; }

      /* ══ TOGGLE SWITCH ═════════════════════════════════════════════════════ */
      .toggle-slider {
        background:   var(--toggle-bg) !important;
        border-color: var(--border-input) !important;
      }
      .toggle-slider:before { background: var(--toggle-knob) !important; }
      input:checked + .toggle-slider {
        background:   var(--accent) !important;
        border-color: var(--accent) !important;
      }
      input:checked + .toggle-slider:before { background: white !important; }

      /* ══ SAVE BAR ══════════════════════════════════════════════════════════ */
      .save-bar {
        background:   var(--save-bar-bg) !important;
        border-color: var(--save-bar-border) !important;
      }

      /* ══ PAGINACIÓN ════════════════════════════════════════════════════════ */
      .pagination a, .pagination span {
        background:   var(--bg-inner) !important;
        color:        var(--text-muted) !important;
        border-color: var(--border) !important;
      }
      .pagination a:hover { color: var(--text-primary) !important; }

      /* ══ SELECTOR DE TEMA ══════════════════════════════════════════════════ */
      .theme-toggle {
        display: flex;
        align-items: center;
        gap: 2px;
        background: var(--bg-inner);
        border: 1px solid var(--border);
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
        background: var(--accent);
        box-shadow: 0 0 0 2px var(--accent);
      }
    `;
    document.head.appendChild(s);
  }

  // ── Ejecutar ──────────────────────────────────────────────────────────────
  init();
  injectStyles();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectToggle);
  } else {
    injectToggle();
  }

  window.EMDTheme = { set: setTheme, apply: applyTheme };
})();
