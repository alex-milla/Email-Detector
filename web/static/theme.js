/**
 * theme.js — Selector de tema claro / oscuro / sistema.
 *
 * Las paletas viven en app.css (`:root` para oscuro y `[data-theme="light"]`
 * para claro). Este módulo solo gestiona el atributo `data-theme`, la
 * preferencia guardada y el botón de cambio. Sin CSS inyectado.
 */
(function () {
  'use strict';

  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function resolve(theme) {
    if (theme === 'system') return systemPrefersDark() ? 'dark' : 'light';
    return theme === 'light' ? 'light' : 'dark';
  }

  function updateToggleUI(theme) {
    document.querySelectorAll('.theme-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.theme === theme);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', resolve(theme));
    updateToggleUI(theme);
  }

  function setTheme(theme) {
    localStorage.setItem('emd_theme', theme);
    applyTheme(theme);
    fetch('/api/theme', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme: theme })
    }).catch(function () { /* sin sesión o sin red */ });
  }

  function buildToggle() {
    var saved = localStorage.getItem('emd_theme') || 'dark';
    var wrap = document.createElement('div');
    wrap.className = 'theme-toggle';
    wrap.title = 'Cambiar tema';

    [
      { key: 'light', icon: '☀️', label: 'Claro' },
      { key: 'system', icon: '💻', label: 'Sistema' },
      { key: 'dark', icon: '🌙', label: 'Oscuro' }
    ].forEach(function (opt) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'theme-btn' + (saved === opt.key ? ' active' : '');
      btn.dataset.theme = opt.key;
      btn.title = opt.label;
      btn.textContent = opt.icon;
      btn.addEventListener('click', function () { setTheme(opt.key); });
      wrap.appendChild(btn);
    });
    return wrap;
  }

  function injectToggle() {
    var navRight = document.querySelector('.nav-right');
    if (!navRight || navRight.querySelector('.theme-toggle')) return;
    navRight.insertBefore(buildToggle(), navRight.firstChild);
  }

  applyTheme(localStorage.getItem('emd_theme') || 'dark');

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (localStorage.getItem('emd_theme') === 'system') applyTheme('system');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectToggle);
  } else {
    injectToggle();
  }

  window.EMDTheme = { set: setTheme, apply: applyTheme };
})();
