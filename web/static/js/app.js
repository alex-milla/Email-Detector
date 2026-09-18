/**
 * app.js — Utilidades comunes de la interfaz.
 * CSRF en fetch, toasts, modal, navegación móvil y theme toggle.
 */
(function () {
  'use strict';

  /* ── CSRF: inyecta X-CSRF-Token en toda petición no-GET ─────────────────── */
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var _fetch = window.fetch.bind(window);

  window.fetch = function (url, opts) {
    opts = opts || {};
    var method = (opts.method || 'GET').toUpperCase();
    if (method !== 'GET' && CSRF) {
      if (opts.headers instanceof Headers) {
        if (!opts.headers.has('X-CSRF-Token')) opts.headers.set('X-CSRF-Token', CSRF);
      } else {
        opts.headers = opts.headers || {};
        if (!opts.headers['X-CSRF-Token']) opts.headers['X-CSRF-Token'] = CSRF;
      }
    }
    return _fetch(url, opts);
  };

  /* ── Toast ──────────────────────────────────────────────────────────────── */
  function toast(message, type, ms) {
    var el = document.getElementById('emd-toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'emd-toast';
      el.className = 'toast';
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.className = 'toast ' + (type || 'info');
    void el.offsetWidth;
    el.classList.add('show');
    clearTimeout(el._t);
    el._t = setTimeout(function () { el.classList.remove('show'); }, ms || 3200);
  }

  /* ── fetch JSON con manejo de error uniforme ────────────────────────────── */
  async function fetchJSON(url, opts) {
    var resp = await fetch(url, opts);
    var data = null;
    try { data = await resp.json(); } catch (e) { data = null; }
    if (!resp.ok) {
      var msg = (data && (data.error || data.message)) || ('Error HTTP ' + resp.status);
      throw new Error(msg);
    }
    return data;
  }

  /* ── Modal ──────────────────────────────────────────────────────────────── */
  function openModal(id) {
    var el = document.getElementById(id);
    if (el) el.classList.add('open');
  }
  function closeModal(id) {
    var el = id ? document.getElementById(id) : null;
    if (el) { el.classList.remove('open'); return; }
    document.querySelectorAll('.modal-overlay.open').forEach(function (m) {
      m.classList.remove('open');
    });
  }

  document.addEventListener('click', function (ev) {
    var opener = ev.target.closest('[data-modal-open]');
    if (opener) { openModal(opener.getAttribute('data-modal-open')); return; }

    var closer = ev.target.closest('[data-modal-close]');
    if (closer) {
      ev.preventDefault();
      var id = closer.getAttribute('data-modal-close');
      closeModal(id || null);
      return;
    }

    if (ev.target.classList && ev.target.classList.contains('modal-overlay')) {
      ev.target.classList.remove('open');
    }
  });

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') closeModal();
  });

  /* ── Navegación móvil ───────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.querySelector('.nav-toggle');
    var nav = document.querySelector('nav');
    if (toggle && nav) {
      toggle.addEventListener('click', function () {
        nav.classList.toggle('open');
      });
    }
  });

  /* ── Reporte de errores del navegador → logs/frontend.log ──────────────── */
  function reportError(payload) {
    try {
      var body = Object.assign({
        url: location.href,
        ts: new Date().toISOString(),
        userAgent: navigator.userAgent
      }, payload || {});
      _fetch('/api/client-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
        body: JSON.stringify(body),
        keepalive: true
      }).catch(function () {});
    } catch (e) { /* nunca romper por el logger */ }
  }

  window.addEventListener('error', function (e) {
    if (!e || !e.message) return;
    reportError({
      message: e.message,
      source: e.filename,
      line: e.lineno,
      col: e.colno,
      stack: e.error && e.error.stack
    });
  });

  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason;
    reportError({
      message: 'Unhandled rejection: ' + (r && r.message ? r.message : String(r)),
      stack: r && r.stack
    });
  });

  document.addEventListener('securitypolicyviolation', function (e) {
    reportError({
      message: 'CSP: ' + e.violatedDirective + ' bloqueó ' + e.blockedURI,
      source: e.sourceFile,
      line: e.lineNumber
    });
  });

  window.EMD = {
    toast: toast,
    fetchJSON: fetchJSON,
    openModal: openModal,
    closeModal: closeModal,
    report: reportError,
  };
})();
