/**
 * settings.js — Configuración de correo, GPU, Anti-Clanker y TLS (Fase 2).
 * Sin handlers ni estilos inline.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;

  function $(id) { return document.getElementById(id); }
  function escapeHtml(text) {
    if (text === undefined || text === null) return '';
    var div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }
  function showResult(id, state, msg) {
    var el = $(id);
    if (!el) return;
    el.className = 'test-result' + (state ? ' ' + state : '');
    el.textContent = msg;
  }
  function showTest(sid, state, msg) { showResult('test-' + sid, state, msg); }

  /* ── Configuración de correo ────────────────────────────────────────────── */
  function collectAll() {
    return {
      default_provider:    $('default-provider').value,
      imap_server:         $('imap-server').value.trim(),
      imap_port:           $('imap-port').value.trim() || '993',
      imap_user:           $('imap-user').value.trim(),
      imap_password:       $('imap-password').value,
      ms365_client_id:     $('m365-client-id').value.trim(),
      ms365_client_secret: $('m365-client-secret').value.trim(),
      ms365_tenant_id:     $('m365-tenant-id').value.trim(),
      ms365_user_email:    $('m365-email').value.trim(),
      gmail_client_id:     $('gmail-client-id').value.trim(),
      gmail_client_secret: $('gmail-client-secret').value.trim(),
    };
  }

  async function saveAll() {
    try {
      var res = await window.EMD.fetchJSON('/api/settings/mail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(collectAll())
      });
      if (res.success) toast('✓ Configuración guardada', 'success');
      else toast('Error al guardar: ' + (res.error || ''), 'error');
    } catch (e) {
      toast('Error al guardar: ' + e.message, 'error');
    }
  }

  async function saveGlobal() {
    var apiKey = $('vt-apikey');
    if (!apiKey) return;
    var value = apiKey.value.trim();
    if (!value) { toast('Introduce una API Key', 'error'); return; }
    try {
      var res = await window.EMD.fetchJSON('/api/settings/global', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ VIRUSTOTAL_API_KEY: value })
      });
      if (res.success) toast('✓ API Key de VirusTotal guardada', 'success');
      else toast('Error al guardar: ' + (res.error || ''), 'error');
    } catch (e) {
      toast('Error al guardar: ' + e.message, 'error');
    }
  }

  async function testConn(provider) {
    var idMap = { imap: 'imap', m365: 'm365', virustotal: 'vt' };
    var sid = idMap[provider];
    showTest(sid, 'loading', '⏳ Probando...');

    var payload = { provider: provider };
    if (provider === 'imap') {
      payload.server = $('imap-server').value.trim();
      payload.port = $('imap-port').value.trim();
      payload.user = $('imap-user').value.trim();
      payload.password = $('imap-password').value;
    } else if (provider === 'm365') {
      payload.client_id = $('m365-client-id').value.trim();
      payload.client_secret = $('m365-client-secret').value.trim();
      payload.tenant_id = $('m365-tenant-id').value.trim();
    } else if (provider === 'virustotal') {
      payload.api_key = $('vt-apikey').value.trim();
    }

    try {
      var res = await window.EMD.fetchJSON('/api/settings/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showTest(sid, res.success ? 'ok' : 'error', res.message || '');
    } catch (e) {
      showTest(sid, 'error', 'Error de red');
    }
  }

  /* ── GPU ────────────────────────────────────────────────────────────────── */
  (async function initGpu() {
    try {
      var data = await window.EMD.fetchJSON('/api/settings/global');
      var val = String(data.USE_GPU || 'false').toLowerCase();
      var tog = $('use-gpu-toggle');
      var txt = $('gpu-status-text');
      tog.checked = (val === 'true' || val === '1');
      txt.textContent = tog.checked ? 'GPU activada' : 'No disponible';
      tog.addEventListener('change', function () {
        txt.textContent = tog.checked ? 'GPU activada' : 'GPU desactivada (CPU)';
      });
    } catch (e) {
      var t = $('gpu-status-text');
      if (t) t.textContent = 'No disponible';
    }
  })();

  async function saveGpu() {
    var tog = $('use-gpu-toggle');
    showResult('gpu-save-result', 'loading', '⏳ Guardando...');
    try {
      var data = await window.EMD.fetchJSON('/api/settings/global', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ USE_GPU: tog.checked ? 'true' : 'false' })
      });
      if (data.success || data.ok) {
        showResult('gpu-save-result', 'ok', '✓ Guardado. Re-entrena para aplicar.');
      } else {
        showResult('gpu-save-result', 'error', 'Error al guardar');
      }
    } catch (e) {
      showResult('gpu-save-result', 'error', 'Error de conexión');
    }
  }

  /* ── Anti-Clanker ───────────────────────────────────────────────────────── */
  function hideClankerPanel() {
    var p = $('clanker-panel');
    if (p) p.classList.add('hidden');
  }

  async function clankerLoadStatus() {
    try {
      var d = await window.EMD.fetchJSON('/api/clanker/status');
      var badge = $('clanker-badge');
      if (!d.enabled) {
        badge.textContent = 'No disponible';
        badge.className = 'badge-status missing';
        return;
      }
      badge.textContent = 'Activo';
      badge.className = 'badge-status ok';
      $('clanker-version').textContent = d.rules_version || '-';
      $('clanker-updated').textContent = d.rules_updated || '-';
      $('clanker-rules-count').textContent = d.active_rules + ' / ' + d.total_rules;
      var ui = $('clanker-url-input');
      if (ui && d.rules_url) ui.value = d.rules_url;
      clankerLoadRules();
    } catch (e) {
      hideClankerPanel();
    }
  }

  async function clankerLoadRules() {
    var box = $('clanker-rules-table');
    try {
      var d = await window.EMD.fetchJSON('/api/clanker/rules');
      box.textContent = '';
      if (!d.rules || !d.rules.length) {
        var empty = document.createElement('span');
        empty.className = 'faint text-sm';
        empty.textContent = 'Sin reglas.';
        box.appendChild(empty);
        return;
      }

      var sevClass = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };
      var wrap = document.createElement('div'); wrap.className = 'table-wrapper';
      var table = document.createElement('table'); table.className = 'rules-table';
      var thead = document.createElement('thead');
      var headRow = document.createElement('tr');
      ['ID', 'Categoría', 'Severidad', 'Descripción', 'Activa'].forEach(function (h) {
        var th = document.createElement('th'); th.textContent = h; headRow.appendChild(th);
      });
      thead.appendChild(headRow); table.appendChild(thead);

      var tbody = document.createElement('tbody');
      d.rules.forEach(function (rule) {
        var tr = document.createElement('tr');

        var tdId = document.createElement('td');
        var code = document.createElement('code'); code.className = 'small-code'; code.textContent = rule.id;
        tdId.appendChild(code); tr.appendChild(tdId);

        var tdCat = document.createElement('td');
        var cat = document.createElement('span'); cat.className = 'cat-badge'; cat.textContent = rule.category;
        tdCat.appendChild(cat); tr.appendChild(tdCat);

        var tdSev = document.createElement('td');
        var sev = document.createElement('span');
        sev.className = 'sev-badge ' + (sevClass[rule.severity] || 'sev-low');
        sev.textContent = rule.severity;
        tdSev.appendChild(sev); tr.appendChild(tdSev);

        var tdDesc = document.createElement('td'); tdDesc.className = 'muted'; tdDesc.textContent = rule.description || '';
        tr.appendChild(tdDesc);

        var tdToggle = document.createElement('td');
        var checkWrap = document.createElement('div'); checkWrap.className = 'form-check-switch';
        var label = document.createElement('label'); label.className = 'toggle-switch';
        var input = document.createElement('input'); input.type = 'checkbox'; input.checked = (rule.enabled !== false);
        input.addEventListener('change', function () { clankerToggleRule(rule.id, input); });
        var slider = document.createElement('span'); slider.className = 'toggle-slider';
        label.appendChild(input); label.appendChild(slider);
        checkWrap.appendChild(label); tdToggle.appendChild(checkWrap); tr.appendChild(tdToggle);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody); wrap.appendChild(table); box.appendChild(wrap);
    } catch (e) {
      box.textContent = '';
      var err = document.createElement('span');
      err.className = 'faint text-sm';
      err.textContent = 'Error cargando reglas.';
      box.appendChild(err);
    }
  }

  async function clankerToggleRule(id, cb) {
    try {
      var d = await window.EMD.fetchJSON(
        '/api/clanker/rules/' + encodeURIComponent(id) + '/toggle', { method: 'POST' });
      cb.checked = d.enabled;
      clankerLoadStatus();
    } catch (e) {
      toast('Error al cambiar la regla', 'error');
      cb.checked = !cb.checked;
    }
  }

  async function clankerUpload() {
    var input = $('clanker-rules-file');
    if (!input.files.length) { toast('Selecciona un fichero YAML', 'error'); return; }
    showResult('clanker-upload-result', 'loading', '⏳ Validando...');
    var fd = new FormData();
    fd.append('file', input.files[0]);
    try {
      var r = await fetch('/api/clanker/upload_rules', { method: 'POST', body: fd });
      var d = await r.json();
      if (d.success) {
        showResult('clanker-upload-result', 'ok', '✓ Subido: ' + d.rules_count + ' reglas.');
        input.value = '';
        clankerLoadStatus();
      } else {
        showResult('clanker-upload-result', 'error', '✗ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('clanker-upload-result', 'error', 'Error: ' + e.message);
    }
  }

  async function clankerSaveUrl() {
    var url = $('clanker-url-input').value.trim();
    try {
      var d = await window.EMD.fetchJSON('/api/clanker/set_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
      if (d.success) showResult('clanker-url-result', 'ok', '✓ ' + (url ? 'URL guardada.' : 'URL eliminada.'));
      else showResult('clanker-url-result', 'error', '✗ ' + (d.error || 'Error'));
    } catch (e) {
      showResult('clanker-url-result', 'error', 'Error: ' + e.message);
    }
  }

  async function clankerUpdate() {
    showResult('clanker-url-result', 'loading', '⏳ Comprobando...');
    try {
      var d = await window.EMD.fetchJSON('/api/clanker/update_rules', { method: 'POST' });
      if (d.success) {
        showResult('clanker-url-result', 'ok', '✓ ' + (d.message || 'Actualizado.'));
        clankerLoadStatus();
      } else {
        showResult('clanker-url-result', 'warning', d.message || 'Sin actualizaciones.');
      }
    } catch (e) {
      showResult('clanker-url-result', 'error', 'Error: ' + e.message);
    }
  }

  /* ── TLS ────────────────────────────────────────────────────────────────── */
  async function sslLoadStatus() {
    var panel = $('ssl-panel');
    try {
      var d = await window.EMD.fetchJSON('/api/ssl/status');
      if (!d.enabled) { if (panel) panel.classList.add('hidden'); return; }
      if (panel) panel.classList.remove('hidden');
      var badge = $('ssl-badge');
      var days = (d.days_left === undefined || d.days_left === null) ? '?' : d.days_left;
      if (d.expired) { badge.textContent = 'Expirado'; badge.className = 'badge-status missing'; }
      else if (d.warning) { badge.textContent = '⚠ ' + days + ' días'; badge.className = 'badge-status warn'; }
      else { badge.textContent = 'Válido'; badge.className = 'badge-status ok'; }
      $('ssl-expiry').textContent = d.expiry || '—';
      $('ssl-days').textContent = days + ' días';
      $('ssl-state').textContent = d.expired ? '❌ Expirado' : d.warning ? '⚠ Próximo a expirar' : '✅ OK';
      if (d.error) $('ssl-state').textContent = '⚠ ' + d.error;
    } catch (e) {
      if (panel) panel.classList.add('hidden');
    }
  }

  async function sslRenew() {
    var days = parseInt($('ssl-days-input').value, 10) || 365;
    showResult('ssl-renew-result', 'loading', '⏳ Generando certificado...');
    try {
      var d = await window.EMD.fetchJSON('/api/ssl/renew', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days: days })
      });
      if (d.success) {
        showResult('ssl-renew-result', 'ok',
          '✅ ' + d.message + (d.restart_required ? ' — Reinicia: systemctl restart email-detector' : ''));
        sslLoadStatus();
      } else {
        showResult('ssl-renew-result', 'error', '❌ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('ssl-renew-result', 'error', 'Error: ' + e.message);
    }
  }

  /* ── Pestañas ───────────────────────────────────────────────────────────── */
  function activateTab(name) {
    var tabs = document.querySelectorAll('.tab-btn');
    var exists = false;
    tabs.forEach(function (b) {
      var on = b.getAttribute('data-tab') === name;
      if (on) exists = true;
      b.classList.toggle('active', on);
    });
    if (!exists) {
      name = 'mail';
      tabs.forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-tab') === 'mail'); });
    }
    document.querySelectorAll('[data-tab-panel]').forEach(function (p) {
      p.classList.toggle('hidden', p.getAttribute('data-tab-panel') !== name);
    });
    try { localStorage.setItem('emd_settings_tab', name); } catch (e) { /* privado */ }
  }

  function toggleCollapse(btn) {
    var card = btn.closest('.provider-card');
    if (!card) return;
    var collapsed = card.classList.toggle('collapsed');
    btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }

  /* ── Seguridad: contraseña ──────────────────────────────────────────────── */
  async function changePassword(uid) {
    var p1 = ($('pwd-new') || {}).value || '';
    var p2 = ($('pwd-confirm') || {}).value || '';
    if (!p1 || p1.length < 8) { showResult('pwd-result', 'error', 'Mínimo 8 caracteres'); return; }
    if (p1 !== p2) { showResult('pwd-result', 'error', 'Las contraseñas no coinciden'); return; }
    showResult('pwd-result', 'loading', '⏳ Guardando...');
    try {
      var d = await window.EMD.fetchJSON('/api/users/' + uid + '/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: p1 })
      });
      if (d.success) {
        showResult('pwd-result', 'ok', '✅ Contraseña actualizada');
        $('pwd-new').value = '';
        $('pwd-confirm').value = '';
      } else {
        showResult('pwd-result', 'error', '❌ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('pwd-result', 'error', '❌ ' + e.message);
    }
  }

  /* ── Seguridad: 2FA ─────────────────────────────────────────────────────── */
  function render2FA(enabled) {
    var body = $('tfa-body');
    if (!body) return;
    if (enabled) {
      body.innerHTML = '<div class="row"><span class="feedback-applied benign">✅ 2FA activado</span>' +
        '<button type="button" class="btn btn-danger btn-sm" data-action="tfa-disable">Desactivar</button></div>';
    } else {
      body.innerHTML = '<button type="button" class="btn btn-primary btn-sm" data-action="tfa-setup">📱 Activar 2FA</button>';
    }
  }

  async function load2FA() {
    var body = $('tfa-body');
    if (!body) return;
    var badge = $('tfa-badge');
    try {
      var d = await window.EMD.fetchJSON('/api/2fa/status');
      if (!d.available) {
        badge.textContent = 'No disponible';
        badge.className = 'badge-status missing';
        body.innerHTML = '<span class="faint text-sm">pyotp no instalado en el servidor.</span>';
        return;
      }
      badge.textContent = d.enabled ? 'Activado' : 'Desactivado';
      badge.className = 'badge-status ' + (d.enabled ? 'ok' : 'missing');
      render2FA(d.enabled);
    } catch (e) {
      badge.textContent = 'No disponible';
      badge.className = 'badge-status missing';
    }
  }

  async function tfaSetup() {
    try {
      var d = await window.EMD.fetchJSON('/api/2fa/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      if (!d.success) { toast(d.error || 'Error', 'error'); return; }
      var body = $('tfa-body');
      body.innerHTML =
        '<p class="hint">1) Añade esta clave en tu app (Google Authenticator, Authy…):</p>' +
        '<div class="code-box">' + escapeHtml(d.secret) + '</div>' +
        '<p class="hint">O usa este enlace otpauth:<br><code class="small-code">' + escapeHtml(d.uri) + '</code></p>' +
        '<p class="hint">2) Introduce el código de 6 dígitos para confirmar:</p>' +
        '<div class="row"><input type="text" id="tfa-code" class="input-sm w-auto" placeholder="123456" maxlength="6" inputmode="numeric">' +
        '<button type="button" class="btn btn-primary btn-sm" data-action="tfa-confirm">Confirmar</button></div>' +
        '<div class="test-result mt-1" id="tfa-result"></div>';
    } catch (e) {
      toast(e.message || 'Error', 'error');
    }
  }

  async function tfaConfirm() {
    var codeEl = $('tfa-code');
    var code = codeEl ? codeEl.value.trim() : '';
    if (!/^\d{6}$/.test(code)) { showResult('tfa-result', 'error', 'Introduce un código de 6 dígitos'); return; }
    showResult('tfa-result', 'loading', '⏳ Verificando...');
    try {
      var d = await window.EMD.fetchJSON('/api/2fa/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: code })
      });
      if (d.success) { showResult('tfa-result', 'ok', '✅ 2FA activado'); load2FA(); }
      else { showResult('tfa-result', 'error', '❌ ' + (d.error || 'Código inválido')); }
    } catch (e) {
      showResult('tfa-result', 'error', '❌ ' + e.message);
    }
  }

  async function tfaDisable() {
    if (!confirm('¿Desactivar la autenticación en dos pasos?')) return;
    try {
      var d = await window.EMD.fetchJSON('/api/2fa/disable', { method: 'POST' });
      toast(d.message || '2FA desactivado', 'success');
      load2FA();
    } catch (e) {
      toast(e.message || 'No se pudo desactivar (solo admin)', 'error');
    }
  }

  /* ── Delegación de acciones ─────────────────────────────────────────────── */
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    if (action === 'tab') activateTab(btn.getAttribute('data-tab'));
    else if (action === 'collapse') toggleCollapse(btn);
    else if (action === 'save-all') saveAll();
    else if (action === 'save-global') saveGlobal();
    else if (action === 'test') testConn(btn.getAttribute('data-provider'));
    else if (action === 'save-gpu') saveGpu();
    else if (action === 'clanker-upload') clankerUpload();
    else if (action === 'clanker-save-url') clankerSaveUrl();
    else if (action === 'clanker-update') clankerUpdate();
    else if (action === 'ssl-renew') sslRenew();
    else if (action === 'change-password') changePassword(btn.getAttribute('data-user-id'));
    else if (action === 'tfa-setup') tfaSetup();
    else if (action === 'tfa-confirm') tfaConfirm();
    else if (action === 'tfa-disable') tfaDisable();
  });

  /* Doble clic para mostrar/ocultar contraseñas */
  document.querySelectorAll('input[type=password]').forEach(function (inp) {
    inp.title = 'Doble clic para mostrar/ocultar';
    inp.addEventListener('dblclick', function () {
      inp.type = inp.type === 'password' ? 'text' : 'password';
    });
  });

  (function initSettings() {
    var saved = 'mail';
    try { saved = localStorage.getItem('emd_settings_tab') || 'mail'; } catch (e) { /* privado */ }
    activateTab(saved);
    clankerLoadStatus();
    sslLoadStatus();
    load2FA();
  })();
})();
