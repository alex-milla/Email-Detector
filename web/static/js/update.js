/**
 * update.js — Comprobación y aplicación de actualizaciones (Fase 2).
 * Sin handlers inline ni estilos inline.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;
  var _pollTimer = null;
  var _isApplying = false;

  function $(id) { return document.getElementById(id); }
  function show(el) { if (el) el.classList.remove('hidden'); }
  function hide(el) { if (el) el.classList.add('hidden'); }

  function setLogVisible(state) {
    var log = $('update-log');
    if (!log) return;
    log.classList.remove('hidden', 'running', 'success', 'error');
    if (state) log.classList.add(state);
  }

  function appendLog(lines) {
    var log = $('update-log');
    log.textContent = lines.join('\n');
    log.scrollTop = log.scrollHeight;
  }

  async function checkUpdates() {
    var badge = $('status-badge');
    badge.className = 'badge badge-loading';
    badge.innerHTML = '<span class="spinner"></span> Comprobando...';
    hide($('version-grid'));
    hide($('check-error'));
    hide($('changelog-section'));
    $('action-buttons').innerHTML = '';
    $('update-log').className = 'log-box hidden';
    $('result-banner').className = 'result-banner';

    try {
      var data = await window.EMD.fetchJSON('/api/update/check');
      renderCheckResult(data);
    } catch (err) {
      renderCheckError(err.message || 'No se pudo contactar con el servidor.');
    }
  }

  function renderCheckResult(data) {
    if (data.error) { renderCheckError(data.error); return; }

    $('local-ver').textContent = data.local_version || '—';
    $('remote-ver').textContent = data.remote_version || '—';
    $('remote-date').textContent =
      data.release_date ? 'Publicada: ' + data.release_date : '';

    var remoteBox = $('remote-box');
    remoteBox.className = 'version-box remote' +
      (data.update_available ? ' has-update' : '');
    show($('version-grid'));

    var badge = $('status-badge');
    if (data.update_available) {
      badge.innerHTML = '⚠️ Actualización disponible';
      badge.className = 'badge badge-update';
    } else {
      badge.innerHTML = '✅ Sistema al día';
      badge.className = 'badge badge-ok';
    }

    if (data.update_available && data.changelog) {
      $('changelog-text').textContent = data.changelog;
      show($('changelog-section'));
    }

    renderActionButtons(data.update_available);
  }

  function renderCheckError(msg) {
    var badge = $('status-badge');
    badge.innerHTML = '❌ Error';
    badge.className = 'badge badge-error';
    $('check-error-msg').textContent = '⚠️ ' + msg;
    show($('check-error'));
    renderActionButtons(false);
  }

  function makeButton(label, cls, handler) {
    var button = document.createElement('button');
    button.className = 'btn ' + cls;
    button.textContent = label;
    button.addEventListener('click', handler);
    return button;
  }

  function renderActionButtons(hasUpdate, applying) {
    var div = $('action-buttons');
    div.innerHTML = '';

    var check = makeButton('🔍 Comprobar de nuevo', 'btn-ghost', checkUpdates);
    check.disabled = !!applying;
    div.appendChild(check);

    if (hasUpdate) {
      var apply = makeButton(
        applying ? 'Aplicando...' : '⬇️ Aplicar actualización',
        'btn-success', applyUpdate);
      apply.id = 'apply-btn';
      apply.disabled = !!applying;
      div.appendChild(apply);
    }
  }

  async function applyUpdate() {
    if (_isApplying) return;
    if (!confirm('¿Confirmas que quieres aplicar la actualización?\n\n' +
      'Se hará un backup automático. Si algo falla, se restaurará el estado anterior.')) {
      return;
    }

    _isApplying = true;
    renderActionButtons(true, true);

    var badge = $('status-badge');
    badge.innerHTML = '<span class="spinner"></span> Aplicando...';
    badge.className = 'badge badge-applying';

    setLogVisible('running');
    $('update-log').textContent = 'Iniciando proceso de actualización...\n';
    $('result-banner').className = 'result-banner';

    try {
      var data = await window.EMD.fetchJSON('/api/update/apply', { method: 'POST' });
      if (!data.started) {
        toast(data.error || 'No se pudo iniciar la actualización.', 'error');
        _isApplying = false;
        renderActionButtons(true, false);
        badge.innerHTML = '⚠️ Actualización disponible';
        badge.className = 'badge badge-update';
        return;
      }
      startPolling();
    } catch (err) {
      toast(err.message || 'Error de conexión al iniciar la actualización.', 'error');
      _isApplying = false;
      renderActionButtons(true, false);
    }
  }

  function startPolling() {
    if (_pollTimer) clearInterval(_pollTimer);
    _pollTimer = setInterval(pollStatus, 2000);
  }

  async function pollStatus() {
    try {
      var st = await window.EMD.fetchJSON('/api/update/status');
      if (st.has_systemd === false) show($('standalone-notice'));
      if (st.log && st.log.length > 0) appendLog(st.log);
      if (!st.running) {
        clearInterval(_pollTimer);
        _pollTimer = null;
        _isApplying = false;
        onUpdateFinished(st);
      }
    } catch (err) {
      appendLog(['[...] Esperando respuesta del servidor...']);
    }
  }

  function onUpdateFinished(st) {
    var badge = $('status-badge');
    var banner = $('result-banner');

    if (st.success) {
      setLogVisible('success');
      badge.innerHTML = '✅ Actualización aplicada';
      badge.className = 'badge badge-ok';

      if (st.needs_restart) {
        banner.innerHTML = '✅ Ficheros actualizados correctamente.<br>' +
          '<strong>Reinicio manual requerido:</strong> ejecuta ' +
          '<code>./stop.sh &amp;&amp; ./run.sh</code> en el servidor y recarga esta página.';
        banner.className = 'result-banner success visible';
        toast('Ficheros actualizados. Reinicia manualmente el servidor.', 'success');
        renderActionButtons(true, false);
      } else {
        banner.textContent = '✅ Actualización completada correctamente. La página se recargará en 5 segundos.';
        banner.className = 'result-banner success visible';
        toast('Actualización aplicada correctamente.', 'success');
        setTimeout(function () { location.reload(); }, 5000);
      }
    } else {
      setLogVisible('error');
      badge.innerHTML = '❌ Error en la actualización';
      badge.className = 'badge badge-error';
      banner.textContent = '❌ La actualización falló. Se ha restaurado el estado anterior automáticamente.';
      banner.className = 'result-banner error visible';
      toast('La actualización falló. Se restauró el backup.', 'error');
      renderActionButtons(true, false);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    checkUpdates();
    window.EMD.fetchJSON('/api/update/status').then(function (st) {
      if (st.running) {
        _isApplying = true;
        renderActionButtons(true, true);
        setLogVisible('running');
        startPolling();
      }
    }).catch(function () {});
  });
})();
