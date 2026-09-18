/**
 * edl.js — Gestión de External Dynamic Lists (Ajustes > Detección).
 * Solo admin. Sin handlers ni estilos inline.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;

  function $(id) { return document.getElementById(id); }

  function showResult(id, state, msg) {
    var el = $(id);
    if (!el) return;
    el.className = 'test-result' + (state ? ' ' + state : '');
    el.textContent = msg;
  }

  function fmtDate(value) {
    if (!value) return '—';
    var d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toLocaleString();
  }

  function kindLabel(list) {
    var c = list.counts || {};
    var parts = [];
    if (c.urls) parts.push(c.urls + ' URL');
    if (c.domains) parts.push(c.domains + ' dom');
    if (c.ips) parts.push(c.ips + ' IP');
    return parts.length ? parts.join(' · ') : '0';
  }

  function statusLabel(list) {
    if (list.last_status === 'ok') return { text: 'OK', cls: 'ok' };
    if (list.last_status === 'error') return { text: 'Error', cls: 'missing' };
    return { text: 'Sin sincronizar', cls: 'missing' };
  }

  /* ── Carga y render ─────────────────────────────────────────────────────── */
  async function loadLists() {
    var box = $('edl-table');
    try {
      var data = await window.EMD.fetchJSON('/api/edl/lists');
      var badge = $('edl-badge');
      var lists = data.lists || [];
      var active = lists.filter(function (l) { return l.enabled !== false; }).length;
      var entries = lists.reduce(function (sum, l) { return sum + (l.entries || 0); }, 0);

      if (badge) {
        badge.textContent = lists.length ? active + ' activa(s)' : 'Sin listas';
        badge.className = 'badge-status ' + (lists.length ? 'ok' : 'missing');
      }
      $('edl-count').textContent = active + ' / ' + lists.length;
      $('edl-entries').textContent = entries.toLocaleString();

      var last = lists
        .map(function (l) { return l.last_sync; })
        .filter(Boolean)
        .sort()
        .pop();
      $('edl-last-sync').textContent = fmtDate(last);

      var sched = data.schedule || {};
      var auto = $('edl-auto-toggle');
      if (auto) auto.checked = !!sched.auto_enabled;
      var di = $('edl-default-interval');
      if (di && sched.default_interval_h) di.value = sched.default_interval_h;

      renderTable(lists, box);
    } catch (e) {
      if (box) {
        box.textContent = '';
        var err = document.createElement('span');
        err.className = 'faint text-sm';
        err.textContent = 'Error cargando listas: ' + e.message;
        box.appendChild(err);
      }
    }
  }

  function renderTable(lists, box) {
    box.textContent = '';
    if (!lists.length) {
      var empty = document.createElement('span');
      empty.className = 'faint text-sm';
      empty.textContent = 'No hay listas configuradas.';
      box.appendChild(empty);
      return;
    }

    var wrap = document.createElement('div'); wrap.className = 'table-wrapper';
    var table = document.createElement('table'); table.className = 'rules-table';
    var thead = document.createElement('thead');
    var headRow = document.createElement('tr');
    ['Nombre', 'Tipo', 'Entradas', 'Última sync', 'Estado', 'Activa', 'Acciones']
      .forEach(function (h) {
        var th = document.createElement('th'); th.textContent = h; headRow.appendChild(th);
      });
    thead.appendChild(headRow); table.appendChild(thead);

    var tbody = document.createElement('tbody');
    lists.forEach(function (list) {
      var tr = document.createElement('tr');

      var tdName = document.createElement('td');
      var name = document.createElement('strong'); name.textContent = list.name || list.id;
      tdName.appendChild(name);
      var url = document.createElement('div');
      url.className = 'faint text-sm';
      url.textContent = list.url || '';
      url.title = list.url || '';
      tdName.appendChild(url);
      tr.appendChild(tdName);

      var tdType = document.createElement('td');
      var badge = document.createElement('span');
      badge.className = 'cat-badge';
      badge.textContent = list.kind || '—';
      tdType.appendChild(badge);
      var detail = document.createElement('div');
      detail.className = 'faint text-sm';
      detail.textContent = kindLabel(list);
      tdType.appendChild(detail);
      tr.appendChild(tdType);

      var tdEntries = document.createElement('td');
      tdEntries.textContent = (list.entries || 0).toLocaleString();
      tr.appendChild(tdEntries);

      var tdSync = document.createElement('td');
      tdSync.className = 'muted';
      tdSync.textContent = fmtDate(list.last_sync);
      tr.appendChild(tdSync);

      var tdStatus = document.createElement('td');
      var st = statusLabel(list);
      var stEl = document.createElement('span');
      stEl.className = 'badge-status ' + st.cls;
      stEl.textContent = st.text;
      if (list.last_error) stEl.title = list.last_error;
      tdStatus.appendChild(stEl);
      tr.appendChild(tdStatus);

      var tdToggle = document.createElement('td');
      var label = document.createElement('label'); label.className = 'toggle-switch';
      var input = document.createElement('input'); input.type = 'checkbox';
      input.checked = list.enabled !== false;
      input.addEventListener('change', function () { toggleList(list.id, input); });
      var slider = document.createElement('span'); slider.className = 'toggle-slider';
      label.appendChild(input); label.appendChild(slider);
      tdToggle.appendChild(label); tr.appendChild(tdToggle);

      var tdActions = document.createElement('td');
      var btnSync = document.createElement('button');
      btnSync.type = 'button'; btnSync.className = 'btn btn-secondary btn-sm';
      btnSync.textContent = '🔄';
      btnSync.title = 'Sincronizar ahora';
      btnSync.addEventListener('click', function () { syncOne(list.id, btnSync); });
      var btnDel = document.createElement('button');
      btnDel.type = 'button'; btnDel.className = 'btn btn-danger btn-sm';
      btnDel.textContent = '🗑';
      btnDel.title = 'Eliminar lista';
      btnDel.addEventListener('click', function () { removeList(list.id, list.name); });
      tdActions.appendChild(btnSync);
      tdActions.appendChild(btnDel);
      tr.appendChild(tdActions);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody); wrap.appendChild(table); box.appendChild(wrap);
  }

  /* ── Acciones ───────────────────────────────────────────────────────────── */
  async function addList() {
    var name = $('edl-name').value.trim();
    var url = $('edl-url').value.trim();
    var interval = $('edl-interval').value.trim();
    if (!name || !url) {
      showResult('edl-add-result', 'error', 'Nombre y URL son obligatorios');
      return;
    }
    showResult('edl-add-result', 'loading', '⏳ Añadiendo...');
    try {
      var body = { name: name, url: url };
      if (interval) body.interval_h = parseFloat(interval);
      var d = await window.EMD.fetchJSON('/api/edl/lists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (d.success) {
        showResult('edl-add-result', 'ok', '✓ Lista añadida. Pulsa 🔄 para sincronizarla.');
        $('edl-name').value = ''; $('edl-url').value = ''; $('edl-interval').value = '';
        loadLists();
      } else {
        showResult('edl-add-result', 'error', '✗ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('edl-add-result', 'error', '✗ ' + e.message);
    }
  }

  async function previewUrl() {
    var url = $('edl-url').value.trim();
    if (!url) { showResult('edl-add-result', 'error', 'Introduce una URL'); return; }
    showResult('edl-add-result', 'loading', '⏳ Descargando y analizando...');
    try {
      var d = await window.EMD.fetchJSON('/api/edl/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
      if (d.success) {
        showResult('edl-add-result', 'ok',
          '✓ Tipo: ' + d.kind + ' · ' + d.entries.toLocaleString() + ' indicadores ' +
          '(' + d.counts.urls + ' URL, ' + d.counts.domains + ' dom, ' + d.counts.ips + ' IP)');
      } else {
        showResult('edl-add-result', 'error', '✗ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('edl-add-result', 'error', '✗ ' + e.message);
    }
  }

  async function saveSchedule() {
    var auto = $('edl-auto-toggle').checked;
    var interval = parseFloat($('edl-default-interval').value) || 6;
    showResult('edl-schedule-result', 'loading', '⏳ Guardando...');
    try {
      var d = await window.EMD.fetchJSON('/api/edl/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_enabled: auto, default_interval_h: interval })
      });
      if (d.success) {
        showResult('edl-schedule-result', 'ok', '✓ Programación guardada');
      } else {
        showResult('edl-schedule-result', 'error', '✗ ' + (d.error || 'Error'));
      }
    } catch (e) {
      showResult('edl-schedule-result', 'error', '✗ ' + e.message);
    }
  }

  async function syncAll(btn) {
    showResult('edl-sync-result', 'loading', '⏳ Sincronizando todas...');
    if (btn) btn.disabled = true;
    try {
      var d = await window.EMD.fetchJSON('/api/edl/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      showResult('edl-sync-result', d.success ? 'ok' : 'error',
        (d.success ? '✓ ' : '✗ ') + (d.message || ''));
      loadLists();
    } catch (e) {
      showResult('edl-sync-result', 'error', '✗ ' + e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function syncOne(id, btn) {
    showResult('edl-sync-result', 'loading', '⏳ Sincronizando...');
    if (btn) btn.disabled = true;
    try {
      var d = await window.EMD.fetchJSON('/api/edl/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ list_id: id })
      });
      showResult('edl-sync-result', d.success ? 'ok' : 'error',
        (d.success ? '✓ ' : '✗ ') + (d.message || ''));
      loadLists();
    } catch (e) {
      showResult('edl-sync-result', 'error', '✗ ' + e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function toggleList(id, cb) {
    try {
      var d = await window.EMD.fetchJSON('/api/edl/lists/' + encodeURIComponent(id) + '/toggle',
        { method: 'POST' });
      cb.checked = d.enabled;
      loadLists();
    } catch (e) {
      toast('Error al cambiar la lista', 'error');
      cb.checked = !cb.checked;
    }
  }

  async function removeList(id, name) {
    if (!confirm('¿Eliminar la lista "' + (name || id) + '"?')) return;
    try {
      await window.EMD.fetchJSON('/api/edl/lists/' + encodeURIComponent(id) + '/delete',
        { method: 'POST' });
      toast('✓ Lista eliminada', 'success');
      loadLists();
    } catch (e) {
      toast('Error al eliminar: ' + e.message, 'error');
    }
  }

  /* ── Delegación de acciones ─────────────────────────────────────────────── */
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    if (action === 'edl-refresh') loadLists();
    else if (action === 'edl-add') addList();
    else if (action === 'edl-preview') previewUrl();
    else if (action === 'edl-save-schedule') saveSchedule();
    else if (action === 'edl-sync-all') syncAll(btn);
  });

  (function init() {
    if ($('edl-panel')) loadLists();
  })();
})();
