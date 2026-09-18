/**
 * training.js — Puesta en marcha, mantenimiento, modelos y Anti-Clanker.
 * Sin handlers ni estilos inline. Estado inicial vía atributos data-*.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;
  var IS_ADMIN = (document.body.dataset.role === 'admin');
  var TAB_KEY = 'emd_training_tab';

  function $(id) { return document.getElementById(id); }
  function showSpinner(id) { var e = $(id); if (e) e.classList.remove('hidden'); }
  function hideSpinner(id) { var e = $(id); if (e) e.classList.add('hidden'); }
  function setDisabled(id, disabled, title) {
    var b = $(id);
    if (!b) return;
    b.disabled = disabled;
    if (title) b.title = title; else b.removeAttribute('title');
  }

  function setLog(id, state, text) {
    var el = $(id);
    if (!el) return;
    el.classList.remove('hidden', 'running', 'success', 'error');
    if (state) el.classList.add(state);
    if (text !== undefined) el.textContent = text;
  }

  /* ── Estado inicial (inyectado por el servidor) ─────────────────────────── */
  function getState() {
    var el = $('trainingStatus');
    if (!el) {
      return { modelReady: false, hasFeatures: false, total: 0, csvCount: 0, antiClanker: false };
    }
    return {
      modelReady: el.dataset.modelReady === 'true',
      hasFeatures: el.dataset.hasFeatures === 'true',
      antiClanker: el.dataset.antiClanker === 'true',
      total: parseInt(el.dataset.total, 10) || 0,
      csvCount: parseInt(el.dataset.csvCount, 10) || 0
    };
  }

  /* ── Pestañas ───────────────────────────────────────────────────────────── */
  function activateTab(name) {
    var found = false;
    document.querySelectorAll('.tab-btn').forEach(function (b) {
      var on = b.getAttribute('data-tab') === name;
      if (on) found = true;
      b.classList.toggle('active', on);
    });
    if (!found) name = 'setup';
    document.querySelectorAll('[data-tab-panel]').forEach(function (p) {
      p.classList.toggle('hidden', p.getAttribute('data-tab-panel') !== name);
    });
    try { localStorage.setItem(TAB_KEY, name); } catch (e) { /* privado */ }
  }

  function defaultTab() {
    var valid = IS_ADMIN ? ['setup', 'maintenance', 'models'] : ['setup', 'maintenance'];
    var saved = null;
    try { saved = localStorage.getItem(TAB_KEY); } catch (e) { /* privado */ }
    if (saved && valid.indexOf(saved) !== -1) return saved;
    return getState().modelReady ? 'maintenance' : 'setup';
  }

  /* ── Estado: resumen, CTA y gating de botones ───────────────────────────── */
  function renderPrereq() {
    var el = $('trainPrereq');
    if (!el) return;
    var s = getState();
    if (s.total === 0) {
      el.className = 'alert alert-error';
      el.textContent = 'Necesitas correos etiquetados para entrenar (paso 1).';
    } else if (s.total < 50) {
      el.className = 'alert alert-info';
      el.textContent = 'Tienes ' + s.total + ' correos. Se recomiendan al menos 50; ' +
        'el entrenamiento puede no ser fiable.';
    } else {
      el.className = 'alert alert-success';
      el.textContent = 'Listo para entrenar con ' + s.total + ' correos etiquetados.';
    }
  }

  function applyGating() {
    var s = getState();
    var canTrain = IS_ADMIN && s.total > 0;
    var trainTitle = canTrain ? '' : 'Necesitas correos etiquetados';
    setDisabled('btnFullRetrain', !canTrain, trainTitle);
    setDisabled('btnMainRetrain', !canTrain, trainTitle);
    var canFeatures = IS_ADMIN && s.hasFeatures;
    setDisabled('btnTrainOnly', !canFeatures, canFeatures ? '' : 'Necesitas features generadas (CSVs)');
    setDisabled('btnClankerTrain', !canFeatures, canFeatures ? '' : 'Necesitas features generadas (CSVs)');
    renderPrereq();
  }

  function renderStatus(fb) {
    var s = getState();
    var summary = $('statusSummary');
    var actions = $('statusActions');
    if (!summary || !actions) return;
    var pending = fb ? fb.total : 0;

    if (!s.modelReady) {
      summary.textContent = 'Faltan pasos de la puesta en marcha inicial.';
      actions.innerHTML =
        '<button class="btn btn-primary" data-action="goto-setup">Continuar puesta en marcha →</button>';
      return;
    }
    summary.textContent = 'Modelo listo' +
      (pending > 0 ? ' · ' + pending + ' correcciones sin usar' : ' · sin correcciones pendientes');
    if (IS_ADMIN) {
      actions.innerHTML =
        '<button class="btn btn-primary" data-action="retrain-now">🔁 Reentrenar con mis correcciones</button>' +
        '<button class="btn btn-secondary" data-action="goto-maintenance">Ver mantenimiento</button>';
    } else {
      actions.innerHTML =
        '<button class="btn btn-secondary" data-action="goto-maintenance">Ver mantenimiento</button>';
    }
  }

  /* ── Feedback pendiente ─────────────────────────────────────────────────── */
  async function loadFeedbackStats() {
    try {
      var data = await window.EMD.fetchJSON('/feedback/stats');
      if ($('fbTotal')) $('fbTotal').textContent = data.total;
      if ($('fbBenign')) $('fbBenign').textContent = data.benign;
      if ($('fbMalicious')) $('fbMalicious').textContent = data.malicious;
      var hint = $('fbHint');
      if (hint) {
        if (data.total === 0) {
          hint.textContent = 'Sin correcciones pendientes';
          hint.className = 'fb-hint neutral';
        } else if (data.total < 20) {
          hint.textContent = '⚠️ Se recomiendan al menos 20 antes de re-entrenar';
          hint.className = 'fb-hint warn';
        } else {
          hint.textContent = '✅ Listo para re-entrenar';
          hint.className = 'fb-hint ok';
        }
      }
      renderStatus(data);
    } catch (e) {
      renderStatus(null);
    }
  }

  /* ── Descarga de dataset ────────────────────────────────────────────────── */
  var dlBtn = $('btnDownloadDataset');
  if (dlBtn) dlBtn.addEventListener('click', downloadDataset);

  async function downloadDataset() {
    if (dlBtn) dlBtn.disabled = true;
    showSpinner('dlSpinner');
    if ($('dlStatus')) $('dlStatus').textContent = '⏳ Iniciando descarga...';
    setLog('dlLog', 'running', 'Iniciando descarga del SpamAssassin Public Corpus...\n');
    try {
      var data = await window.EMD.fetchJSON('/dataset/download', { method: 'POST' });
      if (data.started) {
        setLog('dlLog', 'running', 'Descarga iniciada en background. Puede tardar varios minutos; recarga la página al terminar.');
        if ($('dlStatus')) $('dlStatus').textContent = '⏳ Descarga en background';
      } else if (data.success) {
        setLog('dlLog', 'success', data.stdout || 'Dataset descargado correctamente');
        if ($('dlStatus')) $('dlStatus').textContent = '✅ Dataset descargado correctamente';
      } else {
        setLog('dlLog', 'error', data.stderr || data.error || 'Error desconocido');
        if ($('dlStatus')) $('dlStatus').textContent = '❌ Error en la descarga';
      }
    } catch (e) {
      setLog('dlLog', 'error', e.message);
      if ($('dlStatus')) $('dlStatus').textContent = '❌ Error de conexión';
    }
    hideSpinner('dlSpinner');
    if (dlBtn) dlBtn.disabled = false;
  }

  /* ── Entrenamiento en background ────────────────────────────────────────── */
  var _poll = null;
  var CTX_SETUP = { log: 'trainLog', status: 'trainStatus', spinner: 'trainSpinner' };
  var CTX_MAINT = { log: 'trainLog2', status: 'trainStatus2', spinner: 'trainSpinner2' };
  var CTX_CLANKER = { log: 'clankerLog', status: 'clankerStatus', spinner: 'clankerSpinner' };
  var _ctx = CTX_SETUP;
  var ALL_BUTTONS = ['btnFullRetrain', 'btnMainRetrain', 'btnTrainOnly',
                     'btnClankerTrain', 'btnClankerSynthetic'];
  var ALL_SPINNERS = ['trainSpinner', 'trainSpinner2', 'clankerSpinner'];

  function setTrainingUI(running) {
    ALL_SPINNERS.forEach(function (id) {
      var s = $(id);
      if (s) s.classList.toggle('hidden', !running);
    });
    ALL_BUTTONS.forEach(function (id) {
      var b = $(id);
      if (b) b.disabled = running;
    });
    if (!running) applyGating();
  }

  function startPoll() {
    if (_poll) clearInterval(_poll);
    _poll = setInterval(async function () {
      try {
        var st = await window.EMD.fetchJSON('/model/training-status');
        if (!st.running) {
          clearInterval(_poll);
          _poll = null;
          setTrainingUI(false);
          if (st.success === true) {
            setLog(_ctx.log, 'success', st.stdout || 'Entrenamiento completado');
            if ($(_ctx.status)) $(_ctx.status).textContent = '✅ Modelo entrenado correctamente';
            setTimeout(function () { location.reload(); }, 3000);
          } else if (st.success === false && st.stderr) {
            setLog(_ctx.log, 'error', st.stderr || st.stdout || 'Error en el entrenamiento');
            if ($(_ctx.status)) $(_ctx.status).textContent = '❌ Error en el entrenamiento';
          } else {
            setLog(_ctx.log, 'success', st.stdout || 'Proceso finalizado');
            if ($(_ctx.status)) $(_ctx.status).textContent = '✅ Proceso finalizado';
            setTimeout(function () { location.reload(); }, 3000);
          }
        } else {
          var elapsed = st.started_at
            ? Math.round((Date.now() - new Date(st.started_at).getTime()) / 1000)
            : 0;
          if ($(_ctx.status)) {
            $(_ctx.status).textContent =
              '⏳ Entrenando... ' + elapsed + 's transcurridos (puedes navegar mientras esperas)';
          }
        }
      } catch (e) { /* reintenta en el siguiente tick */ }
    }, 5000);
  }

  async function launchTraining(endpoint, ctx, extra) {
    _ctx = ctx || CTX_SETUP;
    setTrainingUI(true);
    setLog(_ctx.log, 'running',
      ((extra && extra.starting) || 'Lanzando entrenamiento en background...') +
      '\nEsto puede tardar varios minutos.\n');
    if ($(_ctx.status)) $(_ctx.status).textContent = '⏳ Iniciando...';

    var opts = { method: 'POST' };
    if (extra && extra.body) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(extra.body);
    }

    try {
      var data = await window.EMD.fetchJSON(endpoint, opts);
      if (data.error) {
        setLog(_ctx.log, 'error', data.error);
        if ($(_ctx.status)) $(_ctx.status).textContent = '❌ ' + data.error;
        setTrainingUI(false);
        return;
      }
      if (data.started) {
        if ($(_ctx.status)) $(_ctx.status).textContent = '⏳ Entrenando en background...';
        startPoll();
      }
    } catch (e) {
      setLog(_ctx.log, 'error', e.message);
      if ($(_ctx.status)) $(_ctx.status).textContent = '❌ Error de conexión';
      setTrainingUI(false);
    }
  }

  function fullRetrain(ctx) { launchTraining('/model/full-retrain', ctx || CTX_SETUP); }
  function trainOnly() { launchTraining('/model/retrain', CTX_MAINT); }
  function retrainClanker(synthetic) {
    launchTraining('/model/retrain-clanker', CTX_CLANKER, {
      body: { synthetic: !!synthetic },
      starting: synthetic
        ? 'Generando dataset sintético Anti-Clanker y reentrenando...'
        : 'Reentrenando Anti-Clanker desde los CSVs de data/processed/...'
    });
  }

  var bFull = $('btnFullRetrain');
  if (bFull) bFull.addEventListener('click', function () { fullRetrain(CTX_SETUP); });
  var bMain = $('btnMainRetrain');
  if (bMain) bMain.addEventListener('click', function () { fullRetrain(CTX_MAINT); });
  var bOnly = $('btnTrainOnly');
  if (bOnly) bOnly.addEventListener('click', trainOnly);
  var bClanker = $('btnClankerTrain');
  if (bClanker) bClanker.addEventListener('click', function () { retrainClanker(false); });
  var bClankerSyn = $('btnClankerSynthetic');
  if (bClankerSyn) bClankerSyn.addEventListener('click', function () { retrainClanker(true); });

  /* ── Delegación de acciones (pestañas y CTA) ────────────────────────────── */
  document.addEventListener('click', function (ev) {
    var el = ev.target.closest('[data-action]');
    if (!el) return;
    var action = el.getAttribute('data-action');
    if (action === 'tab') { activateTab(el.getAttribute('data-tab')); return; }
    if (action === 'goto-setup') { activateTab('setup'); return; }
    if (action === 'goto-maintenance') { activateTab('maintenance'); return; }
    if (action === 'retrain-now') { activateTab('maintenance'); fullRetrain(CTX_MAINT); return; }
  });

  /* ── Toggles de modelos (solo admin) ────────────────────────────────────── */
  function applyState(name, enabled) {
    var card = document.querySelector('.model-card[data-model="' + name + '"]');
    if (!card) return;
    card.classList.toggle('disabled-card', !enabled);
    var input = card.querySelector('.mt-input');
    if (input) input.checked = enabled;
  }

  async function loadModelStates() {
    try {
      var d = await window.EMD.fetchJSON('/api/models/toggle');
      (d.models || []).forEach(function (m) { applyState(m.name, m.enabled); });
    } catch (e) { /* silencioso */ }
  }

  async function toggleModel(name, enabled) {
    if (!IS_ADMIN) return;
    try {
      var d = await window.EMD.fetchJSON('/api/models/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, enabled: enabled })
      });
      if (d.ok) {
        applyState(name, enabled);
        if (!document.querySelectorAll('.mt-input:checked').length) {
          toast('Atención: todos los modelos deshabilitados.', 'warning');
        }
      } else {
        toast('Error: ' + (d.error || '?'), 'error');
      }
    } catch (e) {
      toast(e.message || 'Error de conexión', 'error');
    }
  }

  if (IS_ADMIN) {
    document.querySelectorAll('.model-card[data-model]').forEach(function (card) {
      var name = card.getAttribute('data-model');
      var label = document.createElement('label');
      label.className = 'toggle-switch model-toggle';
      label.title = 'Habilitar/Deshabilitar';

      var input = document.createElement('input');
      input.type = 'checkbox';
      input.className = 'mt-input';
      input.checked = true;
      input.addEventListener('change', function () { toggleModel(name, input.checked); });

      var slider = document.createElement('span');
      slider.className = 'mt-slider';

      label.appendChild(input);
      label.appendChild(slider);
      card.appendChild(label);
    });
    loadModelStates();
  }

  /* ── Estado de reglas Anti-Clanker ──────────────────────────────────────── */
  (async function loadClankerStatus() {
    try {
      var d = await window.EMD.fetchJSON('/api/clanker/status');
      if (!d.enabled) return;
      var el = $('model-10-rules');
      if (el) el.textContent = d.active_rules + ' / ' + d.total_rules;
    } catch (e) { /* silencioso */ }
  })();

  /* ── Arranque ───────────────────────────────────────────────────────────── */
  activateTab(defaultTab());
  applyGating();
  loadFeedbackStats();

  (async function checkOnLoad() {
    try {
      var st = await window.EMD.fetchJSON('/model/training-status');
      if (st.running) {
        setTrainingUI(true);
        if ($('trainStatus')) $('trainStatus').textContent = '⏳ Entrenamiento en curso...';
        if ($('trainStatus2')) $('trainStatus2').textContent = '⏳ Entrenamiento en curso...';
        setLog('trainLog2', 'running', 'Entrenamiento en progreso. Se actualizará al terminar.');
        _ctx = CTX_MAINT;
        startPoll();
      }
    } catch (e) { /* silencioso */ }
  })();
})();
