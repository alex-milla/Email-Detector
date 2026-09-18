/**
 * training.js — Entrenamiento, dataset, anti-clanker y toggles de modelos
 * (Fase 2 del rediseño). Sin handlers ni estilos inline.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;
  var IS_ADMIN = (document.body.dataset.role === 'admin');

  function $(id) { return document.getElementById(id); }
  function showSpinner(id) { var e = $(id); if (e) e.classList.remove('hidden'); }
  function hideSpinner(id) { var e = $(id); if (e) e.classList.add('hidden'); }

  function setLog(id, state, text) {
    var el = $(id);
    if (!el) return;
    el.classList.remove('hidden', 'running', 'success', 'error');
    if (state) el.classList.add(state);
    if (text !== undefined) el.textContent = text;
  }

  /* ── Feedback pendiente ─────────────────────────────────────────────────── */
  (async function loadFeedbackStats() {
    try {
      var data = await window.EMD.fetchJSON('/feedback/stats');
      $('fbTotal').textContent = data.total;
      $('fbBenign').textContent = data.benign;
      $('fbMalicious').textContent = data.malicious;
      var hint = $('fbHint');
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
    } catch (e) { /* silencioso */ }
  })();

  /* ── Descarga de dataset ────────────────────────────────────────────────── */
  var dlBtn = $('btnDownloadDataset');
  if (dlBtn) dlBtn.addEventListener('click', downloadDataset);

  async function downloadDataset() {
    showSpinner('dlSpinner');
    $('dlStatus').textContent = '⏳ Iniciando descarga...';
    setLog('dlLog', 'running', 'Iniciando descarga del SpamAssassin Public Corpus...\n');
    try {
      var data = await window.EMD.fetchJSON('/dataset/download', { method: 'POST' });
      if (data.started) {
        setLog('dlLog', 'running', 'Descarga iniciada en background. Puede tardar varios minutos; revisa el estado más tarde.');
        $('dlStatus').textContent = '⏳ Descarga en background';
      } else if (data.success) {
        setLog('dlLog', 'success', data.stdout || 'Dataset descargado correctamente');
        $('dlStatus').textContent = '✅ Dataset descargado correctamente';
      } else {
        setLog('dlLog', 'error', data.stderr || data.error || 'Error desconocido');
        $('dlStatus').textContent = '❌ Error en la descarga';
      }
    } catch (e) {
      setLog('dlLog', 'error', e.message);
      $('dlStatus').textContent = '❌ Error de conexión';
    }
    hideSpinner('dlSpinner');
  }

  /* ── Entrenamiento en background ────────────────────────────────────────── */
  var _poll = null;
  var _ctx = { log: 'trainLog', status: 'trainStatus' };
  var TRAIN_BUTTONS = ['btnFullRetrain', 'btnTrainOnly', 'btnClankerTrain', 'btnClankerSynthetic'];
  var TRAIN_SPINNERS = ['trainSpinner', 'clankerSpinner'];

  function setTrainingUI(running) {
    TRAIN_SPINNERS.forEach(function (id) {
      var s = $(id);
      if (s) s.classList.toggle('hidden', !running);
    });
    TRAIN_BUTTONS.forEach(function (id) {
      var b = $(id);
      if (b) b.disabled = running;
    });
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
            $(_ctx.status).textContent = '✅ Modelo entrenado correctamente';
            setTimeout(function () { location.reload(); }, 3000);
          } else if (st.success === false && st.stderr) {
            setLog(_ctx.log, 'error', st.stderr || st.stdout || 'Error en el entrenamiento');
            $(_ctx.status).textContent = '❌ Error en el entrenamiento';
          } else {
            setLog(_ctx.log, 'success', st.stdout || 'Proceso finalizado');
            $(_ctx.status).textContent = '✅ Proceso finalizado';
            setTimeout(function () { location.reload(); }, 3000);
          }
        } else {
          var elapsed = st.started_at
            ? Math.round((Date.now() - new Date(st.started_at).getTime()) / 1000)
            : 0;
          $(_ctx.status).textContent =
            '⏳ Entrenando... ' + elapsed + 's transcurridos (puedes navegar mientras esperas)';
        }
      } catch (e) { /* reintenta en el siguiente tick */ }
    }, 5000);
  }

  async function launchTraining(endpoint, ctx) {
    _ctx = ctx || { log: 'trainLog', status: 'trainStatus' };
    setTrainingUI(true);
    setLog(_ctx.log, 'running',
      (_ctx.starting || 'Lanzando entrenamiento en background...') +
      '\nEsto puede tardar varios minutos.\n');
    $(_ctx.status).textContent = '⏳ Iniciando...';

    var opts = { method: 'POST' };
    if (_ctx.body) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(_ctx.body);
    }

    try {
      var data = await window.EMD.fetchJSON(endpoint, opts);
      if (data.error) {
        setLog(_ctx.log, 'error', data.error);
        $(_ctx.status).textContent = '❌ ' + data.error;
        setTrainingUI(false);
        return;
      }
      if (data.started) {
        $(_ctx.status).textContent = '⏳ Entrenando en background...';
        startPoll();
      }
    } catch (e) {
      setLog(_ctx.log, 'error', e.message);
      $(_ctx.status).textContent = '❌ Error de conexión';
      setTrainingUI(false);
    }
  }

  function fullRetrain() {
    launchTraining('/model/full-retrain', { log: 'trainLog', status: 'trainStatus' });
  }
  function trainOnly() {
    launchTraining('/model/retrain', { log: 'trainLog', status: 'trainStatus' });
  }
  function retrainClanker(synthetic) {
    launchTraining('/model/retrain-clanker', {
      log: 'clankerLog', status: 'clankerStatus',
      body: { synthetic: !!synthetic },
      starting: synthetic
        ? 'Generando dataset sintético Anti-Clanker y reentrenando...'
        : 'Reentrenando Anti-Clanker desde los CSVs de data/processed/...'
    });
  }

  var bFull = $('btnFullRetrain');
  if (bFull) bFull.addEventListener('click', fullRetrain);
  var bOnly = $('btnTrainOnly');
  if (bOnly) bOnly.addEventListener('click', trainOnly);
  var bClanker = $('btnClankerTrain');
  if (bClanker) bClanker.addEventListener('click', function () { retrainClanker(false); });
  var bClankerSyn = $('btnClankerSynthetic');
  if (bClankerSyn) bClankerSyn.addEventListener('click', function () { retrainClanker(true); });

  (async function checkOnLoad() {
    try {
      var st = await window.EMD.fetchJSON('/model/training-status');
      if (st.running) {
        setTrainingUI(true);
        $('trainStatus').textContent = '⏳ Entrenamiento en curso...';
        setLog('trainLog', 'running', 'Entrenamiento en progreso. Se actualizará al terminar.');
        startPoll();
      }
    } catch (e) { /* silencioso */ }
  })();

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
})();
