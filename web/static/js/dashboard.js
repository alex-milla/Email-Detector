/**
 * dashboard.js — Dashboard: historial, análisis, modales, feedback y gráfica
 * (Fase 2 del rediseño). Sin handlers ni estilos inline.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;

  function $(id) { return document.getElementById(id); }

  function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }

  function nl(s) {
    return (s || '')
      .replace('MÍNIMO', 'MINIMO').replace('MíNIMO', 'MINIMO')
      .replace('CRÍTICO', 'CRITICO').replace('CRíTICO', 'CRITICO');
  }
  var ew = function (v) { return Math.min(((parseFloat(v) || 0) / 8) * 100, 100).toFixed(1); };
  var ec = function (v) { return (parseFloat(v) || 0) > 5.5 ? '#f0647a' : (parseFloat(v) || 0) > 4.5 ? '#f5c451' : '#3ddc97'; };
  var lcMap = { CRITICO: 'critico', ALTO: 'alto', MEDIO: 'medio', BAJO: 'bajo', MINIMO: 'minimo' };

  var _store = {};
  var currentPage = 1;
  var totalPages = 1;
  var currentDbId = null;
  var selectedFiles = [];

  /* ── Historial ──────────────────────────────────────────────────────────── */
  async function loadHistory(page) {
    try {
      var data = await window.EMD.fetchJSON('/history/page/' + page);
      currentPage = data.page;
      totalPages = data.pages;
      renderHistoryTable(data.items);
      updatePageControls(data.pages, data.total);
    } catch (e) { /* silencioso */ }
  }

  function changePage(page) {
    if (page < 1 || page > totalPages) return;
    loadHistory(page);
  }

  function renderHistoryTable(items) {
    var tbody = $('historyTable');
    if (!tbody) return;
    if (!items || items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center faint">Sin análisis todavía</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(function (r) {
      var fb = (r.feedback_label !== null && r.feedback_label !== undefined)
        ? (r.feedback_label === 0
          ? '<span class="text-success text-sm">✅ Benigno</span>'
          : '<span class="text-danger text-sm">⛔ Malicioso</span>')
        : '<span class="faint text-sm">—</span>';
      return '<tr data-id="' + r.id + '">' +
        '<td class="nowrap">' + escapeHtml((r.timestamp || '-').slice(0, 16)) + '</td>' +
        '<td class="faint clip-sm">' + escapeHtml((r.filename || '-').slice(0, 28)) + '</td>' +
        '<td class="clip-md">' + escapeHtml((r.subject || '(sin asunto)').slice(0, 40)) + '</td>' +
        '<td><span class="risk-badge ' + (r.prediction === 'MALICIOSO' ? 'pred-malicioso' : 'pred-benigno') + '">' + escapeHtml(r.prediction || '-') + '</span></td>' +
        '<td>' + (r.risk_score || 0) + '%</td>' +
        '<td>' + (r.body_entropy || '-') + '</td>' +
        '<td>' + fb + '</td>' +
        '<td><button class="btn btn-secondary btn-sm" data-action="report" data-id="' + r.id + '" title="Informe">📄</button></td>' +
        '</tr>';
    }).join('');
  }

  function updatePageControls(pages, total) {
    if ($('pageInfo')) $('pageInfo').textContent = 'Página ' + currentPage + ' de ' + pages;
    if ($('totalInfo')) $('totalInfo').textContent = '(' + total + ' análisis en total)';
    if ($('btnPrev')) $('btnPrev').disabled = currentPage <= 1;
    if ($('btnNext')) $('btnNext').disabled = currentPage >= pages;
  }

  async function updateStats() {
    try {
      var hist = await window.EMD.fetchJSON('/history');
      if ($('stat-total')) $('stat-total').textContent = hist.length;
      if ($('stat-malicious')) $('stat-malicious').textContent = hist.filter(function (r) { return r.prediction === 'MALICIOSO'; }).length;
      if ($('stat-benign')) $('stat-benign').textContent = hist.filter(function (r) { return r.prediction === 'BENIGNO'; }).length;
    } catch (e) { /* silencioso */ }
    loadHistory(1);
  }

  async function clearHistory() {
    if (!confirm('¿Borrar todo tu historial?')) return;
    try {
      await window.EMD.fetchJSON('/history/clear', { method: 'POST' });
      loadHistory(1);
      updateStats();
    } catch (e) { toast(e.message || 'Error', 'error'); }
  }

  /* ── Detalle ────────────────────────────────────────────────────────────── */
  async function openDetail(dbId) {
    dbId = String(dbId);
    currentDbId = dbId;
    if (_store[dbId] && _store[dbId].metadata) { renderModal(_store[dbId]); return; }
    try {
      var data = await window.EMD.fetchJSON('/history/' + dbId);
      if (data.error) { toast('No se pudo cargar el detalle', 'error'); return; }
      _store[dbId] = data;
      renderModal(data);
    } catch (e) { toast('Error: ' + e.message, 'error'); }
  }

  function feedbackBarHtml(dbId, fb) {
    var actions = fb === null
      ? '<button class="btn-benign" data-action="feedback" data-id="' + dbId + '" data-label="0">✅ Benigno</button>' +
        '<button class="btn-malicious" data-action="feedback" data-id="' + dbId + '" data-label="1">⛔ Malicioso</button>'
      : '<span class="feedback-applied ' + (fb === 0 ? 'benign' : 'malicious') + '">' +
          (fb === 0 ? '✅ Marcado como benigno' : '⛔ Marcado como malicioso') + '</span>' +
        '<button class="btn-benign" data-action="feedback" data-id="' + dbId + '" data-label="0">✅</button>' +
        '<button class="btn-malicious" data-action="feedback" data-id="' + dbId + '" data-label="1">⛔</button>';
    return '<div class="feedback-bar" id="fbBar_' + dbId + '">' +
      '<span class="fb-label">¿Clasificación correcta?</span>' + actions + '</div>';
  }

  function renderModal(r) {
    var dbId = String(r._db_id || currentDbId);
    var ea = r.entropy_analysis || {};
    var md = r.metadata || {};
    var vt = r.virustotal || {};
    var vts = vt.summary || {};
    var fb = (r.feedback_label !== null && r.feedback_label !== undefined) ? r.feedback_label : null;
    var rc = r.prediction === 'MALICIOSO' ? '#f0647a' : '#3ddc97';

    var html =
      '<div class="detail-summary" style="border-left-color:' + rc + '">' +
        '<div class="row-between">' +
          '<div>' +
            '<div class="meta-label">ASUNTO</div>' +
            '<div class="strong mb-1">' + (escapeHtml(r.subject) || '(sin asunto)') + '</div>' +
            '<div class="faint text-sm">De: ' + (escapeHtml(r.from) || '-') + '</div>' +
            '<div class="faint text-sm">Fecha: ' + escapeHtml((r.timestamp || '').slice(0, 16)) + '</div>' +
            '<div class="faint text-sm">Analizado por: ' + (escapeHtml(r.analyzed_by) || '-') + '</div>' +
          '</div>' +
          '<div class="text-right">' +
            '<span class="risk-badge ' + (r.prediction === 'MALICIOSO' ? 'pred-malicioso' : 'pred-benigno') + '">' + (escapeHtml(r.prediction) || '-') + '</span>' +
            '<div style="color:' + rc + '" class="strong mt-1">' + (escapeHtml(r.risk_level) || '-') + ' — ' + (r.risk_score || 0) + '%</div>' +
            '<div class="faint text-sm">Modelo: ' + (escapeHtml(r.model_used) || '-') + '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      feedbackBarHtml(dbId, fb);

    // Autenticación
    html += renderAuthSection(md.auth_results, md.auth_summary, r.auth_analysis, md.raw_headers, r.features);

    // Entropía
    html += '<div class="detail-section"><h4>📊 Análisis de entropía</h4><div class="detail-grid">' +
      detailItem('Cuerpo', ea.body_entropy) +
      detailItem('Asunto', ea.subject_entropy) +
      detailItem('URL máx.', ea.url_entropy_max) +
      detailItem('Adjunto máx.', ea.attachment_content_entropy_max) +
      '</div></div>';

    // URLs
    var urls = md.urls_found || r.urls || [];
    if (urls.length > 0) {
      html += '<div class="detail-section"><h4>🔗 URLs detectadas (' + urls.length + ')</h4><ul class="url-list">';
      urls.slice(0, 10).forEach(function (u) {
        var safeU = escapeHtml(u);
        if (/^https?:\/\//i.test(u)) {
          html += '<li><a href="' + safeU + '" target="_blank" rel="noopener">' + safeU + '</a></li>';
        } else {
          html += '<li class="text-warning">⚠️ ' + safeU + ' <em>(protocolo no seguro)</em></li>';
        }
      });
      if (urls.length > 10) html += '<li class="faint">... y ' + (urls.length - 10) + ' más</li>';
      html += '</ul></div>';
    }

    // QR
    var qrCodes = md.qr_codes_found || [];
    if (qrCodes.length > 0) {
      html += '<div class="detail-section"><h4>📱 Códigos QR detectados (' + qrCodes.length + ')</h4>';
      qrCodes.forEach(function (qr, idx) {
        var res = qr.resolution || {};
        var chain = res.chain || [qr.raw_payload];
        var final = res.final || qr.raw_payload;
        var tags = [
          qr.is_inline ? '📎 inline' : '📎 adjunto',
          res.is_shortener ? '🔗 acortador' : '',
          res.used_js ? '⚡ JS redirect' : '',
          res.used_meta_refresh ? '🔄 meta-refresh' : ''
        ].filter(Boolean).join(' · ');

        html += '<div class="qr-block">' +
          '<div class="faint text-sm mb-1">QR #' + (idx + 1) + ' en ' + escapeHtml(qr.source_filename) + ' · ' + tags + '</div>';
        if (qr.is_url) {
          html += '<div class="text-sm mb-1"><strong>Original:</strong> <code>' + escapeHtml(qr.raw_payload) + '</code></div>';
          if (chain.length > 2) {
            html += '<div class="faint text-sm mb-1"><strong>Cadena (' + (chain.length - 1) + ' saltos):</strong><br>';
            chain.forEach(function (u, i) {
              html += '<div class="ml-1">' + (i + 1) + '. <code>' + escapeHtml(u) + '</code></div>';
            });
            html += '</div>';
          }
          html += '<div class="text-sm mt-1"><strong class="text-danger">Final:</strong> ' +
            '<a href="' + escapeHtml(final) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(final) + '</a></div>';

          var vtMatch = (vt.urls || []).find(function (x) { return x.url === final; });
          if (vtMatch && (vtMatch.malicious > 0 || vtMatch.suspicious > 0)) {
            html += '<div class="alert alert-error mt-1">⚠️ VirusTotal: ' + (vtMatch.malicious || 0) + ' maliciosa · ' + (vtMatch.suspicious || 0) + ' sospechosa (de ' + (vtMatch.total || 0) + ')</div>';
          } else if (vtMatch && vtMatch.found) {
            html += '<div class="alert alert-success mt-1">✅ VirusTotal: limpia (' + (vtMatch.total || 0) + ' motores)</div>';
          }
        } else {
          html += '<div class="text-sm"><strong>Contenido (no-URL):</strong> <code>' + escapeHtml(qr.raw_payload.slice(0, 200)) + '</code></div>';
        }
        html += '</div>';
      });
      html += '</div>';
    }

    // ClickFix
    html += renderClickfixSection(r.clickfix || md.clickfix);

    // VirusTotal
    if (vt && Object.keys(vt).length > 0) {
      var ok = !vts.malicious_files && !vts.malicious_urls;
      html += '<div class="detail-section"><h4>🛡️ VirusTotal</h4>' +
        '<div class="alert ' + (ok ? 'alert-success' : 'alert-error') + '">' +
        (ok ? '✅ Sin amenazas' : '⚠️ ' + (vts.malicious_files || 0) + ' archivos + ' + (vts.malicious_urls || 0) + ' URLs maliciosas') +
        ' — ' + (vts.total_checked || 0) + ' consultas</div>' +
        '<div class="row mt-1"><button class="btn btn-secondary btn-sm" data-action="recheck-vt" data-id="' + dbId + '">🔍 Volver a consultar VirusTotal</button></div></div>';
    }

    html += '<div class="detail-section text-center"><button class="btn btn-primary" data-action="report" data-id="' + dbId + '">📄 Ver informe completo</button></div>';

    $('modalTitle').textContent = escapeHtml(r.filename) || 'Detalle';
    $('modalBody').innerHTML = html;
    window.EMD.openModal('detailModal');
  }

  var AUTH_ORDER = ['spf', 'dkim', 'dmarc', 'arc'];

  function authResultClass(result) {
    var r = String(result || '').toLowerCase();
    if (r === 'pass') return 'pred-benigno';
    if (r === 'fail' || r === 'softfail' || r === 'permerror' || r === 'temperror') return 'pred-malicioso';
    return 'risk-MEDIO';
  }
  function authResultIcon(result) {
    var r = String(result || '').toLowerCase();
    if (r === 'pass') return '✅';
    if (r === 'present') return '✍️';
    if (r === '' || r === 'none') return '➖';
    return '❌';
  }
  function authBadge(method, result) {
    var cls = authResultClass(result);
    var icon = authResultIcon(result);
    return '<span class="risk-badge ' + cls + '">' + icon + ' ' + String(method).toUpperCase() + '=' + escapeHtml(result || 'none') + '</span>';
  }
  function renderAuthBadges(summary) {
    var out = '';
    AUTH_ORDER.forEach(function (m) {
      var s = summary && summary[m];
      if (!s || !s.present) return;
      out += authBadge(m, s.result);
    });
    return out;
  }
  function renderRawHeaders(headers) {
    if (!headers || !Object.keys(headers).length) return '';
    var body = '';
    Object.keys(headers).forEach(function (name) {
      body += '<div class="header-row"><div class="header-name">' + escapeHtml(name) + '</div>';
      (headers[name] || []).forEach(function (v) {
        body += '<pre class="header-value">' + escapeHtml(v) + '</pre>';
      });
      body += '</div>';
    });
    return '<details class="headers-block"><summary>Ver cabeceras de autenticación</summary>' + body + '</details>';
  }
  function badgesFromFeatures(features) {
    if (!features) return '';
    var out = '';
    AUTH_ORDER.forEach(function (m) {
      var v = features[m + '_pass'];
      if (v !== undefined) out += authBadge(m, v ? 'pass' : 'none');
    });
    return out;
  }
  function renderAuthSection(details, summary, analysis, rawHeaders, features) {
    details = details || [];
    var html = '<div class="detail-section"><h4>🔐 Autenticación</h4>';
    var badges = renderAuthBadges(summary) || badgesFromFeatures(features);
    if (badges) {
      html += '<div class="auth-badges">' + badges + '</div>';
    } else if (!details.length) {
      html += '<div class="faint text-sm">Sin cabeceras de autenticación (SPF/DKIM/DMARC)</div>';
    }
    if (details.length) {
      html += '<table class="auth-table"><thead><tr>' +
        '<th>Método</th><th>Resultado</th><th>Dominio</th><th>Servidor</th>' +
        '</tr></thead><tbody>';
      details.forEach(function (d) {
        html += '<tr><td>' + escapeHtml(String(d.method || '').toUpperCase()) + '</td>' +
          '<td>' + authResultIcon(d.result) + ' ' + escapeHtml(d.result || '') + '</td>' +
          '<td class="faint">' + (escapeHtml(d.domain) || '—') + '</td>' +
          '<td class="faint clip-sm">' + (escapeHtml(d.server) || '—') + '</td></tr>';
      });
      html += '</tbody></table>';
    }
    var warnings = (analysis && analysis.warnings) || [];
    if (warnings.length) {
      html += '<div class="alert alert-error mt-1">⚠️ ' + warnings.map(escapeHtml).join('<br>⚠️ ') + '</div>';
    }
    html += renderRawHeaders(rawHeaders);
    html += '</div>';
    return html;
  }
  function detailItem(label, value) {
    return '<div class="detail-item"><div class="label">' + label + '</div><div class="value">' + (value === undefined || value === null ? '-' : value) + '</div></div>';
  }

  function clickfixTags(cf) {
    var tags = (cf.techniques || []).slice();
    if (cf.has_win_r) tags.push('Win+R');
    if (cf.has_encoded_command) tags.push('base64/-enc');
    if (cf.has_powershell) tags.push('PowerShell');
    return tags;
  }

  function renderClickfixSection(cf) {
    if (!cf) return '';
    var detected = cf.detected || cf.clickfix_detected;
    if (!detected) return '';
    var score = (cf.score !== undefined && cf.score !== null) ? cf.score : (cf.clickfix_score || 0);
    var high = cf.high_confidence;
    var urls = cf.payload_urls || [];
    var domains = cf.payload_domains || [];
    var ips = cf.payload_ips || [];
    var decoded = cf.decoded_commands || [];
    var raw = cf.raw_commands || [];
    var lures = cf.lure_phrases || [];
    var sources = cf.source_attachments || [];

    var html = '<div class="detail-section"><h4>🖱️ ClickFix' +
      (high ? ' <span class="risk-badge pred-malicioso">alta confianza</span>' : '') +
      '</h4>' +
      '<div class="alert ' + (high ? 'alert-error' : 'alert-warning') + '">' +
      'Vector de copiado/pegado detectado (score ' + score + ').' +
      (high ? ' Comando ofuscado con indicadores extraídos.' : '') +
      '</div>';

    var tags = clickfixTags(cf);
    if (tags.length) {
      html += '<div class="auth-badges">' + tags.map(function (t) {
        return '<span class="risk-badge">' + escapeHtml(t) + '</span>';
      }).join('') + '</div>';
    }
    if (lures.length) {
      html += '<div class="faint text-sm mt-1">Señuelos: ' +
        lures.slice(0, 6).map(escapeHtml).join(' · ') + '</div>';
    }
    if (sources.length) {
      html += '<div class="faint text-sm mt-1">Adjuntos implicados: ' +
        sources.map(escapeHtml).join(', ') + '</div>';
    }
    if (decoded.length) {
      html += '<div class="text-sm mt-2"><strong>Comando desofuscado:</strong>' +
        decoded.slice(0, 3).map(function (c) {
          return '<pre class="header-value">' + escapeHtml(c.slice(0, 1000)) + '</pre>';
        }).join('') + '</div>';
    } else if (raw.length) {
      html += '<div class="text-sm mt-2"><strong>Comando (ofuscado):</strong>' +
        '<pre class="header-value">' + escapeHtml(raw[0].slice(0, 1000)) + '</pre></div>';
    }
    if (urls.length || domains.length || ips.length) {
      html += '<div class="mt-1"><strong class="muted text-sm">Indicadores originales:</strong>';
      urls.forEach(function (u) {
        html += '<div class="ioc-row">🔗 <a href="' + escapeHtml(u) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(u) + '</a></div>';
      });
      domains.forEach(function (d) { html += '<div class="ioc-row">🌐 <code>' + escapeHtml(d) + '</code></div>'; });
      ips.forEach(function (ip) { html += '<div class="ioc-row">📡 <code>' + escapeHtml(ip) + '</code></div>'; });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  async function doFeedback(dbId, label) {
    try {
      var data = await window.EMD.fetchJSON('/feedback/' + dbId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label })
      });
      if (data.success) {
        if (_store[dbId]) _store[dbId].feedback_label = label;
        var bar = $('fbBar_' + dbId);
        if (bar) bar.outerHTML = feedbackBarHtml(dbId, label);
        loadHistory(currentPage);
      }
    } catch (e) { toast(e.message || 'Error', 'error'); }
  }

  /* ── Informe ────────────────────────────────────────────────────────────── */
  async function showReport(dbId) {
    try {
      var data = await window.EMD.fetchJSON('/api/report/' + dbId);
      renderReportModal(data);
    } catch (e) { toast('Error al generar el informe: ' + e.message, 'error'); }
  }

  function renderReportModal(r) {
    var auth = r.authentication || {};
    var iocSection = function (title, items, fn) {
      if (!items || !items.length) return '';
      return '<div class="mt-1"><strong class="muted text-sm">' + title + ':</strong>' + items.map(fn).join('') + '</div>';
    };
    var urlsHtml = iocSection('URLs', r.indicators && r.indicators.urls,
      function (u) { return '<div class="ioc-row">🔗 ' + escapeHtml(u) + '</div>'; });
    var hashesHtml = iocSection('Hashes', r.indicators && r.indicators.attachment_hashes,
      function (h) { return '<div class="ioc-row"><code>' + escapeHtml(h.sha256 || '-') + '</code> ' + escapeHtml(h.filename) + '</div>'; });
    var domainsHtml = iocSection('Dominios', r.indicators && r.indicators.domains,
      function (d) { return '<div class="ioc-row">🌐 ' + escapeHtml(d) + '</div>'; });

    var html =
      '<div class="detail-summary" style="border-left-color:' + (r.prediction === 'MALICIOSO' ? '#f0647a' : '#3ddc97') + '">' +
        '<div class="row-between"><div>' +
          '<div class="strong">' + escapeHtml(r.file) + '</div>' +
          '<div class="muted text-sm">' + escapeHtml(r.subject) + '</div>' +
          '<div class="faint text-sm">De: ' + escapeHtml(r.from) + ' · ' + (r.timestamp || '').slice(0, 10) + '</div>' +
        '</div><div class="text-right">' +
          '<span class="risk-badge ' + (r.prediction === 'MALICIOSO' ? 'pred-malicioso' : 'pred-benigno') + '">' + escapeHtml(r.prediction) + '</span><br>' +
          '<span class="risk-badge risk-' + escapeHtml(r.risk_level) + '">' + escapeHtml(r.risk_level) + ' — ' + r.risk_score + '%</span>' +
        '</div></div>' +
      '</div>' +
      renderAuthSection(auth.results, auth.summary, r.auth_analysis, auth.headers, auth) +
      renderClickfixSection(r.clickfix) +
      '<div class="detail-section"><h4>🛡️ VirusTotal</h4><div class="text-sm">' +
        'Archivos maliciosos: <strong>' + ((r.virustotal || {}).malicious_files || 0) + '</strong><br>' +
        'URLs maliciosas: <strong>' + ((r.virustotal || {}).malicious_urls || 0) + '</strong><br>' +
        'Consultas: ' + ((r.virustotal || {}).total_checked || 0) +
      '</div></div>' +
      '<div class="detail-section"><h4>🔗 Indicadores (IoCs)</h4>' +
        (urlsHtml + hashesHtml + domainsHtml || '<span class="faint text-sm">Sin indicadores extraídos</span>') +
      '</div>' +
      '<div class="detail-section"><h4>📊 ML & Riesgo</h4><div class="detail-grid">' +
        detailItem('Modelo', escapeHtml(r.model)) +
        detailItem('Confianza ML', (r.ml_confidence) + '%') +
        detailItem('Riesgo', r.risk_score + '% (' + escapeHtml(r.risk_level) + ')') +
        detailItem('Adjuntos', r.attachment_count) +
        detailItem('URLs', r.url_count) +
        detailItem('QRs', r.qr_count) +
      '</div></div>' +
      '<div class="row mt-2" style="justify-content:flex-end">' +
        '<button class="btn btn-secondary btn-sm" data-modal-close="reportModal">Cerrar</button>' +
        '<button class="btn btn-primary btn-sm" data-action="download-report" data-id="' + currentDbId + '">📥 Descargar JSON</button>' +
      '</div>';

    $('reportBody').innerHTML = html;
    window.EMD.openModal('reportModal');
  }

  async function downloadReportJSON(dbId) {
    try {
      var data = await window.EMD.fetchJSON('/api/report/' + dbId);
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'reporte_' + (data.file || 'correo').replace(/\.eml$/, '') + '.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast('Error: ' + e.message, 'error'); }
  }

  async function recheckVT(dbId, btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Consultando...';
    try {
      var data = await window.EMD.fetchJSON('/analyze/virustotal/' + dbId, { method: 'POST' });
      if (data.success && _store[dbId]) _store[dbId].virustotal = data.virustotal;
    } catch (e) { toast('Error al consultar VirusTotal', 'error'); }
    btn.disabled = false;
    btn.textContent = '🔍 Volver a consultar VirusTotal';
  }

  /* ── Subida y análisis ──────────────────────────────────────────────────── */
  var uploadZone = $('uploadZone');
  var fileInput = $('fileInput');
  var analyzeBtn = $('analyzeBtn');

  if (uploadZone && fileInput) {
    uploadZone.addEventListener('click', function () { fileInput.click(); });
    uploadZone.addEventListener('dragover', function (e) { e.preventDefault(); uploadZone.classList.add('dragover'); });
    uploadZone.addEventListener('dragleave', function () { uploadZone.classList.remove('dragover'); });
    uploadZone.addEventListener('drop', function (e) {
      e.preventDefault();
      uploadZone.classList.remove('dragover');
      selectedFiles = Array.from(e.dataTransfer.files).filter(function (f) { return f.name.endsWith('.eml'); });
      updateFileList();
    });
    fileInput.addEventListener('change', function () {
      selectedFiles = Array.from(fileInput.files);
      updateFileList();
    });
  }

  function updateFileList() {
    analyzeBtn.disabled = selectedFiles.length === 0;
    analyzeBtn.textContent = 'Analizar ' + selectedFiles.length + ' archivo(s)';
  }

  async function analyzeFiles() {
    if (!selectedFiles.length) return;
    var spinner = $('analyzeSpinner');
    var resultsDiv = $('results');
    var useVT = $('useVT').checked;
    spinner.classList.remove('hidden');
    analyzeBtn.disabled = true;
    resultsDiv.innerHTML = '';

    var CONCURRENCY = 3;
    var queue = selectedFiles.slice();
    var processed = 0;

    async function processOne(file) {
      var formData = new FormData();
      formData.append('files', file);
      formData.append('use_virustotal', useVT);
      try {
        var resp = await fetch('/analyze', { method: 'POST', body: formData });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var data = await resp.json();
        (data.results || []).forEach(function (res) {
          resultsDiv.insertAdjacentHTML('beforeend', renderCard(res));
        });
      } catch (err) {
        resultsDiv.insertAdjacentHTML('beforeend', renderCard({
          error: err.message, file: file.name, prediction: 'ERROR', risk_level: '-', risk_score: 0
        }));
      }
      processed++;
      analyzeBtn.textContent = 'Analizando... ' + processed + '/' + selectedFiles.length;
    }

    while (queue.length > 0) {
      var batch = queue.splice(0, CONCURRENCY);
      await Promise.all(batch.map(processOne));
    }

    updateStats();
    spinner.classList.add('hidden');
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analizar ' + selectedFiles.length + ' archivo(s)';
  }

  function renderCard(r) {
    if (r.error) return '<div class="result-card">❌ ' + escapeHtml(r.error) + '</div>';
    var rl = nl(r.risk_level || '');
    var ea = r.entropy_analysis || {};
    var lc = lcMap[rl] || '';
    if (r._db_id && r.metadata) _store[String(r._db_id)] = r;
    var dbId = r._db_id;
    var cardAttr = dbId ? ' data-card-id="' + dbId + '"' : '';
    var reportBtn = dbId ? '<button class="btn btn-secondary btn-sm" data-action="report" data-id="' + dbId + '">📄 Informe</button>' : '';
    return '<div class="result-card ' + lc + '"' + cardAttr + '>' +
      '<div class="row-between">' +
        '<div><strong>' + escapeHtml(r.file || '') + '</strong><br><small class="muted">' + escapeHtml(r.subject || '-') + '</small></div>' +
        '<div class="text-right"><span class="risk-badge ' + (r.prediction === 'MALICIOSO' ? 'pred-malicioso' : 'pred-benigno') + '">' + escapeHtml(r.prediction) + ' — ' + escapeHtml(r.risk_level) + '</span><br><small>Riesgo: ' + (r.risk_score) + '%</small></div>' +
      '</div>' +
      '<div class="entropy-grid">' +
        entropyBar('Cuerpo', ea.body_entropy) +
        entropyBar('URL', ea.url_entropy_max) +
        entropyBar('Adj', ea.attachment_content_entropy_max) +
      '</div>' +
      '<div class="row mt-1"><small class="faint">🔍 Clic para ver detalle</small>' + reportBtn + '</div>' +
      '</div>';
  }

  function entropyBar(label, value) {
    var v = value || 0;
    return '<div><small class="muted">' + label + ': ' + v + '</small>' +
      '<div class="entropy-bar"><div class="entropy-fill" style="width:' + ew(v) + '%;background:' + ec(v) + '"></div></div></div>';
  }

  /* ── Fechas / buzón ─────────────────────────────────────────────────────── */
  function fmt(d) { return d.toISOString().split('T')[0]; }

  (function initDates() {
    var today = new Date();
    var week = new Date(today); week.setDate(today.getDate() - 7);
    if ($('dateFrom')) $('dateFrom').value = fmt(week);
    if ($('dateTo')) $('dateTo').value = fmt(today);
  })();

  function setQuick(days) {
    var today = new Date();
    var from = new Date(today); from.setDate(today.getDate() - days + 1);
    if ($('dateFrom')) $('dateFrom').value = fmt(from);
    if ($('dateTo')) $('dateTo').value = fmt(today);
  }

  async function fetchEmails() {
    var spinner = $('fetchSpinner');
    var rd = $('fetchResult');
    spinner.classList.remove('hidden');
    rd.innerHTML = '';
    try {
      var data = await window.EMD.fetchJSON('/fetch-emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: $('provider').value,
          folder: $('folder').value,
          max_emails: $('maxEmails').value,
          use_virustotal: $('fetchVT').checked,
          date_from: $('dateFrom').value,
          date_to: $('dateTo').value
        })
      });
      if (data.success) {
        var html = '<div class="result-card bajo">✅ Descargados: <strong>' + data.downloaded +
          '</strong> | Analizados: <strong>' + data.analyzed + '</strong>' +
          (data.errors > 0 ? ' | ⚠️ Errores: ' + data.errors : '') +
          ' <small class="faint">Clic en un resultado para ver el detalle</small></div>';
        (data.results || []).forEach(function (r) { html += renderCard(r); });
        rd.innerHTML = html;
        updateStats();
      } else {
        rd.innerHTML = '<div class="result-card critico">❌ Error: ' + escapeHtml(data.error) + '</div>';
      }
    } catch (err) {
      var msg = err.message;
      if (msg && (msg.includes('JSON') || msg.includes('token') || msg.includes('HTTP'))) {
        msg = 'El servidor tardó demasiado o devolvió una respuesta inválida. Reduce el número de correos o el rango de fechas.';
      }
      rd.innerHTML = '<div class="result-card critico">❌ Error: ' + escapeHtml(msg) + '</div>';
    }
    spinner.classList.add('hidden');
  }

  /* ── Delegación global de acciones ──────────────────────────────────────── */
  document.addEventListener('click', function (ev) {
    var actionEl = ev.target.closest('[data-action]');
    if (actionEl) {
      var action = actionEl.getAttribute('data-action');
      var id = actionEl.getAttribute('data-id');
      if (action === 'report') { ev.stopPropagation(); showReport(id); return; }
      if (action === 'feedback') { doFeedback(id, parseInt(actionEl.getAttribute('data-label'), 10)); return; }
      if (action === 'recheck-vt') { recheckVT(id, actionEl); return; }
      if (action === 'download-report') { downloadReportJSON(id); return; }
      if (action === 'quick') { setQuick(parseInt(actionEl.getAttribute('data-days'), 10)); return; }
      if (action === 'fetch-emails') { fetchEmails(); return; }
      if (action === 'clear-history') { clearHistory(); return; }
      if (action === 'page') {
        changePage(actionEl.getAttribute('data-page') === 'prev' ? currentPage - 1 : currentPage + 1);
        return;
      }
      return;
    }

    var row = ev.target.closest('tr[data-id]');
    if (row) { openDetail(row.getAttribute('data-id')); return; }
    var card = ev.target.closest('[data-card-id]');
    if (card) { openDetail(card.getAttribute('data-card-id')); }
  });

  /* ── Gráfica ────────────────────────────────────────────────────────────── */
  (async function loadChart() {
    try {
      var d = await window.EMD.fetchJSON('/api/stats/trend');
      var ctx = $('trendChart');
      if (!ctx || typeof Chart === 'undefined') return;
      var css = getComputedStyle(document.documentElement);
      var cMuted = css.getPropertyValue('--text-muted').trim() || '#a9b3cc';
      var cFaint = css.getPropertyValue('--text-faint').trim() || '#6f7a99';
      var cDanger = css.getPropertyValue('--danger').trim() || '#f0647a';
      var cSuccess = css.getPropertyValue('--success').trim() || '#3ddc97';
      var grid = 'rgba(120,130,160,0.18)';
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: d.labels.map(function (l) { return l.slice(5); }),
          datasets: [
            { label: 'Maliciosos', data: d.malicious, backgroundColor: cDanger, borderRadius: 4 },
            { label: 'Benignos', data: d.benign, backgroundColor: cSuccess, borderRadius: 4 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: cMuted, boxWidth: 12 } } },
          scales: {
            x: { ticks: { color: cFaint, maxTicksLimit: 15 }, grid: { color: grid } },
            y: { beginAtZero: true, ticks: { color: cFaint, stepSize: 1 }, grid: { color: grid } }
          }
        }
      });
    } catch (e) { /* silencioso */ }
  })();

  loadHistory(1);
})();
