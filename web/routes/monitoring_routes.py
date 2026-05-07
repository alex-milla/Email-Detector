import os
import json
import time
from datetime import datetime, timedelta

from flask import request, jsonify, Response, session

from web.services.decorators import login_required
from web.services.history_service import get_history

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
MODELS_DIR = os.path.join(PROJECT_DIR, "models")


# ── Métricas Prometheus (soft import) ────────────────────────────────────────
try:
    from prometheus_client import generate_latest, Counter, Gauge, Histogram, CONTENT_TYPE_LATEST
    HAS_PROMETHEUS = True
    ANALYZE_COUNT = Counter("email_analyze_total", "Total de análisis realizados",
                            ["prediction", "risk_level"])
    MALICIOUS_GAUGE = Gauge("email_malicious_current", "Correos maliciosos en historial reciente")
    MODEL_AUC = Gauge("email_model_auc", "AUC del mejor modelo")
    MODEL_SAMPLES = Gauge("email_model_samples", "Muestras de entrenamiento")
except ImportError:
    HAS_PROMETHEUS = False
# ─────────────────────────────────────────────────────────────────────────────


def register_routes(app):

    @app.route("/metrics")
    def prometheus_metrics():
        if not HAS_PROMETHEUS:
            return jsonify({"error": "prometheus_client no instalado. pip install prometheus-client"}), 503
        uid = request.args.get("user_id")
        if not uid:
            try:
                from web.auth import get_db as _get_db
                conn = _get_db()
                uid = conn.execute("SELECT MIN(id) FROM users").fetchone()[0] or 1
                conn.close()
            except Exception:
                uid = 1
        history = get_history(uid)

        malicious = sum(1 for h in history if h.get("prediction") == "MALICIOSO")
        MALICIOUS_GAUGE.set(malicious)

        model_meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
        if os.path.exists(model_meta_path):
            try:
                with open(model_meta_path) as f:
                    meta = json.load(f)
                MODEL_AUC.set(meta.get("auc", 0))
                MODEL_SAMPLES.set(meta.get("total_samples", 0))
            except Exception:
                pass

        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.route("/api/webhook/siem", methods=["POST"])
    @login_required
    def webhook_siem():
        """Endpoint para SIEM externo. Recibe consultas en JSON estandarizado."""
        data = request.get_json(silent=True) or {}
        action = data.get("action", "status")

        if action == "status":
            return jsonify({
                "service": "email-malware-detector",
                "version": "2.0.0",
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
            })

        if action == "recent_alerts":
            limit = min(int(data.get("limit", 10)), 100)
            uid = data.get("user_id")
            if not uid:
                return jsonify({"error": "user_id requerido"}), 400
            history = get_history(uid)
            alerts = [h for h in history if h.get("prediction") == "MALICIOSO"]
            return jsonify({
                "total_alerts": len(alerts),
                "alerts": [
                    {
                        "timestamp": h.get("timestamp", ""),
                        "subject": h.get("subject", ""),
                        "from": h.get("from", ""),
                        "risk_score": h.get("risk_score", 0),
                        "risk_level": h.get("risk_level", ""),
                        "ml_confidence": h.get("ml_confidence", 0),
                    }
                    for h in alerts[:limit]
                ],
            })

        if action == "stats":
            model_meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
            meta = {}
            if os.path.exists(model_meta_path):
                with open(model_meta_path) as f:
                    meta = json.load(f)
            try:
                from web.auth import get_db as _get_db
                conn = _get_db()
                total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                conn.close()
            except Exception:
                total_users = 0
            return jsonify({
                "total_users": total_users,
                "model": meta.get("best_model", "none"),
                "model_auc": meta.get("auc", 0),
                "model_samples": meta.get("total_samples", 0),
                "anti_clanker": meta.get("anti_clanker_trained", False),
                "threshold": meta.get("threshold", 0.5),
            })

        return jsonify({"error": f"Acción desconocida: {action}"}), 400

    @app.route("/api/monitoring/status")
    @login_required
    def monitoring_status():
        """Dashboard de estado interno."""
        uid = request.args.get("user_id") or session.get("user_id")
        if not uid:
            return jsonify({"error": "user_id requerido"}), 400

        history = get_history(uid)
        total = len(history)
        malicious = sum(1 for h in history if h.get("prediction") == "MALICIOSO")
        recent_24h = sum(1 for h in history
                         if h.get("timestamp", "")[:10] >=
                         (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H"))

        model_meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
        meta = {}
        if os.path.exists(model_meta_path):
            with open(model_meta_path) as f:
                meta = json.load(f)

        drift_state_path = os.path.join(PROJECT_DIR, "results", "drift_state.json")
        drift = {}
        if os.path.exists(drift_state_path):
            with open(drift_state_path) as f:
                drift = json.load(f)

        audit_log_path = os.path.join(PROJECT_DIR, "logs", "audit.log")
        audit_lines = 0
        if os.path.exists(audit_log_path):
            with open(audit_log_path) as f:
                audit_lines = sum(1 for _ in f)

        return jsonify({
            "analyses": {
                "total": total,
                "malicious": malicious,
                "malicious_pct": round(malicious / max(total, 1) * 100, 1),
                "last_24h": recent_24h,
            },
            "model": {
                "best": meta.get("best_model", "none"),
                "auc": meta.get("auc", 0),
                "samples": meta.get("total_samples", 0),
                "features": len(meta.get("feature_names", [])),
                "threshold": meta.get("threshold", 0.5),
                "trained_at": meta.get("trained_at", "never"),
            },
            "drift": {
                "last_check": drift.get("last_check"),
                "psi": drift.get("last_result", {}).get("psi", 0),
                "drift_detected": drift.get("last_result", {}).get("drift_detected", False),
                "alerts_count": len(drift.get("alerts", [])),
            },
            "audit_log_entries": audit_lines,
            "timestamp": datetime.now().isoformat(),
        })
