#!/usr/bin/env python3
"""
drift_monitor.py — Monitorea drift del modelo comparando distribuciones
de predicciones recientes vs históricas.

Uso:
    python scripts/drift_monitor.py
    python scripts/drift_monitor.py --alert  # envía notificación si hay drift
"""

import os
import sys
import json
import logging
import math
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
HISTORY_PATH = os.path.join(PROJECT_DIR, "results", "history.json")
METADATA_PATH = os.path.join(PROJECT_DIR, "models", "model_metadata.json")
DRIFT_STATE_PATH = os.path.join(PROJECT_DIR, "results", "drift_state.json")


def load_history():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return []


def load_model_meta():
    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH) as f:
            return json.load(f)
    return {}


def load_drift_state():
    if os.path.exists(DRIFT_STATE_PATH):
        with open(DRIFT_STATE_PATH) as f:
            return json.load(f)
    return {"baseline": {}, "last_check": None, "alerts": []}


def save_drift_state(state):
    os.makedirs(os.path.dirname(DRIFT_STATE_PATH), exist_ok=True)
    with open(DRIFT_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def compute_distribution(history, days=30):
    cutoff = datetime.now() - timedelta(days=days)
    recent = [h for h in history if h.get("timestamp", "")[:10] >= cutoff.strftime("%Y-%m-%d")]
    total = len(recent)
    if total == 0:
        return {"total": 0, "malicious_pct": 0, "avg_risk": 0, "sample_size": 0}
    malicious = sum(1 for h in recent if h.get("prediction") == "MALICIOSO")
    avg_risk = sum(h.get("risk_score", 0) for h in recent) / total
    return {
        "total": total,
        "malicious_pct": round(malicious / total * 100, 2),
        "avg_risk": round(avg_risk, 2),
        "sample_size": total,
    }


def check_psi(expected_dist, actual_dist, buckets=10):
    """Population Stability Index — mide cambio en distribución."""
    if expected_dist["total"] == 0 or actual_dist["total"] == 0:
        return 0
    e_pct = expected_dist["malicious_pct"] / 100
    a_pct = actual_dist["malicious_pct"] / 100
    if e_pct == 0:
        e_pct = 0.01
    if a_pct == 0:
        a_pct = 0.01
    psi = (a_pct - e_pct) * math.log(a_pct / e_pct)
    return round(abs(psi), 4)


def run_drift_check(alert=False):
    history = load_history()
    if len(history) < 10:
        logger.info("Historial insuficiente para drift (< 10 muestras)")
        return

    model_meta = load_model_meta()
    state = load_drift_state()

    recent_30d = compute_distribution(history, 30)
    recent_7d = compute_distribution(history, 7)

    baseline = state.get("baseline", {})
    if not baseline or recent_30d["total"] > baseline.get("total", 0) * 1.5:
        baseline = recent_30d
        state["baseline"] = baseline
        logger.info("Nueva baseline establecida: %d muestras", baseline["total"])

    psi = check_psi(baseline, recent_7d)
    drift_detected = psi > 0.1 and recent_7d["total"] >= 10

    result = {
        "timestamp": datetime.now().isoformat(),
        "psi": psi,
        "drift_detected": drift_detected,
        "baseline": baseline,
        "recent_7d": recent_7d,
        "recent_30d": recent_30d,
        "model": model_meta.get("best_model", "?"),
        "model_trained_at": model_meta.get("trained_at", "?"),
        "total_history": len(history),
    }

    if drift_detected:
        logger.warning("Drift detectado! PSI=%.4f (umbral=0.1)", psi)
        state["alerts"].append({
            "timestamp": datetime.now().isoformat(),
            "psi": psi,
            "baseline_malicious_pct": baseline["malicious_pct"],
            "recent_malicious_pct": recent_7d["malicious_pct"],
        })
        if len(state["alerts"]) > 20:
            state["alerts"] = state["alerts"][-20:]
    else:
        logger.info("Sin drift. PSI=%.4f", psi)

    state["last_check"] = datetime.now().isoformat()
    state["last_result"] = result
    save_drift_state(state)

    if alert and drift_detected:
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from notifier import notify_all
            drift_alert = {
                "file": "drift_monitor",
                "subject": f"Drift detectado (PSI={psi:.4f})",
                "from": "sistema",
                "prediction": "MALICIOSO",
                "risk_level": "ALTO",
                "risk_score": 80,
                "ml_confidence": 0,
                "timestamp": datetime.now().isoformat(),
                "metadata": {"urls_found": [], "attachments": []},
            }
            notify_all(drift_alert)
        except Exception as e:
            logger.error("Error enviando alerta drift: %s", e)

    return result


if __name__ == "__main__":
    alert = "--alert" in sys.argv
    result = run_drift_check(alert=alert)
    print(json.dumps(result, indent=2, ensure_ascii=False))
