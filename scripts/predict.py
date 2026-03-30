#!/usr/bin/env python3
"""
predict.py — Ensemble de todos los modelos habilitados, ponderado por AUC.
Lee DISABLED_MODELS de config/.env para excluir modelos.
"""

import sys, os, json, argparse
import numpy as np, joblib
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from extract_features import extract_features_from_eml
from virustotal import check_email_artifacts

# ── Anti-Clanker (Modelo 10) ─────────────────────────────────────────────────
import sys as _sys_clk
import os as _os_clk
_sys_clk.path.insert(0, _os_clk.path.join(_os_clk.path.dirname(__file__)))
try:
    from extract_clanker_features import extract_clanker_features, get_clanker_score
    _CLANKER_AVAILABLE = True
except ImportError:
    _CLANKER_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────


PROJECT_DIR    = os.path.join(os.path.dirname(__file__), "..")
MODEL_PATH     = os.path.join(PROJECT_DIR, "models", "email_classifier.joblib")
METADATA_PATH  = os.path.join(PROJECT_DIR, "models", "model_metadata.json")
ALL_MODELS_DIR = os.path.join(PROJECT_DIR, "models", "all_models")
ENV_PATH       = os.path.join(PROJECT_DIR, "config", ".env")
RESULTS_DIR    = os.path.join(PROJECT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def get_disabled_models():
    disabled = set()
    try:
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH) as f:
                for line in f:
                    if line.strip().startswith("DISABLED_MODELS="):
                        val = line.strip().split("=", 1)[1].strip()
                        if val:
                            disabled = {m.strip() for m in val.split(",") if m.strip()}
    except Exception:
        pass
    return disabled


def load_all_models(metadata):
    available = metadata.get("models_available", [])
    disabled  = get_disabled_models()
    loaded    = {}
    if os.path.isdir(ALL_MODELS_DIR):
        for name in available:
            if name in disabled:
                print(f"   SKIP: {name} (deshabilitado)")
                continue
            path = os.path.join(ALL_MODELS_DIR, f"{name}.joblib")
            if os.path.exists(path):
                try:
                    loaded[name] = joblib.load(path)
                except Exception as e:
                    print(f"   WARN: {name}: {e}")
    if not loaded and os.path.exists(MODEL_PATH):
        active = [n for n in available if n not in disabled]
        name   = active[0] if active else available[0]
        loaded[name] = joblib.load(MODEL_PATH)
    return loaded


def ensemble_predict(models_dict, features, metadata):
    results_meta  = metadata.get("results", {})
    feature_names = metadata.get("feature_names", [])
    weighted      = np.zeros(2)
    total_w       = 0.0
    individual    = {}
    for name, model in models_dict.items():
        try:
            X      = np.array([[features.get(fn, 0) for fn in feature_names]])
            proba  = model.predict_proba(X)[0]
            weight = results_meta.get(name, {}).get("auc_test", 0.5)
            weighted += proba * weight
            total_w  += weight
            individual[name] = {
                "prob_malicious": round(float(proba[1]) * 100, 2),
                "prob_benign":    round(float(proba[0]) * 100, 2),
                "auc_weight":     round(weight, 4),
            }
        except Exception as e:
            individual[name] = {"error": str(e)}
    if total_w > 0:
        weighted /= total_w
    return weighted, individual


def predict_email(eml_path, use_virustotal=True):
    print(f"\n Analizando: {os.path.basename(eml_path)}")
    features, meta_eml = extract_features_from_eml(eml_path)

    if not os.path.exists(METADATA_PATH):
        return {"error": "Modelo no encontrado. Ejecuta train_model.py", "features": features}

    with open(METADATA_PATH) as f:
        model_meta = json.load(f)

    threshold   = model_meta.get("threshold", 0.5)
    models_dict = load_all_models(model_meta)
    n_models    = len(models_dict)

    if n_models == 0:
        return {"error": "No hay modelos habilitados. Habilita al menos uno en /training."}

    print(f"   Modelos activos: {n_models} ({', '.join(models_dict.keys())})")
    proba, individual = ensemble_predict(models_dict, features, model_meta)
    ml_pred = "MALICIOSO" if proba[1] >= threshold else "BENIGNO"

    vt_results = None
    if use_virustotal:
        vt_results = check_email_artifacts(
            attachment_hashes=meta_eml.get("attachment_hashes", []),
            urls=meta_eml.get("urls_found", []),
            max_checks=6)

    vt_alert = bool(vt_results and (
        vt_results["summary"].get("malicious_files", 0) > 0 or
        vt_results["summary"].get("malicious_urls",  0) > 0))

    final = "MALICIOSO" if (ml_pred == "MALICIOSO" or vt_alert) else "BENIGNO"
    risk  = proba[1] * 100
    if vt_alert:
        risk = max(risk, 90)

    if   risk >= 80: level = "CRITICO"
    elif risk >= 60: level = "ALTO"
    elif risk >= 40: level = "MEDIO"
    elif risk >= 20: level = "BAJO"
    else:            level = "MINIMO"

    result = {
        "timestamp":         datetime.now().isoformat(),
        "file":              os.path.basename(eml_path),
        "subject":           meta_eml.get("subject", ""),
        "from":              meta_eml.get("from", ""),
        "prediction":        final,
        "risk_score":        round(risk, 2),
        "risk_level":        level,
        "ml_prediction":     ml_pred,
        "ml_confidence":     round(float(max(proba)) * 100, 2),
        "ml_prob_benign":    round(float(proba[0]) * 100, 2),
        "ml_prob_malicious": round(float(proba[1]) * 100, 2),
        "model_used":        f"Ensemble ({n_models} modelos activos)",
        "best_model":        model_meta.get("best_model", "unknown"),
        "ensemble_detail":   individual,
        "models_count":      n_models,
        "disabled_models":   list(get_disabled_models()),
        "entropy_analysis": {
            "body_entropy":                   features.get("body_entropy", 0),
            "subject_entropy":                features.get("subject_entropy", 0),
            "url_entropy_max":                features.get("url_entropy_max", 0),
            "attachment_content_entropy_max": features.get("attachment_content_entropy_max", 0),
        },
        "virustotal": vt_results,
        "features":   features,
        "metadata": {
            "urls_found":  meta_eml.get("urls_found", []),
            "attachments": meta_eml.get("attachments", []),
        },
    }
    print(f"   Resultado: {final}  Riesgo: {level} ({risk:.1f}%)")
    return result




def _clanker_predict(html_raw: str, weight: float = 0.1) -> dict:
    """Genera el voto del Modelo 10 Anti-Clanker para el ensemble."""
    if not _CLANKER_AVAILABLE or not html_raw:
        return {"model": "anti_clanker", "score": 0.0, "available": False}
    try:
        feats = extract_clanker_features(html_raw)
        score = feats.get("clanker_weighted_score", 0.0)
        return {
            "model": "anti_clanker",
            "score": score,
            "available": True,
            "features": feats,
            "weight": weight,
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Anti-Clanker predict error: %s", e)
        return {"model": "anti_clanker", "score": 0.0, "available": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("eml_path")
    parser.add_argument("--skip-vt", action="store_true")
    args   = parser.parse_args()
    result = predict_email(args.eml_path, use_virustotal=not args.skip_vt)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
