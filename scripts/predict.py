#!/usr/bin/env python3
"""
predict.py — Ensemble de todos los modelos habilitados, ponderado por AUC.
Lee DISABLED_MODELS de config/.env para excluir modelos.
"""

import sys, os, json, argparse, hashlib, logging
import numpy as np, joblib
from datetime import datetime

logger = logging.getLogger(__name__)

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


def _compute_checksum(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_checksums():
    checksum_path = os.path.join(PROJECT_DIR, "models", "model_checksums.json")
    if os.path.exists(checksum_path):
        try:
            with open(checksum_path) as f:
                return json.load(f)
        except (ValueError, OSError):
            return {}
    return {}


def load_all_models(metadata):
    available = metadata.get("models_available") or []
    disabled  = get_disabled_models()
    loaded    = {}
    checksums = _load_checksums()

    if not available:
        logger.warning(
            "model_metadata.json no define 'models_available'; "
            "se usará el modelo base si existe"
        )

    if os.path.isdir(ALL_MODELS_DIR):
        for name in available:
            if name in disabled:
                logger.info("SKIP: %s (deshabilitado)", name)
                continue
            path = os.path.join(ALL_MODELS_DIR, f"{name}.joblib")
            if os.path.exists(path):
                try:
                    rel = os.path.relpath(path, os.path.join(PROJECT_DIR, "models"))
                    expected = checksums.get(rel)
                    if expected:
                        actual = _compute_checksum(path)
                        if actual != expected:
                            logger.warning("%s: checksum inválido (posible manipulación)", name)
                            continue
                    loaded[name] = joblib.load(path)
                except Exception as e:
                    logger.warning("%s: %s", name, e)
    if not loaded and os.path.exists(MODEL_PATH):
        active = [n for n in available if n not in disabled]
        if active:
            name = active[0]
        elif available:
            name = available[0]
        else:
            name = "email_classifier"
        try:
            loaded[name] = joblib.load(MODEL_PATH)
        except Exception as e:
            logger.warning("Modelo base '%s': %s", name, e)
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


def _clanker_predict(html_raw: str, weight: float = 0.15) -> dict:
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
        logger.warning("Anti-Clanker predict error: %s", e)
        return {"model": "anti_clanker", "score": 0.0, "available": False}


def _get_auth_risk_weight():
    try:
        return max(0.0, min(2.0, float(os.getenv("AUTH_RISK_WEIGHT", "1.0"))))
    except (TypeError, ValueError):
        return 1.0


def _analyze_auth(auth_summary, ml_prob, threshold, vt_alert):
    """
    Complementa la detección con el resultado de SPF/DKIM/DMARC.

    Devuelve avisos y una penalización de riesgo. Solo promueve a
    MALICIOSO cuando ya hay indicios previos (VT o probabilidad ML
    elevada) y existe un fallo duro de autenticación.
    """
    summary = auth_summary or {}
    weight = _get_auth_risk_weight()
    warnings = []

    if not summary.get("present"):
        return {
            "present": False,
            "warnings": ["Sin cabeceras de autenticación (SPF/DKIM/DMARC)"],
            "risk_penalty": 0.0,
            "spf_fail": False,
            "dkim_fail": False,
            "dmarc_fail": False,
            "force_malicious": False,
        }

    spf = summary.get("spf", {}) or {}
    dkim = summary.get("dkim", {}) or {}
    dmarc = summary.get("dmarc", {}) or {}

    dmarc_fail = dmarc.get("result") in ("fail", "permerror", "softfail")
    spf_fail = spf.get("result") in ("fail", "softfail", "permerror")
    dkim_fail = dkim.get("result") in ("fail", "permerror")

    penalty = 0.0
    if dmarc_fail:
        penalty += 15.0
        warnings.append(f"DMARC no superado ({dmarc.get('result', 'fail')})")
    if spf_fail and dkim_fail:
        penalty += 10.0
        warnings.append("SPF y DKIM fallan simultáneamente")
    elif spf_fail or dkim_fail:
        penalty += 5.0
        method = "SPF" if spf_fail else "DKIM"
        warnings.append(f"{method} no superado")
    if not dmarc.get("present"):
        warnings.append("Sin verificación DMARC en las cabeceras")

    penalty *= weight
    already_suspicious = bool(vt_alert or ml_prob >= max(0.2, threshold * 0.5))
    force_malicious = bool(already_suspicious and (dmarc_fail or (spf_fail and dkim_fail)))

    return {
        "present": True,
        "warnings": warnings,
        "risk_penalty": round(penalty, 2),
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        "force_malicious": force_malicious,
    }


def _apply_clickfix(clickfix, final, risk):
    """Escala a MALICIOSO cuando ClickFix se detecta con alta confianza.

    Un ClickFix de alta confianza implica comando PowerShell ofuscado +
    vector de clipboard/Win+R + indicadores de payload: es concluyente.
    """
    if not clickfix or not clickfix.get("high_confidence"):
        return final, risk
    risk = min(100.0, max(float(risk), 90.0))
    if final != "MALICIOSO":
        final = "MALICIOSO"
    return final, risk


def predict_email(eml_path, use_virustotal=True):
    logger.info("Analizando: %s", os.path.basename(eml_path))
    features, meta_eml = extract_features_from_eml(eml_path)

    if not os.path.exists(METADATA_PATH):
        return {"error": "Modelo no encontrado. Ejecuta train_model.py", "features": features}

    try:
        with open(METADATA_PATH) as f:
            model_meta = json.load(f)
    except (ValueError, OSError):
        return {
            "error": "model_metadata.json ausente o corrupto. Reentrena el modelo.",
            "features": features,
        }

    threshold   = model_meta.get("threshold", 0.5)
    models_dict = load_all_models(model_meta)
    n_models    = len(models_dict)

    if n_models == 0:
        return {
            "error": "No hay modelos disponibles. Revisa models/model_metadata.json "
                     "(campo 'models_available') o entrena en /training."
        }

    logger.info("Modelos activos: %d (%s)", n_models, ", ".join(models_dict.keys()))
    proba, individual = ensemble_predict(models_dict, features, model_meta)
    ml_pred = "MALICIOSO" if proba[1] >= threshold else "BENIGNO"

    # ── Anti-Clanker (solo diagnóstico) ──────────────────────────────────────
    # Las features clanker_* ya están integradas en el vector de features
    # del ensemble. Este cálculo es solo para diagnóstico en la UI.
    clanker_result = _clanker_predict(meta_eml.get("body_html", ""))
    if clanker_result.get("available") and clanker_result.get("score", 0) > 0:
        logger.info("Anti-Clanker: score=%.3f", clanker_result["score"])
    # ─────────────────────────────────────────────────────────────────────────

    # ── ClickFix: indicadores originales del comando ofuscado ────────────────
    clickfix = meta_eml.get("clickfix") or {}
    if clickfix.get("clickfix_detected"):
        logger.info(
            "ClickFix: score=%.3f  alta_confianza=%s  IoCs=%d",
            clickfix.get("clickfix_score", 0),
            clickfix.get("high_confidence"),
            len(clickfix.get("payload_urls", []))
            + len(clickfix.get("payload_domains", []))
            + len(clickfix.get("payload_ips", [])),
        )
    # ─────────────────────────────────────────────────────────────────────────

    # URLs a consultar en VirusTotal: las del correo + las decodificadas
    # del payload ClickFix (el indicador original que el atacante oculta).
    vt_urls = list(meta_eml.get("urls_found", []))
    for url in clickfix.get("payload_urls", []):
        if url and url not in vt_urls:
            vt_urls.append(url)

    vt_results = None
    if use_virustotal:
        vt_results = check_email_artifacts(
            attachment_hashes=meta_eml.get("attachment_hashes", []),
            urls=vt_urls,
            max_checks=6)

    vt_alert = bool(vt_results and (
        vt_results["summary"].get("malicious_files", 0) > 0 or
        vt_results["summary"].get("malicious_urls",  0) > 0))

    final = "MALICIOSO" if (ml_pred == "MALICIOSO" or vt_alert) else "BENIGNO"
    risk  = proba[1] * 100
    if vt_alert:
        risk = max(risk, 90)

    # ── Autenticación (SPF/DKIM/DMARC): complementa la detección ──
    auth_analysis = _analyze_auth(
        meta_eml.get("auth_summary", {}),
        float(proba[1]), threshold, vt_alert,
    )
    if auth_analysis.get("risk_penalty"):
        risk = min(100.0, risk + auth_analysis["risk_penalty"])
    if auth_analysis.get("force_malicious") and final == "BENIGNO":
        final = "MALICIOSO"
    # ─────────────────────────────────────────────────────────────────

    # ── ClickFix: escalada a MALICIOSO si hay alta confianza ──
    final, risk = _apply_clickfix(clickfix, final, risk)
    # ─────────────────────────────────────────────────────────

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
        "anti_clanker":      clanker_result,
        "clickfix":          clickfix,
        "entropy_analysis": {
            "body_entropy":                   features.get("body_entropy", 0),
            "subject_entropy":                features.get("subject_entropy", 0),
            "url_entropy_max":                features.get("url_entropy_max", 0),
            "attachment_content_entropy_max": features.get("attachment_content_entropy_max", 0),
        },
        "virustotal": vt_results,
        "auth_analysis": auth_analysis,
        "features":   features,
        "metadata": {
            "urls_found":        meta_eml.get("urls_found", []),
            "attachments":       meta_eml.get("attachments", []),
            "attachment_hashes": meta_eml.get("attachment_hashes", []),
            "qr_codes_found":    meta_eml.get("qr_codes_found", []),
            "auth_results":      meta_eml.get("auth_results", []),
            "auth_summary":      meta_eml.get("auth_summary", {}),
            "raw_headers":       meta_eml.get("raw_headers", {}),
            "clickfix":          clickfix,
        },
    }
    logger.info("Resultado: %s  Riesgo: %s (%.1f%%)", final, level, risk)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("eml_path")
    parser.add_argument("--skip-vt", action="store_true")
    args   = parser.parse_args()
    result = predict_email(args.eml_path, use_virustotal=not args.skip_vt)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
