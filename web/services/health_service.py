#!/usr/bin/env python3
"""
health_service.py — Comprobación de dependencias para el endpoint /health.

Checks rápidos y sin red:
  - Conectividad SQLite (users.db)
  - Fichero del modelo principal
  - Reglas Anti-Clanker (YAML válido)
  - Navegador Chromium de Playwright (heurístico sobre el cache)
  - VirusTotal configurado (solo presencia de API key, no consume cuota)
"""

import os
import sqlite3
from datetime import datetime

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_DIR  = os.path.join(PROJECT_DIR, "config")
MODELS_DIR  = os.path.join(PROJECT_DIR, "models")
DB_PATH     = os.path.join(CONFIG_DIR, "users.db")
RULES_FILE  = os.path.join(CONFIG_DIR, "clanker_rules.yaml")
MODEL_FILE  = os.path.join(MODELS_DIR, "email_classifier.joblib")


def _check_sqlite():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=2)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def _check_model_file():
    if os.path.exists(MODEL_FILE):
        return True, os.path.basename(MODEL_FILE)
    return False, "no entrenado"


def _check_clanker_rules():
    if not os.path.exists(RULES_FILE):
        return False, "no encontrado"
    try:
        import yaml
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        n = len(data.get("rules", [])) if isinstance(data, dict) else 0
        return True, f"{n} reglas"
    except Exception as e:
        return False, str(e)


def _browser_dirs():
    candidates = []
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env:
        candidates.append(env)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(os.path.join(local, "ms-playwright"))
    candidates += [
        os.path.expanduser("~/.cache/ms-playwright"),
        "/ms-playwright",
        os.path.join(PROJECT_DIR, ".playwright"),
    ]
    return candidates


def _check_chromium():
    """Detección heurística del navegador Chromium de Playwright."""
    for directory in _browser_dirs():
        if not directory or not os.path.isdir(directory):
            continue
        try:
            for name in os.listdir(directory):
                if name.startswith("chromium"):
                    return True, name
        except OSError:
            continue
    return False, "no encontrado"


def _check_virustotal():
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    return bool(key), ("configurada" if key else "sin configurar")


_CHECKS = {
    "sqlite":               _check_sqlite,
    "model_file":           _check_model_file,
    "clanker_rules":        _check_clanker_rules,
    "playwright_chromium":  _check_chromium,
    "virustotal_configured": _check_virustotal,
}

# Dependencias que no afectan al estado global (features opcionales)
_OPTIONAL = {"playwright_chromium", "virustotal_configured"}


def check_dependencies():
    """Devuelve el estado de todas las dependencias."""
    checks = {}
    for name, fn in _CHECKS.items():
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, str(e)
        checks[name] = {
            "ok": bool(ok),
            "detail": detail,
            "optional": name in _OPTIONAL,
        }
    return {
        "ok": all(c["ok"] for c in checks.values() if not c["optional"]),
        "checks": checks,
        "checked_at": datetime.now().isoformat(),
    }


def summary():
    """Resumen booleano para incluir en /health."""
    deps = check_dependencies()
    return {name: c["ok"] for name, c in deps["checks"].items()}, deps["ok"]
