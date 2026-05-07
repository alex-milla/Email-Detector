#!/usr/bin/env python3
"""
app.py — Entry point. Importa y registra blueprints.
"""

import os
import re
import sys
import json
import sqlite3
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session
)
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.dirname(__file__))

from predict import predict_email
from mailbox_connector import download_emails
from auth import (
    init_db, authenticate, create_user, delete_user,
    get_all_users, change_password, get_db,
    get_mail_config, save_mail_config, get_all_mail_configs
)
from settings_manager import (
    read_global_env, write_global_env,
    test_imap, test_virustotal, test_m365
)
from updater import check_for_updates, get_update_state, start_update

from web.services.history_service import get_model_meta
from web.services.limiter import limiter

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "config", ".env"))

app = Flask(__name__)
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY no está configurado. "
        "Define la variable de entorno SECRET_KEY en config/.env"
    )
app.secret_key = _secret_key

limiter.init_app(app)

EML_MAX_SIZE_BYTES = 10 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

EML_ALLOWED_MIMETYPES = {
    "message/rfc822",
    "text/plain",
    "application/octet-stream",
}

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
UPLOAD_DIR = os.path.join(PROJECT_DIR, "data", "samples")
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
MODELS_DIR = os.path.join(PROJECT_DIR, "models")
LABELED_DIR = os.path.join(PROJECT_DIR, "data", "labeled")
DB_PATH = os.path.join(PROJECT_DIR, "config", "users.db")

_has_ssl = os.path.exists(os.path.join(PROJECT_DIR, "config", "ssl", "cert.pem"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_has_ssl,
)


@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if _has_ssl:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self';"
    )
    return response


os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

init_db()


@app.route("/health")
def health():
    model_meta = get_model_meta()
    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "model_trained": os.path.exists(os.path.join(MODELS_DIR, "email_classifier.joblib")),
        "models_count": len(model_meta.get("models_available", [])),
        "timestamp": datetime.now().isoformat(),
    })


@app.errorhandler(413)
def upload_too_large(e):
    return jsonify({
        "error": f"La petición supera el límite de tamaño permitido ({app.config['MAX_CONTENT_LENGTH'] // 1024 // 1024} MB total)."
    }), 413


@app.errorhandler(429)
def ratelimit_handler(e):
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"error": "Demasiados intentos. Espera un minuto antes de volver a intentarlo."}), 429
    return render_template("login.html",
        error="Demasiados intentos fallidos. Espera un minuto antes de intentarlo de nuevo."), 429


@app.errorhandler(500)
def internal_error(e):
    app.logger.error("Error 500: %s", e)
    return jsonify({"error": "Error interno del servidor. Revisa los logs."}), 500


@app.errorhandler(502)
def bad_gateway(e):
    return jsonify({"error": "El servidor intermedio no respondió. Intenta con menos archivos."}), 502


@app.errorhandler(504)
def gateway_timeout(e):
    return jsonify({"error": "El servidor tardó demasiado. Intenta subir menos archivos a la vez."}), 504


# ── Anti-Clanker integration ─────────────────────────────────────────────────
import sys as _sys_ck
_sys_ck.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
try:
    from extract_clanker_features import (
        extract_clanker_features,
        get_rules_meta as clanker_rules_meta,
        get_rules_list as clanker_rules_list,
    )
    CLANKER_ENABLED = True
except ImportError:
    CLANKER_ENABLED = False
# ─────────────────────────────────────────────────────────────────────────────


# ── Registrar rutas desde módulos ───────────────────────────────────────────
from web.routes.auth_routes import register_routes as register_auth
from web.routes.analysis_routes import register_routes as register_analysis
from web.routes.settings_routes import register_routes as register_settings
from web.routes.model_routes import register_routes as register_model
from web.routes.clanker_routes import register_routes as register_clanker
from web.routes.update_routes import register_routes as register_update

register_auth(app)
register_analysis(app)
register_settings(app)
register_model(app)
register_clanker(app)
register_update(app)
# ─────────────────────────────────────────────────────────────────────────────


from web.services.decorators import login_required, admin_required
from web.services.csrf import inject_csrf

inject_csrf(app)


if __name__ == "__main__":
    host = os.getenv("WEB_HOST", "0.0.0.0")
    port = int(os.getenv("WEB_PORT", "5000"))
    print(f"\n{'='*50}\n Detector de Correos Maliciosos\n Accede en: http://{host}:{port}\n{'='*50}\n")
    app.run(host=host, port=port, debug=False)
