#!/usr/bin/env python3
"""
app.py — Historial por usuario + menú corregido.
"""

import os
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
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.dirname(__file__))

from predict import predict_email
from mailbox_connector import download_emails
from auth import (
    init_db, authenticate, create_user, delete_user,
    get_all_users, change_password,
    get_mail_config, save_mail_config, get_all_mail_configs
)
from settings_manager import (
    read_global_env, write_global_env,
    test_imap, test_virustotal, test_m365
)

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "config", ".env"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave-temporal-cambiar-ahora")
CORS(app)

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
UPLOAD_DIR  = os.path.join(PROJECT_DIR, "data", "samples")
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
MODELS_DIR  = os.path.join(PROJECT_DIR, "models")
LABELED_DIR = os.path.join(PROJECT_DIR, "data", "labeled")
DB_PATH     = os.path.join(PROJECT_DIR, "config", "users.db")

os.makedirs(UPLOAD_DIR,  exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Estado global del entrenamiento (background) ──
_TRAINING_STATE_FILE = os.path.join(os.path.dirname(__file__), "..", "results", "training_state.json")

def _load_training_state():
    if os.path.exists(_TRAINING_STATE_FILE):
        with open(_TRAINING_STATE_FILE) as f:
            return json.load(f)
    return {"running": False, "success": None, "stdout": "", "stderr": "", "started_at": None, "ended_at": None}

def _save_training_state(state):
    with open(_TRAINING_STATE_FILE, "w") as f:
        json.dump(state, f)

_training_state = _load_training_state()
_training_state["running"] = False  # Al arrancar nunca está corriendo
_save_training_state(_training_state)

init_db()


# ══════════════════════════════════════════════════
#  HISTORIAL EN SQLITE (por usuario)
# ══════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def normalize_result(result):
    """Normaliza el resultado para evitar problemas con caracteres unicode en risk_level."""
    if not isinstance(result, dict):
        return result
    level_map = {
        "M\u00cdNIMO": "MINIMO", "MÍNIMO": "MINIMO", "MíNIMO": "MINIMO",
        "CR\u00cdTICO": "CRITICO", "CRÍTICO": "CRITICO", "CRíTICO": "CRITICO",
        "ALTO": "ALTO", "MEDIO": "MEDIO", "BAJO": "BAJO",
        "MINIMO": "MINIMO", "CRITICO": "CRITICO",
    }
    rl = result.get("risk_level", "")
    result["risk_level"] = level_map.get(rl, rl.upper().replace("Í","I").replace("Ó","O"))
    return result

def save_result(user_id, result):
    result = normalize_result(result)
    ea = result.get("entropy_analysis") or {}
    vt = result.get("virustotal") or {}
    vt_s = vt.get("summary") or {}
    conn = get_db()
    conn.execute("""
        INSERT INTO analysis_history
            (user_id, timestamp, filename, subject, from_addr,
             prediction, risk_score, risk_level, ml_prediction,
             body_entropy, url_entropy,
             vt_malicious_files, vt_malicious_urls, full_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id,
        result.get("timestamp", datetime.now().isoformat()),
        result.get("file", ""),
        result.get("subject", ""),
        result.get("from", ""),
        result.get("prediction", ""),
        result.get("risk_score", 0),
        result.get("risk_level", ""),
        result.get("ml_prediction", ""),
        ea.get("body_entropy", 0),
        ea.get("url_entropy_max", 0),
        vt_s.get("malicious_files", 0),
        vt_s.get("malicious_urls", 0),
        json.dumps(result, default=str),
    ))
    conn.commit()
    conn.close()


def get_history(user_id, limit=200):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, full_json FROM analysis_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT ?
    """, (user_id, limit)).fetchall()
    conn.close()
    results = []
    for r in rows:
        try:
            item = json.loads(r["full_json"])
            item["_db_id"] = r["id"]
            results.append(item)
        except Exception:
            pass
    return results


def get_history_page(user_id, page=1, per_page=25):
    offset = (page - 1) * per_page
    conn   = get_db()
    total  = conn.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    rows = conn.execute("""
        SELECT id, timestamp, filename, subject, prediction,
               risk_score, risk_level, body_entropy
        FROM analysis_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT ? OFFSET ?
    """, (user_id, per_page, offset)).fetchall()
    conn.close()
    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total + per_page - 1) // per_page),
        "items":    [dict(r) for r in rows],
    }


def get_history_item(user_id, db_id):
    conn = get_db()
    row = conn.execute(
        "SELECT full_json FROM analysis_history WHERE id = ? AND user_id = ?",
        (db_id, user_id)
    ).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["full_json"])
        except Exception:
            pass
    return None


def get_history_summary(user_id):
    conn = get_db()
    row = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN prediction='MALICIOSO' THEN 1 ELSE 0 END) as malicious
        FROM analysis_history WHERE user_id = ?
    """, (user_id,)).fetchone()
    conn.close()
    total     = row["total"] or 0 if row else 0
    malicious = row["malicious"] or 0 if row else 0
    return total, malicious, total - malicious


def clear_history(user_id):
    conn = get_db()
    conn.execute("DELETE FROM analysis_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_model_meta():
    p = os.path.join(MODELS_DIR, "model_metadata.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}


# ══════════════════════════════════════════════════
#  DECORADORES
# ══════════════════════════════════════════════════

def current_user():
    return {"id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("user_role")}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.method == "POST":
                return jsonify({"error": "No autenticado"}), 401
            return redirect(url_for("login"))
        if session.get("user_role") != "admin":
            if request.is_json or request.method == "POST":
                return jsonify({"error": "Acceso restringido a administradores", "admin_only": True}), 403
            return render_template("error.html",
                message="Acceso restringido a administradores"), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════
#  AUTENTICACIÓN
# ══════════════════════════════════════════════════


# ── ClamAV integration ──────────────────────────────────────────────────────
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
try:
    from clamav_scanner import (
        is_available as clamav_available,
        get_version  as clamav_version,
        get_db_info  as clamav_db_info,
        scan_file    as clamav_scan_file,
        scan_email_attachments,
        update_signatures as clamav_update,
    )
    CLAMAV_ENABLED = True
except ImportError:
    CLAMAV_ENABLED = False
# ─────────────────────────────────────────────────────────────────────────────


# ── Anti-Clanker integration ─────────────────────────────────────────────────
import sys as _sys_ck
_sys_ck.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
try:
    from extract_clanker_features import (
        extract_clanker_features,
        get_clanker_score,
        get_rules_meta  as clanker_rules_meta,
        get_rules_list  as clanker_rules_list,
    )
    CLANKER_ENABLED = True
except ImportError:
    CLANKER_ENABLED = False
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        user = authenticate(request.form.get("username", "").strip(),
                            request.form.get("password", ""))
        if user:
            session["user_id"]   = user["id"]
            session["username"]  = user["username"]
            session["user_role"] = user["role"]
            return redirect(request.args.get("next") or url_for("index"))
        error = "Usuario o contraseña incorrectos"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════
#  PÁGINAS
# ══════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    uid  = session["user_id"]
    total, malicious, benign = get_history_summary(uid)
    model_meta   = get_model_meta()
    model_exists = os.path.exists(os.path.join(MODELS_DIR, "email_classifier.joblib"))
    return render_template("index.html",
        total=total, malicious=malicious, benign=benign,
        model_exists=model_exists, model_meta=model_meta,
        user=current_user())


@app.route("/training")
@login_required
def training():
    model_meta   = get_model_meta()
    model_exists = os.path.exists(os.path.join(MODELS_DIR, "email_classifier.joblib"))
    benign_count = len(list(Path(os.path.join(LABELED_DIR, "benign")).glob("*.eml"))) \
                   if os.path.exists(os.path.join(LABELED_DIR, "benign")) else 0
    malicious_count = len(list(Path(os.path.join(LABELED_DIR, "malicious")).glob("*.eml"))) \
                      if os.path.exists(os.path.join(LABELED_DIR, "malicious")) else 0
    return render_template("training.html",
        model_exists=model_exists, model_meta=model_meta,
        benign_count=benign_count, malicious_count=malicious_count,
        user=current_user())


@app.route("/users")
@admin_required
def users():
    return render_template("users.html",
        users=get_all_users(),
        mail_configs=get_all_mail_configs(),
        user=current_user())


@app.route("/settings")
@login_required
def settings():
    uid = session["user_id"]
    return render_template("settings.html",
        config=get_mail_config(uid),
        global_cfg=read_global_env(),
        user=current_user())



# ══════════════════════════════════════════════════
#  FEEDBACK AL MODELO
# ══════════════════════════════════════════════════

@app.route("/feedback/<int:db_id>", methods=["POST"])
@login_required
def submit_feedback(db_id):
    """
    Guarda el feedback del usuario sobre un análisis.
    label: 0 = benigno, 1 = malicioso
    """
    import shutil
    data  = request.json or {}
    label = data.get("label")  # 0 o 1

    if label not in (0, 1):
        return jsonify({"error": "label debe ser 0 (benigno) o 1 (malicioso)"}), 400

    uid  = session["user_id"]
    item = get_history_item(uid, db_id)
    if not item:
        return jsonify({"error": "Análisis no encontrado"}), 404

    label_dir = os.path.join(PROJECT_DIR, "data", "labeled",
                             "benign" if label == 0 else "malicious")
    os.makedirs(label_dir, exist_ok=True)

    # Buscar el .eml en data/raw o data/samples
    eml_filename = item.get("file", "")
    labeled_path = None
    for search_dir in ["data/raw", "data/samples"]:
        candidate = os.path.join(PROJECT_DIR, search_dir, eml_filename)
        if os.path.exists(candidate):
            dest = os.path.join(label_dir, eml_filename)
            shutil.copy2(candidate, dest)
            labeled_path = dest
            break

    conn = get_db()

    # Eliminar feedback previo si existía (corrección)
    old = conn.execute(
        "SELECT labeled_path FROM feedback WHERE analysis_id=? AND user_id=?",
        (db_id, uid)
    ).fetchone()
    if old and old["labeled_path"] and os.path.exists(old["labeled_path"]):
        try:
            os.remove(old["labeled_path"])
        except Exception:
            pass
    conn.execute(
        "DELETE FROM feedback WHERE analysis_id=? AND user_id=?", (db_id, uid)
    )

    # Insertar nuevo feedback
    conn.execute("""
        INSERT INTO feedback
            (analysis_id, user_id, original_pred, corrected_label,
             eml_filename, labeled_path, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (
        db_id, uid,
        item.get("prediction", ""),
        label,
        eml_filename,
        labeled_path,
        datetime.now().isoformat()
    ))

    # Actualizar feedback_label en analysis_history
    conn.execute(
        "UPDATE analysis_history SET feedback_label=? WHERE id=? AND user_id=?",
        (label, db_id, uid)
    )
    conn.commit()
    conn.close()

    label_str = "BENIGNO" if label == 0 else "MALICIOSO"
    msg = f"Marcado como {label_str}"
    if labeled_path:
        msg += " y copiado a data/labeled"
    else:
        msg += " (archivo .eml no encontrado, solo registrado)"

    return jsonify({"success": True, "message": msg, "label": label})


@app.route("/feedback/<int:db_id>", methods=["DELETE"])
@login_required
def delete_feedback(db_id):
    """Elimina el feedback de un análisis (deshace la corrección)."""
    import os as _os
    uid  = session["user_id"]
    conn = get_db()
    row  = conn.execute(
        "SELECT labeled_path FROM feedback WHERE analysis_id=? AND user_id=?",
        (db_id, uid)
    ).fetchone()

    if row and row["labeled_path"] and _os.path.exists(row["labeled_path"]):
        try:
            _os.remove(row["labeled_path"])
        except Exception:
            pass

    conn.execute(
        "DELETE FROM feedback WHERE analysis_id=? AND user_id=?", (db_id, uid)
    )
    conn.execute(
        "UPDATE analysis_history SET feedback_label=NULL WHERE id=? AND user_id=?",
        (db_id, uid)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Feedback eliminado"})


@app.route("/feedback/stats")
@login_required
def feedback_stats():
    """Devuelve estadísticas de feedback pendiente de entrenar."""
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    benign    = conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE corrected_label=0"
    ).fetchone()[0]
    malicious = conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE corrected_label=1"
    ).fetchone()[0]
    conn.close()
    return jsonify({
        "total":     total,
        "benign":    benign,
        "malicious": malicious,
    })

# ══════════════════════════════════════════════════
#  API — ANÁLISIS
# ══════════════════════════════════════════════════

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    if "files" not in request.files:
        return jsonify({"error": "No se subieron archivos"}), 400
    files  = request.files.getlist("files")
    use_vt = request.form.get("use_virustotal", "true") == "true"
    uid    = session["user_id"]
    results = []
    for file in files:
        if file.filename and file.filename.endswith(".eml"):
            safe_name = secure_filename(file.filename)
            filepath  = os.path.join(UPLOAD_DIR, safe_name)
            file.save(filepath)
            try:
                result = predict_email(filepath, use_virustotal=use_vt)
                result["analyzed_by"] = session.get("username")
                save_result(uid, result)
                results.append(result)
            except Exception as e:
                results.append({"error": str(e), "file": safe_name})
    return jsonify({"results": results, "total_analyzed": len(results)})


@app.route("/fetch-emails", methods=["POST"])
@login_required
def fetch_emails():
    from datetime import datetime as dt
    uid        = session["user_id"]
    cfg        = get_mail_config(uid)
    provider   = request.json.get("provider", cfg.get("default_provider", "imap"))
    max_emails = int(request.json.get("max_emails", 20))
    folder     = request.json.get("folder", "inbox")
    use_vt     = request.json.get("use_virustotal", False)

    # Rango de fechas (con fallback a days_back)
    date_from = date_to = None
    days_back = 7
    raw_from  = request.json.get("date_from")
    raw_to    = request.json.get("date_to")
    if raw_from:
        try:
            date_from = dt.strptime(raw_from, "%Y-%m-%d")
            date_to   = dt.strptime(raw_to, "%Y-%m-%d") if raw_to else dt.now()
        except ValueError:
            pass
    else:
        days_back = int(request.json.get("days_back", 7))

    env_map = {
        "imap":  {"IMAP_SERVER": cfg["imap_server"], "IMAP_PORT": cfg["imap_port"],
                  "IMAP_USER": cfg["imap_user"], "IMAP_PASSWORD": cfg["imap_password"]},
        "m365":  {"MS365_CLIENT_ID": cfg["ms365_client_id"],
                  "MS365_CLIENT_SECRET": cfg["ms365_client_secret"],
                  "MS365_TENANT_ID": cfg["ms365_tenant_id"],
                  "MS365_USER_EMAIL": cfg["ms365_user_email"]},
        "gmail": {"GMAIL_CLIENT_ID": cfg["gmail_client_id"],
                  "GMAIL_CLIENT_SECRET": cfg["gmail_client_secret"]},
    }
    backup = {}
    for k, v in env_map.get(provider, {}).items():
        backup[k] = os.environ.get(k, "")
        os.environ[k] = v

    try:
        downloaded = download_emails(provider, max_emails, days_back,
                                       folder=folder, date_from=date_from, date_to=date_to)

        # Analizar automáticamente cada correo descargado
        results  = []
        analyzed = 0
        errors   = 0
        for filepath in downloaded:
            try:
                result = predict_email(filepath, use_virustotal=use_vt)
                result["analyzed_by"] = session.get("username")
                save_result(uid, result)
                results.append({
                    "file":       result.get("file"),
                    "subject":    result.get("subject", ""),
                    "prediction": result.get("prediction"),
                    "risk_level": result.get("risk_level"),
                    "risk_score": result.get("risk_score"),
                })
                analyzed += 1
            except Exception as e:
                errors += 1

        return jsonify({
            "success":    True,
            "downloaded": len(downloaded),
            "analyzed":   analyzed,
            "errors":     errors,
            "results":    results,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        for k, v in backup.items():
            os.environ[k] = v


@app.route("/history")
@login_required
def history():
    return jsonify(get_history(session["user_id"]))



@app.route("/history/page/<int:page>")
@login_required
def history_page(page):
    data = get_history_page(session["user_id"], page=page, per_page=25)
    return jsonify(data)


@app.route("/analyze/virustotal/<int:db_id>", methods=["POST"])
@login_required
def analyze_virustotal(db_id):
    """Envía los artefactos de un correo ya analizado a VirusTotal."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    from virustotal import check_email_artifacts

    item = get_history_item(session["user_id"], db_id)
    if not item:
        return jsonify({"error": "Análisis no encontrado"}), 404

    metadata = item.get("metadata") or {}
    vt_results = check_email_artifacts(
        attachment_hashes=metadata.get("attachment_hashes", []),
        urls=metadata.get("urls_found", []),
        max_checks=8
    )

    # Actualizar el full_json con los resultados de VT
    item["virustotal"] = vt_results
    conn = get_db()
    conn.execute(
        "UPDATE analysis_history SET full_json = ? WHERE id = ? AND user_id = ?",
        (json.dumps(item, default=str), db_id, session["user_id"])
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "virustotal": vt_results})

@app.route("/history/<int:db_id>")
@login_required
def history_detail(db_id):
    item = get_history_item(session["user_id"], db_id)
    if item:
        return jsonify(item)
    return jsonify({"error": "No encontrado"}), 404


@app.route("/history/clear", methods=["POST"])
@login_required
def history_clear():
    clear_history(session["user_id"])
    return jsonify({"success": True})


# ══════════════════════════════════════════════════
#  API — CONFIGURACIÓN
# ══════════════════════════════════════════════════

@app.route("/api/settings/mail", methods=["POST"])
@login_required
def api_save_mail():
    save_mail_config(session["user_id"], request.json or {})
    return jsonify({"success": True})


@app.route("/api/settings/global", methods=["POST"])
@admin_required
def api_save_global():
    write_global_env(request.json or {})
    load_dotenv(os.path.join(PROJECT_DIR, "config", ".env"), override=True)
    return jsonify({"success": True})


@app.route("/api/settings/test", methods=["POST"])
@login_required
def api_test_connection():
    data     = request.json or {}
    provider = data.get("provider")
    cfg = get_mail_config(session["user_id"])
    if provider == "imap":
        ok, msg = test_imap(
            data.get("server",   cfg.get("imap_server", "")),
            data.get("port",     cfg.get("imap_port", "993")),
            data.get("user",     cfg.get("imap_user", "")),
            data.get("password", cfg.get("imap_password", ""))
        )
    elif provider == "virustotal":
        ok, msg = test_virustotal(data.get("api_key", ""))
    elif provider == "m365":
        ok, msg = test_m365(
            data.get("client_id",     cfg.get("ms365_client_id", "")),
            data.get("client_secret", cfg.get("ms365_client_secret", "")),
            data.get("tenant_id",     cfg.get("ms365_tenant_id", ""))
        )
    else:
        return jsonify({"success": False, "message": "Proveedor desconocido"}), 400
    return jsonify({"success": ok, "message": msg})


# ══════════════════════════════════════════════════
#  API — USUARIOS
# ══════════════════════════════════════════════════

@app.route("/api/users", methods=["POST"])
@admin_required
def api_create_user():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "user")
    if not username or not password:
        return jsonify({"success": False, "error": "Usuario y contraseña requeridos"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Mínimo 6 caracteres"}), 400
    ok, msg = create_user(username, password, role)
    return jsonify({"success": ok, "error": msg if not ok else None})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_delete_user(user_id):
    if user_id == session["user_id"]:
        return jsonify({"success": False, "error": "No puedes eliminarte a ti mismo"}), 400
    delete_user(user_id)
    return jsonify({"success": True})


@app.route("/api/users/<int:user_id>/password", methods=["POST"])
@login_required
def api_change_password(user_id):
    if session["user_id"] != user_id and session.get("user_role") != "admin":
        return jsonify({"success": False, "error": "Sin permisos"}), 403
    pwd = request.json.get("password", "")
    if len(pwd) < 6:
        return jsonify({"success": False, "error": "Mínimo 6 caracteres"}), 400
    change_password(user_id, pwd)
    return jsonify({"success": True})


# ══════════════════════════════════════════════════
#  API — MODELO (compartido, solo admin entrena)
# ══════════════════════════════════════════════════

@app.route("/model/info")
@login_required
def model_info():
    meta = get_model_meta()
    return jsonify(meta) if meta else (jsonify({"error": "No hay modelo"}), 404)


@app.route("/dataset/download", methods=["POST"])
@admin_required
def dataset_download():
    script = os.path.join(PROJECT_DIR, "download_dataset.sh")
    if not os.path.exists(script):
        return jsonify({"error": "No se encuentra download_dataset.sh"}), 404
    try:
        result = subprocess.run(["bash", script], capture_output=True,
                                text=True, timeout=600, cwd=PROJECT_DIR)
        return jsonify({"success": result.returncode == 0,
                        "stdout": result.stdout[-3000:], "stderr": result.stderr[-1000:]})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _run_training(cmd, cwd):
    """Ejecuta el entrenamiento en un proceso separado."""
    state = {"running": True, "success": None, "stdout": "", "stderr": "",
             "started_at": datetime.now().isoformat(), "ended_at": None}
    _save_training_state(state)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        state["success"] = result.returncode == 0
        state["stdout"]  = result.stdout[-5000:]
        state["stderr"]  = result.stderr[-1000:]
    except Exception as e:
        state["success"] = False
        state["stderr"]  = str(e)
    finally:
        state["running"]   = False
        state["ended_at"]  = datetime.now().isoformat()
        _save_training_state(state)


@app.route("/model/full-retrain", methods=["POST"])
def full_retrain():
    global _training_state
    if _training_state["running"]:
        return jsonify({"error": "Ya hay un entrenamiento en curso"}), 409
    script = os.path.join(PROJECT_DIR, "scripts", "retrain.sh")
    if not os.path.exists(script):
        return jsonify({"error": "No se encuentra scripts/retrain.sh"}), 404
    t = threading.Thread(
        target=_run_training,
        args=(["bash", script], PROJECT_DIR),
        daemon=True
    )
    t.start()
    return jsonify({"started": True, "message": "Entrenamiento iniciado en background"})


@app.route("/model/retrain", methods=["POST"])
def retrain():
    global _training_state
    if _training_state["running"]:
        return jsonify({"error": "Ya hay un entrenamiento en curso"}), 409
    cmd = [sys.executable, os.path.join(PROJECT_DIR, "scripts", "train_model.py")]
    t = threading.Thread(
        target=_run_training,
        args=(cmd, PROJECT_DIR),
        daemon=True
    )
    t.start()
    return jsonify({"started": True, "message": "Entrenamiento iniciado en background"})


@app.route("/model/training-status")
@login_required
def training_status():
    """Devuelve el estado actual del entrenamiento."""
    return jsonify(_load_training_state())




# TOGGLE DE MODELOS (admin) v1.2

@app.route("/api/models/toggle", methods=["GET"])
@admin_required
def api_models_toggle_get():
    meta      = get_model_meta()
    available = meta.get("models_available", [])
    results   = meta.get("results", {})
    env_path  = os.path.join(PROJECT_DIR, "config", ".env")
    disabled  = set()
    try:
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith("DISABLED_MODELS="):
                        val = line.strip().split("=", 1)[1].strip()
                        if val:
                            disabled = {m.strip() for m in val.split(",") if m.strip()}
    except Exception:
        pass
    models_info = [
        {"name": n, "enabled": n not in disabled,
         "auc_test": results.get(n, {}).get("auc_test"),
         "error":    results.get(n, {}).get("error")}
        for n in available
    ]
    models_info.sort(key=lambda x: x.get("auc_test") or 0, reverse=True)
    return jsonify({"models": models_info, "disabled": list(disabled)})


@app.route("/api/models/toggle", methods=["POST"])
@admin_required
def api_models_toggle_post():
    data     = request.get_json() or {}
    name     = data.get("name", "").strip()
    enabled  = data.get("enabled", True)
    if not name:
        return jsonify({"error": "Falta el campo name"}), 400
    env_path = os.path.join(PROJECT_DIR, "config", ".env")
    disabled = set()
    lines    = []
    try:
        if os.path.exists(env_path):
            with open(env_path) as f:
                lines = f.readlines()
        for line in lines:
            if line.strip().startswith("DISABLED_MODELS="):
                val = line.strip().split("=", 1)[1].strip()
                if val:
                    disabled = {m.strip() for m in val.split(",") if m.strip()}
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if enabled:
        disabled.discard(name)
    else:
        disabled.add(name)
    new_val   = ",".join(sorted(disabled))
    new_lines = []
    found     = False
    for line in lines:
        if line.strip().startswith("DISABLED_MODELS="):
            new_lines.append("DISABLED_MODELS=" + new_val + "\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append("DISABLED_MODELS=" + new_val + "\n")
    try:
        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "name": name, "enabled": enabled, "disabled": list(disabled)})



@app.route("/api/clamav/status", methods=["GET"])
@login_required
def clamav_status():
    if not CLAMAV_ENABLED: return jsonify({"enabled":False,"error":"pyclamd no instalado"}),503
    info = clamav_db_info()
    return jsonify({"enabled":True,"available":clamav_available(),
                    "version":info.get("version"),"updated_at":info.get("updated_at")})

@app.route("/api/clamav/update", methods=["POST"])
@login_required
@admin_required
def clamav_update_db():
    if not CLAMAV_ENABLED: return jsonify({"success":False,"error":"pyclamd no instalado"}),503
    result = clamav_update()
    return jsonify(result), 200 if result["success"] else 500

@app.route("/api/clamav/scan", methods=["POST"])
@login_required
def clamav_scan_manual():
    if not CLAMAV_ENABLED: return jsonify({"success":False,"error":"ClamAV no habilitado"}),503
    if not clamav_available():
        return jsonify({"success":False,"error":"clamd no disponible"}),503
    if "file" in request.files:
        uploaded = request.files["file"]
        import tempfile
        suffix = os.path.splitext(uploaded.filename or "file")[1] or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            uploaded.save(tmp.name); tmp_path = tmp.name
        try:
            result = clamav_scan_file(tmp_path)
            result["filename"] = uploaded.filename
        finally:
            try: os.unlink(tmp_path)
            except: pass
        return jsonify({"success":True,"results":[result]})
    data = request.get_json(silent=True) or {}
    return jsonify({"success":False,"error":"Se requiere 'file' o 'email_id'"}),400

@app.route("/api/clamav/results/<int:email_id>", methods=["GET"])
@login_required
def clamav_results_for_email(email_id):
    return jsonify({"email_id":email_id,"scanned":False,"results":[]})

@app.route("/api/user/role", methods=["GET"])
@login_required
def api_user_role():
    try: role = session.get("role","user")
    except: role = "user"
    return jsonify({"role":role})




@app.route("/api/clanker/status", methods=["GET"])
@login_required
def clanker_status():
    if not CLANKER_ENABLED:
        return jsonify({"enabled": False, "error": "extract_clanker_features no disponible"}), 503
    meta = clanker_rules_meta()
    rules = clanker_rules_list()
    active = sum(1 for r in rules if r.get("enabled", True))
    env_path = os.path.join(os.path.dirname(__file__), "..", "config", ".env")
    rules_url = ""
    try:
        with open(env_path) as f:
            for line in f:
                if line.startswith("CLANKER_RULES_URL="):
                    rules_url = line.split("=", 1)[1].strip()
                    break
    except Exception:
        pass
    return jsonify({
        "enabled": True,
        "rules_version": meta.get("version", "?"),
        "rules_updated": meta.get("updated_at", "?"),
        "total_rules": len(rules),
        "active_rules": active,
        "rules_url": rules_url,
    })

@app.route("/api/clanker/set_url", methods=["POST"])
@login_required
@admin_required
def clanker_set_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    env_path = os.path.join(os.path.dirname(__file__), "..", "config", ".env")
    try:
        with open(env_path, "r") as f:
            lines = f.readlines()
        new_lines = []
        found = False
        for line in lines:
            if line.startswith("CLANKER_RULES_URL="):
                new_lines.append("CLANKER_RULES_URL=" + url + chr(10))
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append("CLANKER_RULES_URL=" + url + chr(10))
        with open(env_path, "w") as f:
            f.writelines(new_lines)
        return jsonify({"success": True, "url": url})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/clanker/update_rules", methods=["POST"])
@login_required
@admin_required
def clanker_trigger_update():
    import subprocess
    scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
    updater = os.path.join(scripts_dir, "update_clanker_rules.py")
    python_bin = os.path.join(os.path.dirname(__file__), "..", "venv", "bin", "python")
    if not os.path.isfile(python_bin):
        python_bin = "python3"
    try:
        proc = subprocess.run(
            [python_bin, updater],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(updater)
        )
        updated = proc.returncode == 0 and "actualizadas" in proc.stdout.lower()
        no_update = "no hay actualizacion" in proc.stdout.lower() or "no configurada" in proc.stdout.lower()
        out_lines = proc.stdout.strip().splitlines()
        last_line = out_lines[-1] if out_lines else ""
        if not last_line:
            last_line = "Sin actualizaciones disponibles." if no_update else proc.stderr.strip() or "Sin cambios."
        return jsonify({"success": updated, "message": last_line})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Timeout (60s)"}), 504
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/clanker/rules", methods=["GET"])
@login_required
def clanker_list_rules():
    if not CLANKER_ENABLED:
        return jsonify({"enabled": False, "rules": []}), 503
    rules = clanker_rules_list()
    safe_rules = [{k: v for k, v in r.items() if not k.startswith("_")}
                  for r in rules]
    return jsonify({"rules": safe_rules, "meta": clanker_rules_meta()})

@app.route("/api/clanker/rules/<rule_id>/toggle", methods=["POST"])
@login_required
@admin_required
def clanker_toggle_rule(rule_id):
    import yaml
    rules_path = os.path.join(os.path.dirname(__file__), "..", "config", "clanker_rules.yaml")
    try:
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f) or {}
        for rule in data.get("rules", []):
            if rule.get("id") == rule_id:
                rule["enabled"] = not rule.get("enabled", True)
                with open(rules_path, "w") as f:
                    yaml.dump(data, f, allow_unicode=True, sort_keys=False)
                return jsonify({"id": rule_id, "enabled": rule["enabled"]})
        return jsonify({"error": "Regla no encontrada"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/clanker/analyze", methods=["POST"])
@login_required
def clanker_analyze():
    if not CLANKER_ENABLED:
        return jsonify({"enabled": False}), 503
    data = request.get_json(silent=True) or {}
    html_raw = data.get("html", "")
    if not html_raw:
        return jsonify({"error": "Campo 'html' requerido"}), 400
    try:
        feats = extract_clanker_features(html_raw)
        return jsonify({"enabled": True, "features": feats,
                        "score": feats.get("clanker_weighted_score", 0.0)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/clanker/upload_rules", methods=["POST"])
@login_required
@admin_required
def clanker_upload_rules():
    import yaml, shutil
    from datetime import datetime
    rules_path = os.path.join(os.path.dirname(__file__), "..", "config", "clanker_rules.yaml")
    if "file" not in request.files:
        return jsonify({"success": False, "error": "Campo 'file' requerido"}), 400
    uploaded = request.files["file"]
    try:
        raw = uploaded.read().decode("utf-8")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict) or "rules" not in data:
            return jsonify({"success": False, "error": "Estructura YAML inválida"}), 400
        for rule in data["rules"]:
            for field in ("id", "pattern", "target", "severity"):
                if field not in rule:
                    return jsonify({"success": False,
                                    "error": f"Campo obligatorio '{field}' faltante en regla"}), 400
            import re as _re
            try: _re.compile(rule["pattern"])
            except _re.error as e:
                return jsonify({"success": False,
                                "error": f"Regex inválido en {rule['id']}: {e}"}), 400
        backup_path = rules_path + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if os.path.exists(rules_path):
            shutil.copy2(rules_path, backup_path)
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(raw)
        return jsonify({"success": True, "backup": backup_path,
                        "rules_count": len(data["rules"])})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ══════════════════════════════════════════════════
#  ACTUALIZACIONES DEL SISTEMA
# ══════════════════════════════════════════════════

# Importar el módulo de actualizaciones (web/updater.py)
from updater import check_for_updates


@app.route("/update")
@admin_required
def update_page():
    """Página de gestión de actualizaciones. Solo accesible para admins."""
    return render_template("update.html", user=current_user())


@app.route("/api/update/check")
@admin_required
def api_update_check():
    """
    Consulta GitHub y devuelve el estado de actualización.
    Llamado por la GUI vía fetch() para no bloquear la carga de página.
    """
    result = check_for_updates()
    return jsonify(result)

if __name__ == "__main__":
    host = os.getenv("WEB_HOST", "0.0.0.0")
    port = int(os.getenv("WEB_PORT", "5000"))
    print(f"\n{'='*50}\n Detector de Correos Maliciosos\n Accede en: http://{host}:{port}\n{'='*50}\n")
    app.run(host=host, port=port, debug=False)
