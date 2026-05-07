import os
import sys
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from flask import request, jsonify, render_template, session

from web.services.decorators import login_required, admin_required, current_user
from web.services.history_service import get_model_meta
from web.services.validation_service import validate_script_path
from web.services.training_service import run_training, load_training_state


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
    LABELED_DIR = os.path.join(PROJECT_DIR, "data", "labeled")
    MODELS_DIR = os.path.join(PROJECT_DIR, "models")
    ENV_PATH = os.path.join(PROJECT_DIR, "config", ".env")

    @app.route("/training")
    @login_required
    def training():
        model_meta = get_model_meta()
        model_exists = os.path.exists(os.path.join(MODELS_DIR, "email_classifier.joblib"))
        benign_count = len(list(Path(os.path.join(LABELED_DIR, "benign")).glob("*.eml"))) \
                       if os.path.exists(os.path.join(LABELED_DIR, "benign")) else 0
        malicious_count = len(list(Path(os.path.join(LABELED_DIR, "malicious")).glob("*.eml"))) \
                          if os.path.exists(os.path.join(LABELED_DIR, "malicious")) else 0
        return render_template("training.html",
            model_exists=model_exists, model_meta=model_meta,
            benign_count=benign_count, malicious_count=malicious_count,
            user=current_user(), active_page='training')

    @app.route("/model/info")
    @login_required
    def model_info():
        meta = get_model_meta()
        return jsonify(meta) if meta else (jsonify({"error": "No hay modelo"}), 404)

    @app.route("/dataset/download", methods=["POST"])
    @admin_required
    def dataset_download():
        script = os.path.join(PROJECT_DIR, "download_dataset.sh")
        ok, reason = validate_script_path(script, PROJECT_DIR)
        if not ok:
            return jsonify({"error": "El script no pasó la validación de seguridad."}), 403
        try:
            result = subprocess.run(
                [script], capture_output=True, text=True, timeout=600, cwd=PROJECT_DIR
            )
            return jsonify({
                "success": result.returncode == 0,
                "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-1000:],
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Timeout"}), 504
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/model/full-retrain", methods=["POST"])
    @admin_required
    def full_retrain():
        state = load_training_state()
        if state.get("running"):
            return jsonify({"error": "Ya hay un entrenamiento en curso"}), 409
        script = os.path.join(PROJECT_DIR, "scripts", "retrain.sh")
        ok, reason = validate_script_path(script, PROJECT_DIR)
        if not ok:
            return jsonify({"error": "El script de entrenamiento no pasó la validación de seguridad."}), 403
        t = threading.Thread(
            target=run_training, args=(["bash", script], PROJECT_DIR), daemon=True
        )
        t.start()
        return jsonify({"started": True, "message": "Entrenamiento iniciado en background"})

    @app.route("/model/retrain", methods=["POST"])
    @admin_required
    def retrain():
        state = load_training_state()
        if state.get("running"):
            return jsonify({"error": "Ya hay un entrenamiento en curso"}), 409
        python_bin = sys.executable
        cmd = [python_bin, os.path.join(PROJECT_DIR, "scripts", "train_model.py")]
        t = threading.Thread(
            target=run_training, args=(cmd, PROJECT_DIR), daemon=True
        )
        t.start()
        return jsonify({"started": True, "message": "Entrenamiento iniciado en background"})

    @app.route("/model/training-status")
    @login_required
    def training_status():
        return jsonify(load_training_state())

    @app.route("/api/models/toggle", methods=["GET"])
    @admin_required
    def api_models_toggle_get():
        meta = get_model_meta()
        available = meta.get("models_available", [])
        results = meta.get("results", {})
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
        models_info = [
            {"name": n, "enabled": n not in disabled,
             "auc_test": results.get(n, {}).get("auc_test"),
             "error": results.get(n, {}).get("error")}
            for n in available
        ]
        models_info.sort(key=lambda x: x.get("auc_test") or 0, reverse=True)
        return jsonify({"models": models_info, "disabled": list(disabled)})

    @app.route("/api/models/toggle", methods=["POST"])
    @admin_required
    def api_models_toggle_post():
        data = request.get_json() or {}
        name = data.get("name", "").strip()
        enabled = data.get("enabled", True)
        if not name:
            return jsonify({"error": "Falta el campo name"}), 400
        disabled = set()
        lines = []
        try:
            if os.path.exists(ENV_PATH):
                with open(ENV_PATH) as f:
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
        new_val = ",".join(sorted(disabled))
        new_lines = []
        found = False
        for line in lines:
            if line.strip().startswith("DISABLED_MODELS="):
                new_lines.append("DISABLED_MODELS=" + new_val + "\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append("DISABLED_MODELS=" + new_val + "\n")
        try:
            with open(ENV_PATH, "w") as f:
                f.writelines(new_lines)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"ok": True, "name": name, "enabled": enabled, "disabled": list(disabled)})
