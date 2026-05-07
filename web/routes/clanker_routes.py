import os
import sys
import subprocess
import re as _re
from datetime import datetime
import shutil

from flask import request, jsonify
import yaml

from web.services.decorators import login_required, admin_required

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

try:
    from extract_clanker_features import (
        extract_clanker_features,
        get_rules_meta as clanker_rules_meta,
        get_rules_list as clanker_rules_list,
    )
    CLANKER_ENABLED = True
except ImportError:
    CLANKER_ENABLED = False


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
    ENV_PATH = os.path.join(PROJECT_DIR, "config", ".env")

    @app.route("/api/clanker/status", methods=["GET"])
    @login_required
    def clanker_status():
        if not CLANKER_ENABLED:
            return jsonify({"enabled": False, "error": "extract_clanker_features no disponible"}), 503
        meta = clanker_rules_meta()
        rules = clanker_rules_list()
        active = sum(1 for r in rules if r.get("enabled", True))
        rules_url = ""
        try:
            with open(ENV_PATH) as f:
                for line in f:
                    if line.startswith("CLANKER_RULES_URL="):
                        rules_url = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
        resp = {
            "enabled": True, "rules_version": meta.get("version", "?"),
            "rules_updated": meta.get("updated_at", "?"),
            "total_rules": len(rules), "active_rules": active,
            "rules_url": rules_url,
        }
        if len(rules) == 0:
            rules_path = os.path.join(PROJECT_DIR, "config", "clanker_rules.yaml")
            resp["debug"] = {
                "rules_file_exists": os.path.exists(rules_path),
                "rules_file_path": rules_path,
                "rules_file_size": os.path.getsize(rules_path) if os.path.exists(rules_path) else 0,
            }
        return jsonify(resp)

    @app.route("/api/clanker/validate", methods=["GET"])
    @login_required
    @admin_required
    def clanker_validate():
        rules_path = os.path.join(PROJECT_DIR, "config", "clanker_rules.yaml")
        result = {
            "file_exists": os.path.exists(rules_path),
            "file_path": rules_path,
            "file_size": os.path.getsize(rules_path) if os.path.exists(rules_path) else 0,
        }
        if not os.path.exists(rules_path):
            return jsonify({"valid": False, **result, "error": "Fichero no encontrado"})
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            result["valid"] = True
            result["yaml_type"] = type(data).__name__
            result["has_meta"] = isinstance(data, dict) and "meta" in data
            result["has_rules"] = isinstance(data, dict) and "rules" in data
            result["rules_count"] = len(data.get("rules", [])) if isinstance(data, dict) else 0
            result["meta_version"] = data.get("meta", {}).get("version", "?") if isinstance(data, dict) else "?"
            return jsonify(result)
        except Exception as e:
            return jsonify({"valid": False, **result, "error": str(e)})

    @app.route("/api/clanker/set_url", methods=["POST"])
    @login_required
    @admin_required
    def clanker_set_url():
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        if url and not url.startswith("https://"):
            return jsonify({"success": False, "error": "La URL debe usar HTTPS."}), 400
        try:
            with open(ENV_PATH, "r") as f:
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
            with open(ENV_PATH, "w") as f:
                f.writelines(new_lines)
            return jsonify({"success": True, "url": url})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/clanker/update_rules", methods=["POST"])
    @login_required
    @admin_required
    def clanker_trigger_update():
        scripts_dir = os.path.join(PROJECT_DIR, "scripts")
        updater = os.path.join(scripts_dir, "update_clanker_rules.py")
        python_bin = sys.executable
        try:
            proc = subprocess.run(
                [python_bin, updater], capture_output=True, text=True, timeout=60, cwd=scripts_dir
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
        safe_rules = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rules]
        return jsonify({"rules": safe_rules, "meta": clanker_rules_meta()})

    @app.route("/api/clanker/rules/<rule_id>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def clanker_toggle_rule(rule_id):
        rules_path = os.path.join(PROJECT_DIR, "config", "clanker_rules.yaml")
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
        rules_path = os.path.join(PROJECT_DIR, "config", "clanker_rules.yaml")
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
                try:
                    _re.compile(rule["pattern"])
                except _re.error as e:
                    return jsonify({"success": False,
                                    "error": f"Regex inválido en {rule['id']}: {e}"}), 400
            backup_path = rules_path + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if os.path.exists(rules_path):
                shutil.copy2(rules_path, backup_path)
            with open(rules_path, "w", encoding="utf-8") as f:
                f.write(raw)
            return jsonify({"success": True, "backup": backup_path, "rules_count": len(data["rules"])})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
