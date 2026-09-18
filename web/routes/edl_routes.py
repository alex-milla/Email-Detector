import os
import sys
import subprocess

from flask import request, jsonify

from web.services.decorators import login_required, admin_required
from web.services.limiter import limiter, user_or_ip_key

try:
    from edl_manager import (
        get_public_lists, schedule_info, add_list, update_list, toggle_list,
        remove_list, set_schedule, preview_url,
    )
    EDL_ENABLED = True
except ImportError:
    EDL_ENABLED = False


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

    @app.route("/api/edl/lists", methods=["GET"])
    @login_required
    @admin_required
    def edl_lists():
        if not EDL_ENABLED:
            return jsonify({"enabled": False, "lists": [], "schedule": {}}), 503
        return jsonify({
            "enabled": True,
            "lists": get_public_lists(),
            "schedule": schedule_info(),
        })

    @app.route("/api/edl/lists", methods=["POST"])
    @login_required
    @admin_required
    def edl_add_list():
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        data = request.get_json(silent=True) or {}
        try:
            entry = add_list(
                data.get("name", ""),
                data.get("url", ""),
                interval_h=data.get("interval_h"),
            )
            item = {k: v for k, v in entry.items() if k != "headers"}
            return jsonify({"success": True, "list": item})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/lists/<list_id>/update", methods=["POST"])
    @login_required
    @admin_required
    def edl_update_list(list_id):
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        data = request.get_json(silent=True) or {}
        try:
            entry = update_list(
                list_id,
                name=data.get("name"),
                url=data.get("url"),
                interval_h=data.get("interval_h"),
            )
            item = {k: v for k, v in entry.items() if k != "headers"}
            return jsonify({"success": True, "list": item})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/lists/<list_id>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def edl_toggle_list(list_id):
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        try:
            entry = toggle_list(list_id)
            return jsonify({"success": True, "enabled": entry.get("enabled", True)})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 404
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/lists/<list_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def edl_delete_list(list_id):
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        try:
            remove_list(list_id)
            return jsonify({"success": True})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 404
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/schedule", methods=["POST"])
    @login_required
    @admin_required
    def edl_set_schedule():
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        data = request.get_json(silent=True) or {}
        try:
            schedule = set_schedule(
                auto_enabled=data.get("auto_enabled"),
                default_interval_h=data.get("default_interval_h"),
            )
            return jsonify({"success": True, "schedule": schedule})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/preview", methods=["POST"])
    @limiter.limit("10 per minute", key_func=user_or_ip_key)
    @login_required
    @admin_required
    def edl_preview():
        if not EDL_ENABLED:
            return jsonify({"success": False, "error": "edl_manager no disponible"}), 503
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()
        if not url:
            return jsonify({"success": False, "error": "URL requerida"}), 400
        try:
            info = preview_url(url)
            return jsonify({"success": True, **info})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/edl/sync", methods=["POST"])
    @limiter.limit("5 per minute", key_func=user_or_ip_key)
    @login_required
    @admin_required
    def edl_sync():
        if not EDL_ENABLED:
            return jsonify({"success": False, "message": "edl_manager no disponible"}), 503
        data = request.get_json(silent=True) or {}
        list_id = str(data.get("list_id", "")).strip()
        scripts_dir = os.path.join(PROJECT_DIR, "scripts")
        updater = os.path.join(scripts_dir, "update_edl.py")
        cmd = [sys.executable, updater]
        if list_id:
            cmd += ["--list", list_id]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180, cwd=scripts_dir
            )
            out_lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
            message = out_lines[-1] if out_lines else (proc.stderr.strip() or "Sin cambios.")
            return jsonify({"success": proc.returncode == 0, "message": message})
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "message": "Timeout (180s)"}), 504
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500
