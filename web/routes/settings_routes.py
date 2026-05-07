import os
import json
import subprocess
from datetime import datetime, timezone

from flask import request, jsonify, render_template, session
from dotenv import load_dotenv

from web.services.decorators import login_required, admin_required, current_user
from web.auth import (
    get_mail_config, save_mail_config, get_db,
    generate_totp_secret, get_totp_uri, verify_totp,
    enable_totp, disable_totp, is_totp_enabled, has_2fa,
)
from settings_manager import read_global_env, write_global_env, test_imap, test_virustotal, test_m365


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

    @app.route("/settings")
    @login_required
    def settings():
        uid = session["user_id"]
        return render_template("settings.html",
            config=get_mail_config(uid),
            global_cfg=read_global_env(),
            user=current_user(), active_page='settings')

    @app.route("/api/settings/mail", methods=["POST"])
    @login_required
    def api_save_mail():
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({"success": False, "error": "Payload vacío o inválido"}), 400
        try:
            ok = save_mail_config(session["user_id"], data)
            if not ok:
                return jsonify({"success": False, "error": "No hay campos válidos para guardar"}), 400
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/settings/global", methods=["GET"])
    @login_required
    def api_get_global():
        return jsonify(read_global_env())

    @app.route("/api/settings/global", methods=["POST"])
    @admin_required
    def api_save_global():
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({"success": False, "error": "Payload vacío o inválido"}), 400
        try:
            write_global_env(data)
            env_path = os.path.join(PROJECT_DIR, "config", ".env")
            load_dotenv(env_path, override=True)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/settings/test", methods=["POST"])
    @login_required
    def api_test_connection():
        data = request.get_json(silent=True) or {}
        provider = data.get("provider")
        cfg = get_mail_config(session["user_id"])
        if provider == "imap":
            ok, msg = test_imap(
                data.get("server", cfg.get("imap_server", "")),
                data.get("port", cfg.get("imap_port", "993")),
                data.get("user", cfg.get("imap_user", "")),
                data.get("password", cfg.get("imap_password", ""))
            )
        elif provider == "virustotal":
            ok, msg = test_virustotal(data.get("api_key", ""))
        elif provider == "m365":
            ok, msg = test_m365(
                data.get("client_id", cfg.get("ms365_client_id", "")),
                data.get("client_secret", cfg.get("ms365_client_secret", "")),
                data.get("tenant_id", cfg.get("ms365_tenant_id", ""))
            )
        else:
            return jsonify({"success": False, "message": "Proveedor desconocido"}), 400
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/theme", methods=["GET"])
    @login_required
    def api_theme_get():
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT theme FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()
            theme = row["theme"] if row and "theme" in row.keys() else "dark"
        except Exception:
            theme = "dark"
        finally:
            conn.close()
        return jsonify({"theme": theme or "dark"})

    @app.route("/api/theme", methods=["POST"])
    @login_required
    def api_theme_set():
        data = request.get_json(silent=True) or {}
        theme = data.get("theme", "dark")
        if theme not in ("dark", "light", "system"):
            return jsonify({"error": "Tema no válido"}), 400
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET theme = ? WHERE id = ?", (theme, session["user_id"])
            )
            conn.commit()
        except Exception:
            try:
                conn.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'dark'")
                conn.execute(
                    "UPDATE users SET theme = ? WHERE id = ?", (theme, session["user_id"])
                )
                conn.commit()
            except Exception as e:
                conn.close()
                return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
        session["user_theme"] = theme
        return jsonify({"success": True, "theme": theme})

    @app.route("/api/ssl/status")
    @admin_required
    def api_ssl_status():
        cert_path = os.path.join(PROJECT_DIR, "config", "ssl", "cert.pem")
        if not os.path.exists(cert_path):
            return jsonify({"enabled": False, "message": "No hay certificado TLS configurado."})
        try:
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return jsonify({"enabled": True, "error": "No se pudo leer el certificado."}), 500
            expiry_str = result.stdout.strip().split("=", 1)[1]
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            days_left = (expiry_dt - now_dt).days
            return jsonify({
                "enabled": True, "expiry": expiry_dt.strftime("%Y-%m-%d"),
                "days_left": days_left, "warning": days_left <= 30, "expired": days_left <= 0,
            })
        except Exception as e:
            return jsonify({"enabled": True, "error": str(e)}), 500

    @app.route("/api/ssl/renew", methods=["POST"])
    @admin_required
    def api_ssl_renew():
        data = request.get_json(silent=True) or {}
        days = int(data.get("days", 365))
        days = max(1, min(365, days))
        ssl_dir = os.path.join(PROJECT_DIR, "config", "ssl")
        cert_path = os.path.join(ssl_dir, "cert.pem")
        key_path = os.path.join(ssl_dir, "key.pem")
        if not os.path.isdir(ssl_dir):
            return jsonify({"success": False, "error": "Directorio SSL no existe. ¿HTTPS está habilitado?"}), 400
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if os.path.exists(cert_path):
            import shutil
            shutil.copy2(cert_path, f"{cert_path}.bak_{ts}")
            shutil.copy2(key_path, f"{key_path}.bak_{ts}")
        try:
            import socket
            hostname = socket.getfqdn()
            result = subprocess.run([
                "openssl", "req", "-x509",
                "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", str(days),
                "-keyout", key_path, "-out", cert_path,
                "-subj", f"/C=ES/ST=Spain/L=Local/O=Email Malware Detector/OU=Security/CN={hostname}"
            ], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return jsonify({"success": False, "error": "openssl falló al generar el certificado."}), 500
            return jsonify({
                "success": True,
                "message": f"Certificado renovado ({days} días). Reinicia el servicio para aplicarlo.",
                "restart_required": True,
            })
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Timeout generando el certificado."}), 500
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # ── TOTP / 2FA ──────────────────────────────────────────────────────────

    @app.route("/api/2fa/status")
    @login_required
    def api_2fa_status():
        uid = session["user_id"]
        return jsonify({
            "available": has_2fa(),
            "enabled": is_totp_enabled(uid),
        })

    @app.route("/api/2fa/setup", methods=["POST"])
    @login_required
    def api_2fa_setup():
        if not has_2fa():
            return jsonify({"error": "pyotp no instalado. pip install pyotp"}), 503
        uid = session["user_id"]
        code = (request.get_json(silent=True) or {}).get("code", "")
        if code:
            if verify_totp(uid, code):
                return jsonify({"success": True, "message": "2FA activado"})
            return jsonify({"success": False, "error": "Código inválido"}), 400
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, session.get("username", "user"))
        enable_totp(uid, secret)
        return jsonify({"success": True, "secret": secret, "uri": uri, "qrcode": uri})

    @app.route("/api/2fa/disable", methods=["POST"])
    @admin_required
    def api_2fa_disable():
        uid = session["user_id"]
        disable_totp(uid)
        return jsonify({"success": True, "message": "2FA desactivado"})
