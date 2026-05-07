from flask import render_template, request, jsonify, redirect, url_for, session

from web.services.decorators import login_required, admin_required, current_user
from web.auth import (
    authenticate, create_user, delete_user,
    get_all_users, change_password,
    save_mail_config, get_all_mail_configs,
)
from web.services.history_service import get_history_summary, get_model_meta
from web.services.limiter import limiter
from web.services.audit_service import log_admin_action

import os


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
    MODELS_DIR = os.path.join(PROJECT_DIR, "models")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("index"))
        error = None
        if request.method == "POST":
            user = authenticate(request.form.get("username", "").strip(),
                                request.form.get("password", ""))
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["user_role"] = user["role"]
                return redirect(request.args.get("next") or url_for("index"))
            error = "Usuario o contraseña incorrectos"
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        uid = session["user_id"]
        total, malicious, benign = get_history_summary(uid)
        model_meta = get_model_meta()
        model_exists = os.path.exists(os.path.join(MODELS_DIR, "email_classifier.joblib"))
        return render_template("index.html",
            total=total, malicious=malicious, benign=benign,
            model_exists=model_exists, model_meta=model_meta,
            user=current_user(), active_page='dashboard')

    @app.route("/users")
    @admin_required
    def users():
        return render_template("users.html",
            users=get_all_users(),
            mail_configs=get_all_mail_configs(),
            user=current_user(), active_page='users')

    # ── API endpoints ──

    @app.route("/api/users", methods=["POST"])
    @admin_required
    def api_create_user():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        role = data.get("role", "user")
        if not username or not password:
            return jsonify({"success": False, "error": "Usuario y contraseña requeridos"}), 400
        ok, msg = create_user(username, password, role)
        if ok:
            log_admin_action(session.get("user_id"), session.get("username"),
                           "CREAR_USUARIO", f"username={username} role={role}")
        return jsonify({"success": ok, "error": msg if not ok else None})

    @app.route("/api/users/<int:user_id>", methods=["DELETE"])
    @admin_required
    def api_delete_user(user_id):
        if user_id == session["user_id"]:
            return jsonify({"success": False, "error": "No puedes eliminarte a ti mismo"}), 400
        delete_user(user_id)
        log_admin_action(session.get("user_id"), session.get("username"),
                       "ELIMINAR_USUARIO", f"user_id={user_id}")
        return jsonify({"success": True})

    @app.route("/api/users/<int:user_id>/password", methods=["POST"])
    @login_required
    def api_change_password(user_id):
        if session["user_id"] != user_id and session.get("user_role") != "admin":
            return jsonify({"success": False, "error": "Sin permisos"}), 403
        body = request.get_json(silent=True) or {}
        pwd = body.get("password", "")
        ok, msg = change_password(user_id, pwd)
        if not ok:
            return jsonify({"success": False, "error": msg}), 400
        return jsonify({"success": True, "message": msg})

    @app.route("/api/user/role", methods=["GET"])
    @login_required
    def api_user_role():
        role = session.get("user_role", "user")
        return jsonify({"role": role})
