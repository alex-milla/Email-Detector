from functools import wraps
from flask import session, redirect, url_for, request, jsonify, render_template


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
