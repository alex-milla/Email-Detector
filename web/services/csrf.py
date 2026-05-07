import secrets
import hmac
from hashlib import sha256
from flask import session, request, jsonify, abort


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token():
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return True
    if request.is_json:
        return True
    token = request.form.get("_csrf_token")
    expected = session.get("_csrf_token")
    if not token or not expected:
        abort(400, "CSRF token faltante")
    if not hmac.compare_digest(token, expected):
        abort(400, "CSRF token inválido")
    return True


def inject_csrf(app):
    @app.before_request
    def _check_csrf():
        if request.endpoint and request.endpoint != "login":
            return
        validate_csrf_token()

    @app.context_processor
    def _inject_token():
        return {"csrf_token": generate_csrf_token}
