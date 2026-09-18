#!/usr/bin/env python3
"""
Tests de autenticación, autorización y CSRF.

Cubren los fixes de seguridad del Sprint 1 (validación CSRF global, incluidas
peticiones JSON) y el flujo de login/logout. Usan una users.db temporal.
"""

import os
import sys

import pytest

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

TOKEN = "test-csrf-token"


@pytest.fixture
def auth_module(tmp_path, monkeypatch):
    """Apunta web.auth a una base de datos temporal."""
    import web.auth as auth
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "users.db"))
    auth.init_db()
    ok, msg = auth.create_user("tester", "TestPass1", role="admin")
    assert ok, msg
    return auth


def _session(client, **values):
    with client.session_transaction() as sess:
        sess.update(values)


class TestCSRF:
    def test_post_without_token_is_rejected(self):
        from web.app import app
        with app.test_client() as client:
            _session(client, _csrf_token=TOKEN)
            resp = client.post("/api/users", json={"username": "x", "password": "TestPass1"})
            assert resp.status_code == 400

    def test_json_post_is_not_bypassed(self):
        from web.app import app
        with app.test_client() as client:
            _session(client, _csrf_token=TOKEN)
            resp = client.post("/api/users", json={"username": "y", "password": "TestPass1"})
            assert resp.status_code == 400
            assert b"CSRF" in resp.data

    def test_post_with_header_token_passes_csrf(self, auth_module):
        from web.app import app
        with app.test_client() as client:
            _session(client, user_id=1, username="tester", user_role="admin", _csrf_token=TOKEN)
            resp = client.post(
                "/api/users",
                headers={"X-CSRF-Token": TOKEN},
                json={"username": "nuevo", "password": "TestPass1"},
            )
            assert resp.status_code == 200
            assert resp.get_json().get("success") is True

    def test_get_requests_are_not_csrf_protected(self):
        from web.app import app
        with app.test_client() as client:
            assert client.get("/health").status_code == 200


class TestLoginLogout:
    def test_login_with_valid_credentials(self, auth_module):
        from web.app import app
        with app.test_client() as client:
            client.get("/login")
            with client.session_transaction() as sess:
                token = sess["_csrf_token"]
            resp = client.post("/login", data={
                "username": "tester", "password": "TestPass1", "_csrf_token": token,
            })
            assert resp.status_code in (301, 302, 303)
            with client.session_transaction() as sess:
                assert sess.get("user_id") is not None
                assert sess.get("username") == "tester"
                assert sess.permanent is True

    def test_login_with_invalid_credentials(self, auth_module):
        from web.app import app
        with app.test_client() as client:
            client.get("/login")
            with client.session_transaction() as sess:
                token = sess["_csrf_token"]
            resp = client.post("/login", data={
                "username": "tester", "password": "WrongPass1", "_csrf_token": token,
            })
            assert resp.status_code == 200
            assert b"incorrectos" in resp.data
            with client.session_transaction() as sess:
                assert "user_id" not in sess

    def test_logout_clears_session(self):
        from web.app import app
        with app.test_client() as client:
            _session(client, user_id=1, username="tester", user_role="admin")
            resp = client.get("/logout")
            assert resp.status_code in (301, 302, 303)
            with client.session_transaction() as sess:
                assert "user_id" not in sess


class TestAuthorization:
    def test_admin_endpoint_unauthenticated_returns_401(self):
        from web.app import app
        with app.test_client() as client:
            _session(client, _csrf_token=TOKEN)
            resp = client.post(
                "/api/users",
                headers={"X-CSRF-Token": TOKEN},
                json={"username": "z", "password": "TestPass1"},
            )
            assert resp.status_code == 401

    def test_admin_endpoint_forbidden_for_regular_user(self):
        from web.app import app
        with app.test_client() as client:
            _session(client, user_id=2, username="normal", user_role="user", _csrf_token=TOKEN)
            resp = client.post(
                "/api/users",
                headers={"X-CSRF-Token": TOKEN},
                json={"username": "z", "password": "TestPass1"},
            )
            assert resp.status_code == 403


class TestSessionLifetime:
    def test_session_lifetime_configured(self):
        from datetime import timedelta
        from web.app import app
        assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=8)
        assert app.config["SESSION_REFRESH_EACH_REQUEST"] is True


class TestPasswordPolicy:
    def test_weak_passwords_rejected(self, auth_module):
        assert auth_module.validate_password("short")
        assert auth_module.validate_password("alllowercase1")
        assert auth_module.validate_password("ALLUPPERCASE1")
        assert auth_module.validate_password("NoDigitsHere")

    def test_valid_password_accepted(self, auth_module):
        assert auth_module.validate_password("TestPass1") == []
