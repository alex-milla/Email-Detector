#!/usr/bin/env python3
"""
Tests del rate limiting ampliado (punto 5.1): clave por usuario y límites en
endpoints costosos.
"""

import os
import sys

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

TOKEN = "test-csrf-token"


def _session(client, **values):
    with client.session_transaction() as sess:
        sess.update(values)


class TestUserOrIpKey:
    def test_prefers_session_user(self):
        from flask import session
        from web.app import app
        from web.services.limiter import user_or_ip_key
        with app.test_request_context("/"):
            session["user_id"] = 42
            assert user_or_ip_key() == "user:42"

    def test_falls_back_to_remote_ip(self):
        from web.app import app
        from web.services.limiter import user_or_ip_key
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "1.2.3.4"}):
            assert user_or_ip_key() == "ip:1.2.3.4"


class TestRateLimits:
    def test_health_is_not_rate_limited(self):
        from web.app import app
        with app.test_client() as client:
            for _ in range(15):
                assert client.get("/health").status_code == 200

    def test_update_apply_is_rate_limited(self, monkeypatch):
        import web.routes.update_routes as ur
        monkeypatch.setattr(ur, "check_for_updates",
                            lambda: {"update_available": False})

        from web.app import app
        with app.test_client() as client:
            _session(client, user_id=1, username="admin",
                     user_role="admin", _csrf_token=TOKEN)
            headers = {"X-CSRF-Token": TOKEN, "X-Requested-With": "XMLHttpRequest"}
            codes = [
                client.post("/api/update/apply", headers=headers).status_code
                for _ in range(6)
            ]

        assert codes[:5] == [400] * 5
        assert codes[5] == 429
