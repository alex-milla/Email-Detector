#!/usr/bin/env python3
"""
Tests del endpoint de logging de errores del frontend (/api/client-log).
"""

import os
import sys

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

TOKEN = "test-csrf-token"


def _session(client):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = TOKEN


class TestClientLog:
    def test_requires_csrf(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.post("/api/client-log", json={"message": "x"})
            assert resp.status_code == 400

    def test_requires_message(self):
        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.post("/api/client-log",
                               headers={"X-CSRF-Token": TOKEN}, json={})
            assert resp.status_code == 400

    def test_logs_message(self, monkeypatch):
        import web.app as wa

        captured = []

        class _Logger:
            def warning(self, *args, **kwargs):
                captured.append(args)

        monkeypatch.setattr(wa, "frontend_logger", _Logger())

        with wa.app.test_client() as client:
            _session(client)
            resp = client.post(
                "/api/client-log",
                headers={"X-CSRF-Token": TOKEN},
                json={"message": "boom-test", "url": "/x", "line": 3},
            )
            assert resp.status_code == 200
            assert resp.get_json()["ok"] is True

        assert captured
        assert any("boom-test" in str(a) for a in captured[0])
