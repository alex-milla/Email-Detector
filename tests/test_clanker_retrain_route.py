#!/usr/bin/env python3
"""
Tests de integración para la ruta de reentrenamiento Anti-Clanker
(/model/retrain-clanker).
"""

import os
import sys

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))


def _login_admin(client, token="test-csrf-token"):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["user_role"] = "admin"
        sess["_csrf_token"] = token


class TestRetrainClankerRoute:
    def test_unauthenticated_is_rejected(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.post("/model/retrain-clanker")
            assert resp.status_code in (400, 401, 403)

    def test_admin_starts_background_retrain(self, monkeypatch):
        import threading
        import web.routes.model_routes as mr

        monkeypatch.setattr(mr, "load_training_state", lambda: {"running": False})
        monkeypatch.setattr(mr, "log_admin_action", lambda *a, **k: None)
        captured = {}
        done = threading.Event()

        def _fake_run(cmd, cwd):
            captured["cmd"] = cmd
            captured["cwd"] = cwd
            done.set()

        monkeypatch.setattr(mr, "run_training", _fake_run)

        from web.app import app
        with app.test_client() as client:
            _login_admin(client)
            resp = client.post(
                "/model/retrain-clanker",
                headers={"X-CSRF-Token": "test-csrf-token"},
                json={"synthetic": True},
            )
            assert resp.status_code == 200
            body = resp.get_json()
            assert body.get("started") is True

        assert done.wait(timeout=5), "el hilo de entrenamiento no se ejecutó"
        assert "retrain_clanker.py" in " ".join(captured["cmd"])
        assert "--synthetic" in captured["cmd"]

    def test_conflict_when_already_running(self, monkeypatch):
        import web.routes.model_routes as mr
        monkeypatch.setattr(mr, "load_training_state", lambda: {"running": True})

        from web.app import app
        with app.test_client() as client:
            _login_admin(client)
            resp = client.post(
                "/model/retrain-clanker",
                headers={"X-CSRF-Token": "test-csrf-token"},
                json={"synthetic": False},
            )
            assert resp.status_code == 409
