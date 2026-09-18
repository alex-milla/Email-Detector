#!/usr/bin/env python3
"""
Tests de integración para la ruta de reentrenamiento completo
(/model/full-retrain), que ejecuta scripts/retrain.sh.
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


class TestFullRetrainRoute:
    def test_unauthenticated_is_rejected(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.post("/model/full-retrain")
            assert resp.status_code in (400, 401, 403)

    def test_admin_starts_background_full_retrain(self, monkeypatch):
        import threading
        import web.routes.model_routes as mr

        monkeypatch.setattr(mr, "load_training_state", lambda: {"running": False})
        monkeypatch.setattr(mr, "log_admin_action", lambda *a, **k: None)
        monkeypatch.setattr(mr, "validate_script_path", lambda *a, **k: (True, ""))
        captured = {}
        done = threading.Event()

        def _fake_run(cmd, cwd):
            captured["cmd"] = cmd
            done.set()

        monkeypatch.setattr(mr, "run_training", _fake_run)

        from web.app import app
        with app.test_client() as client:
            _login_admin(client)
            resp = client.post(
                "/model/full-retrain",
                headers={"X-CSRF-Token": "test-csrf-token"},
            )
            assert resp.status_code == 200
            assert resp.get_json().get("started") is True

        assert done.wait(timeout=5), "el hilo de entrenamiento no se ejecutó"
        assert captured["cmd"][0] == "bash"
        assert captured["cmd"][1].replace("\\", "/").endswith("scripts/retrain.sh")

    def test_rejects_unvalidated_script(self, monkeypatch):
        import web.routes.model_routes as mr
        monkeypatch.setattr(mr, "load_training_state", lambda: {"running": False})
        monkeypatch.setattr(mr, "validate_script_path", lambda *a, **k: (False, "inseguro"))

        from web.app import app
        with app.test_client() as client:
            _login_admin(client)
            resp = client.post(
                "/model/full-retrain",
                headers={"X-CSRF-Token": "test-csrf-token"},
            )
            assert resp.status_code == 403

    def test_conflict_when_already_running(self, monkeypatch):
        import web.routes.model_routes as mr
        monkeypatch.setattr(mr, "load_training_state", lambda: {"running": True})

        from web.app import app
        with app.test_client() as client:
            _login_admin(client)
            resp = client.post(
                "/model/full-retrain",
                headers={"X-CSRF-Token": "test-csrf-token"},
            )
            assert resp.status_code == 409
