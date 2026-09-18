#!/usr/bin/env python3
"""Tests de las rutas HTTP de gestión de EDL."""

import os
import sys

import pytest

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

import edl_manager as edl  # noqa: E402

TOKEN = "test-csrf-token"


@pytest.fixture
def edl_env(tmp_path, monkeypatch):
    directory = tmp_path / "edl"
    monkeypatch.setattr(edl, "EDL_DIR", str(directory))
    monkeypatch.setattr(edl, "REGISTRY_FILE", str(directory / "lists.json"))
    monkeypatch.setattr(edl, "LOCK_FILE", str(directory / ".sync.lock"))
    edl.invalidate_index()
    return directory


def _session(client, role="admin"):
    with client.session_transaction() as sess:
        sess.update({
            "user_id": 1, "username": "tester", "user_role": role,
            "_csrf_token": TOKEN,
        })


def _headers():
    return {"X-CSRF-Token": TOKEN}


class TestAuthorization:
    def test_lists_requires_login(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            assert client.get("/api/edl/lists").status_code in (302, 401)

    def test_lists_forbidden_for_non_admin(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            _session(client, role="user")
            assert client.get("/api/edl/lists").status_code == 403


class TestListManagement:
    def test_empty_lists(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.get("/api/edl/lists")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["enabled"] is True
            assert data["lists"] == []

    def test_add_toggle_delete(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.post("/api/edl/lists", headers=_headers(),
                               json={"name": "Mi lista", "url": "https://example.com/l"})
            assert resp.status_code == 200
            list_id = resp.get_json()["list"]["id"]

            resp = client.post(f"/api/edl/lists/{list_id}/toggle", headers=_headers())
            assert resp.status_code == 200
            assert resp.get_json()["enabled"] is False

            resp = client.post(f"/api/edl/lists/{list_id}/delete", headers=_headers())
            assert resp.status_code == 200
            assert edl.get_public_lists() == []

    def test_add_rejects_http(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.post("/api/edl/lists", headers=_headers(),
                               json={"name": "X", "url": "http://example.com/l"})
            assert resp.status_code == 400

    def test_schedule_update(self, edl_env):
        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.post("/api/edl/schedule", headers=_headers(),
                               json={"auto_enabled": True, "default_interval_h": 3})
            assert resp.status_code == 200
            assert edl.schedule_info()["auto_enabled"] is True
            assert edl.schedule_info()["default_interval_h"] == 3


class TestSyncRoute:
    def test_sync_success(self, edl_env, monkeypatch):
        from web.routes import edl_routes

        class _Proc:
            returncode = 0
            stdout = "EDL: 1 de 1 listas sincronizadas (10 indicadores)\n"
            stderr = ""

        monkeypatch.setattr(edl_routes.subprocess, "run", lambda *a, **k: _Proc())

        from web.app import app
        with app.test_client() as client:
            _session(client)
            resp = client.post("/api/edl/sync", headers=_headers(), json={})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert "sincronizadas" in data["message"]
