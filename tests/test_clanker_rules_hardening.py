#!/usr/bin/env python3
"""
Tests de hardening de reglas Anti-Clanker (puntos 5.7 y 5.8):
rotación de backups y límite de tamaño en la subida.
"""

import io
import os
import sys

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

from web.routes.clanker_routes import (  # noqa: E402
    _rotate_backups, _create_backup, RULES_MAX_BYTES,
)

TOKEN = "test-csrf-token"


def _touch_backups(tmp_path, n):
    for i in range(n):
        (tmp_path / f"rules.yaml.bak_20260101_0000{i:02d}").write_text(str(i), encoding="utf-8")


class TestBackupRotation:
    def test_keeps_only_latest(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("data", encoding="utf-8")
        _touch_backups(tmp_path, 12)

        _rotate_backups(str(rules), keep=10)

        remaining = sorted(p.name for p in tmp_path.glob("rules.yaml.bak_*"))
        assert len(remaining) == 10
        assert remaining[0].endswith("_000002")
        assert remaining[-1].endswith("_000011")

    def test_keeps_all_when_fewer_than_limit(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("data", encoding="utf-8")
        _touch_backups(tmp_path, 3)

        _rotate_backups(str(rules), keep=10)

        assert len(list(tmp_path.glob("rules.yaml.bak_*"))) == 3

    def test_create_backup_rotates(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("contenido", encoding="utf-8")
        _touch_backups(tmp_path, 12)

        path = _create_backup(str(rules), keep=10)

        assert path and os.path.exists(path)
        assert len(list(tmp_path.glob("rules.yaml.bak_*"))) == 10

    def test_create_backup_missing_file_returns_none(self, tmp_path):
        assert _create_backup(str(tmp_path / "no_existe.yaml")) is None


class TestUploadSizeLimit:
    def test_oversized_upload_rejected(self):
        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(user_id=1, username="admin",
                            user_role="admin", _csrf_token=TOKEN)
            big = b"x" * (RULES_MAX_BYTES + 1)
            resp = client.post(
                "/api/clanker/upload_rules",
                headers={"X-CSRF-Token": TOKEN},
                data={"file": (io.BytesIO(big), "rules.yaml")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 400
        assert "límite" in resp.get_json()["error"]

    def test_invalid_yaml_rejected(self):
        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(user_id=1, username="admin",
                            user_role="admin", _csrf_token=TOKEN)
            resp = client.post(
                "/api/clanker/upload_rules",
                headers={"X-CSRF-Token": TOKEN},
                data={"file": (io.BytesIO(b"no: es: yaml: ["), "rules.yaml")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 400
