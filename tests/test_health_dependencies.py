#!/usr/bin/env python3
"""
Tests del health check de dependencias (punto 5.3).
"""

import os
import sys

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

EXPECTED_CHECKS = {
    "sqlite", "model_file", "clanker_rules",
    "playwright_chromium", "virustotal_configured",
}


class TestCheckDependencies:
    def test_returns_all_checks(self):
        from web.services.health_service import check_dependencies
        deps = check_dependencies()
        assert set(deps["checks"].keys()) == EXPECTED_CHECKS
        assert isinstance(deps["ok"], bool)
        assert "checked_at" in deps

    def test_sqlite_is_reachable(self):
        from web.services.health_service import check_dependencies
        checks = check_dependencies()["checks"]
        assert checks["sqlite"]["ok"] is True

    def test_summary_shape(self):
        from web.services.health_service import summary
        values, overall = summary()
        assert set(values.keys()) == EXPECTED_CHECKS
        assert isinstance(overall, bool)

    def test_optional_dependencies_do_not_fail_overall(self, monkeypatch):
        from web.services import health_service as hs
        monkeypatch.setattr(hs, "_CHECKS", {
            "sqlite": lambda: (True, "ok"),
            "virustotal_configured": lambda: (False, "sin configurar"),
        })
        deps = hs.check_dependencies()
        assert deps["ok"] is True
        assert deps["checks"]["virustotal_configured"]["optional"] is True


class TestHealthEndpoints:
    def test_health_includes_dependencies(self):
        from web.app import app
        with app.test_client() as client:
            data = client.get("/health").get_json()
            assert "dependencies" in data
            assert set(data["dependencies"].keys()) == EXPECTED_CHECKS
            assert "dependencies_ok" in data

    def test_dependencies_endpoint_requires_auth(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.get("/health/dependencies")
            assert resp.status_code in (301, 302, 303)

    def test_dependencies_endpoint_for_admin(self):
        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["username"] = "admin"
                sess["user_role"] = "admin"
            resp = client.get("/health/dependencies")
            assert resp.status_code == 200
            body = resp.get_json()
            assert set(body["checks"].keys()) == EXPECTED_CHECKS
