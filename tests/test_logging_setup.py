#!/usr/bin/env python3
"""
Tests del logging standalone (punto 5.4): logs de acceso/error a fichero.
"""

import logging
import os
import sys

import pytest

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

from web.services.logging_setup import configure_standalone_logging  # noqa: E402


def _clear_handlers():
    access = logging.getLogger("web.access")
    for handler in list(access.handlers):
        access.removeHandler(handler)
        handler.close()
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_emd_error", False):
            root.removeHandler(handler)
            handler.close()


@pytest.fixture
def clean_logging():
    _clear_handlers()
    yield
    _clear_handlers()


def _make_app():
    from flask import Flask
    app = Flask(__name__)

    @app.route("/ping")
    def ping():
        return "pong"

    return app


class TestStandaloneLogging:
    def test_writes_access_and_error_logs(self, tmp_path, clean_logging):
        app = _make_app()
        configure_standalone_logging(app, str(tmp_path))

        with app.test_client() as client:
            assert client.get("/ping").status_code == 200

        logging.getLogger().warning("emo-test-warning")

        for logger in (logging.getLogger("web.access"), logging.getLogger()):
            for handler in logger.handlers:
                handler.flush()

        access_log = (tmp_path / "access.log").read_text(encoding="utf-8")
        error_log = (tmp_path / "error.log").read_text(encoding="utf-8")
        assert "/ping" in access_log
        assert "200" in access_log
        assert "emo-test-warning" in error_log

    def test_is_idempotent(self, tmp_path, clean_logging):
        app = _make_app()
        configure_standalone_logging(app, str(tmp_path))
        n_first = len(logging.getLogger("web.access").handlers)
        configure_standalone_logging(app, str(tmp_path))
        n_second = len(logging.getLogger("web.access").handlers)
        assert n_first >= 1
        assert n_second == n_first

    def test_creates_logs_dir(self, tmp_path, clean_logging):
        logs_dir = tmp_path / "nested" / "logs"
        app = _make_app()
        configure_standalone_logging(app, str(logs_dir))
        assert logs_dir.is_dir()
        assert (logs_dir / "access.log").exists()
