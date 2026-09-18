#!/usr/bin/env python3
"""Tests de la instalación de dependencias del updater (PEP 668).

El updater nunca debe usar el pip global: instala con el python del venv del
proyecto (`venv/bin/python -m pip`) para evitar "externally-managed-environment".
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class _Result:
    def __init__(self, code=0, out="", err=""):
        self.returncode = code
        self.stdout = out
        self.stderr = err


def test_install_requirements_uses_venv_python(monkeypatch, tmp_path):
    import updater

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Result(0)

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    monkeypatch.setattr(updater, "_venv_python",
                        lambda: "/opt/email-detector/venv/bin/python")

    ok, err = updater._install_requirements(str(tmp_path / "requirements.txt"))

    assert ok is True
    assert err == ""
    cmd = captured["cmd"]
    assert cmd[:3] == ["/opt/email-detector/venv/bin/python", "-m", "pip"]
    assert cmd[3] == "install"
    assert "-r" in cmd


def test_install_requirements_reports_error(monkeypatch, tmp_path):
    import updater

    monkeypatch.setattr(updater.subprocess, "run",
                        lambda cmd, **kwargs: _Result(1, err="boom"))
    monkeypatch.setattr(updater, "_venv_python", lambda: "/venv/bin/python")

    ok, err = updater._install_requirements(str(tmp_path / "requirements.txt"))

    assert ok is False
    assert "boom" in err


def test_venv_python_returns_string():
    import updater

    assert isinstance(updater._venv_python(), str)
