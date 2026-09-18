#!/usr/bin/env python3
"""
Tests para bump_version.py y la consistencia de release.json (punto 5.9).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestBuildVersionData:
    def test_fields(self):
        from bump_version import build_version_data
        data = build_version_data("9.9.9", "resumen")
        assert set(data) == {"version", "release_date", "changelog",
                             "min_version", "zip_url"}
        assert data["version"] == "9.9.9"
        assert data["changelog"] == "resumen"
        assert data["zip_url"].endswith("/v9.9.9.zip")


class TestBuildReleaseData:
    def test_fields(self):
        from bump_version import build_release_data
        data = build_release_data("9.9.9", "cuerpo")
        assert data["tag_name"] == "v9.9.9"
        assert data["name"] == "Email Malware Detector v9.9.9"
        assert data["body"] == "cuerpo"
        assert data["draft"] is False
        assert data["prerelease"] is False


class TestReleaseJsonConsistency:
    def test_release_json_matches_version(self):
        with open(os.path.join(PROJECT_DIR, "VERSION"), encoding="utf-8") as f:
            version = f.read().strip()
        with open(os.path.join(PROJECT_DIR, "release.json"), encoding="utf-8") as f:
            release = json.load(f)
        assert release["tag_name"] == f"v{version}"

    def test_version_json_matches_version(self):
        with open(os.path.join(PROJECT_DIR, "VERSION"), encoding="utf-8") as f:
            version = f.read().strip()
        with open(os.path.join(PROJECT_DIR, "version.json"), encoding="utf-8") as f:
            meta = json.load(f)
        assert meta["version"] == version
