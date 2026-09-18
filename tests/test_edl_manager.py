#!/usr/bin/env python3
"""Tests del motor de External Dynamic Lists (EDL)."""

import os
import sys

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import edl_manager as edl  # noqa: E402


@pytest.fixture
def edl_env(tmp_path, monkeypatch):
    directory = tmp_path / "edl"
    monkeypatch.setattr(edl, "EDL_DIR", str(directory))
    monkeypatch.setattr(edl, "REGISTRY_FILE", str(directory / "lists.json"))
    monkeypatch.setattr(edl, "LOCK_FILE", str(directory / ".sync.lock"))
    edl.invalidate_index()
    return directory


def _fake_download(payload):
    return lambda url, headers=None: payload


class TestParser:
    def test_detects_mixed_entries(self):
        raw = (
            "# FireHOL-style header\n"
            "# Category: attacks\n"
            "0.0.0.0 ads.evil.com\n"
            "127.0.0.1 tracker.evil.com\n"
            "1.2.3.4\n"
            "10.0.0.0/8\n"
            "hxxp://bad.example/path\n"
            "https://Example.COM:443/a?b=1\n"
            "evil-domain.com  # inline comment\n"
            "http://[2001:db8::1]:8080/x\n"
            "this is not valid\n"
        )
        parsed = edl.detect_and_parse(raw)
        assert "ads.evil.com" in parsed["domains"]
        assert "tracker.evil.com" in parsed["domains"]
        assert "evil-domain.com" in parsed["domains"]
        assert "1.2.3.4" in parsed["ips"]
        assert "10.0.0.0/8" in parsed["networks"]
        assert "http://bad.example/path" in parsed["urls"]
        assert "https://example.com/a?b=1" in parsed["urls"]
        assert "http://[2001:db8::1]:8080/x" in parsed["urls"]
        assert parsed["kind"] == "mixed"
        assert parsed["counts"] == {"urls": 3, "domains": 3, "ips": 2}

    def test_url_does_not_expand_to_domain(self):
        parsed = edl.detect_and_parse("https://evil.com/malware.exe\n")
        assert parsed["urls"] == ["https://evil.com/malware.exe"]
        assert parsed["domains"] == []
        assert parsed["kind"] == "url"

    def test_ignores_comments_and_blanks(self):
        parsed = edl.detect_and_parse("# a\n\n; b\n// c\n")
        assert parsed["counts"] == {"urls": 0, "domains": 0, "ips": 0}
        assert parsed["kind"] == "empty"


class TestRegistry:
    def test_add_list_requires_https(self, edl_env):
        with pytest.raises(ValueError):
            edl.add_list("Lista", "http://example.com/list")

    def test_add_list_rejects_duplicate_url(self, edl_env):
        edl.add_list("Uno", "https://example.com/list")
        with pytest.raises(ValueError):
            edl.add_list("Dos", "https://example.com/list")

    def test_toggle_and_remove(self, edl_env):
        entry = edl.add_list("Lista", "https://example.com/list")
        assert entry["enabled"] is True
        toggled = edl.toggle_list(entry["id"])
        assert toggled["enabled"] is False
        removed = edl.remove_list(entry["id"])
        assert removed["id"] == entry["id"]
        assert edl.get_public_lists() == []


class TestIndexMatching:
    def test_domain_subdomain_and_suffix_boundary(self, edl_env, monkeypatch):
        monkeypatch.setattr(edl, "_download", _fake_download(b"evil.com\n"))
        entry = edl.add_list("D", "https://example.com/d")
        assert edl.sync_list(entry["id"])["success"]
        index = edl.load_index(force=True)
        assert index.match_domain("a.evil.com")
        assert index.match_domain("deep.a.evil.com")
        assert index.match_domain("notevil.com") == []
        assert index.match_domain("evil.com.attacker.net") == []

    def test_ip_and_cidr(self, edl_env, monkeypatch):
        monkeypatch.setattr(
            edl, "_download",
            _fake_download(b"1.2.3.4\n203.0.113.0/24\n"),
        )
        entry = edl.add_list("I", "https://example.com/i")
        assert edl.sync_list(entry["id"])["success"]
        index = edl.load_index(force=True)
        assert index.match_ip("1.2.3.4")
        assert index.match_ip("203.0.113.55")
        assert index.match_ip("203.0.114.1") == []

    def test_url_exact(self, edl_env, monkeypatch):
        monkeypatch.setattr(
            edl, "_download",
            _fake_download(b"http://bad.example/mal.exe\n"),
        )
        entry = edl.add_list("U", "https://example.com/u")
        assert edl.sync_list(entry["id"])["success"]
        index = edl.load_index(force=True)
        assert index.match_url("http://bad.example/mal.exe")
        assert index.match_url("http://bad.example/otro.exe") == []

    def test_sync_replaces_removed_indicators(self, edl_env, monkeypatch):
        monkeypatch.setattr(edl, "_download", _fake_download(b"old-evil.com\n"))
        entry = edl.add_list("H", "https://example.com/h")
        assert edl.sync_list(entry["id"])["success"]
        assert edl.load_index(force=True).match_domain("old-evil.com")

        monkeypatch.setattr(edl, "_download", _fake_download(b"new-evil.com\n"))
        assert edl.sync_list(entry["id"])["success"]
        index = edl.load_index(force=True)
        assert index.match_domain("new-evil.com")
        assert index.match_domain("old-evil.com") == []

    def test_sync_rejects_empty_list(self, edl_env, monkeypatch):
        monkeypatch.setattr(edl, "_download", _fake_download(b"# solo comentarios\n"))
        entry = edl.add_list("E", "https://example.com/e")
        result = edl.sync_list(entry["id"])
        assert result["success"] is False

    def test_download_requires_https(self, edl_env):
        with pytest.raises(ValueError):
            edl._download("http://example.com/list")


class TestEmailMatching:
    def test_matches_urls_domains_and_ips(self, edl_env, monkeypatch):
        monkeypatch.setattr(
            edl, "_download",
            _fake_download(
                b"evil.com\n1.2.3.4\nhttps://bad.example/x\n"
            ),
        )
        entry = edl.add_list("M", "https://example.com/m")
        assert edl.sync_list(entry["id"])["success"]
        edl.load_index(force=True)

        meta = {
            "urls_found": ["https://evil.com/page", "https://bad.example/x"],
            "clickfix": {
                "payload_urls": [],
                "payload_domains": [],
                "payload_ips": ["1.2.3.4"],
            },
            "raw_headers": {"Received": ["from relay ([8.8.8.8]) by host"]},
        }
        result = edl.match_email_indicators(meta)
        assert result["enabled"] is True
        found = {(m["indicator"], m["kind"]) for m in result["matches"]}
        assert ("evil.com", "domain") in found
        assert ("1.2.3.4", "ip") in found
        assert ("https://bad.example/x", "url") in found

    def test_global_kill_switch(self, edl_env, monkeypatch):
        monkeypatch.setenv("EDL_ENABLED", "false")
        result = edl.match_email_indicators({"urls_found": ["https://evil.com/x"]})
        assert result["enabled"] is False
        assert result["count"] == 0

    def test_no_match_returns_zero(self, edl_env, monkeypatch):
        monkeypatch.setattr(edl, "_download", _fake_download(b"evil.com\n"))
        entry = edl.add_list("N", "https://example.com/n")
        assert edl.sync_list(entry["id"])["success"]
        result = edl.match_email_indicators({"urls_found": ["https://good.test"]})
        assert result["count"] == 0


class TestSchedule:
    def test_due_when_never_synced(self, edl_env):
        edl.set_schedule(auto_enabled=True, default_interval_h=1)
        edl.add_list("S", "https://example.com/s")
        registry = edl.load_registry()
        assert edl.list_is_due(registry["lists"][0], registry["schedule"])

    def test_not_due_right_after_sync(self, edl_env):
        edl.set_schedule(auto_enabled=True, default_interval_h=6)
        edl.add_list("S", "https://example.com/s")
        registry = edl.load_registry()
        registry["lists"][0]["last_sync"] = edl._now_iso()
        edl.save_registry(registry)
        assert not edl.list_is_due(registry["lists"][0], registry["schedule"])

    def test_disabled_auto_is_never_due(self, edl_env):
        edl.set_schedule(auto_enabled=False, default_interval_h=1)
        edl.add_list("S", "https://example.com/s")
        registry = edl.load_registry()
        assert not edl.list_is_due(registry["lists"][0], registry["schedule"])
