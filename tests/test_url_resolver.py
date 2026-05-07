#!/usr/bin/env python3
"""
Tests para url_resolver.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


def test_shortener_detection():
    from url_resolver import is_shortener

    assert is_shortener("https://bit.ly/3xyZ") is True
    assert is_shortener("https://t.co/abc123") is True
    assert is_shortener("https://example.com") is False
    assert is_shortener("https://sub.domain.example.org/path") is False


def test_shortener_with_port():
    from url_resolver import is_shortener

    assert is_shortener("https://bit.ly:8080/3xyZ") is True


def test_invalid_url():
    from url_resolver import resolve_url

    result = resolve_url("not-a-url", use_js=False)
    assert result["error"] == "URL inválida"
    assert result["hop_count"] == 0


def test_ssrf_private_ip_blocked():
    from url_resolver import resolve_url

    result = resolve_url("http://192.168.1.1/admin", use_js=False)
    assert "SSRF" in result.get("error", "")


def test_ssrf_loopback_blocked():
    from url_resolver import resolve_url

    result = resolve_url("http://127.0.0.1/secret", use_js=False)
    assert "SSRF" in result.get("error", "")


def test_ssrf_localhost_blocked():
    from url_resolver import resolve_url

    result = resolve_url("http://localhost/api", use_js=False)
    assert "SSRF" in result.get("error", "")


def test_valid_public_url():
    from url_resolver import resolve_url

    # httpbin.org/redirect/1 hace 1 redirect a /get
    result = resolve_url("https://httpbin.org/redirect/1", use_js=False)
    # Puede fallar por red, pero no debe dar error SSRF
    error_msg = result.get("error") or ""
    assert "SSRF" not in error_msg


def test_meta_refresh_detection():
    from url_resolver import _detect_meta_refresh

    html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
    assert _detect_meta_refresh(html, "https://start.com") == "https://evil.com"

    html2 = '<meta http-equiv="refresh" content="5; URL=https://example.com/path">'
    assert _detect_meta_refresh(html2, "https://start.com") == "https://example.com/path"


def test_meta_refresh_no_match():
    from url_resolver import _detect_meta_refresh

    html = '<meta charset="utf-8">'
    assert _detect_meta_refresh(html, "https://start.com") is None


def test_is_safe_url_private():
    from url_resolver import _is_safe_url

    assert _is_safe_url("http://192.168.1.1") is False
    assert _is_safe_url("http://10.0.0.1") is False
    assert _is_safe_url("http://127.0.0.1") is False
    assert _is_safe_url("http://172.16.0.1") is False


def test_is_safe_url_public():
    from url_resolver import _is_safe_url

    # Nota: esto requiere resolución DNS, puede fallar sin internet
    # pero asumimos que httpbin.org resuelve a IP pública
    result = _is_safe_url("https://httpbin.org/get")
    assert result is True
