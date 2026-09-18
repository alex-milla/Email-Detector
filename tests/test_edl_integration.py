#!/usr/bin/env python3
"""Integración del escalado EDL en el veredicto de predict."""

import os
import sys

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import predict  # noqa: E402


class TestApplyEdl:
    def test_match_forces_malicious_and_risk_floor(self):
        final, risk = predict._apply_edl({"count": 1}, "BENIGNO", 12.0)
        assert final == "MALICIOSO"
        assert risk == 90.0

    def test_no_match_keeps_verdict(self):
        final, risk = predict._apply_edl({"count": 0}, "BENIGNO", 12.0)
        assert final == "BENIGNO"
        assert risk == 12.0

    def test_empty_result_keeps_verdict(self):
        final, risk = predict._apply_edl(None, "MALICIOSO", 95.0)
        assert final == "MALICIOSO"
        assert risk == 95.0
