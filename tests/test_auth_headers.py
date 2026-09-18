#!/usr/bin/env python3
"""
Tests de cabeceras de autenticación (SPF/DKIM/DMARC/ARC) e informe.

Cubren:
- Parseo tolerante de Authentication-Results / Received-SPF / DKIM-Signature.
- Metadatos de autenticación expuestos por extract_features.
- Penalización de riesgo en predict._analyze_auth.
- Regresión: /api/report no debe fallar cuando virustotal es None.
"""

import email
import os
from email import policy

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("EMAIL_DETECTOR_RELAX_SCRIPT_CHECK", "1")

_RAW_PASS = (
    "From: Alice <alice@example.com>\n"
    "To: Bob <bob@example.com>\n"
    "Authentication-Results: mx.google.com;\n"
    "       dkim=pass header.d=example.com header.s=sel;\n"
    "       spf=pass (google.com: domain of alice@example.com) "
    "smtp.mailfrom=example.com;\n"
    "       dmarc=pass (p=REJECT) header.from=example.com\n"
    "Received-SPF: pass (domain of example.com)\n"
    "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel;\n"
)

_RAW_FAIL = (
    "From: Eve <eve@evil.com>\n"
    "Authentication-Results: mx.example;\n"
    "       spf=fail smtp.mailfrom=evil.com;\n"
    "       dkim=fail header.d=evil.com;\n"
    "       dmarc=fail header.from=evil.com\n"
)


def _msg(raw):
    return email.message_from_string(raw, policy=policy.default)


class TestAuthHeaderParsing:
    def test_all_pass(self):
        from extract_features import _parse_auth_headers
        details, summary, flags = _parse_auth_headers(_msg(_RAW_PASS))
        assert flags["spf_pass"] == 1
        assert flags["dkim_pass"] == 1
        assert flags["dmarc_pass"] == 1
        assert summary["dmarc"]["pass"] == 1
        assert summary["all_pass"] is True

    def test_domains_extracted(self):
        from extract_features import _parse_auth_headers
        details, _, _ = _parse_auth_headers(_msg(_RAW_PASS))
        dmarc = [d for d in details if d["method"] == "dmarc"]
        assert dmarc and dmarc[0]["domain"] == "example.com"
        spf = [d for d in details if d["method"] == "spf"]
        assert any(d["domain"] == "example.com" for d in spf)

    def test_any_fail(self):
        from extract_features import _parse_auth_headers
        _, summary, flags = _parse_auth_headers(_msg(_RAW_FAIL))
        assert flags["spf_pass"] == 0
        assert flags["dkim_pass"] == 0
        assert flags["dmarc_pass"] == 0
        assert summary["any_fail"] is True
        assert summary["dmarc"]["fail"] == 1

    def test_extract_features_includes_auth_metadata(self, tmp_path):
        from extract_features import extract_features_from_eml
        eml = tmp_path / "auth.eml"
        eml.write_text(_RAW_PASS, encoding="utf-8")
        features, metadata = extract_features_from_eml(str(eml))
        assert features["spf_pass"] == 1
        assert features["dkim_pass"] == 1
        assert features["dmarc_pass"] == 1
        assert metadata["auth_results"]
        assert metadata["auth_summary"]["all_pass"] is True
        assert "Authentication-Results" in metadata["raw_headers"]


class TestAuthRiskAnalysis:
    def _summary(self, result):
        return {
            "present": True,
            "spf": {"present": True, "result": result, "pass": 0, "fail": 1},
            "dkim": {"present": True, "result": result, "pass": 0, "fail": 1},
            "dmarc": {"present": True, "result": result, "pass": 0, "fail": 1},
        }

    def test_missing_headers_no_penalty(self):
        from predict import _analyze_auth
        res = _analyze_auth({}, 0.1, 0.5, False)
        assert res["present"] is False
        assert res["risk_penalty"] == 0.0
        assert res["force_malicious"] is False

    def test_dmarc_fail_penalizes(self, monkeypatch):
        monkeypatch.setenv("AUTH_RISK_WEIGHT", "1.0")
        from predict import _analyze_auth
        res = _analyze_auth(self._summary("fail"), 0.5, 0.5, False)
        assert res["risk_penalty"] >= 25.0
        assert res["force_malicious"] is True

    def test_all_pass_no_penalty(self, monkeypatch):
        monkeypatch.setenv("AUTH_RISK_WEIGHT", "1.0")
        from predict import _analyze_auth
        summary = self._summary("pass")
        for method in ("spf", "dkim", "dmarc"):
            summary[method].update({"pass": 1, "fail": 0})
        res = _analyze_auth(summary, 0.5, 0.5, False)
        assert res["risk_penalty"] == 0.0
        assert res["force_malicious"] is False


class TestReportResilience:
    def test_report_with_null_virustotal(self, monkeypatch):
        import web.routes.analysis_routes as ar

        fake = {
            "file": "x.eml", "subject": "Asunto", "from": "a@b.c",
            "timestamp": "2026-01-01T00:00:00", "prediction": "BENIGNO",
            "risk_score": 10, "risk_level": "BAJO", "ml_confidence": 90,
            "model_used": "Ensemble", "virustotal": None,
            "entropy_analysis": None, "features": None, "metadata": None,
        }
        monkeypatch.setattr(ar, "get_history_item", lambda uid, db_id: fake)

        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["username"] = "tester"
            resp = client.get("/api/report/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["virustotal"]["malicious_files"] == 0
        assert data["authentication"]["results"] == []
        assert data["auth_analysis"] == {}

    def test_report_includes_auth_headers(self, monkeypatch):
        import web.routes.analysis_routes as ar

        fake = {
            "file": "y.eml", "subject": "Asunto", "from": "a@b.c",
            "timestamp": "2026-01-01T00:00:00", "prediction": "MALICIOSO",
            "risk_score": 80, "risk_level": "CRITICO", "ml_confidence": 95,
            "model_used": "Ensemble", "virustotal": {"summary": {}},
            "features": {"spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0},
            "auth_analysis": {"warnings": ["DMARC no superado (fail)"],
                              "risk_penalty": 15.0},
            "metadata": {
                "auth_results": [{"method": "dmarc", "result": "fail",
                                  "domain": "evil.com", "server": "mx"}],
                "auth_summary": {"present": True,
                                 "dmarc": {"present": True, "result": "fail"}},
                "raw_headers": {"Authentication-Results": ["mx; dmarc=fail"]},
            },
        }
        monkeypatch.setattr(ar, "get_history_item", lambda uid, db_id: fake)

        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["username"] = "tester"
            resp = client.get("/api/report/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["authentication"]["results"]
        assert data["authentication"]["headers"]
        assert data["auth_analysis"]["warnings"]
