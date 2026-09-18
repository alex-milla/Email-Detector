#!/usr/bin/env python3
"""
Tests de robustez de la carga de modelos en predict.load_all_models.

Evita el IndexError/TypeError cuando model_metadata.json no define
'models_available' o no hay ningún modelo cargable.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


def _isolate(monkeypatch, tmp_path):
    import predict
    monkeypatch.setattr(predict, "ALL_MODELS_DIR", str(tmp_path / "no_models"))
    monkeypatch.setattr(predict, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    return predict


def test_metadata_without_models_available(monkeypatch, tmp_path):
    predict = _isolate(monkeypatch, tmp_path)
    assert predict.load_all_models({}) == {}


def test_models_available_none(monkeypatch, tmp_path):
    predict = _isolate(monkeypatch, tmp_path)
    assert predict.load_all_models({"models_available": None}) == {}


def test_only_disabled_models(monkeypatch, tmp_path):
    predict = _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(predict, "get_disabled_models", lambda: {"m1"})
    assert predict.load_all_models({"models_available": ["m1"]}) == {}


def test_corrupt_base_model_does_not_raise(monkeypatch, tmp_path):
    predict = _isolate(monkeypatch, tmp_path)
    bad = tmp_path / "email_classifier.joblib"
    bad.write_bytes(b"not a joblib file")
    monkeypatch.setattr(predict, "MODEL_PATH", str(bad))
    assert predict.load_all_models({}) == {}


def test_apply_clickfix_high_confidence_escalates():
    import predict
    final, risk = predict._apply_clickfix({"high_confidence": True}, "BENIGNO", 5.0)
    assert final == "MALICIOSO"
    assert risk >= 90.0


def test_apply_clickfix_low_confidence_keeps_verdict():
    import predict
    final, risk = predict._apply_clickfix(
        {"high_confidence": False, "clickfix_detected": True}, "BENIGNO", 12.0)
    assert final == "BENIGNO"
    assert risk == 12.0


def test_apply_clickfix_none_safe():
    import predict
    final, risk = predict._apply_clickfix(None, "BENIGNO", 3.0)
    assert final == "BENIGNO"
    assert risk == 3.0
