#!/usr/bin/env python3
"""
Tests del historial de entrenamientos y del endurecimiento de monitoring.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))


def _isolate_history(monkeypatch, tmp_path):
    import train_model
    hist = tmp_path / "training_history.json"
    monkeypatch.setattr(train_model, "HISTORY_PATH", str(hist))
    return train_model, hist


def test_append_appends_and_trims(monkeypatch, tmp_path):
    train_model, hist = _isolate_history(monkeypatch, tmp_path)
    monkeypatch.setattr(train_model, "HISTORY_MAX_RUNS", 2)
    train_model._append_training_history({"auc": 0.1})
    train_model._append_training_history({"auc": 0.2})
    train_model._append_training_history({"auc": 0.3})
    data = json.loads(hist.read_text())
    assert [d["auc"] for d in data] == [0.2, 0.3]


def test_append_tolerates_corrupt(monkeypatch, tmp_path):
    train_model, hist = _isolate_history(monkeypatch, tmp_path)
    hist.write_text("{broken")
    train_model._append_training_history({"auc": 0.5})
    assert json.loads(hist.read_text()) == [{"auc": 0.5}]


def test_get_training_history_reads(monkeypatch, tmp_path):
    from web.services import training_service as ts
    f = tmp_path / "training_history.json"
    f.write_text("[{\"auc\": 1}, {\"auc\": 2}]")
    monkeypatch.setattr(ts, "TRAINING_HISTORY_FILE", str(f))
    assert ts.get_training_history() == [{"auc": 1}, {"auc": 2}]
    assert ts.get_training_history(limit=1) == [{"auc": 2}]


def test_get_training_history_tolerates_corrupt(monkeypatch, tmp_path):
    from web.services import training_service as ts
    f = tmp_path / "training_history.json"
    f.write_text("{not json")
    monkeypatch.setattr(ts, "TRAINING_HISTORY_FILE", str(f))
    assert ts.get_training_history() == []


def test_get_training_history_missing(monkeypatch, tmp_path):
    from web.services import training_service as ts
    monkeypatch.setattr(ts, "TRAINING_HISTORY_FILE", str(tmp_path / "nope.json"))
    assert ts.get_training_history() == []


def test_load_model_meta_tolerates_corrupt(monkeypatch, tmp_path):
    import web.routes.monitoring_routes as mr
    models = tmp_path / "models"
    models.mkdir()
    (models / "model_metadata.json").write_text("{bad json")
    monkeypatch.setattr(mr, "MODELS_DIR", str(models))
    assert mr._load_model_meta() == {}


def test_load_model_meta_reads_valid(monkeypatch, tmp_path):
    import web.routes.monitoring_routes as mr
    models = tmp_path / "models"
    models.mkdir()
    (models / "model_metadata.json").write_text('{"auc": 0.9}')
    monkeypatch.setattr(mr, "MODELS_DIR", str(models))
    assert mr._load_model_meta() == {"auc": 0.9}
