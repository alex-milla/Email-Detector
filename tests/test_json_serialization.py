#!/usr/bin/env python3
"""
Regresión: la metadata de entrenamiento contiene tipos numpy (int32/float32)
que json.dump no serializa por defecto. Los scripts de entrenamiento deben
usar un `default` que los convierta a tipos nativos.
"""

import json
import os

import numpy as np


def test_train_model_json_default_handles_numpy():
    from train_model import _json_default
    data = {
        "int32": np.int32(7),
        "int64": np.int64(9),
        "float32": np.float32(1.5),
        "bool": np.bool_(True),
        "array": np.array([1, 2, 3]),
    }
    out = json.loads(json.dumps(data, default=_json_default))
    assert out == {"int32": 7, "int64": 9, "float32": 1.5, "bool": True, "array": [1, 2, 3]}


def test_train_model_metadata_dump_does_not_raise(tmp_path):
    from train_model import _json_default
    metadata = {
        "auc": np.float32(0.99),
        "total_samples": np.int32(100),
        "results": {"RandomForest": {"confusion_matrix": [[5, 1], [2, 8]],
                                     "calibrated": np.bool_(True)}},
    }
    path = tmp_path / "model_metadata.json"
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2, default=_json_default)
    loaded = json.loads(path.read_text())
    assert loaded["total_samples"] == 100
    assert loaded["results"]["RandomForest"]["calibrated"] is True


def test_train_clanker_json_default_handles_numpy():
    from train_clanker_model import _json_default
    data = {"auc": np.float64(0.5), "n": np.int32(3), "cols": np.array([1, 2])}
    out = json.loads(json.dumps(data, default=_json_default))
    assert out == {"auc": 0.5, "n": 3, "cols": [1, 2]}


def test_write_json_is_atomic(tmp_path):
    from train_model import _write_json
    path = tmp_path / "meta.json"
    _write_json(str(path), {"n": np.int32(5)})
    assert json.loads(path.read_text()) == {"n": 5}
    assert not (tmp_path / "meta.json.tmp").exists()


def test_get_model_meta_tolerates_corrupt_json(tmp_path, monkeypatch):
    from web.services import history_service as hs
    models = tmp_path / "models"
    models.mkdir()
    (models / "model_metadata.json").write_text('{"best_model": "Random')
    monkeypatch.setattr(hs, "PROJECT_DIR", str(tmp_path))
    assert hs.get_model_meta() == {}


def test_load_checksums_tolerates_corrupt_json(tmp_path, monkeypatch):
    import predict
    models = tmp_path / "models"
    models.mkdir()
    (models / "model_checksums.json").write_text("{not json")
    monkeypatch.setattr(predict, "PROJECT_DIR", str(tmp_path))
    assert predict._load_checksums() == {}


def test_predict_email_tolerates_corrupt_metadata(tmp_path, monkeypatch):
    import predict
    bad = tmp_path / "model_metadata.json"
    bad.write_text("{broken")
    monkeypatch.setattr(predict, "METADATA_PATH", str(bad))
    eml = os.path.join(os.path.dirname(__file__), "fixtures", "benign.eml")
    res = predict.predict_email(eml, use_virustotal=False)
    assert "error" in res
