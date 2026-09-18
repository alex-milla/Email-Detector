#!/usr/bin/env python3
"""
Regresión: la metadata de entrenamiento contiene tipos numpy (int32/float32)
que json.dump no serializa por defecto. Los scripts de entrenamiento deben
usar un `default` que los convierta a tipos nativos.
"""

import json

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
