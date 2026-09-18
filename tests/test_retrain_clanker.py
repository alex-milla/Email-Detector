#!/usr/bin/env python3
"""
Tests para el orquestador retrain_clanker.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from retrain_clanker import resolve_csvs  # noqa: E402


class TestResolveCsvs:
    def test_explicit_takes_precedence(self, tmp_path):
        assert resolve_csvs(str(tmp_path), explicit=["a.csv", "b.csv"]) == ["a.csv", "b.csv"]

    def test_no_csv_returns_none(self, tmp_path):
        assert resolve_csvs(str(tmp_path)) is None

    def test_uses_processed_csvs(self, tmp_path):
        csv = tmp_path / "features.csv"
        csv.write_text("label,clanker_weighted_score\n0,0.0\n", encoding="utf-8")
        result = resolve_csvs(str(tmp_path))
        assert result == [str(csv)]

    def test_synthetic_forces_generation(self, tmp_path):
        csv = tmp_path / "features.csv"
        csv.write_text("label,clanker_weighted_score\n0,0.0\n", encoding="utf-8")
        assert resolve_csvs(str(tmp_path), synthetic=True) is None

    def test_explicit_wins_over_synthetic(self, tmp_path):
        assert resolve_csvs(str(tmp_path), explicit=["x.csv"], synthetic=True) == ["x.csv"]
