import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(scope="session")
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def benign_eml_path(fixtures_dir):
    return os.path.join(fixtures_dir, "benign.eml")


@pytest.fixture
def malicious_eml_path(fixtures_dir):
    return os.path.join(fixtures_dir, "malicious.eml")


@pytest.fixture
def benign_eml_bytes(benign_eml_path):
    with open(benign_eml_path, "rb") as f:
        return f.read()


@pytest.fixture
def malicious_eml_bytes(malicious_eml_path):
    with open(malicious_eml_path, "rb") as f:
        return f.read()
