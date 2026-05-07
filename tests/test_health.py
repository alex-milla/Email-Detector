import os
import json

os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["EMAIL_DETECTOR_RELAX_SCRIPT_CHECK"] = "1"


class TestHealth:
    def test_health_endpoint(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["status"] == "ok"
            assert "version" in data
            assert "timestamp" in data

    def test_health_model_status(self):
        from web.app import app
        with app.test_client() as client:
            resp = client.get("/health")
            data = json.loads(resp.data)
            assert "model_trained" in data
            assert "models_count" in data
