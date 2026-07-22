from fastapi.testclient import TestClient

from crops_security.main import app


def test_health_contract(monkeypatch) -> None:
    monkeypatch.setattr("crops_security.main.database_is_ready", lambda: True)
    monkeypatch.setattr("crops_security.main.redis_is_ready", lambda: True)
    monkeypatch.setattr("crops_security.main.worker_is_ready", lambda: True)

    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "backend": {"status": "online"},
        "database": {"status": "online"},
        "redis": {"status": "online"},
        "worker": {"status": "online"},
    }


def test_health_is_degraded_when_worker_is_offline(monkeypatch) -> None:
    monkeypatch.setattr("crops_security.main.database_is_ready", lambda: True)
    monkeypatch.setattr("crops_security.main.redis_is_ready", lambda: True)
    monkeypatch.setattr("crops_security.main.worker_is_ready", lambda: False)

    with TestClient(app) as client:
        payload = client.get("/api/v1/health").json()

    assert payload["status"] == "degraded"
    assert payload["worker"]["status"] == "offline"
