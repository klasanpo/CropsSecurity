from fastapi.testclient import TestClient

from crops_security.main import app


def scan_record(target: str) -> dict[str, object]:
    return {
        "id": "scan-001",
        "module_id": "web.sensitive-data-finder",
        "target": target,
        "status": "queued",
        "progress": 0,
        "phase": "Aguardando worker",
        "parameters": {
            "max_urls": 80,
            "depth": 2,
            "timeout_seconds": 10,
            "max_resource_bytes": 2_000_000,
            "include_external": False,
            "verify_tls": True,
            "custom_words": [],
        },
        "pages_scanned": 0,
        "findings_count": 0,
        "error": None,
        "created_at": "2026-07-22T12:00:00+00:00",
        "started_at": None,
        "finished_at": None,
        "cancel_requested": False,
    }


def test_lists_available_modules() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/modules")

    assert response.status_code == 200
    assert response.json()[0]["id"] == "web.sensitive-data-finder"


def test_requires_explicit_authorization() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "module_id": "web.sensitive-data-finder",
                "target": "https://app.example.test",
                "authorized": False,
            },
        )

    assert response.status_code == 422


def test_queues_normalized_authorized_scan(monkeypatch) -> None:
    queued: list[tuple[str, str]] = []

    class FakeRedis:
        def lpush(self, queue: str, scan_id: str) -> None:
            queued.append((queue, scan_id))

    monkeypatch.setattr(
        "crops_security.main.create_scan",
        lambda _module, target, _parameters: scan_record(target),
    )
    monkeypatch.setattr("crops_security.main.redis_client", lambda: FakeRedis())

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "module_id": "web.sensitive-data-finder",
                "target": "WWW.Example.Test/app#fragment",
                "authorized": True,
            },
        )

    assert response.status_code == 202
    assert response.json()["target"] == "https://www.example.test/app"
    assert queued == [("cropssecurity:scan_queue", "scan-001")]
