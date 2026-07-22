import html

from fastapi.testclient import TestClient

from crops_security.main import app
from crops_security.schemas import ScanParameters


def scan_record(target: str) -> dict[str, object]:
    return {
        "id": "scan-001",
        "module_id": "web.sensitive-data-finder",
        "target": target,
        "status": "queued",
        "progress": 0,
        "phase": "Aguardando worker",
        "parameters": {
            "max_urls": 200,
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
        "batch_id": None,
    }


def test_lists_available_modules() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/modules")

    assert response.status_code == 200
    assert response.json()[0]["id"] == "web.sensitive-data-finder"


def test_uses_safe_standard_scan_defaults() -> None:
    parameters = ScanParameters()

    assert parameters.max_urls == 200
    assert parameters.context_chars == 1500


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


def test_queues_multiple_targets_as_one_scope(monkeypatch) -> None:
    queued: list[tuple[str, str]] = []
    created: list[tuple[str, str | None]] = []

    class FakeRedis:
        def lpush(self, queue: str, scan_id: str) -> None:
            queued.append((queue, scan_id))

    def fake_create(_module: str, target: str, _parameters: object, batch_id: str | None = None):
        record = scan_record(target)
        record["id"] = f"scan-{len(created) + 1}"
        record["batch_id"] = batch_id
        created.append((target, batch_id))
        return record

    monkeypatch.setattr("crops_security.main.create_scan", fake_create)
    monkeypatch.setattr("crops_security.main.get_scan", lambda _scan_id: None)
    monkeypatch.setattr("crops_security.main.redis_client", lambda: FakeRedis())

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scan-batches",
            json={
                "module_id": "web.sensitive-data-finder",
                "targets": ["one.example.test", "two.example.test", "one.example.test"],
                "authorized": True,
                "label": "Escopo homologação",
            },
        )

    assert response.status_code == 202
    assert len(response.json()) == 2
    assert created[0][1] == created[1][1]
    assert created[0][1]
    assert queued == [
        ("cropssecurity:scan_queue", "scan-1"),
        ("cropssecurity:scan_queue", "scan-2"),
    ]


def test_exports_original_findings_as_html(monkeypatch) -> None:
    scan = scan_record("https://app.example.test/")
    scan["status"] = "completed"
    finding = {
        "id": "finding-1",
        "scan_id": "scan-001",
        "severity": "high",
        "confidence": "high",
        "category": "Credencial",
        "indicator": "Assignment: password",
        "url": "https://app.example.test/app.js",
        "file_name": "app.js",
        "line": 10,
        "snippet": 'password = "ProductionSecret17"',
        "match_text": 'password = "ProductionSecret17"',
        "created_at": "2026-07-22T12:00:00+00:00",
    }
    monkeypatch.setattr("crops_security.main.get_scan", lambda _scan_id: scan)
    monkeypatch.setattr("crops_security.main.list_findings", lambda _scan_id: [finding])

    with TestClient(app) as client:
        response = client.get("/api/v1/scans/scan-001/export/html")

    assert response.status_code == 200
    assert "Detector de Dados Sensíveis" in response.text
    assert 'password = "ProductionSecret17"' in html.unescape(response.text)
    assert "attachment" in response.headers["content-disposition"]


def test_deletes_finished_scan(monkeypatch) -> None:
    scan = scan_record("https://app.example.test/")
    scan["status"] = "completed"
    deleted: list[str] = []

    def fake_delete(scan_id: str) -> bool:
        deleted.append(scan_id)
        return True

    monkeypatch.setattr("crops_security.main.get_scan", lambda _scan_id: scan)
    monkeypatch.setattr("crops_security.main.delete_scan", fake_delete)

    with TestClient(app) as client:
        response = client.delete("/api/v1/scans/scan-001")

    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "scan_id": "scan-001"}
    assert deleted == ["scan-001"]


def test_rejects_deletion_while_scan_is_active(monkeypatch) -> None:
    scan = scan_record("https://app.example.test/")
    scan["status"] = "running"
    monkeypatch.setattr("crops_security.main.get_scan", lambda _scan_id: scan)

    with TestClient(app) as client:
        response = client.delete("/api/v1/scans/scan-001")

    assert response.status_code == 409
    assert "Cancele" in response.json()["detail"]
