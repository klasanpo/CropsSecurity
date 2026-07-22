import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import settings
from .core.findings import Finding


def create_database_engine(url: str | None = None) -> Engine:
    database_url = url or settings.database_url
    connect_args = (
        {"check_same_thread": False, "timeout": 30} if database_url.startswith("sqlite") else {}
    )
    return create_engine(database_url, connect_args=connect_args)


engine = create_database_engine()


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def initialize_database() -> None:
    statements = (
        "CREATE TABLE IF NOT EXISTS platform_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            module_id TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL,
            parameters_json TEXT NOT NULL,
            pages_scanned INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            category TEXT NOT NULL,
            indicator TEXT NOT NULL,
            url TEXT NOT NULL,
            file_name TEXT NOT NULL,
            line INTEGER NOT NULL,
            snippet TEXT NOT NULL,
            match_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )""",
        "CREATE INDEX IF NOT EXISTS scan_runs_created_at_idx ON scan_runs(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id)",
        "CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings(severity)",
    )
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(
            text(
                "INSERT OR IGNORE INTO platform_metadata "
                "(key, value) VALUES ('schema_version', '2')"
            )
        )
        connection.execute(
            text("UPDATE platform_metadata SET value = '2' WHERE key = 'schema_version'")
        )


def database_is_ready() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def create_scan(module_id: str, target: str, parameters: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(uuid4())
    created_at = now_iso()
    with engine.begin() as connection:
        connection.execute(
            text(
                """INSERT INTO scan_runs
                (id, module_id, target, status, progress, phase, parameters_json, created_at)
                VALUES (:id, :module_id, :target, 'queued', 0,
                        'Aguardando worker', :parameters, :created_at)"""
            ),
            {
                "id": scan_id,
                "module_id": module_id,
                "target": target,
                "parameters": json.dumps(parameters, ensure_ascii=False),
                "created_at": created_at,
            },
        )
    return get_scan(scan_id) or {}


def _scan_row(row: Any) -> dict[str, Any]:
    result = dict(row._mapping)
    result["parameters"] = json.loads(result.pop("parameters_json"))
    result["cancel_requested"] = bool(result["cancel_requested"])
    return result


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT * FROM scan_runs WHERE id = :id"), {"id": scan_id}
        ).first()
    return _scan_row(row) if row else None


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT :limit"), {"limit": limit}
        ).all()
    return [_scan_row(row) for row in rows]


def update_scan(scan_id: str, **fields: Any) -> None:
    allowed = {
        "status",
        "progress",
        "phase",
        "pages_scanned",
        "findings_count",
        "error",
        "started_at",
        "finished_at",
        "cancel_requested",
    }
    values = {key: value for key, value in fields.items() if key in allowed}
    if not values:
        return
    assignments = ", ".join(f"{key} = :{key}" for key in values)
    values["id"] = scan_id
    with engine.begin() as connection:
        connection.execute(text(f"UPDATE scan_runs SET {assignments} WHERE id = :id"), values)


def save_findings(scan_id: str, findings: tuple[Finding, ...]) -> None:
    if not findings:
        return
    created_at = now_iso()
    payload = [
        {"id": str(uuid4()), "scan_id": scan_id, "created_at": created_at, **finding.as_dict()}
        for finding in findings
    ]
    with engine.begin() as connection:
        connection.execute(
            text(
                """INSERT INTO findings
                (id, scan_id, severity, confidence, category, indicator, url, file_name, line,
                 snippet, match_text, created_at)
                VALUES (:id, :scan_id, :severity, :confidence, :category, :indicator, :url,
                        :file_name, :line, :snippet, :match_text, :created_at)"""
            ),
            payload,
        )


def list_findings(scan_id: str) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    """SELECT * FROM findings WHERE scan_id = :scan_id
                ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, url, line"""
                ),
                {"scan_id": scan_id},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


def request_scan_cancel(scan_id: str) -> bool:
    scan = get_scan(scan_id)
    if not scan or scan["status"] in {"completed", "failed", "cancelled"}:
        return False
    update_scan(scan_id, cancel_requested=1, phase="Cancelamento solicitado")
    return True


def scan_cancelled(scan_id: str) -> bool:
    scan = get_scan(scan_id)
    return bool(scan and scan["cancel_requested"])
