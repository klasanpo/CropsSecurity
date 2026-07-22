from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Response, status

from . import __version__
from .core.scope import ScopeValidationError, normalize_target
from .database import (
    create_scan,
    database_is_ready,
    delete_scan,
    get_scan,
    initialize_database,
    list_findings,
    list_scans,
    now_iso,
    request_scan_cancel,
    update_scan,
)
from .health import ComponentHealth, HealthResponse, redis_client, redis_is_ready, worker_is_ready
from .reporting import findings_csv, findings_html, findings_json
from .schemas import ScanBatchCreate, ScanCreate, ScanResponse
from .tools.registry import MODULES, list_modules


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


app = FastAPI(title="CropsSecurity API", version=__version__, lifespan=lifespan)


@app.get("/api/v1/health", response_model=HealthResponse, tags=["platform"])
def health() -> HealthResponse:
    database_ok = database_is_ready()
    redis_ok = redis_is_ready()
    worker_ok = worker_is_ready()
    return HealthResponse(
        status="healthy" if database_ok and redis_ok and worker_ok else "degraded",
        backend=ComponentHealth(status="online"),
        database=ComponentHealth(status="online" if database_ok else "offline"),
        redis=ComponentHealth(status="online" if redis_ok else "offline"),
        worker=ComponentHealth(status="online" if worker_ok else "offline"),
    )


@app.get("/api/v1/modules", tags=["modules"])
def modules() -> list[dict[str, object]]:
    return list_modules()


@app.post(
    "/api/v1/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["scans"],
)
def start_scan(payload: ScanCreate) -> dict[str, object]:
    if payload.module_id not in MODULES:
        raise HTTPException(status_code=404, detail="Módulo não encontrado.")
    try:
        target = normalize_target(payload.target)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = create_scan(payload.module_id, target.url, payload.parameters.model_dump())
    try:
        redis_client().lpush("cropssecurity:scan_queue", scan["id"])
    except Exception as exc:
        update_scan(
            str(scan["id"]),
            status="failed",
            phase="Fila indisponível",
            error="Não foi possível encaminhar a análise ao worker.",
            finished_at=now_iso(),
        )
        raise HTTPException(
            status_code=503, detail="A fila de execução está indisponível."
        ) from exc
    return scan


@app.post(
    "/api/v1/scan-batches",
    response_model=list[ScanResponse],
    status_code=status.HTTP_202_ACCEPTED,
    tags=["scans"],
)
def start_scan_batch(payload: ScanBatchCreate) -> list[dict[str, object]]:
    if payload.module_id not in MODULES:
        raise HTTPException(status_code=404, detail="Módulo não encontrado.")
    normalized_targets = []
    try:
        for raw_target in payload.targets:
            target = normalize_target(raw_target)
            if target.url not in normalized_targets:
                normalized_targets.append(target.url)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    batch_id = str(uuid4())
    parameters = payload.parameters.model_dump()
    if payload.label:
        parameters["batch_label"] = payload.label.strip()
    scans = [
        create_scan(payload.module_id, target, parameters, batch_id=batch_id)
        for target in normalized_targets
    ]
    try:
        client = redis_client()
        for scan in scans:
            client.lpush("cropssecurity:scan_queue", scan["id"])
    except Exception as exc:
        for scan in scans:
            update_scan(
                str(scan["id"]),
                status="failed",
                phase="Fila indisponível",
                error="Não foi possível encaminhar o escopo ao worker.",
                finished_at=now_iso(),
            )
        raise HTTPException(
            status_code=503, detail="A fila de execução está indisponível."
        ) from exc
    return [get_scan(str(scan["id"])) or scan for scan in scans]


@app.get("/api/v1/scans", response_model=list[ScanResponse], tags=["scans"])
def scans(limit: int = Query(default=20, ge=1, le=100)) -> list[dict[str, object]]:
    return list_scans(limit)


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
def scan_detail(scan_id: str) -> dict[str, object]:
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Execução não encontrada.")
    return scan


@app.get("/api/v1/scans/{scan_id}/findings", tags=["scans"])
def scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|informative)$"),
    indicator: str | None = Query(default=None, max_length=120),
    search: str | None = Query(default=None, max_length=120),
) -> list[dict[str, object]]:
    if not get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Execução não encontrada.")
    return list_findings(scan_id, severity=severity, indicator=indicator, search=search)


@app.get("/api/v1/scans/{scan_id}/export/{export_format}", tags=["scans"])
def export_scan(scan_id: str, export_format: str) -> Response:
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Execução não encontrada.")
    findings = list_findings(scan_id)
    formats = {
        "json": (findings_json(scan, findings), "application/json", "json"),
        "csv": ("\ufeff" + findings_csv(findings), "text/csv; charset=utf-8", "csv"),
        "html": (findings_html(scan, findings), "text/html; charset=utf-8", "html"),
    }
    if export_format not in formats:
        raise HTTPException(status_code=404, detail="Formato disponível: HTML, CSV ou JSON.")
    content, media_type, extension = formats[export_format]
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="crops-sensitive-{scan_id}.{extension}"'
        },
    )


@app.get("/api/v1/scans/{scan_id}/comparison/{baseline_id}", tags=["scans"])
def compare_scans(scan_id: str, baseline_id: str) -> dict[str, object]:
    current = get_scan(scan_id)
    baseline = get_scan(baseline_id)
    if not current or not baseline:
        raise HTTPException(status_code=404, detail="Execução de teste ou reteste não encontrada.")
    if current["module_id"] != baseline["module_id"]:
        raise HTTPException(status_code=422, detail="As execuções precisam usar o mesmo módulo.")

    def fingerprint(item: dict[str, object]) -> tuple[object, ...]:
        return (
            item["indicator"],
            item["url"],
            item["file_name"],
            item["line"],
            item["match_text"],
        )

    current_items = {fingerprint(item): item for item in list_findings(scan_id)}
    baseline_items = {fingerprint(item): item for item in list_findings(baseline_id)}
    new_keys = current_items.keys() - baseline_items.keys()
    resolved_keys = baseline_items.keys() - current_items.keys()
    persistent_keys = current_items.keys() & baseline_items.keys()
    return {
        "current_scan_id": scan_id,
        "baseline_scan_id": baseline_id,
        "new": [current_items[key] for key in new_keys],
        "resolved": [baseline_items[key] for key in resolved_keys],
        "persistent": [current_items[key] for key in persistent_keys],
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "persistent": len(persistent_keys),
        },
    }


@app.post("/api/v1/scans/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
def cancel_scan(scan_id: str) -> dict[str, str]:
    if not request_scan_cancel(scan_id):
        raise HTTPException(status_code=409, detail="A execução não pode mais ser cancelada.")
    return {"status": "cancel_requested"}


@app.delete("/api/v1/scans/{scan_id}", tags=["scans"])
def remove_scan(scan_id: str) -> dict[str, str]:
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Execução não encontrada.")
    if scan["status"] in {"queued", "running"}:
        raise HTTPException(
            status_code=409,
            detail="Cancele e aguarde o encerramento antes de excluir esta execução.",
        )
    if not delete_scan(scan_id):
        raise HTTPException(status_code=409, detail="A execução não pôde ser excluída.")
    return {"status": "deleted", "scan_id": scan_id}
