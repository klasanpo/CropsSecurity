from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, status

from . import __version__
from .core.scope import ScopeValidationError, normalize_target
from .database import (
    create_scan,
    database_is_ready,
    get_scan,
    initialize_database,
    list_findings,
    list_scans,
    now_iso,
    request_scan_cancel,
    update_scan,
)
from .health import ComponentHealth, HealthResponse, redis_client, redis_is_ready, worker_is_ready
from .schemas import ScanCreate, ScanResponse
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
def scan_findings(scan_id: str) -> list[dict[str, object]]:
    if not get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Execução não encontrada.")
    return list_findings(scan_id)


@app.post("/api/v1/scans/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
def cancel_scan(scan_id: str) -> dict[str, str]:
    if not request_scan_cancel(scan_id):
        raise HTTPException(status_code=409, detail="A execução não pode mais ser cancelada.")
    return {"status": "cancel_requested"}
