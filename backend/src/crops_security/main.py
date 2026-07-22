from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .database import database_is_ready, initialize_database
from .health import ComponentHealth, HealthResponse, redis_is_ready, worker_is_ready


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

