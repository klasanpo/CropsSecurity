from typing import Literal

from pydantic import BaseModel
from redis import Redis

from .config import settings


class ComponentHealth(BaseModel):
    status: Literal["online", "offline"]


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded"]
    backend: ComponentHealth
    database: ComponentHealth
    redis: ComponentHealth
    worker: ComponentHealth


def redis_client() -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)


def redis_is_ready() -> bool:
    try:
        return bool(redis_client().ping())
    except Exception:
        return False


def worker_is_ready() -> bool:
    try:
        return redis_client().exists("cropssecurity:worker:heartbeat") == 1
    except Exception:
        return False

