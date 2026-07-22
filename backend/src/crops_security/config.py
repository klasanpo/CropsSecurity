from dataclasses import dataclass
from os import getenv


@dataclass(frozen=True)
class Settings:
    database_url: str = getenv("DATABASE_URL", "sqlite:///./cropssecurity.db")
    redis_url: str = getenv("REDIS_URL", "redis://localhost:6379/0")


settings = Settings()
