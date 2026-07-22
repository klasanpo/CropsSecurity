from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import settings


def create_database_engine(url: str | None = None) -> Engine:
    database_url = url or settings.database_url
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args)


engine = create_database_engine()


def initialize_database() -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS platform_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT OR IGNORE INTO platform_metadata (key, value) "
                "VALUES ('schema_version', '1')"
            )
        )


def database_is_ready() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

