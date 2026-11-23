"""SQLAlchemy engine/session setup and Alembic upgrades."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from .config import database_url


def make_engine(url: str | None = None):
    url = url or database_url()
    kwargs = {"connect_args": {"check_same_thread": False, "timeout": 30}} if url.startswith("sqlite") else {}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def sqlite_pragmas(connection, _record):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
    return engine


def make_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


def upgrade_to_head(url: str | None = None) -> None:
    here = Path(__file__).resolve().parents[2]
    root = Path(__import__("os").getenv("WGOCTOPUS_MIGRATIONS_PATH", str(here / "migrations")))
    config = Config(__import__("os").getenv("WGOCTOPUS_ALEMBIC_CONFIG", str(here / "alembic.ini")))
    config.set_main_option("script_location", str(root))
    if url:
        config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    elif database_url() != "sqlite:///./wgoctopus.db":
        config.set_main_option("sqlalchemy.url", database_url().replace("%", "%%"))
    command.upgrade(config, "head")
