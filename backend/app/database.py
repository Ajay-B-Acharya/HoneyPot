"""Database engine, session, and base model configuration.

Uses SQLAlchemy 2.x with SQLite. Designed to be swappable to PostgreSQL
by changing DATABASE_URL without restructuring the application.
"""

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


def _get_engine():
    """Create the SQLAlchemy engine from settings."""
    settings = get_settings()
    connect_args = {}

    # SQLite-specific: allow multi-threaded access
    if settings.DATABASE_URL.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        settings.DATABASE_URL,
        connect_args=connect_args,
        echo=settings.DEBUG,
    )

    # Enable WAL mode and foreign keys for SQLite
    if settings.DATABASE_URL.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = _get_engine()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session.

    Ensures the session is closed after the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables defined by Base metadata.

    This is a simple initialization mechanism suitable for development.
    For production, replace with Alembic migrations.
    """
    Base.metadata.create_all(bind=engine)
