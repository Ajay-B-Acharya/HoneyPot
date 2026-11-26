"""Database engine, session, and base model configuration.

Uses SQLAlchemy 2.x with SQLite. Designed to be swappable to PostgreSQL
by changing DATABASE_URL without restructuring the application.
"""

from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
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


def _ensure_schema_columns() -> None:
    """Apply lightweight, idempotent column migrations for existing SQLite tables."""
    inspector = inspect(engine)
    if "security_events" in inspector.get_table_names():
        existing_cols = {col["name"] for col in inspector.get_columns("security_events")}
        if "client_event_id" not in existing_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE security_events ADD COLUMN client_event_id VARCHAR(64)")
                )
                conn.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS ix_security_events_client_event_id "
                        "ON security_events (client_event_id)"
                    )
                )


def init_db() -> None:
    """Create all tables defined by Base metadata.

    This is a simple initialization mechanism suitable for development.
    For production, replace with Alembic migrations.
    """
    Base.metadata.create_all(bind=engine)
    _ensure_schema_columns()
