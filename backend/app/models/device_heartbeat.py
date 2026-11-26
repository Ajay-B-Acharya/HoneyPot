"""SQLAlchemy model for physical FRDM-RW612 device heartbeats."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class DeviceHeartbeat(Base):
    """Stores the latest physical heartbeat state for a registered honeypot device."""

    __tablename__ = "device_heartbeats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    device_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    wifi_connected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    uptime_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    free_heap_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    firmware_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    heartbeat_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
