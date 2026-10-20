"""SQLAlchemy model for security events detected by the honeypot."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityEvent(Base):
    """Represents a security event detected by the honeypot system."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    time_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(
        Text, nullable=True, doc="Structured JSON metadata stored as text"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_security_events_severity", "severity"),
        Index("ix_security_events_timestamp_device", "timestamp", "device_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent(id={self.id}, device_id='{self.device_id}', "
            f"event_type='{self.event_type}', severity='{self.severity}')>"
        )
