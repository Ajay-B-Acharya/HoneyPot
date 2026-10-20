"""SQLAlchemy model for HTTP request logs captured by the honeypot."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RequestLog(Base):
    """Represents an HTTP request observed by the honeypot device."""

    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classification: Mapped[str] = mapped_column(
        String(20), nullable=False, default="normal"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_request_logs_classification", "classification"),
        Index("ix_request_logs_timestamp_device", "timestamp", "device_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<RequestLog(id={self.id}, device_id='{self.device_id}', "
            f"method='{self.method}', endpoint='{self.endpoint}', "
            f"classification='{self.classification}')>"
        )
