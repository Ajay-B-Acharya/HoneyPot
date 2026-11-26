"""SQLAlchemy model for compact edge observations from FRDM-RW612."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeObservation(Base):
    """Represents a compact request/threat observation sent from the edge MCU."""

    __tablename__ = "edge_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observation_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    endpoint_id: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(256), nullable=True)
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    sequence_num: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triggered_event: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    transition_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    shared_ip_suspected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_edge_obs_ip_ts", "source_ip", "event_timestamp", "sequence_num"),
    )
