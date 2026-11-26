"""SQLAlchemy model for Behavioral IP Profiles captured by the honeypot."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IPProfile(Base):
    """Represents a behavioral security profile for a source IP address."""

    __tablename__ = "ip_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    total_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_requests: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    repeated_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_endpoints_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    endpoints_json: Mapped[str | None] = mapped_column(
        Text, nullable=True, doc="JSON list of unique endpoints visited"
    )
    request_frequency: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, doc="Calculated requests per minute"
    )
    threat_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, doc="Dynamic threat score 0-100"
    )
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="low", index=True
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
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

    __table_args__ = (
        Index("ix_ip_profiles_threat_score", "threat_score"),
        Index("ix_ip_profiles_last_seen", "last_seen"),
    )

    def __repr__(self) -> str:
        return (
            f"<IPProfile(ip='{self.ip_address}', threat_score={self.threat_score}, "
            f"risk_level='{self.risk_level}', total_requests={self.total_requests})>"
        )
