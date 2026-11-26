"""Pydantic schemas for compact edge observations and split-stage correlation."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EdgeObservationCreate(BaseModel):
    """Compact observation sent from the FRDM-RW612 edge node."""
    observation_id: str = Field(..., min_length=1, max_length=64)
    device_id: str = Field(..., min_length=1, max_length=128)
    source_ip: str = Field(..., min_length=1, max_length=45)
    endpoint_id: int = Field(..., ge=0)
    endpoint: str | None = Field(None, max_length=256)
    event_timestamp: datetime = Field(...)
    sequence_num: int = Field(0, ge=0)
    edge_score: int = Field(0, ge=0, le=100)
    triggered_event: str | None = Field(None, max_length=64)
    metadata: dict[str, Any] | None = None

    @field_validator("event_timestamp", mode="before")
    @classmethod
    def parse_ts(cls, v):
        if isinstance(v, str):
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class EdgeObservationBatchCreate(BaseModel):
    """Batch of compact edge observations."""
    observations: list[EdgeObservationCreate] = Field(..., min_length=1, max_length=100)


class EdgeObservationResponse(BaseModel):
    """Response for an ingested and correlated edge observation."""
    id: int
    observation_id: str
    device_id: str
    source_ip: str
    endpoint_id: int
    endpoint: str | None
    event_timestamp: datetime
    sequence_num: int
    edge_score: int
    triggered_event: str | None
    correlation_score: int
    correlation_confidence: float
    transition_fingerprint: str | None
    shared_ip_suspected: bool
    derived_event_id: int | None = None
    duplicate: bool = False

    model_config = {"from_attributes": True}


class EdgeObservationBatchResponse(BaseModel):
    """Batch ingestion summary for compact edge observations."""
    received: int
    inserted: int
    duplicates: int
    acked_ids: list[str] = Field(default_factory=list)
    derived_alerts_created: int = 0
