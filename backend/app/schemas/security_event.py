"""Pydantic schemas for security event validation and serialization."""

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SeverityEnum(str, Enum):
    """Valid severity levels for security events."""
    informational = "informational"
    warning = "warning"
    critical = "critical"


class SecurityEventCreate(BaseModel):
    """Schema for creating a new security event."""
    timestamp: datetime = Field(..., description="UTC timestamp of the event")
    device_id: str = Field(..., min_length=1, max_length=128, description="Device identifier")
    event_type: str = Field(..., min_length=1, max_length=64, description="Event classification")
    severity: SeverityEnum = Field(..., description="Event severity level")
    description: str = Field(..., min_length=1, description="Human-readable description")
    source_ip: str | None = Field(None, max_length=45, description="Source IP address")
    request_count: int | None = Field(None, ge=0, description="Associated request count")
    time_window_seconds: int | None = Field(
        None, ge=0, description="Time window in seconds"
    )
    metadata: dict[str, Any] | None = Field(
        None, description="Structured JSON metadata"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """Ensure timestamp is properly parsed."""
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


class SecurityEventResponse(BaseModel):
    """Schema for security event response."""
    id: int
    timestamp: datetime
    device_id: str
    event_type: str
    severity: str
    description: str
    source_ip: str | None
    request_count: int | None
    time_window_seconds: int | None
    metadata: dict[str, Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("metadata", mode="before")
    @classmethod
    def parse_metadata_json(cls, v):
        """Deserialize metadata_json string to dict."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (json.JSONDecodeError, TypeError):
                return None
        return v


class SecurityEventPaginatedResponse(BaseModel):
    """Paginated response for security events."""
    items: list[SecurityEventResponse]
    total: int
    skip: int
    limit: int
