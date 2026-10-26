"""Pydantic schemas for request log validation and serialization."""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ClassificationEnum(str, Enum):
    """Valid classification values for request logs."""
    normal = "normal"
    unusual = "unusual"
    suspicious = "suspicious"


VALID_HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
}


class RequestLogCreate(BaseModel):
    """Schema for creating a new request log entry."""
    timestamp: datetime = Field(..., description="UTC timestamp of the observed request")
    device_id: str = Field(..., min_length=1, max_length=128, description="Device identifier")
    source_ip: str | None = Field(None, max_length=45, description="Source IP address")
    method: str = Field(..., min_length=1, max_length=10, description="HTTP method")
    endpoint: str = Field(..., min_length=1, max_length=512, description="Requested path")
    response_code: int | None = Field(None, ge=100, le=599, description="HTTP response code")
    classification: ClassificationEnum = Field(
        ClassificationEnum.normal, description="Request classification"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """Ensure timestamp is properly parsed and timezone-aware UTC."""
        if isinstance(v, str):
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        """Validate and normalize HTTP method."""
        method_clean = v.strip().upper()
        if method_clean not in VALID_HTTP_METHODS:
            raise ValueError(
                f"Invalid HTTP method: '{v}'. Must be a valid standard HTTP method."
            )
        return method_clean

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        """Validate endpoint path format."""
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Endpoint path cannot be empty")
        if not cleaned.startswith("/"):
            raise ValueError("Endpoint must be an absolute path starting with '/'")
        if "\x00" in cleaned or any(ord(c) < 32 for c in cleaned):
            raise ValueError("Endpoint contains invalid control characters")
        return cleaned


class RequestLogResponse(BaseModel):
    """Schema for request log response."""
    id: int
    timestamp: datetime
    device_id: str
    source_ip: str | None
    method: str
    endpoint: str
    response_code: int | None
    classification: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RequestLogPaginatedResponse(BaseModel):
    """Paginated response for request logs."""
    items: list[RequestLogResponse]
    total: int
    skip: int
    limit: int
