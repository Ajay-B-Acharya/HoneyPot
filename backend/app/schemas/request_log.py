"""Pydantic schemas for request log validation and serialization."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ClassificationEnum(str, Enum):
    """Valid classification values for request logs."""
    normal = "normal"
    unusual = "unusual"
    suspicious = "suspicious"


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
        """Ensure timestamp is properly parsed."""
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


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
