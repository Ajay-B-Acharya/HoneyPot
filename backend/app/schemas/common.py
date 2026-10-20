"""Common/shared Pydantic schemas used across multiple endpoints."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str


class PaginatedResponse(BaseModel):
    """Base paginated response wrapper.

    Subclasses should override the items field with the appropriate type.
    """
    items: list
    total: int
    skip: int
    limit: int


class ErrorResponse(BaseModel):
    """Standard error response format."""
    detail: str
    status_code: int
