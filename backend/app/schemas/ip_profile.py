"""Pydantic schemas for Behavioral IP Profiles."""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class RiskLevelEnum(str, Enum):
    """Risk levels for IP profiles."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IPProfileResponse(BaseModel):
    """Schema representing an IP behavioral profile response."""

    id: int = Field(..., description="Unique profile identifier")
    ip_address: str = Field(..., description="Source IPv4 or IPv6 address")
    device_id: str = Field(..., description="Target honeypot device identifier")
    total_requests: int = Field(..., description="Total requests observed from this IP")
    suspicious_requests: int = Field(
        ..., description="Number of suspicious / rule-violating requests"
    )
    repeated_requests: int = Field(
        ..., description="Number of repeated identical requests"
    )
    unique_endpoints_count: int = Field(
        ..., description="Count of distinct endpoints targeted"
    )
    unique_endpoints: list[str] = Field(
        default_factory=list, description="List of unique endpoints targeted"
    )
    request_frequency: float = Field(
        ..., description="Estimated request frequency (req/min)"
    )
    threat_score: int = Field(
        ..., ge=0, le=100, description="Dynamic threat score between 0 and 100"
    )
    risk_level: RiskLevelEnum = Field(..., description="Calculated threat risk category")
    first_seen: datetime = Field(..., description="UTC timestamp of first request")
    last_seen: datetime = Field(..., description="UTC timestamp of most recent activity")
    is_active: bool = Field(..., description="Whether profile is considered actively monitored")
    created_at: datetime = Field(..., description="Record creation timestamp")
    updated_at: datetime = Field(..., description="Record last updated timestamp")

    model_config = ConfigDict(from_attributes=True)


class IPProfilePaginatedResponse(BaseModel):
    """Paginated list response for IP profiles."""

    items: list[IPProfileResponse] = Field(..., description="List of IP profiles")
    total: int = Field(..., description="Total matching records count")
    skip: int = Field(..., description="Records skipped")
    limit: int = Field(..., description="Max records per page")


class IPProfileSummary(BaseModel):
    """High-level summary statistics of monitored IP profiles."""

    total_profiles: int = Field(..., description="Total unique source IPs profiled")
    active_profiles: int = Field(..., description="Currently active IP profiles")
    critical_threats: int = Field(..., description="IPs with critical risk (score >= 90)")
    high_threats: int = Field(..., description="IPs with high risk (score 70-89)")
    medium_threats: int = Field(..., description="IPs with medium risk (score 30-69)")
    low_threats: int = Field(..., description="IPs with low risk (score < 30)")
    top_threat_ip: str | None = Field(None, description="IP with highest threat score")
    max_threat_score: int = Field(0, description="Highest threat score recorded")
