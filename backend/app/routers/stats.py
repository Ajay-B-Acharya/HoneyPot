"""Dashboard statistics API endpoint."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services import stats_service


class EventsBySeverity(BaseModel):
    """Event counts grouped by severity."""
    informational: int = 0
    warning: int = 0
    critical: int = 0


class RequestsByClassification(BaseModel):
    """Request counts grouped by classification."""
    normal: int = 0
    unusual: int = 0
    suspicious: int = 0


class StatsResponse(BaseModel):
    """Dashboard statistics response."""
    total_requests: int = 0
    normal_requests: int = 0
    unusual_requests: int = 0
    suspicious_requests: int = 0
    total_security_events: int = 0
    events_by_severity: EventsBySeverity = EventsBySeverity()
    requests_by_classification: RequestsByClassification = RequestsByClassification()


router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get(
    "",
    response_model=StatsResponse,
    summary="Dashboard statistics",
    description="Returns aggregated statistics for the dashboard.",
)
async def get_stats(
    db: Session = Depends(get_db),
) -> StatsResponse:
    """Return dashboard statistics."""
    data = stats_service.get_dashboard_stats(db)
    return StatsResponse(
        total_requests=data["total_requests"],
        normal_requests=data["normal_requests"],
        unusual_requests=data["unusual_requests"],
        suspicious_requests=data["suspicious_requests"],
        total_security_events=data["total_security_events"],
        events_by_severity=EventsBySeverity(**data["events_by_severity"]),
        requests_by_classification=RequestsByClassification(**data["requests_by_classification"]),
    )
