"""Security events API endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventPaginatedResponse,
    SecurityEventResponse,
    SeverityEnum,
)
from app.services import event_service

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.post(
    "",
    response_model=SecurityEventResponse,
    status_code=201,
    summary="Create a security event",
    description="Record a new security event detected by a honeypot device.",
)
async def create_security_event(
    event_data: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEventResponse:
    """Create a new security event."""
    db_event = event_service.create_event(db, event_data)
    # Build response, mapping metadata_json to metadata
    response_data = {
        "id": db_event.id,
        "timestamp": db_event.timestamp,
        "device_id": db_event.device_id,
        "event_type": db_event.event_type,
        "severity": db_event.severity,
        "description": db_event.description,
        "source_ip": db_event.source_ip,
        "request_count": db_event.request_count,
        "time_window_seconds": db_event.time_window_seconds,
        "metadata": db_event.metadata_json,
        "created_at": db_event.created_at,
    }
    return SecurityEventResponse.model_validate(response_data)


@router.get(
    "",
    response_model=SecurityEventPaginatedResponse,
    summary="List security events",
    description="Retrieve security events with optional filtering and pagination.",
)
async def list_security_events(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    severity: SeverityEnum | None = Query(None, description="Filter by severity"),
    event_type: str | None = Query(None, description="Filter by event type"),
    device_id: str | None = Query(None, description="Filter by device ID"),
    start_time: datetime | None = Query(None, description="Filter events after this ISO 8601 timestamp"),
    end_time: datetime | None = Query(None, description="Filter events before this ISO 8601 timestamp"),
    db: Session = Depends(get_db),
) -> SecurityEventPaginatedResponse:
    """List security events with filtering and pagination."""
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=400,
            detail="start_time must be before end_time",
        )

    severity_value = severity.value if severity else None
    events, total = event_service.get_events(
        db,
        skip=skip,
        limit=limit,
        severity=severity_value,
        event_type=event_type,
        device_id=device_id,
        start_time=start_time,
        end_time=end_time,
    )

    items = []
    for e in events:
        items.append(SecurityEventResponse.model_validate({
            "id": e.id,
            "timestamp": e.timestamp,
            "device_id": e.device_id,
            "event_type": e.event_type,
            "severity": e.severity,
            "description": e.description,
            "source_ip": e.source_ip,
            "request_count": e.request_count,
            "time_window_seconds": e.time_window_seconds,
            "metadata": e.metadata_json,
            "created_at": e.created_at,
        }))

    return SecurityEventPaginatedResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
    )
