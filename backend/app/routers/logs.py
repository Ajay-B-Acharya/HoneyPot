"""Request logs API endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.request_log import (
    ClassificationEnum,
    RequestLogCreate,
    RequestLogPaginatedResponse,
    RequestLogResponse,
)
from app.services import log_service

router = APIRouter(prefix="/logs", tags=["Request Logs"])


@router.post(
    "",
    response_model=RequestLogResponse,
    status_code=201,
    summary="Create a request log",
    description="Record a new HTTP request observed by a honeypot device.",
)
async def create_request_log(
    log_data: RequestLogCreate,
    db: Session = Depends(get_db),
) -> RequestLogResponse:
    """Create a new request log entry."""
    db_log = log_service.create_log(db, log_data)
    return RequestLogResponse.model_validate(db_log)


@router.get(
    "",
    response_model=RequestLogPaginatedResponse,
    summary="List request logs",
    description="Retrieve request logs with optional filtering and pagination.",
)
async def list_request_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum records to return"),
    classification: ClassificationEnum | None = Query(None, description="Filter by classification"),
    device_id: str | None = Query(None, description="Filter by device ID"),
    start_time: datetime | None = Query(None, description="Filter logs after this ISO 8601 timestamp"),
    end_time: datetime | None = Query(None, description="Filter logs before this ISO 8601 timestamp"),
    db: Session = Depends(get_db),
) -> RequestLogPaginatedResponse:
    """List request logs with filtering and pagination."""
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=400,
            detail="start_time must be before end_time",
        )

    classification_value = classification.value if classification else None
    logs, total = log_service.get_logs(
        db,
        skip=skip,
        limit=limit,
        classification=classification_value,
        device_id=device_id,
        start_time=start_time,
        end_time=end_time,
    )

    return RequestLogPaginatedResponse(
        items=[RequestLogResponse.model_validate(log) for log in logs],
        total=total,
        skip=skip,
        limit=limit,
    )
