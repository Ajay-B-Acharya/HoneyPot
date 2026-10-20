"""Service layer for request log operations."""

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.request_log import RequestLog
from app.schemas.request_log import RequestLogCreate


def create_log(db: Session, log_data: RequestLogCreate) -> RequestLog:
    """Create a new request log record.

    Args:
        db: Database session.
        log_data: Validated log creation data.

    Returns:
        The created RequestLog ORM instance.
    """
    db_log = RequestLog(
        timestamp=log_data.timestamp,
        device_id=log_data.device_id,
        source_ip=log_data.source_ip,
        method=log_data.method,
        endpoint=log_data.endpoint,
        response_code=log_data.response_code,
        classification=log_data.classification.value,
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


def get_logs(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    classification: str | None = None,
    device_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[RequestLog], int]:
    """Retrieve request logs with filtering and pagination.

    Args:
        db: Database session.
        skip: Number of records to skip.
        limit: Maximum number of records to return.
        classification: Filter by classification.
        device_id: Filter by device identifier.
        start_time: Filter logs after this timestamp.
        end_time: Filter logs before this timestamp.

    Returns:
        Tuple of (list of logs, total count matching filters).
    """
    query = db.query(RequestLog)

    if classification:
        query = query.filter(RequestLog.classification == classification)
    if device_id:
        query = query.filter(RequestLog.device_id == device_id)
    if start_time:
        query = query.filter(RequestLog.timestamp >= start_time)
    if end_time:
        query = query.filter(RequestLog.timestamp <= end_time)

    total = query.count()
    logs = query.order_by(RequestLog.timestamp.desc()).offset(skip).limit(limit).all()

    return logs, total


def count_by_classification(db: Session) -> dict[str, int]:
    """Count request logs grouped by classification.

    Returns:
        Dictionary mapping classification values to their counts.
    """
    results = (
        db.query(RequestLog.classification, func.count(RequestLog.id))
        .group_by(RequestLog.classification)
        .all()
    )
    counts = {"normal": 0, "unusual": 0, "suspicious": 0}
    for classification, count in results:
        counts[classification] = count
    return counts


def count_total_requests(db: Session) -> int:
    """Count total number of request logs."""
    return db.query(func.count(RequestLog.id)).scalar() or 0
