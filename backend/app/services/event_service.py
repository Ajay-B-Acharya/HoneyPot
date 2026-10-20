"""Service layer for security event operations."""

import json
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate


def create_event(db: Session, event_data: SecurityEventCreate) -> SecurityEvent:
    """Create a new security event record.

    Args:
        db: Database session.
        event_data: Validated event creation data.

    Returns:
        The created SecurityEvent ORM instance.
    """
    db_event = SecurityEvent(
        timestamp=event_data.timestamp,
        device_id=event_data.device_id,
        event_type=event_data.event_type,
        severity=event_data.severity.value,
        description=event_data.description,
        source_ip=event_data.source_ip,
        request_count=event_data.request_count,
        time_window_seconds=event_data.time_window_seconds,
        metadata_json=json.dumps(event_data.metadata) if event_data.metadata else None,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def get_events(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    severity: str | None = None,
    event_type: str | None = None,
    device_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[SecurityEvent], int]:
    """Retrieve security events with filtering and pagination.

    Args:
        db: Database session.
        skip: Number of records to skip.
        limit: Maximum number of records to return.
        severity: Filter by severity level.
        event_type: Filter by event type.
        device_id: Filter by device identifier.
        start_time: Filter events after this timestamp.
        end_time: Filter events before this timestamp.

    Returns:
        Tuple of (list of events, total count matching filters).
    """
    query = db.query(SecurityEvent)

    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if device_id:
        query = query.filter(SecurityEvent.device_id == device_id)
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(SecurityEvent.timestamp <= end_time)

    total = query.count()
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()

    return events, total


def count_events_by_severity(db: Session) -> dict[str, int]:
    """Count security events grouped by severity level.

    Returns:
        Dictionary mapping severity levels to their counts.
    """
    results = (
        db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
        .all()
    )
    counts = {"informational": 0, "warning": 0, "critical": 0}
    for severity, count in results:
        counts[severity] = count
    return counts


def count_total_events(db: Session) -> int:
    """Count total number of security events."""
    return db.query(func.count(SecurityEvent.id)).scalar() or 0
