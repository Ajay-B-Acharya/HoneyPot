"""Service layer for security event operations."""

import json
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.security_event import (
    BatchSyncResponse,
    SecurityEventBatchCreate,
    SecurityEventCreate,
)


def create_event(db: Session, event_data: SecurityEventCreate) -> SecurityEvent:
    """Create a new security event record.

    Args:
        db: Database session.
        event_data: Validated event creation data.

    Returns:
        The created SecurityEvent ORM instance.
    """
    if event_data.client_event_id:
        existing = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.client_event_id == event_data.client_event_id)
            .first()
        )
        if existing:
            return existing

    meta = dict(event_data.metadata or {})
    if event_data.client_event_id:
        meta["client_event_id"] = event_data.client_event_id

    db_event = SecurityEvent(
        client_event_id=event_data.client_event_id,
        timestamp=event_data.timestamp,
        device_id=event_data.device_id,
        event_type=event_data.event_type,
        severity=event_data.severity.value,
        description=event_data.description,
        source_ip=event_data.source_ip,
        request_count=event_data.request_count,
        time_window_seconds=event_data.time_window_seconds,
        metadata_json=json.dumps(meta) if meta else None,
    )
    db.add(db_event)
    try:
        db.commit()
        db.refresh(db_event)
        return db_event
    except IntegrityError:
        db.rollback()
        if event_data.client_event_id:
            existing = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.client_event_id == event_data.client_event_id)
                .first()
            )
            if existing:
                return existing
        raise


def create_events_batch(
    db: Session, batch: SecurityEventBatchCreate
) -> BatchSyncResponse:
    """Batch reconcile security events idempotently with per-item savepoints.

    Supports partial batch failures and intra-batch / concurrent duplicates
    while returning explicit acknowledged and failed client_event_id lists.
    """
    inserted = 0
    duplicates = 0
    acked_ids: list[str] = []
    failed_ids: list[str] = []

    for item in batch.events:
        cid = item.client_event_id
        if cid:
            existing = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.client_event_id == cid)
                .first()
            )
            if existing:
                duplicates += 1
                acked_ids.append(cid)
                continue

        meta = dict(item.metadata or {})
        if cid:
            meta["client_event_id"] = cid

        db_event = SecurityEvent(
            client_event_id=cid,
            timestamp=item.timestamp,
            device_id=item.device_id,
            event_type=item.event_type,
            severity=item.severity.value,
            description=item.description,
            source_ip=item.source_ip,
            request_count=item.request_count,
            time_window_seconds=item.time_window_seconds,
            metadata_json=json.dumps(meta) if meta else None,
        )
        try:
            with db.begin_nested():
                db.add(db_event)
                db.flush()
            inserted += 1
            if cid:
                acked_ids.append(cid)
        except IntegrityError:
            duplicates += 1
            if cid:
                acked_ids.append(cid)
        except Exception:
            if cid:
                failed_ids.append(cid)

    db.commit()
    status = "reconciled" if not failed_ids else "partial"
    return BatchSyncResponse(
        received=len(batch.events),
        inserted=inserted,
        duplicates=duplicates,
        acked_ids=acked_ids,
        failed_ids=failed_ids,
        status=status,
    )


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
    events = query.order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).offset(skip).limit(limit).all()

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


def delete_event(db: Session, event_id: int) -> bool:
    """Delete a single security event by ID.

    Returns:
        True if the event existed and was deleted, False otherwise.
    """
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if event is None:
        return False
    db.delete(event)
    db.commit()
    return True


def clear_events(db: Session, severity: str | None = None) -> int:
    """Delete security events, optionally filtered by severity.

    Returns:
        Number of deleted events.
    """
    query = db.query(SecurityEvent)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    deleted_count = query.delete(synchronize_session=False)
    db.commit()
    return int(deleted_count)
