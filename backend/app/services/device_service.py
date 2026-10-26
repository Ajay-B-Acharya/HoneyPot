"""Service layer for device status operations.

Note: Device status is derived from recorded activity (request logs and
security events). The 'status' field reflects when the device was last
seen, NOT whether the device is currently reachable. A device shown as
'active' simply means it has been seen recently; it does not guarantee
real-time connectivity. A device shown as 'inactive' has not sent data
within the configured threshold. 'unknown' means the device has no
recorded activity.

For reliable device connectivity monitoring, implement a dedicated
heartbeat or health-check mechanism.
"""

from datetime import datetime, timezone

from sqlalchemy import func, union_all, literal_column
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.request_log import RequestLog
from app.models.security_event import SecurityEvent


def _to_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetime to UTC timezone-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _update_device_map(
    device_map: dict[str, datetime | None],
    device_id: str,
    last_seen: datetime | None,
) -> None:
    """Safely update device last_seen timestamp in the map."""
    utc_seen = _to_utc(last_seen)
    if device_id not in device_map:
        device_map[device_id] = utc_seen
    elif utc_seen is not None:
        existing = device_map[device_id]
        if existing is None or utc_seen > existing:
            device_map[device_id] = utc_seen


def get_device_statuses(db: Session) -> list[dict]:
    """Get status information for all known devices.

    Derives device status from the most recent activity across both
    request logs and security events.

    Returns:
        List of device status dictionaries.
    """
    settings = get_settings()
    threshold_seconds = settings.DEVICE_INACTIVE_THRESHOLD_SECONDS

    # Get last-seen timestamps from request logs
    log_devices = (
        db.query(
            RequestLog.device_id,
            func.max(RequestLog.timestamp).label("last_seen"),
        )
        .group_by(RequestLog.device_id)
        .all()
    )

    # Get last-seen timestamps from security events
    event_devices = (
        db.query(
            SecurityEvent.device_id,
            func.max(SecurityEvent.timestamp).label("last_seen"),
        )
        .group_by(SecurityEvent.device_id)
        .all()
    )

    # Merge device data safely
    device_map: dict[str, datetime | None] = {}
    for device_id, last_seen in log_devices:
        _update_device_map(device_map, device_id, last_seen)

    for device_id, last_seen in event_devices:
        _update_device_map(device_map, device_id, last_seen)

    now = datetime.now(timezone.utc)
    devices = []

    for device_id, last_seen in sorted(device_map.items()):
        if last_seen is None:
            status = "unknown"
            last_activity = None
        else:
            elapsed = (now - last_seen).total_seconds()
            status = "active" if elapsed <= threshold_seconds else "inactive"
            last_activity = last_seen.isoformat()

        devices.append({
            "device_id": device_id,
            "status": status,
            "last_seen": last_activity,
            "last_activity": last_activity,
        })

    return devices
