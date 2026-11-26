"""Service layer for physical device presence & heartbeat monitoring."""

from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.device_heartbeat import DeviceHeartbeat
from app.models.request_log import RequestLog
from app.models.security_event import SecurityEvent


def _to_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetime to UTC timezone-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def record_heartbeat(
    db: Session,
    *,
    device_id: str,
    uptime_seconds: int,
    wifi_connected: bool,
    device_ip: str | None,
    free_heap_bytes: int,
    firmware_version: str | None,
    heartbeat_seq: int,
) -> tuple[DeviceHeartbeat, bool]:
    """Store latest device heartbeat, handling restarts and rejecting stale packets.

    Returns:
        Tuple of (DeviceHeartbeat, accepted: bool).
    """
    now = datetime.now(timezone.utc)
    existing = (
        db.query(DeviceHeartbeat)
        .filter(DeviceHeartbeat.device_id == device_id)
        .first()
    )

    if existing is None:
        hb = DeviceHeartbeat(
            device_id=device_id,
            device_ip=device_ip,
            wifi_connected=wifi_connected,
            uptime_seconds=uptime_seconds,
            free_heap_bytes=free_heap_bytes,
            firmware_version=firmware_version,
            heartbeat_seq=heartbeat_seq,
            last_heartbeat_at=now,
        )
        db.add(hb)
        db.commit()
        db.refresh(hb)
        return hb, True

    # Detect reboot (uptime reset) or strictly newer monotonic sequence
    is_reboot = uptime_seconds < existing.uptime_seconds
    is_newer_seq = heartbeat_seq > existing.heartbeat_seq
    if not is_reboot and not is_newer_seq:
        # Stale or duplicate heartbeat — do not overwrite newer state
        return existing, False

    existing.device_ip = device_ip
    existing.wifi_connected = wifi_connected
    existing.uptime_seconds = uptime_seconds
    existing.free_heap_bytes = free_heap_bytes
    existing.firmware_version = firmware_version
    existing.heartbeat_seq = heartbeat_seq
    existing.last_heartbeat_at = now
    db.commit()
    db.refresh(existing)
    return existing, True


def evaluate_heartbeat_status(hb: DeviceHeartbeat, now: datetime | None = None) -> str:
    """Evaluate physical presence state from latest heartbeat."""
    settings = get_settings()
    now_utc = now or datetime.now(timezone.utc)
    last_hb = _to_utc(hb.last_heartbeat_at)
    if last_hb is None:
        return "not_registered"

    elapsed = (now_utc - last_hb).total_seconds()
    if elapsed > settings.DEVICE_HEARTBEAT_OFFLINE_SECONDS or not hb.wifi_connected:
        return "offline"
    if elapsed > settings.DEVICE_HEARTBEAT_UNSTABLE_SECONDS:
        return "connection_unstable"
    return "online"


def get_device_statuses(db: Session) -> list[dict]:
    """Return physical presence status for all registered or observed devices."""
    now = datetime.now(timezone.utc)

    heartbeats = {
        hb.device_id: hb for hb in db.query(DeviceHeartbeat).all()
    }

    # Also include any device_ids seen in logs/events that haven't sent a heartbeat
    activity_map: dict[str, datetime | None] = {}
    for device_id, last_seen in (
        db.query(RequestLog.device_id, func.max(RequestLog.timestamp))
        .group_by(RequestLog.device_id)
        .all()
    ):
        utc_ts = _to_utc(last_seen)
        if utc_ts and (device_id not in activity_map or activity_map[device_id] is None or utc_ts > activity_map[device_id]):
            activity_map[device_id] = utc_ts

    for device_id, last_seen in (
        db.query(SecurityEvent.device_id, func.max(SecurityEvent.timestamp))
        .group_by(SecurityEvent.device_id)
        .all()
    ):
        utc_ts = _to_utc(last_seen)
        if utc_ts and (device_id not in activity_map or activity_map[device_id] is None or utc_ts > activity_map[device_id]):
            activity_map[device_id] = utc_ts

    all_ids = sorted(set(heartbeats.keys()) | set(activity_map.keys()))
    devices: list[dict] = []

    for device_id in all_ids:
        hb = heartbeats.get(device_id)
        act_ts = activity_map.get(device_id)
        act_iso = act_ts.isoformat() if act_ts else None

        if hb is not None:
            hb_utc = _to_utc(hb.last_heartbeat_at)
            hb_iso = hb_utc.isoformat() if hb_utc else None
            status = evaluate_heartbeat_status(hb, now)
            devices.append({
                "device_id": device_id,
                "status": status,
                "last_seen": hb_iso,
                "last_heartbeat": hb_iso,
                "last_activity": act_iso,
                "device_ip": hb.device_ip,
                "uptime_seconds": hb.uptime_seconds,
                "wifi_connected": hb.wifi_connected,
                "free_heap_bytes": hb.free_heap_bytes,
                "firmware_version": hb.firmware_version,
                "heartbeat_seq": hb.heartbeat_seq,
            })
        else:
            devices.append({
                "device_id": device_id,
                "status": "not_registered",
                "last_seen": act_iso,
                "last_heartbeat": None,
                "last_activity": act_iso,
                "device_ip": None,
                "uptime_seconds": None,
                "wifi_connected": False,
                "free_heap_bytes": None,
                "firmware_version": None,
                "heartbeat_seq": None,
            })

    return devices
