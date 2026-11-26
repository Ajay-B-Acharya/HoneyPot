"""Device presence & heartbeat API endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.services import device_service


class DeviceHeartbeatCreate(BaseModel):
    """Heartbeat payload transmitted periodically by the physical FRDM-RW612."""
    device_id: str = Field(..., min_length=1, max_length=128)
    uptime_seconds: int = Field(..., ge=0)
    wifi_connected: bool = Field(...)
    device_ip: str | None = Field(None, max_length=45)
    free_heap_bytes: int = Field(..., ge=0)
    firmware_version: str | None = Field(None, max_length=64)
    heartbeat_seq: int = Field(..., ge=0)


class DeviceHeartbeatResponse(BaseModel):
    """Acknowledgement returned to the MCU after heartbeat ingestion."""
    device_id: str
    status: str
    accepted: bool
    heartbeat_seq: int
    last_heartbeat: str


class DeviceStatusItem(BaseModel):
    """Status information for a single device."""
    device_id: str
    status: str
    last_seen: str | None = None
    last_heartbeat: str | None = None
    last_activity: str | None = None
    device_ip: str | None = None
    uptime_seconds: int | None = None
    wifi_connected: bool = False
    free_heap_bytes: int | None = None
    firmware_version: str | None = None
    heartbeat_seq: int | None = None


class DeviceStatusResponse(BaseModel):
    """Response containing status of all known devices."""
    devices: list[DeviceStatusItem] = []


router = APIRouter(prefix="/device", tags=["Device"])


@router.post(
    "/heartbeat",
    response_model=DeviceHeartbeatResponse,
    status_code=200,
    summary="Ingest physical device heartbeat",
)
async def ingest_heartbeat(
    payload: DeviceHeartbeatCreate,
    db: Session = Depends(get_db),
) -> DeviceHeartbeatResponse:
    """Record a physical FRDM-RW612 heartbeat and return evaluated status."""
    hb, accepted = device_service.record_heartbeat(
        db,
        device_id=payload.device_id,
        uptime_seconds=payload.uptime_seconds,
        wifi_connected=payload.wifi_connected,
        device_ip=payload.device_ip,
        free_heap_bytes=payload.free_heap_bytes,
        firmware_version=payload.firmware_version,
        heartbeat_seq=payload.heartbeat_seq,
    )
    status = device_service.evaluate_heartbeat_status(hb)
    return DeviceHeartbeatResponse(
        device_id=hb.device_id,
        status=status,
        accepted=accepted,
        heartbeat_seq=hb.heartbeat_seq,
        last_heartbeat=hb.last_heartbeat_at.isoformat(),
    )


@router.get(
    "/status",
    response_model=DeviceStatusResponse,
    summary="Device physical presence status",
)
async def get_device_status(
    db: Session = Depends(get_db),
) -> DeviceStatusResponse:
    """Return physical presence status evaluated from device heartbeats."""
    devices = device_service.get_device_statuses(db)
    return DeviceStatusResponse(
        devices=[DeviceStatusItem(**d) for d in devices],
    )
