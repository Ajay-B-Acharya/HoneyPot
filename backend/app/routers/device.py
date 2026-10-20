"""Device status API endpoint."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services import device_service


class DeviceStatusItem(BaseModel):
    """Status information for a single device."""
    device_id: str
    status: str
    last_seen: str | None = None
    last_activity: str | None = None


class DeviceStatusResponse(BaseModel):
    """Response containing status of all known devices."""
    devices: list[DeviceStatusItem] = []


router = APIRouter(prefix="/device", tags=["Device"])


@router.get(
    "/status",
    response_model=DeviceStatusResponse,
    summary="Device status",
    description=(
        "Returns status information for all known devices based on recorded activity. "
        "Status is derived from the most recent request log or security event timestamp. "
        "A device is 'active' if seen within the configured threshold, 'inactive' otherwise, "
        "and 'unknown' if no activity has been recorded. "
        "This does NOT represent real-time connectivity — only last-seen activity."
    ),
)
async def get_device_status(
    db: Session = Depends(get_db),
) -> DeviceStatusResponse:
    """Return device status based on recorded activity."""
    devices = device_service.get_device_statuses(db)
    return DeviceStatusResponse(
        devices=[DeviceStatusItem(**d) for d in devices],
    )
