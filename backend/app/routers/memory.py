"""Device memory diagnostics and threat preservation API router."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ip_profile import IPProfile
from app.schemas.memory_stats import DeviceMemoryStats, ThreatEvictionSummary
from app.services import memory_service

router = APIRouter(prefix="/device/memory", tags=["Memory Diagnostics"])


@router.get(
    "",
    response_model=DeviceMemoryStats,
    summary="Get device memory diagnostics",
    description="Returns memory usage, pressure level, FreeRTOS heap watermarks, and eviction statistics.",
)
async def get_device_memory(db: Session = Depends(get_db)) -> DeviceMemoryStats:
    """Retrieve device memory diagnostics."""
    active_count = db.query(IPProfile).count()
    return memory_service.get_memory_stats(active_ip_count=active_count)


@router.post(
    "/report",
    response_model=DeviceMemoryStats,
    summary="Update device memory diagnostics",
    description="Ingest memory telemetry reported directly from FRDM-RW612.",
)
async def report_device_memory(stats: DeviceMemoryStats) -> DeviceMemoryStats:
    """Ingest memory report from board."""
    return memory_service.update_memory_stats(stats)
