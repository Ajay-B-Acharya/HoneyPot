"""Health check endpoint."""

from fastapi import APIRouter

from app.schemas.common import HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns the health status of the backend service.",
)
async def health_check() -> HealthResponse:
    """Return service health status."""
    return HealthResponse(status="ok", service="iot-honeypot-backend")
