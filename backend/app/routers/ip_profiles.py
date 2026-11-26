"""Behavioral IP Profiles API endpoints."""

import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ip_profile import IPProfile
from app.schemas.ip_profile import (
    IPProfilePaginatedResponse,
    IPProfileResponse,
    IPProfileSummary,
    RiskLevelEnum,
)
from app.services import ip_profile_service

router = APIRouter(prefix="/ip-profiles", tags=["IP Profiles"])


def _to_schema(profile: IPProfile) -> IPProfileResponse:
    """Helper to convert ORM model to response schema, expanding endpoints_json."""
    endpoints: list[str] = []
    if profile.endpoints_json:
        try:
            endpoints = json.loads(profile.endpoints_json)
        except Exception:
            endpoints = []

    return IPProfileResponse(
        id=profile.id,
        ip_address=profile.ip_address,
        device_id=profile.device_id,
        total_requests=profile.total_requests,
        suspicious_requests=profile.suspicious_requests,
        repeated_requests=profile.repeated_requests,
        unique_endpoints_count=profile.unique_endpoints_count,
        unique_endpoints=endpoints,
        request_frequency=profile.request_frequency,
        threat_score=profile.threat_score,
        risk_level=RiskLevelEnum(profile.risk_level),
        correlation_confidence=getattr(profile, "correlation_confidence", 1.0),
        shared_ip_suspected=getattr(profile, "shared_ip_suspected", False),
        transition_fingerprint=getattr(profile, "transition_fingerprint", None),
        first_seen=profile.first_seen,
        last_seen=profile.last_seen,
        is_active=profile.is_active,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get(
    "/summary",
    response_model=IPProfileSummary,
    summary="Get IP profiles summary statistics",
)
async def get_ip_profiles_summary(
    db: Session = Depends(get_db),
) -> IPProfileSummary:
    """Retrieve high-level summary metrics across all tracked IP profiles."""
    summary_data = ip_profile_service.get_ip_profile_summary(db)
    return IPProfileSummary.model_validate(summary_data)


@router.get(
    "",
    response_model=IPProfilePaginatedResponse,
    summary="List behavioral IP profiles",
)
async def list_ip_profiles(
    skip: int = Query(0, ge=0, description="Records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Max records per page"),
    risk_level: RiskLevelEnum | None = Query(None, description="Filter by risk category"),
    min_threat_score: int | None = Query(None, ge=0, le=100, description="Minimum threat score"),
    search_ip: str | None = Query(None, description="Search by IP substring"),
    active_only: bool = Query(False, description="Filter active profiles only"),
    db: Session = Depends(get_db),
) -> IPProfilePaginatedResponse:
    """List behavioral IP profiles with filtering and pagination."""
    risk_val = risk_level.value if risk_level else None
    profiles, total = ip_profile_service.get_ip_profiles(
        db,
        skip=skip,
        limit=limit,
        risk_level=risk_val,
        min_threat_score=min_threat_score,
        search_ip=search_ip,
        active_only=active_only,
    )

    items = [_to_schema(p) for p in profiles]
    return IPProfilePaginatedResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{ip_address}",
    response_model=IPProfileResponse,
    summary="Get behavioral profile for a specific IP",
)
async def get_ip_profile(
    ip_address: str,
    db: Session = Depends(get_db),
) -> IPProfileResponse:
    """Retrieve detailed behavioral profile for a specific source IP."""
    profile = ip_profile_service.get_ip_profile_by_ip(db, ip_address)
    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=f"IP profile for '{ip_address}' not found",
        )
    return _to_schema(profile)


@router.post(
    "/expire",
    summary="Expire inactive IP profiles",
)
async def expire_inactive_profiles(
    timeout_seconds: int = Query(300, ge=30, description="Inactivity timeout in seconds"),
    db: Session = Depends(get_db),
) -> dict:
    """Mark inactive profiles as not active if no activity within threshold."""
    expired_count = ip_profile_service.expire_inactive_profiles(
        db, timeout_seconds=timeout_seconds
    )
    return {
        "status": "ok",
        "expired_count": expired_count,
        "timeout_seconds": timeout_seconds,
    }
