"""Compact Edge Observation ingestion and correlation API router."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.edge_observation import EdgeObservation
from app.schemas.observation import (
    EdgeObservationBatchCreate,
    EdgeObservationBatchResponse,
    EdgeObservationCreate,
    EdgeObservationResponse,
)
from app.services import correlation_service

router = APIRouter(prefix="/observations", tags=["Edge Observations"])


@router.post(
    "",
    response_model=EdgeObservationResponse,
    status_code=201,
    summary="Ingest and correlate a compact edge observation",
)
async def ingest_observation(
    obs: EdgeObservationCreate,
    db: Session = Depends(get_db),
) -> EdgeObservationResponse:
    return correlation_service.process_observation(db, obs)


@router.post(
    "/batch",
    response_model=EdgeObservationBatchResponse,
    status_code=201,
    summary="Batch ingest and correlate compact edge observations",
)
async def ingest_observations_batch(
    batch: EdgeObservationBatchCreate,
    db: Session = Depends(get_db),
) -> EdgeObservationBatchResponse:
    return correlation_service.process_observations_batch(db, batch)


@router.get(
    "",
    response_model=list[EdgeObservationResponse],
    summary="List recent correlated edge observations",
)
async def list_observations(
    limit: int = Query(50, ge=1, le=200),
    source_ip: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[EdgeObservationResponse]:
    q = db.query(EdgeObservation)
    if source_ip:
        q = q.filter(EdgeObservation.source_ip == source_ip)
    rows = q.order_by(EdgeObservation.event_timestamp.desc(), EdgeObservation.sequence_num.desc()).limit(limit).all()
    return [EdgeObservationResponse.model_validate(r) for r in rows]
