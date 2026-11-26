"""Split-Stage Edge-to-Backend Threat Correlation Service.

Correlates compact edge observations over a longer time window (300s):
- Orders delayed and out-of-order observations by (event_timestamp, sequence_num)
- Evaluates transition fingerprints & behavioral cadence
- Detects shared-IP / NAT ambiguity (maintaining uncertainty instead of merging)
- Detects IP churn / roaming attacker fingerprints across changing IPs
- Generates derived SecurityEvents preserving original observation_id references
"""

from datetime import datetime, timedelta, timezone
import json
import threading
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.edge_observation import EdgeObservation
from app.models.ip_profile import IPProfile
from app.models.security_event import SecurityEvent
from app.schemas.observation import (
    EdgeObservationBatchCreate,
    EdgeObservationBatchResponse,
    EdgeObservationCreate,
    EdgeObservationResponse,
)
from app.services.sequence_service import AttackSequenceService


CORRELATION_WINDOW_SECONDS = 300
CHURN_WINDOW_SECONDS = 120
_churn_lock = threading.Lock()
# fingerprint -> (source_ip, last_timestamp, avg_cadence_sec)
_fingerprint_index: dict[str, tuple[str, datetime, float]] = {}


def _ensure_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _categorize_obs(obs: EdgeObservation) -> str:
    if obs.endpoint:
        return AttackSequenceService.categorize_endpoint(obs.endpoint)
    # Compact endpoint_id fallback mapping
    return f"ep_{obs.endpoint_id}"


def _build_transition_fingerprint(ordered: list[EdgeObservation]) -> str:
    cats = [_categorize_obs(o) for o in ordered[-4:]]
    return "->".join(cats)


def _detect_shared_ip_ambiguity(ordered: list[EdgeObservation]) -> bool:
    """Detect if a single IP mixes benign health polling with exploit probing."""
    cats = [_categorize_obs(o) for o in ordered]
    has_benign_poll = any(c in ("status", "info") for c in cats)
    has_attack_probe = any(c in ("admin", "login", "config", "unknown") for c in cats)
    # If >= 2 benign polls AND >= 2 attack probes are interleaved on the same IP
    benign_cnt = sum(1 for c in cats if c in ("status", "info"))
    attack_cnt = sum(1 for c in cats if c in ("admin", "login", "config", "unknown"))
    return has_benign_poll and has_attack_probe and benign_cnt >= 2 and attack_cnt >= 2


def _compute_cadence_seconds(ordered: list[EdgeObservation]) -> float:
    if len(ordered) < 2:
        return 0.0
    deltas = []
    for i in range(1, len(ordered)):
        t0 = _ensure_utc(ordered[i - 1].event_timestamp)
        t1 = _ensure_utc(ordered[i].event_timestamp)
        deltas.append(max((t1 - t0).total_seconds(), 0.0))
    return sum(deltas) / len(deltas)


def process_observation(
    db: Session,
    obs_data: EdgeObservationCreate,
) -> EdgeObservationResponse:
    """Ingest a compact edge observation idempotently and run backend correlation."""
    # 1. Deduplicate by observation_id
    existing = (
        db.query(EdgeObservation)
        .filter(EdgeObservation.observation_id == obs_data.observation_id)
        .first()
    )
    if existing:
        return EdgeObservationResponse(
            id=existing.id,
            observation_id=existing.observation_id,
            device_id=existing.device_id,
            source_ip=existing.source_ip,
            endpoint_id=existing.endpoint_id,
            endpoint=existing.endpoint,
            event_timestamp=existing.event_timestamp,
            sequence_num=existing.sequence_num,
            edge_score=existing.edge_score,
            triggered_event=existing.triggered_event,
            correlation_score=existing.correlation_score,
            correlation_confidence=existing.correlation_confidence,
            transition_fingerprint=existing.transition_fingerprint,
            shared_ip_suspected=existing.shared_ip_suspected,
            duplicate=True,
        )

    obs_ts = _ensure_utc(obs_data.event_timestamp)

    db_obs = EdgeObservation(
        observation_id=obs_data.observation_id,
        device_id=obs_data.device_id,
        source_ip=obs_data.source_ip.strip(),
        endpoint_id=obs_data.endpoint_id,
        endpoint=obs_data.endpoint,
        event_timestamp=obs_ts,
        sequence_num=obs_data.sequence_num,
        edge_score=obs_data.edge_score,
        triggered_event=obs_data.triggered_event,
        metadata_json=json.dumps(obs_data.metadata) if obs_data.metadata else None,
    )

    try:
        with db.begin_nested():
            db.add(db_obs)
            db.flush()
    except IntegrityError:
        existing = (
            db.query(EdgeObservation)
            .filter(EdgeObservation.observation_id == obs_data.observation_id)
            .first()
        )
        if existing:
            return EdgeObservationResponse(
                id=existing.id,
                observation_id=existing.observation_id,
                device_id=existing.device_id,
                source_ip=existing.source_ip,
                endpoint_id=existing.endpoint_id,
                endpoint=existing.endpoint,
                event_timestamp=existing.event_timestamp,
                sequence_num=existing.sequence_num,
                edge_score=existing.edge_score,
                triggered_event=existing.triggered_event,
                correlation_score=existing.correlation_score,
                correlation_confidence=existing.correlation_confidence,
                transition_fingerprint=existing.transition_fingerprint,
                shared_ip_suspected=existing.shared_ip_suspected,
                duplicate=True,
            )
        raise

    # 2. Fetch longer-window observations for this IP and sort by (event_timestamp, sequence_num)
    cutoff = obs_ts - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
    window_obs = (
        db.query(EdgeObservation)
        .filter(
            EdgeObservation.source_ip == db_obs.source_ip,
            EdgeObservation.event_timestamp >= cutoff,
        )
        .order_by(EdgeObservation.event_timestamp.asc(), EdgeObservation.sequence_num.asc())
        .all()
    )

    fingerprint = _build_transition_fingerprint(window_obs)
    shared_ip = _detect_shared_ip_ambiguity(window_obs)
    avg_cadence = _compute_cadence_seconds(window_obs)

    # 3. Reconstruct attack sequence & compute backend correlation score
    cats = [_categorize_obs(o) for o in window_obs]
    corr_score = obs_data.edge_score
    pattern_name: str | None = None

    seen_root = False
    seen_admin = False
    for c in cats:
        if not seen_root and c == "root":
            seen_root = True
        elif seen_root and not seen_admin and c == "admin":
            seen_admin = True
        elif seen_admin and c in ("config", "login"):
            pattern_name = "reconnaissance_probe"
            corr_score = max(corr_score, 85)
            break

    if not pattern_name:
        seen_a = False
        for c in cats:
            if not seen_a and c == "admin":
                seen_a = True
            elif seen_a and c == "login":
                pattern_name = "credential_hunting"
                corr_score = max(corr_score, 75)
                break

    if not pattern_name and sum(1 for c in cats if c == "unknown") >= 3:
        pattern_name = "unknown_sweep"
        corr_score = max(corr_score, 70)

    # 4. IP Churn / Roaming Fingerprint Check
    roaming_from_ip: str | None = None
    is_suspicious_fp = any(c in ("admin", "login", "config", "unknown") for c in cats)
    if is_suspicious_fp and len(window_obs) >= 2:
        with _churn_lock:
            prev = _fingerprint_index.get(fingerprint)
            if prev is not None:
                prev_ip, prev_ts, _ = prev
                if prev_ip != db_obs.source_ip and abs((obs_ts - _ensure_utc(prev_ts)).total_seconds()) <= CHURN_WINDOW_SECONDS:
                    roaming_from_ip = prev_ip
                    corr_score = min(100, max(corr_score, 75) + 10)
            _fingerprint_index[fingerprint] = (db_obs.source_ip, obs_ts, avg_cadence)

    # 5. Compute Correlation Confidence (0.0 - 1.0)
    confidence = 0.90 if len(window_obs) >= 3 else 0.75
    if shared_ip:
        # Maintain explicit uncertainty when multiple devices likely share an IP
        confidence = round(min(confidence, 0.55), 2)
        corr_score = min(corr_score, 65)
    elif roaming_from_ip:
        confidence = 0.80

    db_obs.correlation_score = min(100, corr_score)
    db_obs.correlation_confidence = confidence
    db_obs.transition_fingerprint = fingerprint
    db_obs.shared_ip_suspected = shared_ip

    # Update IPProfile correlation fields if profile exists
    ip_prof = db.query(IPProfile).filter(IPProfile.ip_address == db_obs.source_ip).first()
    if ip_prof is not None:
        ip_prof.correlation_confidence = confidence
        ip_prof.shared_ip_suspected = shared_ip
        ip_prof.transition_fingerprint = fingerprint

    # 6. Emit derived SecurityEvent when a multi-stage or roaming sequence is correlated
    derived_event_id: int | None = None
    if pattern_name or roaming_from_ip:
        derived_cid = f"corr-{db_obs.observation_id}"
        existing_evt = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.client_event_id == derived_cid)
            .first()
        )
        if existing_evt is None:
            timeline = [
                {
                    "observation_id": o.observation_id,
                    "endpoint": o.endpoint or f"ep:{o.endpoint_id}",
                    "edge_score": o.edge_score,
                    "timestamp": _ensure_utc(o.event_timestamp).isoformat(),
                    "seq": o.sequence_num,
                }
                for o in window_obs[-8:]
            ]
            desc = (
                f"Correlated {pattern_name or 'roaming_attack'} from {db_obs.source_ip} "
                f"(edge={obs_data.edge_score}, corr={db_obs.correlation_score}, conf={int(confidence * 100)}%)"
            )
            if roaming_from_ip:
                desc += f" [IP churn linked to {roaming_from_ip}]"
            if shared_ip:
                desc += " [Shared-IP uncertainty]"

            sev = "critical" if (db_obs.correlation_score >= 75 and not shared_ip) else "warning"
            derived_evt = SecurityEvent(
                client_event_id=derived_cid,
                timestamp=obs_ts,
                device_id=db_obs.device_id,
                event_type="correlated_attack_sequence",
                severity=sev,
                description=desc,
                source_ip=db_obs.source_ip,
                request_count=len(window_obs),
                time_window_seconds=CORRELATION_WINDOW_SECONDS,
                metadata_json=json.dumps({
                    "observation_id": db_obs.observation_id,
                    "source_observation_ids": [o.observation_id for o in window_obs[-8:]],
                    "edge_score": obs_data.edge_score,
                    "correlation_score": db_obs.correlation_score,
                    "correlation_confidence": confidence,
                    "shared_ip_suspected": shared_ip,
                    "transition_fingerprint": fingerprint,
                    "roaming_from_ip": roaming_from_ip,
                    "pattern": pattern_name or "roaming_fingerprint_match",
                    "attack_timeline": timeline,
                    "sequence": [t["endpoint"] for t in timeline],
                }),
            )
            db.add(derived_evt)
            db.flush()
            derived_event_id = derived_evt.id

    db.commit()
    db.refresh(db_obs)

    return EdgeObservationResponse(
        id=db_obs.id,
        observation_id=db_obs.observation_id,
        device_id=db_obs.device_id,
        source_ip=db_obs.source_ip,
        endpoint_id=db_obs.endpoint_id,
        endpoint=db_obs.endpoint,
        event_timestamp=db_obs.event_timestamp,
        sequence_num=db_obs.sequence_num,
        edge_score=db_obs.edge_score,
        triggered_event=db_obs.triggered_event,
        correlation_score=db_obs.correlation_score,
        correlation_confidence=db_obs.correlation_confidence,
        transition_fingerprint=db_obs.transition_fingerprint,
        shared_ip_suspected=db_obs.shared_ip_suspected,
        derived_event_id=derived_event_id,
        duplicate=False,
    )


def process_observations_batch(
    db: Session,
    batch: EdgeObservationBatchCreate,
) -> EdgeObservationBatchResponse:
    """Process a batch of compact observations in chronological order."""
    ordered_items = sorted(
        batch.observations,
        key=lambda o: (_ensure_utc(o.event_timestamp), o.sequence_num),
    )
    inserted = 0
    duplicates = 0
    derived_alerts = 0
    acked_ids: list[str] = []

    for item in ordered_items:
        res = process_observation(db, item)
        acked_ids.append(res.observation_id)
        if res.duplicate:
            duplicates += 1
        else:
            inserted += 1
        if res.derived_event_id is not None:
            derived_alerts += 1

    return EdgeObservationBatchResponse(
        received=len(batch.observations),
        inserted=inserted,
        duplicates=duplicates,
        acked_ids=acked_ids,
        derived_alerts_created=derived_alerts,
    )
