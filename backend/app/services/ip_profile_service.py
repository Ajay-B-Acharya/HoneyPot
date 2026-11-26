"""Service layer for Behavioral IP Profile operations."""

from datetime import datetime, timezone
import json

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.ip_profile import IPProfile
from app.models.request_log import RequestLog
from app.models.security_event import SecurityEvent


def _calculate_threat_score(
    total_requests: int,
    suspicious_requests: int,
    repeated_requests: int,
    unique_endpoints_count: int,
    frequency_rpm: float,
) -> tuple[int, str]:
    """Calculate normalized threat score (0-100) and risk level."""
    score = 0

    # 1. Suspicious / unknown endpoint probes (15 pts each, max 45)
    if suspicious_requests > 0:
        susp_pts = suspicious_requests * 15
        score += min(susp_pts, 45)

    # 2. Repeated probes on same endpoint (4 pts each, max 25)
    if repeated_requests > 0:
        rep_pts = repeated_requests * 4
        score += min(rep_pts, 25)

    # 3. Scanning / endpoint enumeration behavior
    if unique_endpoints_count >= 3:
        score += 15
    elif unique_endpoints_count == 2:
        score += 5

    # 4. Request frequency bursts
    if frequency_rpm >= 60.0:
        score += 25
    elif frequency_rpm >= 30.0:
        score += 15

    # 5. Volume weighting
    if total_requests >= 20:
        score += 10
    elif total_requests >= 10:
        score += 5

    score = min(score, 100)

    if score >= 90:
        risk_level = "critical"
    elif score >= 70:
        risk_level = "high"
    elif score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return score, risk_level


def record_ip_activity(
    db: Session,
    log: RequestLog,
    triggered_events: list[SecurityEvent] | None = None,
) -> IPProfile | None:
    """Update or create a behavioral IP profile when a request is ingested.

    Args:
        db: Active database session.
        log: Newly ingested RequestLog instance.
        triggered_events: Any security events generated from this request.

    Returns:
        Updated or newly created IPProfile instance, or None if no source IP.
    """
    if not log.source_ip:
        return None

    source_ip = log.source_ip.strip()
    if not source_ip:
        return None

    is_suspicious_req = (
        log.classification != "normal"
        or (triggered_events is not None and len(triggered_events) > 0)
    )

    profile = (
        db.query(IPProfile).filter(IPProfile.ip_address == source_ip).first()
    )

    log_timestamp = log.timestamp
    if log_timestamp.tzinfo is None:
        log_timestamp = log_timestamp.replace(tzinfo=timezone.utc)

    if profile is None:
        # Initial profile creation
        endpoints_list = [log.endpoint]
        score, risk = _calculate_threat_score(
            total_requests=1,
            suspicious_requests=1 if is_suspicious_req else 0,
            repeated_requests=0,
            unique_endpoints_count=1,
            frequency_rpm=1.0,
        )

        profile = IPProfile(
            ip_address=source_ip,
            device_id=log.device_id,
            total_requests=1,
            suspicious_requests=1 if is_suspicious_req else 0,
            repeated_requests=0,
            unique_endpoints_count=1,
            endpoints_json=json.dumps(endpoints_list),
            request_frequency=1.0,
            threat_score=score,
            risk_level=risk,
            first_seen=log_timestamp,
            last_seen=log_timestamp,
            is_active=True,
        )
        db.add(profile)
    else:
        # Update existing profile
        profile.total_requests += 1
        if is_suspicious_req:
            profile.suspicious_requests += 1

        # Track unique endpoints and repeated accesses
        endpoints_list: list[str] = []
        if profile.endpoints_json:
            try:
                endpoints_list = json.loads(profile.endpoints_json)
            except Exception:
                endpoints_list = []

        if endpoints_list and endpoints_list[-1] == log.endpoint:
            profile.repeated_requests += 1

        if log.endpoint not in endpoints_list:
            endpoints_list.append(log.endpoint)
            # Keep up to 20 recent unique endpoints
            if len(endpoints_list) > 20:
                endpoints_list.pop(0)

        profile.endpoints_json = json.dumps(endpoints_list)
        profile.unique_endpoints_count = len(set(endpoints_list))

        # Calculate frequency
        profile_first_seen = profile.first_seen
        if profile_first_seen.tzinfo is None:
            profile_first_seen = profile_first_seen.replace(tzinfo=timezone.utc)

        span_seconds = max((log_timestamp - profile_first_seen).total_seconds(), 1.0)
        frequency_rpm = (profile.total_requests / span_seconds) * 60.0
        profile.request_frequency = round(frequency_rpm, 2)

        # Re-compute threat score
        score, risk = _calculate_threat_score(
            total_requests=profile.total_requests,
            suspicious_requests=profile.suspicious_requests,
            repeated_requests=profile.repeated_requests,
            unique_endpoints_count=profile.unique_endpoints_count,
            frequency_rpm=profile.request_frequency,
        )
        profile.threat_score = score
        profile.risk_level = risk
        profile.last_seen = log_timestamp
        profile.is_active = True

    return profile


def get_ip_profiles(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    risk_level: str | None = None,
    min_threat_score: int | None = None,
    search_ip: str | None = None,
    active_only: bool = False,
) -> tuple[list[IPProfile], int]:
    """Retrieve paginated IP profiles with optional filters."""
    query = db.query(IPProfile)

    if risk_level:
        query = query.filter(IPProfile.risk_level == risk_level)
    if min_threat_score is not None:
        query = query.filter(IPProfile.threat_score >= min_threat_score)
    if search_ip:
        query = query.filter(IPProfile.ip_address.contains(search_ip))
    if active_only:
        query = query.filter(IPProfile.is_active.is_(True))

    total = query.count()
    profiles = (
        query.order_by(IPProfile.threat_score.desc(), IPProfile.last_seen.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return profiles, total


def get_ip_profile_by_ip(db: Session, ip_address: str) -> IPProfile | None:
    """Retrieve an IP profile by its exact IP address."""
    return db.query(IPProfile).filter(IPProfile.ip_address == ip_address).first()


def get_ip_profile_summary(db: Session) -> dict:
    """Calculate summary statistics across all IP profiles."""
    total = db.query(func.count(IPProfile.id)).scalar() or 0
    active = (
        db.query(func.count(IPProfile.id))
        .filter(IPProfile.is_active.is_(True))
        .scalar()
        or 0
    )

    risk_counts = (
        db.query(IPProfile.risk_level, func.count(IPProfile.id))
        .group_by(IPProfile.risk_level)
        .all()
    )
    risk_map = {level: count for level, count in risk_counts}

    top_threat = (
        db.query(IPProfile.ip_address, IPProfile.threat_score)
        .order_by(IPProfile.threat_score.desc())
        .first()
    )

    return {
        "total_profiles": total,
        "active_profiles": active,
        "critical_threats": risk_map.get("critical", 0),
        "high_threats": risk_map.get("high", 0),
        "medium_threats": risk_map.get("medium", 0),
        "low_threats": risk_map.get("low", 0),
        "top_threat_ip": top_threat[0] if top_threat else None,
        "max_threat_score": top_threat[1] if top_threat else 0,
    }


def expire_inactive_profiles(
    db: Session,
    timeout_seconds: int = 300,
) -> int:
    """Mark inactive profiles that have had no traffic within threshold."""
    now = datetime.now(timezone.utc)
    profiles = db.query(IPProfile).filter(IPProfile.is_active.is_(True)).all()
    count = 0

    for p in profiles:
        last = p.last_seen
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if (now - last).total_seconds() >= timeout_seconds and p.threat_score < 70:
            p.is_active = False
            count += 1

    if count > 0:
        db.commit()
    return count
