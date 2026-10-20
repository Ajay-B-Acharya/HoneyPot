"""Service layer for dashboard statistics."""

from sqlalchemy.orm import Session

from app.services.event_service import count_events_by_severity, count_total_events
from app.services.log_service import count_by_classification, count_total_requests


def get_dashboard_stats(db: Session) -> dict:
    """Calculate dashboard statistics using database aggregation.

    Returns:
        Dictionary containing all dashboard statistics.
    """
    total_requests = count_total_requests(db)
    classification_counts = count_by_classification(db)
    total_events = count_total_events(db)
    severity_counts = count_events_by_severity(db)

    return {
        "total_requests": total_requests,
        "normal_requests": classification_counts.get("normal", 0),
        "unusual_requests": classification_counts.get("unusual", 0),
        "suspicious_requests": classification_counts.get("suspicious", 0),
        "total_security_events": total_events,
        "events_by_severity": severity_counts,
        "requests_by_classification": classification_counts,
    }
