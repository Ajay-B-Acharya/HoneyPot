"""Attack Sequence Detection Service.

Identifies multi-stage suspicious HTTP request sequences per source IP:
- Pattern 1 (Reconnaissance): Root -> Admin -> Config / Login
- Pattern 2 (Credential Hunting): Admin -> Login endpoint probing
- Pattern 3 (Config Probing): Repeated configuration access attempts
- Pattern 4 (Unknown Sweep): Rapid successive probes to non-existent endpoints
"""

from collections import deque
from datetime import datetime, timezone
import threading
import time
from typing import Any

from app.schemas.security_event import SecurityEventCreate, SeverityEnum


class AttackSequenceService:
    """Thread-safe multi-stage attack sequence detector."""

    def __init__(
        self,
        window_seconds: int = 30,
        cooldown_seconds: int = 15,
        max_entries: int = 10000,
    ):
        self._lock = threading.Lock()
        self._window_seconds = window_seconds
        self._cooldown_seconds = cooldown_seconds
        self._max_entries = max_entries
        # key: (device_id, source_ip) -> deque of (endpoint_cat, endpoint_str, timestamp)
        self._history: dict[tuple[str, str], deque[tuple[str, str, float]]] = {}
        # key: (device_id, source_ip, pattern_name) -> last_alert_time
        self._cooldowns: dict[tuple[str, str, str], float] = {}

    @staticmethod
    def categorize_endpoint(endpoint: str | None) -> str:
        """Classify endpoint path into an attack categorization token."""
        if not endpoint:
            return "other"

        clean = endpoint.strip().lower()
        if clean in ("/", ""):
            return "root"
        if clean in ("/status", "/status/"):
            return "status"
        if clean in ("/info", "/info/"):
            return "info"
        if any(token in clean for token in ("/config", "/setup", "/system", "/settings")):
            return "config"
        if any(token in clean for token in ("/admin", "/administrator", "/wp-admin", "/manager")):
            return "admin"
        if any(token in clean for token in ("/login", "/auth", "/signin", "/wp-login")):
            return "login"

        return "unknown"

    def evaluate_request(
        self,
        log: Any,
        current_time: float | None = None,
    ) -> SecurityEventCreate | None:
        """Evaluate request history for the client IP to detect attack sequences.

        Args:
            log: RequestLog model or schema.
            current_time: Optional explicit timestamp for deterministic testing.

        Returns:
            SecurityEventCreate schema if an attack sequence is detected, else None.
        """
        device_id = getattr(log, "device_id", "rw612-security-01")
        source_ip = getattr(log, "source_ip", None)
        endpoint = getattr(log, "endpoint", "/")

        if not source_ip:
            return None

        source_ip = source_ip.strip()
        if not source_ip:
            return None

        # Resolve timestamp
        if current_time is None:
            log_ts = getattr(log, "timestamp", None)
            if isinstance(log_ts, datetime):
                if log_ts.tzinfo is None:
                    log_ts = log_ts.replace(tzinfo=timezone.utc)
                now_sec = log_ts.timestamp()
                now_dt = log_ts
            else:
                now_sec = time.time()
                now_dt = datetime.fromtimestamp(now_sec, tz=timezone.utc)
        else:
            now_sec = current_time
            now_dt = datetime.fromtimestamp(current_time, tz=timezone.utc)

        cat = self.categorize_endpoint(endpoint)
        key = (device_id, source_ip)

        with self._lock:
            # Enforce max table size bounds
            if len(self._history) >= self._max_entries:
                self._prune_expired(now_sec)
                if len(self._history) >= self._max_entries:
                    oldest_k = next(iter(self._history))
                    del self._history[oldest_k]

            deq = self._history.setdefault(key, deque())

            # Prune records outside time window
            cutoff = now_sec - self._window_seconds
            while deq and deq[0][2] < cutoff:
                deq.popleft()

            # Append current request
            deq.append((cat, endpoint, now_sec))

            # Need at least 2 requests to detect a sequence
            if len(deq) < 2:
                return None

            items = list(deq)
            detected_pattern: str | None = None
            detected_threat_score = 0
            detected_desc = ""
            matched_sequence: list[str] = [item[1] for item in items]

            # -------------------------------------------------------------
            # Pattern 1: Reconnaissance (Root -> Admin -> Config / Login)
            # -------------------------------------------------------------
            seen_root = False
            seen_admin = False
            for c, ep, _ in items:
                if not seen_root and c == "root":
                    seen_root = True
                elif seen_root and not seen_admin and c == "admin":
                    seen_admin = True
                elif seen_admin and c in ("config", "login"):
                    detected_pattern = "reconnaissance_probe"
                    detected_threat_score = 35
                    detected_desc = (
                        f"Reconnaissance sequence detected from {source_ip}: "
                        f"Root discovery followed by administrative probe and configuration/login access"
                    )
                    break

            # -------------------------------------------------------------
            # Pattern 2: Credential Hunting (Admin -> Login)
            # -------------------------------------------------------------
            if not detected_pattern:
                seen_admin_ch = False
                for c, ep, _ in items:
                    if not seen_admin_ch and c == "admin":
                        seen_admin_ch = True
                    elif seen_admin_ch and c == "login":
                        detected_pattern = "credential_hunting"
                        detected_threat_score = 30
                        detected_desc = (
                            f"Credential hunting sequence detected from {source_ip}: "
                            f"Administrative discovery followed by login endpoint probing"
                        )
                        break

            # -------------------------------------------------------------
            # Pattern 3: Repeated Configuration Probing (>= 3 config hits)
            # -------------------------------------------------------------
            if not detected_pattern:
                config_count = sum(1 for c, _, _ in items if c == "config")
                if config_count >= 3:
                    detected_pattern = "config_probing"
                    detected_threat_score = 25
                    detected_desc = (
                        f"Repeated configuration probing detected from {source_ip}: "
                        f"{config_count} requests targeting configuration interfaces"
                    )

            # -------------------------------------------------------------
            # Pattern 4: Unknown Endpoint Sweep (>= 3 consecutive unknown)
            # -------------------------------------------------------------
            if not detected_pattern:
                unknown_streak = 0
                max_streak = 0
                for c, _, _ in items:
                    if c == "unknown":
                        unknown_streak += 1
                        if unknown_streak > max_streak:
                            max_streak = unknown_streak
                    else:
                        unknown_streak = 0
                if max_streak >= 3:
                    detected_pattern = "unknown_sweep"
                    detected_threat_score = 30
                    detected_desc = (
                        f"Multi-endpoint sweep detected from {source_ip}: "
                        f"{max_streak} sequential probes targeting unmapped endpoints"
                    )

            if not detected_pattern:
                return None

            # Check cooldown to prevent duplicate alert storms
            cooldown_key = (device_id, source_ip, detected_pattern)
            last_alert = self._cooldowns.get(cooldown_key, 0)
            if (now_sec - last_alert) < self._cooldown_seconds:
                return None

            self._cooldowns[cooldown_key] = now_sec

            severity = (
                SeverityEnum.critical
                if detected_pattern in ("reconnaissance_probe", "credential_hunting")
                else SeverityEnum.warning
            )

            return SecurityEventCreate(
                timestamp=now_dt,
                device_id=device_id,
                event_type="attack_sequence",
                severity=severity,
                description=detected_desc,
                source_ip=source_ip,
                request_count=len(matched_sequence),
                time_window_seconds=self._window_seconds,
                metadata={
                    "pattern": detected_pattern,
                    "sequence": matched_sequence,
                    "sequence_threat_score": detected_threat_score,
                    "source_ip": source_ip,
                },
            )

    def _prune_expired(self, current_time: float) -> None:
        """Purge entries older than window."""
        cutoff = current_time - (self._window_seconds * 2)
        expired_keys = []
        for k, deq in self._history.items():
            while deq and deq[0][2] < cutoff:
                deq.popleft()
            if not deq:
                expired_keys.append(k)

        for k in expired_keys:
            del self._history[k]

        expired_cooldowns = [
            k for k, ts in self._cooldowns.items() if ts < cutoff
        ]
        for k in expired_cooldowns:
            del self._cooldowns[k]

    def reset(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._history.clear()
            self._cooldowns.clear()


# Global singleton instance
_sequence_service_instance: AttackSequenceService | None = None
_instance_lock = threading.Lock()


def get_sequence_service() -> AttackSequenceService:
    """Return the global sequence detection service instance."""
    global _sequence_service_instance
    with _instance_lock:
        if _sequence_service_instance is None:
            _sequence_service_instance = AttackSequenceService()
        return _sequence_service_instance


def reset_sequence_service() -> None:
    """Reset sequence detection service state."""
    global _sequence_service_instance
    with _instance_lock:
        if _sequence_service_instance is not None:
            _sequence_service_instance.reset()
            _sequence_service_instance = None
