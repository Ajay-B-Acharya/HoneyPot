"""Application configuration module.

Loads settings from environment variables with sensible defaults.
Uses python-dotenv to load .env files.
"""

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "iot-honeypot-backend"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./honeypot.db"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Device status threshold (seconds) - device considered "inactive" after this
    DEVICE_INACTIVE_THRESHOLD_SECONDS: int = 300

    # Detection Engine Configuration
    DETECTION_ALLOWED_ENDPOINTS: str = "/status,/info,/config"
    DETECTION_RATE_THRESHOLD: int = 20
    DETECTION_RATE_WINDOW_SECONDS: int = 10
    DETECTION_RATE_COOLDOWN_SECONDS: int = 10
    DETECTION_REPEATED_THRESHOLD: int = 10
    DETECTION_REPEATED_WINDOW_SECONDS: int = 10
    DETECTION_REPEATED_COOLDOWN_SECONDS: int = 10
    DETECTION_MAX_TRACKING_ENTRIES: int = 10000
    DETECTION_TRACKING_EXPIRATION_SECONDS: int = 60

    @property
    def detection_allowed_endpoints_set(self) -> set[str]:
        """Parse DETECTION_ALLOWED_ENDPOINTS into a set of normalized paths."""
        return {
            ep.strip()
            for ep in self.DETECTION_ALLOWED_ENDPOINTS.split(",")
            if ep.strip()
        }

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ORIGINS comma-separated string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
