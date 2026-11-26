"""FastAPI application entry point.

IoT Honeypot Monitor: Embedded Network Intrusion Detection System
Using NXP FRDM-RW612.
"""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import init_db
from app.routers import device, events, health, ip_profiles, logs, memory, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - initializes database on startup."""
    init_db()
    yield


def create_app() -> FastAPI:
    """Application factory - creates and configures the FastAPI app."""
    settings = get_settings()

    app = FastAPI(
        title="IoT Honeypot Monitor API",
        description=(
            "Backend API for the IoT Honeypot Monitor system. "
            "Collects and analyzes HTTP request logs and security events "
            "from NXP FRDM-RW612 honeypot devices."
        ),
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers under /api prefix
    app.include_router(health.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(logs.router, prefix="/api")
    app.include_router(stats.router, prefix="/api")
    app.include_router(device.router, prefix="/api")
    app.include_router(ip_profiles.router, prefix="/api")
    app.include_router(memory.router, prefix="/api")

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Catch unhandled exceptions and return a safe error response.

        Never expose internal details, stack traces, or credentials, while
        logging the exception server-side and preserving CORS headers for
        allowed origins.
        """
        logging.getLogger("uvicorn.error").exception(
            "Unhandled exception on %s %s", request.method, request.url.path
        )
        headers: dict[str, str] = {}
        origin = request.headers.get("origin")
        if origin and origin in settings.cors_origins_list:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        return JSONResponse(
            status_code=500,
            headers=headers,
            content={
                "detail": "An internal server error occurred.",
                "status_code": 500,
            },
        )

    return app


app = create_app()
