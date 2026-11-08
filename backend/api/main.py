"""FastAPI application entrypoint for Universal AI Job Application Assistant."""

import os
from contextlib import asynccontextmanager
from pathlib import Path

# Phase C.0: Load environment before importing/instantiating application components
from src.config.env_loader import load_production_env, validate_production_configuration
load_production_env()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routers import (
    applications,
    auth,
    dashboard,
    discovery,
    jobs,
    matching,
    profile,
    settings,
)
from dashboard.services.dashboard_service import DashboardService
from src.utils.logger import setup_logger

logger = setup_logger("API")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Resolve APP_ENV
    app_env = os.environ.get("APP_ENV", "development").lower()
    app.state.app_env = app_env

    # 2. Phase C.0.1: Production configuration validation BEFORE database or backend initialization
    if app_env == "production":
        try:
            validate_production_configuration()
            app.state.config_ready = True
            app.state.config_error = None
            logger.info("Production configuration validation passed successfully.")
        except Exception as e:
            logger.critical("Production configuration validation failed: %s", e)
            app.state.config_ready = False
            app.state.config_error = str(e)
            raise RuntimeError(f"Production configuration validation failed: {e}") from e
    else:
        app.state.config_ready = True
        app.state.config_error = None

    # 3. Initialize backend singleton on startup (only after configuration is confirmed valid)
    logger.info("Initializing DashboardService and DatabaseManager...")
    service = DashboardService.get_instance()

    # 4. Ensure nested storage directories exist for persistent storage
    if hasattr(service.db, "db_path") and service.db.db_path != ":memory:":
        base = Path(service.db.db_path).parent.parent
        for d in [base / "users", base / "exports", base / "storage" / "backups"]:
            d.mkdir(parents=True, exist_ok=True)

    # 5. Phase B.3.3: Startup recovery of interrupted PENDING/RUNNING discovery runs
    try:
        recovered = service.db.recover_interrupted_discovery_runs()
        if recovered > 0:
            logger.warning("Recovered %d interrupted discovery run(s) on server startup.", recovered)
        else:
            logger.info("Startup recovery: Zero interrupted discovery runs found.")
        app.state.discovery_ready = True
        app.state.discovery_recovery_error = None
    except Exception as e:
        logger.critical("Failed to recover interrupted discovery runs on startup: %s", e)
        app.state.discovery_ready = False
        app.state.discovery_recovery_error = str(e)

    yield
    logger.info("FastAPI application shutdown.")


app = FastAPI(
    title="Universal AI Job Application Assistant API",
    description="Secure, authenticated REST API powering the modern candidate SaaS experience.",
    version="2.1.1",
    lifespan=lifespan,
)

cors_origins_env = os.environ.get("CORS_ORIGINS", "")
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8501",
    "http://127.0.0.1:8501",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
if cors_origins_env:
    for o in cors_origins_env.split(","):
        clean_origin = o.strip()
        if clean_origin and clean_origin not in allowed_origins:
            allowed_origins.append(clean_origin)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(discovery.router)
app.include_router(profile.router)
app.include_router(jobs.router)
app.include_router(matching.router)
app.include_router(applications.router)
app.include_router(settings.router)


@app.get("/api/health")
def health_check(request: Request):
    """Health check endpoint for reverse proxy and service readiness monitoring."""
    config_ready = getattr(request.app.state, "config_ready", True)
    config_error = getattr(request.app.state, "config_error", None)
    discovery_ready = getattr(request.app.state, "discovery_ready", True)
    recovery_error = getattr(request.app.state, "discovery_recovery_error", None)
    app_env = getattr(request.app.state, "app_env", os.environ.get("APP_ENV", "development").lower())

    service = DashboardService.get_instance()
    db_connected = True
    db_error = None
    try:
        with service.db.get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as e:
        db_connected = False
        db_error = str(e)

    db_path = str(getattr(service.db, "db_path", ""))
    storage_base = str(getattr(service, "storage_base_dir", ""))
    persistent_storage_ready = Path(storage_base).exists() if storage_base and storage_base != ":memory:" else True

    is_healthy = discovery_ready and config_ready and db_connected
    status_code = 200 if is_healthy else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if is_healthy else "degraded",
            "version": "2.1.1",
            "framework": "FastAPI + React SaaS",
            "environment": {
                "app_env": app_env,
                "database_connected": db_connected,
                "persistent_storage_ready": persistent_storage_ready,
                "database_path": db_path,
                "storage_base": storage_base,
                "db_error": db_error,
            },
            "configuration_subsystem": {
                "ready": config_ready,
                "error": config_error,
            },
            "discovery_subsystem": {
                "ready": discovery_ready,
                "recovery_error": recovery_error,
            },
            "single_worker_mode": True,
        },
    )


# Mount built frontend if available (Production & IIS deployment mode)
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str, request: Request):
        # Don't intercept API routes
        if full_path.startswith("api/") or full_path == "api":
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        
        file_path = FRONTEND_DIST / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIST / "index.html")
