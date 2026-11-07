"""FastAPI application entrypoint for Universal AI Job Application Assistant."""

from contextlib import asynccontextmanager
from pathlib import Path

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
    # Initialize backend singleton on startup
    logger.info("Initializing DashboardService and DatabaseManager...")
    service = DashboardService.get_instance()
    # Ensure nested storage directories exist
    if hasattr(service.db, "db_path") and service.db.db_path != ":memory:":
        base = Path(service.db.db_path).parent.parent
        for d in [base / "users", base / "exports", base / "storage" / "backups"]:
            d.mkdir(parents=True, exist_ok=True)

    # Phase B.3.3: Startup recovery of interrupted PENDING/RUNNING discovery runs
    try:
        recovered = service.db.recover_interrupted_discovery_runs()
        if recovered > 0:
            logger.warning("Recovered %d interrupted discovery run(s) on server startup.", recovered)
        else:
            logger.info("Startup recovery: Zero interrupted discovery runs found.")
    except Exception as e:
        logger.error("Failed to recover interrupted discovery runs on startup: %s", e)

    yield
    logger.info("FastAPI application shutdown.")


app = FastAPI(
    title="Universal AI Job Application Assistant API",
    description="Secure, authenticated REST API powering the modern candidate SaaS experience.",
    version="2.1.1",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
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
def health_check():
    """Health check endpoint for reverse proxy monitoring."""
    return {
        "status": "healthy",
        "version": "2.1.1",
        "framework": "FastAPI + React SaaS",
    }


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
