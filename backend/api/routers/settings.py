"""Settings, backup, and data export endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.post("/backup")
def trigger_backup(auth_ctx=Depends(get_current_user_and_session)):
    """Triggers an online atomic hot backup of the SQLite database."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        backup_path = service.backup_database()
        return {
            "status": "ok",
            "backup_path": str(backup_path),
            "message": f"Backup created successfully at {getattr(backup_path, 'name', str(backup_path))}",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Backup failed: {str(e)}")


@router.get("/export/csv")
def export_csv(auth_ctx=Depends(get_current_user_and_session)):
    """Generates and downloads a clean CSV export of tracked applications."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    export_path = service.export_jobs_to_csv()
    if not export_path or not export_path.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Export generation failed.")
        
    return FileResponse(
        path=str(export_path),
        filename=export_path.name,
        media_type="text/csv",
    )
