"""Authentication dependency for FastAPI endpoints."""

from typing import Optional, Tuple
from fastapi import Cookie, Header, HTTPException, status
from src.security.session_manager import SessionManager
from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import SecurityAuthorizationError, InvalidSessionError


def get_session_token(
    session_id: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
) -> str:
    """Extracts session token from Cookie or Authorization header."""
    token = session_id
    if not token and authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
            
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in to access this resource.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


def get_current_user_and_session(
    session_token: str = Cookie(None, alias="session_id"),
    authorization: Optional[str] = Header(None),
) -> Tuple[int, object]:
    """Authoritatively validates server-side candidate session.
    
    Returns:
        (user_id: int, session: CandidateSession)
    """
    token = get_session_token(session_token, authorization)
    service = DashboardService.get_instance()
    
    try:
        session_mgr = getattr(service, "session_manager", None) or SessionManager.get_instance()
        verified_session = session_mgr.validate_session(token)
        
        user_id = verified_session.user_id
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session is missing associated candidate user ID.",
            )
            
        return user_id, verified_session
    except (SecurityAuthorizationError, InvalidSessionError, Exception) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Session authentication failed: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
