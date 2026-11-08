"""Authentication dependency for FastAPI endpoints."""

import hmac
from typing import Optional, Tuple
from fastapi import Cookie, Header, HTTPException, Request, status
from src.security.session_manager import SessionManager
from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import SecurityAuthorizationError, InvalidSessionError


def get_current_user_and_session(
    request: Request,
    session_token: Optional[str] = Cookie(None, alias="session_id"),
    authorization: Optional[str] = Header(None),
) -> Tuple[int, object]:
    """Authoritatively validates server-side candidate session with CSRF protection.
    
    Returns:
        (user_id: int, session: CandidateSession)
    """
    is_cookie_session = False
    token = None
    
    if authorization and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]

    if not token and session_token and session_token.strip():
        token = session_token
        is_cookie_session = True
            
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in to access this resource.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # CSRF Defense: For cookie-authenticated mutating requests (POST, PUT, PATCH, DELETE),
    # verify X-CSRF-Token header matches csrf_token cookie.
    # When Authorization: Bearer is explicitly passed by API clients, CSRF token is not required.
    if is_cookie_session and not authorization and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.url.path not in ("/api/auth/login", "/api/auth/register"):
            header_csrf = request.headers.get("X-CSRF-Token")
            cookie_csrf = request.cookies.get("csrf_token")
            if not header_csrf or not cookie_csrf or not hmac.compare_digest(header_csrf, cookie_csrf):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF verification failed. Missing or mismatched CSRF token.",
                )

    service = DashboardService.get_instance()
    try:
        session_mgr = getattr(service, "session_manager", None) or SessionManager.get_instance()
        verified_session = session_mgr.validate_session(token.strip())
        
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
