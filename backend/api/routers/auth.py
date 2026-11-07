"""Authentication endpoints using Argon2id and SessionManager."""

import os
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from dashboard.services.dashboard_service import DashboardService
from backend.api.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    SessionResponse,
    UserResponse,
)
from backend.api.dependencies.auth import get_current_user_and_session
from src.database.exceptions import (
    AccountLockedError,
    AuthenticationFailedError,
    DuplicateUserError,
    ValidationError,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _is_secure_cookie() -> bool:
    env = os.getenv("APP_ENV", "").lower()
    return env in ("prod", "production") or os.getenv("SECURE_COOKIES", "false").lower() == "true"


@router.post("/register", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, response: Response):
    """Registers a new candidate with Argon2id password hashing."""
    service = DashboardService.get_instance()
    try:
        user = service.register_candidate(
            email=req.email,
            password=req.password,
            full_name=req.full_name,
            profession_industry=req.profession_industry,
            career_level=req.career_level,
        )
        _, session = service.login_candidate(email=req.email, password=req.password)
        
        csrf_token = secrets.token_urlsafe(32)
        is_secure = _is_secure_cookie()
        
        # Set HttpOnly session cookie
        response.set_cookie(
            key="session_id",
            value=session.session_id,
            httponly=True,
            samesite="lax",
            secure=is_secure,
            max_age=86400 * 7,
        )
        
        # Set non-HttpOnly CSRF token cookie for frontend headers
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=is_secure,
            max_age=86400 * 7,
        )
        
        user_res = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            profession_industry=getattr(user, "profession_industry", None),
            career_level=getattr(user, "career_level", None),
        )
        return SessionResponse(session_id=session.session_id, user=user_res, message="Registration successful")
    except DuplicateUserError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration failed: {str(e)}")


@router.post("/login", response_model=SessionResponse)
def login(req: LoginRequest, response: Response, request: Request):
    """Authenticates candidate with Argon2id and issues a cryptographically signed server session."""
    service = DashboardService.get_instance()
    client_ip = request.client.host if request.client else None
    
    try:
        user, session = service.login_candidate(email=req.email, password=req.password, client_ip=client_ip)
        
        csrf_token = secrets.token_urlsafe(32)
        is_secure = _is_secure_cookie()
        
        response.set_cookie(
            key="session_id",
            value=session.session_id,
            httponly=True,
            samesite="lax",
            secure=is_secure,
            max_age=86400 * 7,
        )
        
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=is_secure,
            max_age=86400 * 7,
        )
        
        user_res = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            profession_industry=getattr(user, "profession_industry", None),
            career_level=getattr(user, "career_level", None),
        )
        return SessionResponse(session_id=session.session_id, user=user_res, message="Sign in successful")
    except AuthenticationFailedError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Login failed: {str(e)}")


@router.post("/logout")
def logout(
    response: Response,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Revokes active server session and clears cookies."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    service.logout_candidate(session.session_id)
    
    response.delete_cookie(key="session_id")
    response.delete_cookie(key="csrf_token")
    return {"message": "Signed out successfully", "status": "ok"}


@router.get("/me", response_model=UserResponse)
def get_me(auth_ctx=Depends(get_current_user_and_session)):
    """Returns profile for currently authenticated candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    user = service.db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found")
        
    u_id = user["id"] if isinstance(user, dict) else user.id
    u_email = user["email"] if isinstance(user, dict) else user.email
    u_name = user["full_name"] if isinstance(user, dict) else user.full_name
    u_ind = user.get("profession_industry") if isinstance(user, dict) else getattr(user, "profession_industry", None)
    u_lvl = user.get("career_level") if isinstance(user, dict) else getattr(user, "career_level", None)
        
    return UserResponse(
        id=u_id,
        email=u_email,
        full_name=u_name,
        profession_industry=u_ind,
        career_level=u_lvl,
    )
