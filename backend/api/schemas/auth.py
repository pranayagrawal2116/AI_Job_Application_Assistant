"""Authentication request and response schemas."""

from typing import Optional
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=120)
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)
    profession_industry: Optional[str] = None
    career_level: Optional[str] = None


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1)


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    profession_industry: Optional[str] = None
    career_level: Optional[str] = None


class SessionResponse(BaseModel):
    session_id: Optional[str] = None
    user: UserResponse
    message: str = "Authenticated successfully"
