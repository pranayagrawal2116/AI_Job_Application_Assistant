"""Candidate profile and resume schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ProfileUpdateRequest(BaseModel):
    profile_data: Dict[str, Any]


class ProfileResponse(BaseModel):
    user_id: int
    profile_data: Dict[str, Any]
    version: int = 1
    updated_at: Optional[str] = None


class ResumeResponse(BaseModel):
    id: int
    user_id: int
    original_filename: str
    file_format: str
    file_size_bytes: int
    file_hash: str
    is_primary: bool
    upload_date: Optional[str] = None
    created_at: Optional[str] = None


class ResumeSyncResponse(BaseModel):
    success: bool
    message: str
    updated_fields: List[str] = []
