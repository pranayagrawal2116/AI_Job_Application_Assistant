"""Application workspace, preparation, and tracking schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ApplicationCreateRequest(BaseModel):
    job_id: Optional[int] = None
    job_description_id: Optional[int] = None
    resume_id: Optional[int] = None
    company_name: Optional[str] = None
    job_title: Optional[str] = None


class ApplicationResponse(BaseModel):
    id: int
    user_id: int
    company_name: str
    job_title: str
    status: str
    job_id: Optional[int] = None
    job_description_id: Optional[int] = None
    resume_id: Optional[int] = None
    external_application_url: Optional[str] = None
    target_role: Optional[str] = None
    location: Optional[str] = None
    application_deadline: Optional[str] = None
    date_prepared: Optional[str] = None
    date_submitted: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    is_archived: bool = False


class ApplicationStatusUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = None


class TailorResumeRequest(BaseModel):
    template: Optional[str] = "modern"


class CoverLetterRequest(BaseModel):
    tone: Optional[str] = "Professional & Direct"
    custom_notes: Optional[str] = None


class ScreeningQuestionsRequest(BaseModel):
    questions: List[Dict[str, Any]]


class PreparedPacketResponse(BaseModel):
    id: int
    user_id: int
    application_id: int
    packet_version: int
    packet_version_hash: str
    is_active_revision: bool
    status: str = "DRAFT"
    tailored_resume: Dict[str, Any] = {}
    cover_letter: Dict[str, Any] = {}
    screening_qa: Dict[str, Any] = {}
    created_at: Optional[str] = None


class IssueTicketResponse(BaseModel):
    ticket: str
    action_type: str
    application_id: int
    packet_hash: str


class AuthorizePacketRequest(BaseModel):
    approver_name: str
    action_ticket: str
    candidate_confirmed: bool = True


class ConfirmSubmissionRequest(BaseModel):
    submission_ticket: str
    submission_channel: str = "COMPANY_PORTAL"
    confirmation_reference: Optional[str] = None
    candidate_notes: Optional[str] = None
    candidate_confirmed: bool = True


class FollowUpCreateRequest(BaseModel):
    follow_up_type: str = "STATUS_INQUIRY"
    scheduled_date: str
    notes: Optional[str] = None


class FollowUpResponse(BaseModel):
    id: int
    application_id: int
    user_id: int
    follow_up_type: str
    scheduled_date: str
    is_completed: bool
    completed_at: Optional[str] = None
    outcome_notes: Optional[str] = None
