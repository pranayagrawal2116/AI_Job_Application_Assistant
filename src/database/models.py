"""Data models, enums, and structured representations for the database layer."""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any, Dict, List, Optional


class ApplicationStatus(str, Enum):
    """Permitted application lifecycle statuses, covering both Phase 7 universal statuses
    and legacy Phase 2-6 compatibility statuses."""
    # Phase 7 Universal Lifecycle Statuses
    DRAFT = "DRAFT"
    PREPARING = "PREPARING"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    APPROVED = "APPROVED"
    SUBMITTED = "SUBMITTED"
    IN_PROGRESS = "IN_PROGRESS"
    ASSESSMENT = "ASSESSMENT"
    INTERVIEW = "INTERVIEW"
    OFFER = "OFFER"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"
    CLOSED = "CLOSED"

    # Legacy Phase 2-6 Compatibility Aliases
    DISCOVERED = "Discovered"
    UNDER_REVIEW = "Under Review"
    SHORTLISTED = "Shortlisted"
    APPLICATION_PREPARED = "Application Prepared"
    AWAITING_APPROVAL = "Awaiting Approval"
    APPLIED = "Applied"
    LEGACY_INTERVIEW = "Interview"
    LEGACY_REJECTED = "Rejected"
    LEGACY_WITHDRAWN = "Withdrawn"

    @classmethod
    def list(cls) -> List[str]:
        return [c.value for c in cls]

    @classmethod
    def universal_statuses(cls) -> List[str]:
        """Returns the 12 primary universal lifecycle statuses."""
        return [
            cls.DRAFT.value,
            cls.PREPARING.value,
            cls.READY_FOR_REVIEW.value,
            cls.APPROVED.value,
            cls.SUBMITTED.value,
            cls.IN_PROGRESS.value,
            cls.ASSESSMENT.value,
            cls.INTERVIEW.value,
            cls.OFFER.value,
            cls.REJECTED.value,
            cls.WITHDRAWN.value,
            cls.CLOSED.value,
        ]

    @classmethod
    def from_str(cls, val: str) -> "ApplicationStatus":
        clean = (val or "").strip()
        for item in cls:
            if item.value.lower() == clean.lower() or item.name.lower() == clean.lower():
                return item
        raise ValueError(f"Unknown status '{val}'. Valid options: {cls.list()}")


class SubmissionChannel(str, Enum):
    """Controlled channels for external application submission."""
    COMPANY_PORTAL = "COMPANY_PORTAL"
    LINKEDIN = "LINKEDIN"
    INDEED = "INDEED"
    EMAIL = "EMAIL"
    RECRUITER = "RECRUITER"
    REFERRAL = "REFERRAL"
    OTHER = "OTHER"

    @classmethod
    def list(cls) -> List[str]:
        return [c.value for c in cls]


class FollowUpType(str, Enum):
    """Controlled categories for candidate-scheduled follow-up tasks."""
    STATUS_INQUIRY = "STATUS_INQUIRY"
    THANK_YOU_NOTE = "THANK_YOU_NOTE"
    PORTFOLIO_UPDATE = "PORTFOLIO_UPDATE"
    RECRUITER_CHECKIN = "RECRUITER_CHECKIN"
    PHONE_CALL = "PHONE_CALL"
    OTHER = "OTHER"

    @classmethod
    def list(cls) -> List[str]:
        return [c.value for c in cls]


class ApplicationSource(str, Enum):
    """Source origin of an application record."""
    JOB_DESCRIPTION = "JOB_DESCRIPTION"
    MATCH_RESULT = "MATCH_RESULT"
    PREPARED_PACKET = "PREPARED_PACKET"
    MANUAL = "MANUAL"

    @classmethod
    def list(cls) -> List[str]:
        return [c.value for c in cls]


@dataclass
class Company:
    name: str
    id: Optional[int] = None
    website: Optional[str] = None
    careers_url: Optional[str] = None
    location: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Job:
    company_name: str
    job_title: str
    job_url: str
    platform: str
    id: Optional[int] = None
    company_id: Optional[int] = None
    job_description: Optional[str] = None
    location: Optional[str] = None
    stipend: Optional[str] = None
    required_skills: Any = field(default_factory=list)
    eligibility_criteria: Any = field(default_factory=dict)
    application_deadline: Optional[str] = None
    match_score: float = 0.0
    match_classification: str = "Low"
    is_eligible: bool = True
    score_breakdown: Any = field(default_factory=dict)
    discovery_date: Optional[str] = None
    work_arrangement: Optional[str] = None
    publication_date: Optional[str] = None
    internship_duration: Optional[str] = None
    listing_status: str = "ACTIVE"
    last_verified: Optional[str] = None
    extraction_confidence: float = 1.0
    notes: Optional[str] = None
    user_id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def get_skills_as_json(self) -> str:
        if isinstance(self.required_skills, (list, dict)):
            return json.dumps(self.required_skills)
        return json.dumps([s.strip() for s in str(self.required_skills or "").split(",") if s.strip()])

    def get_eligibility_as_json(self) -> str:
        if isinstance(self.eligibility_criteria, (dict, list)):
            return json.dumps(self.eligibility_criteria)
        return json.dumps({"description": str(self.eligibility_criteria or "")})

    def get_score_breakdown_as_json(self) -> str:
        if isinstance(self.score_breakdown, (dict, list)):
            return json.dumps(self.score_breakdown)
        return json.dumps({"summary": str(self.score_breakdown or "")})

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("required_skills"), str):
            try:
                data["required_skills"] = json.loads(data["required_skills"])
            except Exception:
                pass
        if isinstance(data.get("eligibility_criteria"), str):
            try:
                data["eligibility_criteria"] = json.loads(data["eligibility_criteria"])
            except Exception:
                pass
        if isinstance(data.get("score_breakdown"), str):
            try:
                data["score_breakdown"] = json.loads(data["score_breakdown"])
            except Exception:
                pass
        return data


@dataclass
class Application:
    company_name: str = "Unknown"
    job_title: str = "Role"
    job_id: Optional[int] = None
    job_description_id: Optional[int] = None
    user_id: Optional[int] = None
    resume_id: Optional[int] = None
    status: str = ApplicationStatus.DISCOVERED.value
    id: Optional[int] = None
    date_prepared: Optional[str] = None
    date_submitted: Optional[str] = None
    resume_used: Optional[str] = None
    cover_letter_reference: Optional[str] = None
    notes: Optional[str] = None
    application_source: str = ApplicationSource.JOB_DESCRIPTION.value
    external_application_url: Optional[str] = None
    target_role: Optional[str] = None
    employment_type: Optional[str] = None
    location: Optional[str] = None
    salary_range: Optional[str] = None
    application_deadline: Optional[str] = None
    is_archived: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationEvent:
    """Immutable, append-only timeline event in the application lifecycle."""
    application_id: int
    user_id: int
    sequence_no: int
    event_type: str
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    actor_type: str = "CANDIDATE"
    actor_identifier: str = "Candidate"
    session_reference: Optional[str] = None
    event_payload_json: str = "{}"
    previous_event_hash: str = "GENESIS"
    event_hash: str = ""
    id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubmissionConfirmation:
    """Authoritative record of a confirmed manual job application submission."""
    application_id: int
    user_id: int
    submission_timestamp: str
    submission_channel: str
    packet_id: Optional[int] = None
    packet_version_hash: Optional[str] = None
    confirmation_reference: Optional[str] = None
    confirmation_doc_path: Optional[str] = None
    confirmation_doc_hash: Optional[str] = None
    candidate_notes: Optional[str] = None
    is_active_confirmation: int = 1
    id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationFollowUp:
    """Candidate-scheduled reminder or follow-up task."""
    application_id: int
    user_id: int
    follow_up_date: str
    follow_up_type: str
    description: str
    is_completed: int = 0
    completed_at: Optional[str] = None
    outcome_notes: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationLog:
    action: str
    job_id: Optional[int] = None
    id: Optional[int] = None
    application_id: Optional[int] = None
    user_id: Optional[int] = None
    anonymized_user_pseudonym: Optional[str] = None
    timestamp: Optional[str] = None
    details: Any = None

    def get_details_as_str(self) -> str:
        if isinstance(self.details, (dict, list)):
            return json.dumps(self.details)
        return str(self.details or "")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("details"), str):
            try:
                data["details"] = json.loads(data["details"])
            except Exception:
                pass
        return data


@dataclass
class CandidateProfileRecord:
    """Candidate profile snapshot (supports both user-scoped and legacy single-candidate)."""
    profile_data: Any
    id: Optional[int] = None
    user_id: Optional[int] = None
    profile_hash: Optional[str] = None
    version: int = 1
    is_active: bool = True
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    """Authenticated platform user."""
    id: int
    email: str
    password_hash: str
    password_salt: str
    full_name: str
    profession_industry: Optional[str] = None
    career_level: Optional[str] = None
    account_status: str = "active"
    failed_login_attempts: int = 0
    locked_until: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PasswordResetToken:
    """Single-use password reset token record."""
    id: int
    user_id: int
    token_hash: str
    token_salt: str
    expires_at: str
    ip_address: Optional[str] = None
    is_used: bool = False
    used_at: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreparedPacket:
    """Application revision materials bundle."""
    application_id: int
    user_id: int
    packet_version_hash: str
    original_resume_hash: str
    job_description_snapshot_hash: str
    screening_answers_json: str
    id: Optional[int] = None
    version_num: int = 1
    original_resume_id: Optional[int] = None
    tailored_resume_path: Optional[str] = None
    tailored_resume_hash: Optional[str] = None
    cover_letter_path: Optional[str] = None
    cover_letter_hash: Optional[str] = None
    form_payload_json: Optional[str] = None
    form_payload_hash: Optional[str] = None
    attachments_manifest_json: Optional[str] = None
    attachments_manifest_hash: Optional[str] = None
    is_active_revision: bool = True
    created_at: Optional[str] = None
    canonical_snapshot_json: Optional[str] = None
    candidate_profile_version: Optional[int] = None
    candidate_profile_hash: Optional[str] = None
    matching_result_id: Optional[int] = None
    matching_engine_version: Optional[str] = None
    scoring_configuration_version: Optional[str] = None
    scoring_profile: Optional[str] = None
    original_resume_version_num: Optional[int] = None
    job_description_id: Optional[int] = None
    template_id: Optional[str] = None
    template_version: Optional[str] = None

    @property
    def is_legacy(self) -> bool:
        """Returns True if this prepared packet is a legacy record without a complete canonical snapshot."""
        return self.canonical_snapshot_json is None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationApproval:
    """Human approval record."""
    application_id: int
    packet_version_hash: str
    ticket_nonce: str
    key_id: str
    approver_name: str
    session_id: str
    id: Optional[int] = None
    packet_id: Optional[int] = None
    user_id: Optional[int] = None
    approved_at: Optional[str] = None
    consumed_at: Optional[str] = None
    is_consumed: bool = False
    is_revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JobDescription:
    """Manual or parsed user-provided job description snapshot."""
    user_id: int
    source_type: str
    company_name: str
    job_title: str
    raw_content: str
    content_hash: str
    id: Optional[int] = None
    source_url: Optional[str] = None
    original_filename: Optional[str] = None
    storage_filename: Optional[str] = None
    file_hash: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_format: Optional[str] = None
    snapshot_hash: Optional[str] = None
    parsed_data: Optional[str] = None
    parser_version: Optional[str] = "1.0.0"
    extraction_confidence: Optional[float] = 1.0
    supersedes_job_description_id: Optional[int] = None
    binary_integrity_state: str = "REQUIRED"
    is_active: bool = True
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("parsed_data"), str):
            try:
                data["parsed_data"] = json.loads(data["parsed_data"])
            except Exception:
                pass
        return data


@dataclass
class ResumeRecord:
    """User-owned resume document record."""
    user_id: int
    storage_filename: str
    original_filename: str
    file_format: str
    file_hash: str
    file_size_bytes: int
    id: Optional[int] = None
    parsed_data: Optional[str] = None
    is_primary: bool = False
    label: str = "General"
    target_role: Optional[str] = None
    parsing_status: str = "COMPLETED"
    active_version: int = 1
    is_active: int = 1
    uploaded_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResumeVersionRecord:
    """Historical version snapshot of a user resume."""
    resume_id: int
    user_id: int
    version_num: int
    snapshot_json: str
    id: Optional[int] = None
    storage_filename: Optional[str] = None
    file_hash: Optional[str] = None
    file_size_bytes: Optional[int] = None
    change_notes: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MatchResult:
    """User-owned immutable match evaluation record between a resume/profile and a job description."""
    user_id: int
    match_score: float
    match_classification: str
    eligibility_status: str  # 'ELIGIBLE', 'INELIGIBLE', 'UNKNOWN'
    score_breakdown: str     # JSON string of dimensional breakdown
    explanation: str         # Summary / text explanation
    id: Optional[int] = None
    resume_id: Optional[int] = None
    resume_version_num: int = 1
    resume_file_hash: Optional[str] = None
    candidate_profile_version: int = 1
    candidate_profile_hash: Optional[str] = None
    job_id: Optional[int] = None
    job_description_id: Optional[int] = None
    job_snapshot_hash: Optional[str] = None
    scoring_profile: str = "general_baseline"
    scoring_config_version: str = "1.0.0"
    assessment_confidence: float = 1.0
    engine_version: str = "2.1.1"
    matching_skills: Optional[str] = None      # JSON list/dict
    related_skills: Optional[str] = None       # JSON list/dict
    partial_matches: Optional[str] = None      # JSON list/dict
    missing_skills: Optional[str] = None       # JSON list/dict
    education_analysis: Optional[str] = None   # JSON dict
    experience_analysis: Optional[str] = None  # JSON dict
    certification_analysis: Optional[str] = None  # JSON dict
    eligibility_reasons: Optional[str] = None  # JSON list
    scoring_explanations: Optional[str] = None # JSON dict
    recommendations: Optional[str] = None      # JSON list
    details_json: Optional[str] = None         # Canonical RFC 8785 JSON of full evaluation details
    evaluated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for json_field in (
            "score_breakdown", "matching_skills", "related_skills",
            "partial_matches", "missing_skills", "education_analysis",
            "experience_analysis", "certification_analysis",
            "eligibility_reasons", "scoring_explanations", "recommendations",
            "details_json",
        ):
            val = data.get(json_field)
            if isinstance(val, str):
                try:
                    data[json_field] = json.loads(val)
                except Exception:
                    pass
        return data


@dataclass(frozen=True)
class VerifiedApprovalGrant:
    """Verifiable, single-use approval grant issued exclusively by SessionManager.

    Proof that a HUMAN_APPROVAL action ticket was cryptographically verified,
    bound to the candidate session, and consumed.
    Contains cryptographic server signature and issuance metadata preventing forgery.
    """
    grant_id: str
    user_id: int
    session_id: str
    application_id: int
    packet_id: int
    packet_version_hash: str
    ticket_nonce: str
    key_id: str
    action_type: str = "HUMAN_APPROVAL"
    issued_at: int = 0
    expires_at: int = 0
    grant_signature: str = ""
    approver_name: str = "Human Candidate"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Backward-compatible alias
VerifiedApprovalContext = VerifiedApprovalGrant


# -----------------------------------------------------------------------------
# PHASE 9.1.2: SECURITY SCANS & OVERRIDES
# -----------------------------------------------------------------------------

@dataclass
class SecurityScan:
    """Authenticated, immutable security scan record."""
    id: int
    user_id: int
    source_type: str  # 'job_description' or 'resume'
    source_id: int
    source_version: int
    source_hash: str
    snapshot_hash: Optional[str]
    scanner_version: str
    policy_version: str
    risk_score: float
    classification: str  # CLEAN, SUSPICIOUS, QUARANTINED
    threats_detected_json: str
    key_id: str
    hmac_signature: str
    source_binary_hash: Optional[str] = None
    source_binary_size_bytes: Optional[int] = None
    source_binary_format: Optional[str] = None
    manifest_version: str = "v1"
    scanned_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(self.threats_detected_json, str):
            try:
                data["threats_detected"] = json.loads(self.threats_detected_json)
            except Exception:
                data["threats_detected"] = []
        return data


@dataclass
class SecurityScanOverride:
    """Audit log of candidate or administrator security scan override."""
    id: int
    user_id: int
    scan_id: int
    source_type: str
    source_id: int
    source_version: int
    override_reason: str
    actor_type: str = "candidate"
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LegacyIntegrityException:
    """Audit log of grandfathered legacy job description binary integrity exception."""
    id: int
    user_id: int
    job_description_id: int
    original_source_type: str
    previous_binary_state: Optional[str]
    assigned_legacy_state: str
    source_snapshot_hash: Optional[str]
    migration_version: str
    migration_timestamp: str
    migration_reason: str
    outcome: str
    evidence_type: Optional[str] = None
    evidence_reference_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LegacyEvidenceAttestation:
    """Authoritative independent evidence attesting to the historical origin of a job description."""
    id: int
    user_id: int
    job_description_id: int
    evidence_type: str
    evidence_reference_id: str
    source_snapshot_hash: str
    attested_by: str
    attested_at: str
    evidence_artifact_hash: Optional[str] = None
    evidence_payload_hash: Optional[str] = None
    issuer_id: Optional[str] = None
    key_id: Optional[str] = None
    signature_algorithm: Optional[str] = None
    evidence_signature: Optional[str] = None
    migration_boundary: Optional[str] = None
    verified_at: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)





