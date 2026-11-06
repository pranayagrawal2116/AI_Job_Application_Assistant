"""Playwright Form Inspection & Pre-filler module with strict anti-bot and submission safeguards."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from src.database.models import Job
from src.utils.logger import setup_logger

logger = setup_logger("FormPrefiller")


@dataclass
class FormFieldMapping:
    field_name: str
    target_selector: str
    field_type: str  # text, email, tel, textarea, file, select
    intended_value: str
    status: str  # PREPARED, REQUIRES_AUTH, MANUAL_ONLY
    is_sensitive: bool = False


@dataclass
class VerifiedAttachmentRef:
    """Authoritative cryptographic attachment reference binding physical file and persistent scan."""
    user_id: int
    resume_id: int
    version_num: int
    storage_filename: str
    file_path: str
    file_hash: str
    file_size_bytes: int
    file_format: str
    scan_id: int
    scan_signature: str
    verified_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormFillPlan:
    job_id: int
    company_name: str
    target_url: str
    fields_to_fill: List[FormFieldMapping] = field(default_factory=list)
    resume_attachment_ready: bool = False
    resume_file_path: Optional[str] = None
    attachment_ref: Optional[VerifiedAttachmentRef] = None
    unmapped_fields: List[str] = field(default_factory=list)
    anti_automation_detected: bool = False
    safety_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FormPrefiller:
    """Prepares structured form pre-filling payloads while enforcing strict safety gates."""

    def __init__(
        self,
        candidate_profile: Optional[Dict[str, Any]] = None,
        db_manager: Optional[Any] = None,
        file_validator: Optional[Any] = None,
    ):
        self.profile = candidate_profile or {}
        self.db = db_manager
        self.file_validator = file_validator

    def detect_anti_automation(self, snapshot_text: str) -> bool:
        """Detects anti-bot mechanisms like Cloudflare, CAPTCHA, or login gates."""
        anti_bot_patterns = [
            r"cloudflare", r"just a moment", r"turnstile", r"verify you are human",
            r"captcha", r"recaptcha", r"hcaptcha", r"bot detection", r"access denied",
            r"please log in to apply", r"sign in to apply"
        ]
        lower_snap = snapshot_text.lower()
        for pat in anti_bot_patterns:
            if re.search(pat, lower_snap):
                return True
        return False

    def build_form_payload(
        self,
        job: Job | Dict[str, Any],
        cover_letter_text: str = "",
        resume_file_path: Optional[str] = None,
        answers: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
    ) -> FormFillPlan:
        """Constructs an executable form filling plan without executing forbidden actions."""
        # Security preflight: Centralized HMAC enforcement and strict external agent gate (Phase 9.1.2.1 Part C & Phase 9.1.2.2)
        from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
        from src.database.exceptions import (
            CrossUserAccessError,
            QuarantinedSourceError,
            SecurityAuthorizationError,
        )
        from src.security.security_preflight import SecurityPreflightManager
        from src.security.resume_verifier import ResumeIntegrityVerifier

        target_action = "external_agent_execution"

        # Resolve authenticated user_id
        uid = user_id or self.profile.get("user_id")
        job_id = job.get("id") if isinstance(job, dict) else getattr(job, "id", None)

        # 1. Authoritative Job Description Security Preflight
        is_persisted_job = False
        if isinstance(job, Job):
            is_persisted_job = True
        elif hasattr(job, "source_type") or hasattr(job, "snapshot_hash") or hasattr(job, "raw_content"):
            is_persisted_job = bool(job_id)
        elif isinstance(job, dict):
            if job.get("is_persisted") is True or job.get("source_type") in ("upload", "uploaded", "url", "pasted", "PASTE", "URL", "UPLOAD"):
                is_persisted_job = True
            elif job.get("id") and (job.get("user_id") or user_id or self.db):
                is_persisted_job = True

        if is_persisted_job:
            if not self.db or not uid:
                raise SecurityAuthorizationError(
                    "Persisted job description verification requires authenticated user_id and database manager."
                )
            job_owner_id = job.get("user_id") if isinstance(job, dict) else getattr(job, "user_id", None)
            if job_owner_id is not None and job_owner_id != uid:
                raise CrossUserAccessError(
                    user_id=uid,
                    target_user_id=job_owner_id,
                    resource=f"job_description #{job_id}",
                )
            preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
            preflight.check_job_description_security(
                user_id=uid,
                jd_id=job_id,
                target_action=target_action,
            )
        else:
            # Ephemeral scanning for unpersisted text inputs or when DB record is not provided
            detector = PromptInjectionDetector()
            jd_text = ""
            if isinstance(job, dict):
                jd_text = job.get("job_description") or job.get("raw_content") or ""
            elif hasattr(job, "job_description"):
                jd_text = job.job_description or ""

            if jd_text:
                jd_scan = detector.scan(jd_text)
                if jd_scan.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                    raise QuarantinedSourceError(
                        f"Action '{target_action}' blocked: Job description text is {jd_scan.classification} "
                        f"(Risk: {jd_scan.risk_score:.2f}) and cannot be exposed to external agents.",
                        source_type="job_description",
                        source_id=job_id or 0,
                        classification=jd_scan.classification,
                        risk_score=jd_scan.risk_score,
                    )

        # 2. Cover Letter Text Security Check
        detector = PromptInjectionDetector()
        if cover_letter_text:
            cl_scan = detector.scan(cover_letter_text)
            if cl_scan.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                raise QuarantinedSourceError(
                    f"Action '{target_action}' blocked: Cover letter text is {cl_scan.classification} "
                    f"(Risk: {cl_scan.risk_score:.2f}) and cannot be exposed to external agents.",
                    source_type="cover_letter",
                    source_id=0,
                    classification=cl_scan.classification,
                    risk_score=cl_scan.risk_score,
                )

        # 3. Screening Question Answers Security Check
        if answers and isinstance(answers, dict):
            for k, val in answers.items():
                if isinstance(val, str) and len(val) > 10:
                    ans_scan = detector.scan(val)
                    if ans_scan.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                        raise QuarantinedSourceError(
                            f"Action '{target_action}' blocked: Screening question answer '{k}' is {ans_scan.classification} "
                            f"(Risk: {ans_scan.risk_score:.2f}) and cannot be exposed to external agents.",
                            source_type="screening_answer",
                            source_id=0,
                            classification=ans_scan.classification,
                            risk_score=ans_scan.risk_score,
                        )

        # 4. Authoritative Resume Security Preflight & Attachment Validation (Phase 9.1.2.2 Part A & Phase 9.1.2.3 Part D)
        resume_ready = False
        verified_attachment_path: Optional[str] = None
        attachment_ref: Optional[VerifiedAttachmentRef] = None

        if resume_id is not None:
            if not self.db or not uid:
                raise SecurityAuthorizationError(
                    "Resume attachment verification requires authenticated user_id and database manager."
                )
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
            v_res = verifier.verify_and_load_resume(
                user_id=uid,
                resume_id=resume_id,
                version_num=resume_version_num,
                fresh_parse=False,
            )
            preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
            preflight.check_resume_security(
                user_id=uid,
                resume_id=resume_id,
                version_num=resume_version_num,
                verified_resume=v_res,
                target_action=target_action,
            )
            if resume_file_path:
                if Path(resume_file_path).resolve() != v_res.resolved_path.resolve():
                    raise SecurityAuthorizationError(
                        f"Provided resume_file_path '{resume_file_path}' does not match verified resume record '{v_res.resolved_path}'."
                    )
            verified_attachment_path = str(v_res.resolved_path)
            resume_ready = True

            # Retrieve the latest security scan to construct authoritative VerifiedAttachmentRef
            latest_scan = self.db.get_latest_security_scan(
                user_id=uid,
                source_type="resume",
                source_id=resume_id,
                source_version=v_res.version_num,
            )
            from datetime import datetime, timezone
            attachment_ref = VerifiedAttachmentRef(
                user_id=uid,
                resume_id=resume_id,
                version_num=v_res.version_num,
                storage_filename=v_res.storage_filename,
                file_path=str(v_res.resolved_path),
                file_hash=v_res.file_hash,
                file_size_bytes=v_res.file_size_bytes,
                file_format=v_res.file_format,
                scan_id=latest_scan.id if latest_scan else 0,
                scan_signature=latest_scan.hmac_signature if latest_scan else "",
                verified_at=datetime.now(timezone.utc).isoformat(),
            )
        elif resume_file_path is not None:
            raise SecurityAuthorizationError(
                "Unverified resume file path cannot bypass authoritative resume verification. "
                "Resume attachment requires authenticated user_id and resume_id."
            )

        if isinstance(job, dict):
            job_id = job.get("id", 0)
            company_name = job.get("company_name", "Unknown")
            job_url = job.get("job_url", "") or job.get("source_url", "")
        else:
            job_id = job.id or 0
            company_name = job.company_name
            job_url = getattr(job, "job_url", None) or getattr(job, "source_url", "") or ""

        personal = self.profile.get("personal", {})
        full_name = personal.get("full_name", "")
        name_parts = full_name.split()
        first_name = name_parts[0] if name_parts else ""
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
        email = personal.get("email", "")
        phone = personal.get("phone", "")
        location = personal.get("location", "")
        github = personal.get("github", "")
        linkedin = personal.get("linkedin", "")

        edu = self.profile.get("education", [{}])[0] if self.profile.get("education") else {}
        institution = edu.get("institution", "")
        degree = edu.get("degree", "")
        grad_year = str(edu.get("expected_graduation_year") or edu.get("graduation_year", ""))
        cgpa = str(edu.get("current_cgpa") or edu.get("cgpa", ""))

        fields: List[FormFieldMapping] = [
            FormFieldMapping(
                field_name="Full Name",
                target_selector="input[name*='name'], input[id*='name']",
                field_type="text",
                intended_value=full_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="First Name",
                target_selector="input[name*='first_name'], input[id*='first_name']",
                field_type="text",
                intended_value=first_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Last Name",
                target_selector="input[name*='last_name'], input[id*='last_name']",
                field_type="text",
                intended_value=last_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Email Address",
                target_selector="input[type='email'], input[name*='email']",
                field_type="email",
                intended_value=email,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Phone Number",
                target_selector="input[type='tel'], input[name*='phone'], input[name*='mobile']",
                field_type="tel",
                intended_value=phone,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Current Location / City",
                target_selector="input[name*='location'], input[name*='city']",
                field_type="text",
                intended_value=location,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="LinkedIn Profile",
                target_selector="input[name*='linkedin'], input[id*='linkedin']",
                field_type="text",
                intended_value=linkedin,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="GitHub Profile",
                target_selector="input[name*='github'], input[id*='github']",
                field_type="text",
                intended_value=github,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="University / College",
                target_selector="input[name*='college'], input[name*='university'], input[name*='school']",
                field_type="text",
                intended_value=institution,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Degree / Qualification",
                target_selector="input[name*='degree'], select[name*='degree']",
                field_type="text",
                intended_value=degree,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Graduation Year",
                target_selector="input[name*='grad'], select[name*='grad']",
                field_type="text",
                intended_value=grad_year,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="CGPA / Percentage",
                target_selector="input[name*='gpa'], input[name*='cgpa'], input[name*='grade']",
                field_type="text",
                intended_value=cgpa,
                status="PREPARED",
            ),
        ]

        if cover_letter_text:
            fields.append(
                FormFieldMapping(
                    field_name="Cover Letter / Summary",
                    target_selector="textarea[name*='cover'], textarea[id*='cover'], textarea[name*='summary']",
                    field_type="textarea",
                    intended_value=cover_letter_text,
                    status="PREPARED",
                )
            )

        if resume_ready and verified_attachment_path:
            fields.append(
                FormFieldMapping(
                    field_name="Resume File Attachment",
                    target_selector="input[type='file'], input[name*='resume']",
                    field_type="file",
                    intended_value=verified_attachment_path,
                    status="REQUIRES_AUTH",
                    is_sensitive=True,
                )
            )

        return FormFillPlan(
            job_id=job_id,
            company_name=company_name,
            target_url=job_url,
            fields_to_fill=fields,
            resume_attachment_ready=resume_ready,
            resume_file_path=verified_attachment_path,
            attachment_ref=attachment_ref,
            anti_automation_detected=False,
            safety_message="Form fields prepared. Human review and explicit approval required prior to submission.",
        )

    def open_verified_attachment(
        self,
        plan_or_ref: Union[FormFillPlan, VerifiedAttachmentRef],
        user_id: int,
    ) -> bytes:
        """Opens and verifies an authoritative attachment binary immediately before form upload (use-time TOCTOU defense).

        Re-validates:
        1. User ownership and identity binding
        2. Physical file existence, symlink traversal prevention, and candidate directory containment
        3. Exact SHA-256 hash matching attachment_ref
        4. Exact file byte size matching attachment_ref
        5. File format magic byte headers (%PDF- or PK\x03\x04)
        6. Security scan record HMAC validity, key active/unrevoked status, and non-quarantine status

        Returns:
            bytes: The verified raw file binary.

        Raises:
            CrossUserAccessError: If user_id mismatches attachment_ref.user_id.
            SecurityAuthorizationError: If any binary integrity, format, or cryptographic check fails.
        """
        import hashlib
        from src.database.exceptions import CrossUserAccessError, SecurityAuthorizationError
        from src.security.file_security import FileSecurityValidator
        from src.security.scan_signer import SecurityScanSigner

        if isinstance(plan_or_ref, FormFillPlan):
            ref = plan_or_ref.attachment_ref
            if not ref:
                raise SecurityAuthorizationError("FormFillPlan does not contain an authoritative attachment_ref.")
        elif isinstance(plan_or_ref, VerifiedAttachmentRef):
            ref = plan_or_ref
        else:
            raise SecurityAuthorizationError(f"Invalid plan_or_ref of type {type(plan_or_ref)}.")

        if ref.user_id != user_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=ref.user_id,
                resource=f"VerifiedAttachmentRef for Resume #{ref.resume_id}",
            )

        file_validator = self.file_validator or FileSecurityValidator()
        res_dir = file_validator.get_user_resumes_dir(user_id)
        path = Path(ref.file_path).resolve()

        # Symlink / directory containment check
        try:
            path.relative_to(res_dir.resolve())
        except ValueError:
            raise SecurityAuthorizationError(
                f"Attachment path '{ref.file_path}' traverses outside authorized candidate directory '{res_dir}'."
            )

        if not path.is_file():
            raise SecurityAuthorizationError(f"Attachment file '{ref.file_path}' does not exist or is not a regular file.")

        try:
            with open(path, "rb") as f:
                content_bytes = f.read()
        except Exception as e:
            raise SecurityAuthorizationError(f"Failed to read attachment file '{ref.file_path}': {e}") from e

        # Use-time size check
        if len(content_bytes) != ref.file_size_bytes:
            raise SecurityAuthorizationError(
                f"TOCTOU detection: Attachment file size altered. Expected {ref.file_size_bytes} bytes, got {len(content_bytes)} bytes."
            )

        # Use-time SHA-256 check
        actual_hash = hashlib.sha256(content_bytes).hexdigest()
        if actual_hash != ref.file_hash:
            raise SecurityAuthorizationError(
                f"TOCTOU detection: Attachment file hash altered. Expected '{ref.file_hash}', got '{actual_hash}'."
            )

        # Use-time format magic bytes check
        fmt = (ref.file_format or "").lower().strip()
        if fmt == "pdf":
            if not content_bytes.startswith(b"%PDF-"):
                raise SecurityAuthorizationError("Attachment file lacks valid PDF header magic bytes.")
        elif fmt == "docx":
            if not content_bytes.startswith(b"PK\x03\x04"):
                raise SecurityAuthorizationError("Attachment file lacks valid DOCX (ZIP) header magic bytes.")
        else:
            raise SecurityAuthorizationError(f"Unsupported attachment file format '{fmt}'.")

        # Reverity security scan in database
        if self.db:
            scan = self.db.get_latest_security_scan(
                user_id=user_id,
                source_type="resume",
                source_id=ref.resume_id,
                source_version=ref.version_num,
            )
            if not scan:
                raise SecurityAuthorizationError(f"No security scan record found for Resume #{ref.resume_id} v{ref.version_num}.")
            if scan.id != ref.scan_id:
                raise SecurityAuthorizationError(
                    f"Scan ID mismatch: attachment ref refers to scan #{ref.scan_id}, but latest scan is #{scan.id}."
                )
            if scan.classification == "QUARANTINED":
                raise SecurityAuthorizationError(f"Attachment Resume #{ref.resume_id} is QUARANTINED and cannot be opened for form upload.")

            signer = SecurityScanSigner(db_manager=self.db)
            signer.verify_scan_record(
                expected_user_id=user_id,
                expected_source_type="resume",
                expected_source_id=ref.resume_id,
                expected_source_version=ref.version_num,
                expected_source_hash=ref.file_hash,
                expected_snapshot_hash=None,
                scan_row=scan.to_dict() if hasattr(scan, "to_dict") else dict(scan),
                expected_source_binary_hash=ref.file_hash,
                expected_source_binary_size_bytes=ref.file_size_bytes,
                expected_source_binary_format=ref.file_format,
            )

        return content_bytes

    def ingest_and_prepare_attachment(
        self,
        user_id: int,
        file_path: Union[str, Path],
        label: str = "Prepared Attachment",
    ) -> int:
        """Explicit legacy compatibility helper: validates, sandboxes, persists, and scans an attachment before prefill.

        Returns:
            The authoritative resume_id to be used in build_form_payload.
        """
        from src.database.exceptions import SecurityAuthorizationError
        if not self.db:
            raise SecurityAuthorizationError("ingest_and_prepare_attachment requires configured DatabaseManager.")
        from src.security.file_security import FileSecurityValidator
        from src.security.security_preflight import SecurityPreflightManager
        file_validator = self.file_validator or FileSecurityValidator()
        f_path = Path(file_path).resolve()
        if not f_path.exists():
            raise FileNotFoundError(f"Resume file '{file_path}' not found.")

        with open(f_path, "rb") as f:
            file_bytes = f.read()

        file_validator.validate_file(file_bytes, f_path.name)

        rec = self.db.upload_user_resume(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=f_path.name,
            label=label,
            user_base_dir=getattr(file_validator, "base_storage_dir", None),
        )
        resume_id = rec["id"]

        # Preflight and scan
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=file_validator)
        preflight.check_resume_security(
            user_id=user_id,
            resume_id=resume_id,
            target_action="external_agent_execution",
        )
        return resume_id

