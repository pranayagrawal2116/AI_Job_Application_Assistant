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
    """Offline preparation plan for job application form filling.

    IMPORTANT SAFETY BOUNDARY:
    FormFillPlan represents an offline preparation artifact and must NEVER be interpreted as proof
    that external browser upload has occurred. External browser automation and automated form submission
    remain strictly disabled until an authoritative ApplicationFormFillingBroker is implemented in future
    milestones. Raw filesystem paths ('resume_file_path') must NEVER be consumed directly by external
    browser automation; all consumption MUST go through open_verified_attachment() which performs
    descriptor-relative verification and enforces clean security scans.
    """
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
            is_persisted_job = False
        elif hasattr(job, "source_type") or hasattr(job, "snapshot_hash") or hasattr(job, "raw_content"):
            is_persisted_job = bool(job_id)
        elif isinstance(job, dict):
            if job.get("job_description_id"):
                is_persisted_job = True
                job_id = job.get("job_description_id")
            elif job.get("source_type") in ("upload", "uploaded", "url", "pasted", "PASTE", "URL", "UPLOAD"):
                is_persisted_job = True
            elif job.get("is_persisted") is True or (job.get("id") and (job.get("user_id") or user_id or self.db)):
                if self.db and uid and self.db.get_job_description(user_id=uid, jd_id=job_id):
                    is_persisted_job = True
                else:
                    is_persisted_job = False

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
        """Opens, verifies, and returns the authoritative attachment binary immediately before external upload.

        CRITICAL SECURITY ENFORCEMENT (Phase 9.1.2.4 Part B):
        1. Mandatory authoritative database manager: fails closed with SecurityAuthorizationError if self.db is None.
        2. Reference integrity validation: strictly validates all fields of VerifiedAttachmentRef (no malformed IDs,
           invalid hashes, bad formats, traversal characters, or cross-user references).
        3. Authoritative resume re-resolution: invokes ResumeIntegrityVerifier.verify_and_load_resume() for the exact
           referenced version and compares all 8 fields against VerifiedAttachmentRef.
        4. Centralized security preflight: calls SecurityPreflightManager.check_resume_security(target_action='external_agent_execution').
           Enforces active scanner and policy versions, valid scan HMAC, and clean scan status.
           BOTH SUSPICIOUS and QUARANTINED scans strictly fail closed; overrides NEVER unlock external attachment.
        5. Scan identity and signature binding: verifies scan ID, HMAC signature, and unrevoked key status.
        6. Descriptor-relative verification: invokes FileSecurityValidator.resolve_and_verify_candidate_file()
           and returns the actual verified in-memory bytes directly without reopening the path.

        NOTE ON EXTERNAL AUTOMATION:
        External browser form upload execution remains disabled until a restricted ApplicationFormFillingBroker is
        implemented in future milestones. This method serves as the authorized attachment gateway for such execution.

        Returns:
            bytes: The verified raw file binary read from descriptor-relative inspection.

        Raises:
            CrossUserAccessError: If user_id mismatches attachment_ref.user_id.
            SecurityAuthorizationError: If any verification, preflight, or cryptographic check fails.
        """
        from src.database.exceptions import CrossUserAccessError, SecurityAuthorizationError
        from src.security.file_security import FileSecurityValidator
        from src.security.scan_signer import SecurityScanSigner
        from src.security.resume_verifier import ResumeIntegrityVerifier
        from src.security.security_preflight import SecurityPreflightManager
        from src.security.prompt_injection_detector import ScanClassification

        # 4.1 Mandatory database requirement
        if not self.db:
            raise SecurityAuthorizationError(
                "Authoritative attachment verification requires a configured DatabaseManager. "
                "Path-only and filesystem-only fallbacks are strictly prohibited."
            )

        # 4.6 Reference integrity & input resolution
        if isinstance(plan_or_ref, FormFillPlan):
            ref = plan_or_ref.attachment_ref
            if not ref:
                raise SecurityAuthorizationError("FormFillPlan does not contain an authoritative attachment_ref.")
        elif isinstance(plan_or_ref, VerifiedAttachmentRef):
            ref = plan_or_ref
        else:
            raise SecurityAuthorizationError(f"Invalid plan_or_ref of type {type(plan_or_ref)}.")

        if not ref.user_id or not isinstance(ref.user_id, int) or ref.user_id <= 0:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid user_id.")
        if ref.user_id != user_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=ref.user_id,
                resource=f"VerifiedAttachmentRef for Resume #{ref.resume_id}",
            )

        if not ref.resume_id or not isinstance(ref.resume_id, int) or ref.resume_id <= 0:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid resume_id.")
        if not ref.version_num or not isinstance(ref.version_num, int) or ref.version_num <= 0:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid version_num.")
        if not ref.storage_filename or not isinstance(ref.storage_filename, str) or not ref.storage_filename.strip():
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid storage_filename.")
        if "/" in ref.storage_filename or "\\" in ref.storage_filename or "\x00" in ref.storage_filename or ".." in ref.storage_filename:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains illegal path components in storage_filename.")
        if not ref.file_path or not isinstance(ref.file_path, str) or not ref.file_path.strip():
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid file_path.")
        if not ref.file_hash or not isinstance(ref.file_hash, str) or len(ref.file_hash) != 64:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid SHA-256 file_hash.")
        try:
            int(ref.file_hash, 16)
        except ValueError:
            raise SecurityAuthorizationError("VerifiedAttachmentRef file_hash is not valid hex.")
        if not ref.file_size_bytes or not isinstance(ref.file_size_bytes, int) or ref.file_size_bytes <= 0:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid file_size_bytes.")
        clean_ref_fmt = (ref.file_format or "").lower().strip()
        if clean_ref_fmt not in ("pdf", "docx"):
            raise SecurityAuthorizationError(f"VerifiedAttachmentRef contains unsupported file_format '{ref.file_format}'.")
        if not ref.scan_id or not isinstance(ref.scan_id, int) or ref.scan_id <= 0:
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid scan_id.")
        if not ref.scan_signature or not isinstance(ref.scan_signature, str) or not ref.scan_signature.strip():
            raise SecurityAuthorizationError("VerifiedAttachmentRef contains invalid scan_signature.")

        # 4.2 Re-resolve authoritative resume record from database
        verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
        try:
            v_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=ref.resume_id,
                version_num=ref.version_num,
                fresh_parse=False,
            )
        except Exception as e:
            raise SecurityAuthorizationError(f"TOCTOU detection: Authoritative resume re-resolution failed for Resume #{ref.resume_id}: {e}") from e

        # Compare verified result against VerifiedAttachmentRef
        if v_res.user_id != ref.user_id:
            raise SecurityAuthorizationError(
                f"Authoritative resume user_id '{v_res.user_id}' does not match attachment_ref user_id '{ref.user_id}'."
            )
        if v_res.resume_id != ref.resume_id:
            raise SecurityAuthorizationError(
                f"Authoritative resume_id '{v_res.resume_id}' does not match attachment_ref resume_id '{ref.resume_id}'."
            )
        if v_res.version_num != ref.version_num:
            raise SecurityAuthorizationError(
                f"Authoritative version '{v_res.version_num}' does not match attachment_ref version '{ref.version_num}'."
            )
        if v_res.storage_filename != ref.storage_filename:
            raise SecurityAuthorizationError(
                f"Authoritative storage_filename '{v_res.storage_filename}' does not match attachment_ref '{ref.storage_filename}'."
            )
        if v_res.file_hash.lower() != ref.file_hash.lower():
            raise SecurityAuthorizationError(
                f"Authoritative file_hash '{v_res.file_hash}' does not match attachment_ref '{ref.file_hash}'."
            )
        if v_res.file_size_bytes != ref.file_size_bytes:
            raise SecurityAuthorizationError(
                f"Authoritative file_size_bytes {v_res.file_size_bytes} does not match attachment_ref {ref.file_size_bytes}."
            )
        if v_res.file_format.lower() != clean_ref_fmt:
            raise SecurityAuthorizationError(
                f"Authoritative file_format '{v_res.file_format}' does not match attachment_ref '{ref.file_format}'."
            )
        if v_res.resolved_path is not None and v_res.resolved_path.resolve() != Path(ref.file_path).resolve():
            raise SecurityAuthorizationError(
                f"Authoritative resolved_path '{v_res.resolved_path}' does not match attachment_ref file_path '{ref.file_path}'."
            )

        # 4.3 Mandatory centralized security preflight
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        preflight_res = preflight.check_resume_security(
            user_id=user_id,
            resume_id=ref.resume_id,
            version_num=ref.version_num,
            verified_resume=v_res,
            target_action="external_agent_execution",
        )
        if preflight_res.classification != ScanClassification.CLEAN:
            raise SecurityAuthorizationError(
                f"Attachment Resume #{ref.resume_id} is classified as {preflight_res.classification.value}; "
                "only CLEAN resumes may be opened for external attachment."
            )

        # 4.4 Scan identity and signature binding
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
                f"Scan ID mismatch: attachment ref refers to scan #{ref.scan_id}, but latest authoritative scan is #{scan.id}."
            )
        if scan.hmac_signature != ref.scan_signature:
            raise SecurityAuthorizationError(
                f"Scan signature mismatch: attachment ref signature does not match authoritative scan #{scan.id} signature."
            )
        if scan.scanner_version != preflight.detector.engine_version:
            raise SecurityAuthorizationError(
                f"Scan #{scan.id} has stale scanner_version '{scan.scanner_version}' vs current '{preflight.detector.engine_version}'."
            )
        if scan.policy_version != preflight.detector.policy_version:
            raise SecurityAuthorizationError(
                f"Scan #{scan.id} has stale policy_version '{scan.policy_version}' vs current '{preflight.detector.policy_version}'."
            )

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

        # 4.5 Descriptor-relative file verification and direct byte return (no reopening)
        file_validator = self.file_validator or FileSecurityValidator()
        resolved_path, file_bytes, actual_hash, actual_size = file_validator.resolve_and_verify_candidate_file(
            user_id=user_id,
            file_path=ref.file_path,
            expected_hash=ref.file_hash,
            expected_size=ref.file_size_bytes,
            expected_format=clean_ref_fmt,
            is_mandatory=True,
            resource_desc=f"Attachment Resume #{ref.resume_id}",
        )

        return file_bytes

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

