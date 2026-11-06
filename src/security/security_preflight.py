"""Centralized Security Preflight and Quarantine Enforcement Engine.

Validates source integrity, verifies HMAC signatures of security scans,
and strictly enforces quarantine restrictions before security-sensitive preparation,
generation, matching, and external agent workflows.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    JobDescriptionNotFoundError,
    QuarantinedSourceError,
    ValidationError,
)
from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
from src.security.resume_verifier import ResumeIntegrityVerifier, VerifiedResume
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner
from src.utils.logger import setup_logger

logger = setup_logger("SecurityPreflightManager")


@dataclass(frozen=True)
class PreflightCheckResult:
    """Result of security preflight evaluation."""
    is_allowed: bool
    classification: str
    risk_score: float
    source_type: str
    source_id: int
    source_version: int
    source_hash: str
    has_override: bool
    override_reason: Optional[str]
    threat_count: int
    summary: str


class SecurityPreflightManager:
    """Centralized security preflight validator enforcing quarantine policies."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        key_manager: Optional[ScanKeyManager] = None,
        detector: Optional[PromptInjectionDetector] = None,
        file_validator: Optional[Any] = None,
    ):
        self.db = db_manager
        self.key_manager = key_manager or ScanKeyManager(db_manager=db_manager)
        self.signer = SecurityScanSigner(key_manager=self.key_manager)
        self.detector = detector or PromptInjectionDetector()
        self.file_validator = file_validator

    # -------------------------------------------------------------------------
    # JOB DESCRIPTION PREFLIGHT
    # -------------------------------------------------------------------------

    def check_job_description_security(
        self,
        user_id: int,
        jd_id: int,
        target_action: str = "document_generation",
    ) -> PreflightCheckResult:
        """Evaluates security status of a job description, verifying scan HMAC and quarantine."""
        jd = self.db.get_job_description(user_id=user_id, jd_id=jd_id)
        if not jd:
            raise JobDescriptionNotFoundError(f"Job description #{jd_id} not found for user {user_id}.")

        # Retrieve latest scan
        scan = self.db.get_latest_security_scan(
            user_id=user_id,
            source_type="job_description",
            source_id=jd_id,
            source_version=1,
        )

        if not scan:
            # Execute JIT scan on authoritative raw content
            logger.info("Executing JIT security scan for JobDescription #%d (User #%d)...", jd_id, user_id)
            scan_result = self.detector.scan(jd.raw_content)
            manifest, sig, key_id = self.signer.sign_scan_result(
                user_id=user_id,
                source_type="job_description",
                source_id=jd_id,
                source_version=1,
                source_hash=jd.content_hash,
                snapshot_hash=jd.snapshot_hash,
                scan_result=scan_result,
            )
            threats_dicts = [t.to_dict() for t in scan_result.threats_detected]
            scan = self.db.save_security_scan(
                user_id=user_id,
                source_type="job_description",
                source_id=jd_id,
                source_version=1,
                source_hash=jd.content_hash,
                snapshot_hash=jd.snapshot_hash,
                scanner_version=scan_result.engine_version,
                policy_version=scan_result.policy_version,
                risk_score=scan_result.risk_score,
                classification=scan_result.classification,
                threats_detected=threats_dicts,
                key_id=key_id,
                hmac_signature=sig,
                scanned_at=manifest["scanned_at"],
            )

        # Verify scan record HMAC and integrity
        scan_dict = {
            "id": scan.id,
            "user_id": scan.user_id,
            "source_type": scan.source_type,
            "source_id": scan.source_id,
            "source_version": scan.source_version,
            "source_hash": scan.source_hash,
            "snapshot_hash": scan.snapshot_hash,
            "scanner_version": scan.scanner_version,
            "policy_version": scan.policy_version,
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "threats_detected_json": scan.threats_detected_json,
            "key_id": scan.key_id,
            "hmac_signature": scan.hmac_signature,
            "scanned_at": scan.scanned_at,
        }

        self.signer.verify_scan_record(
            expected_user_id=user_id,
            expected_source_type="job_description",
            expected_source_id=jd_id,
            expected_source_version=1,
            expected_source_hash=jd.content_hash,
            expected_snapshot_hash=jd.snapshot_hash,
            scan_row=scan_dict,
        )

        # Check for candidate override
        override = self.db.get_security_scan_override(user_id=user_id, scan_id=scan.id)
        has_override = override is not None
        override_reason = override.override_reason if override else None

        threats_data = scan.to_dict().get("threats_detected", [])
        threat_count = len(threats_data)

        # Evaluate policy based on classification
        if scan.classification == ScanClassification.CLEAN:
            return PreflightCheckResult(
                is_allowed=True,
                classification=scan.classification,
                risk_score=scan.risk_score,
                source_type="job_description",
                source_id=jd_id,
                source_version=1,
                source_hash=jd.content_hash,
                has_override=has_override,
                override_reason=override_reason,
                threat_count=threat_count,
                summary=f"Clean security scan (Risk: {scan.risk_score:.2f}). Proceeding with {target_action}.",
            )

        if scan.classification == ScanClassification.SUSPICIOUS:
            if target_action in ("external_agent_execution", "automated_submission"):
                raise QuarantinedSourceError(
                    f"Action '{target_action}' blocked: Job description #{jd_id} is classified as SUSPICIOUS "
                    f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external action-capable agents.",
                    source_type="job_description",
                    source_id=jd_id,
                    classification=scan.classification,
                    risk_score=scan.risk_score,
                )
            logger.warning(
                "Job description #%d is SUSPICIOUS (Risk: %.2f). Permitting %s under restricted audit monitoring.",
                jd_id, scan.risk_score, target_action,
            )
            return PreflightCheckResult(
                is_allowed=True,
                classification=scan.classification,
                risk_score=scan.risk_score,
                source_type="job_description",
                source_id=jd_id,
                source_version=1,
                source_hash=jd.content_hash,
                has_override=has_override,
                override_reason=override_reason,
                threat_count=threat_count,
                summary=f"Suspicious security scan (Risk: {scan.risk_score:.2f}). Permitted with audit warnings.",
            )

        # scan.classification == ScanClassification.QUARANTINED
        if target_action in ("external_agent_execution", "automated_submission"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' strictly blocked: Job description #{jd_id} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external agents even with an override.",
                source_type="job_description",
                source_id=jd_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        if not has_override:
            raise QuarantinedSourceError(
                f"Action '{target_action}' blocked: Job description #{jd_id} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}, {threat_count} threats detected). "
                "Candidate review and explicit security override required.",
                source_type="job_description",
                source_id=jd_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        logger.info(
            "Permitting %s for QUARANTINED JobDescription #%d under verified candidate override (Reason: '%s').",
            target_action, jd_id, override_reason,
        )
        return PreflightCheckResult(
            is_allowed=True,
            classification=scan.classification,
            risk_score=scan.risk_score,
            source_type="job_description",
            source_id=jd_id,
            source_version=1,
            source_hash=jd.content_hash,
            has_override=True,
            override_reason=override_reason,
            threat_count=threat_count,
            summary=f"Quarantined source permitted under candidate override (Reason: {override_reason}).",
        )

    # -------------------------------------------------------------------------
    # RESUME PREFLIGHT
    # -------------------------------------------------------------------------

    def check_resume_security(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        target_action: str = "document_generation",
        verified_resume: Optional[VerifiedResume] = None,
    ) -> PreflightCheckResult:
        """Evaluates security status of a candidate resume, verifying scan HMAC and quarantine."""
        # 1. Authoritative JIT binary verification
        if verified_resume is not None:
            if verified_resume.user_id != user_id or verified_resume.resume_id != resume_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=verified_resume.user_id,
                    resource=f"VerifiedResume #{verified_resume.resume_id}",
                )
            v_res = verified_resume
        else:
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
            v_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=resume_id,
                version_num=version_num,
                fresh_parse=True,
            )

        target_ver = v_res.version_num
        target_hash = v_res.file_hash

        # 2. Retrieve latest scan
        scan = self.db.get_latest_security_scan(
            user_id=user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=target_ver,
        )

        if not scan:
            # Execute JIT scan on fresh in-memory parsed text / raw representation
            logger.info("Executing JIT security scan for Resume #%d v%d (User #%d)...", resume_id, target_ver, user_id)
            # Reconstruct searchable text from parsed_resume
            text_to_scan = v_res.raw_text if hasattr(v_res, "raw_text") and v_res.raw_text else ""
            if not text_to_scan:
                # Fallback to structured text rendering from parsed candidate facts
                facts = v_res.parsed_resume
                if hasattr(facts, "to_dict") and callable(facts.to_dict):
                    facts_dict = facts.to_dict()
                elif isinstance(facts, dict):
                    facts_dict = facts
                else:
                    facts_dict = {}

                parts = []
                if hasattr(facts, "raw_text") and facts.raw_text:
                    parts.append(str(facts.raw_text))
                if isinstance(facts_dict, dict):
                    if facts_dict.get("summary"):
                        parts.append(str(facts_dict["summary"]))
                    if facts_dict.get("skills") and isinstance(facts_dict["skills"], (list, tuple)):
                        parts.extend(str(s) for s in facts_dict["skills"])
                    if facts_dict.get("work_experience") and isinstance(facts_dict["work_experience"], list):
                        for exp in facts_dict["work_experience"]:
                            if isinstance(exp, dict) and exp.get("description"):
                                parts.append(str(exp["description"]))
                    if facts_dict.get("projects") and isinstance(facts_dict["projects"], list):
                        for proj in facts_dict["projects"]:
                            if isinstance(proj, dict) and proj.get("description"):
                                parts.append(str(proj["description"]))
                text_to_scan = " ".join(parts)

            scan_result = self.detector.scan(text_to_scan)
            manifest, sig, key_id = self.signer.sign_scan_result(
                user_id=user_id,
                source_type="resume",
                source_id=resume_id,
                source_version=target_ver,
                source_hash=target_hash,
                snapshot_hash=None,
                scan_result=scan_result,
            )
            threats_dicts = [t.to_dict() for t in scan_result.threats_detected]
            scan = self.db.save_security_scan(
                user_id=user_id,
                source_type="resume",
                source_id=resume_id,
                source_version=target_ver,
                source_hash=target_hash,
                snapshot_hash=None,
                scanner_version=scan_result.engine_version,
                policy_version=scan_result.policy_version,
                risk_score=scan_result.risk_score,
                classification=scan_result.classification,
                threats_detected=threats_dicts,
                key_id=key_id,
                hmac_signature=sig,
                scanned_at=manifest["scanned_at"],
            )

        # 3. Verify scan record HMAC and integrity
        scan_dict = {
            "id": scan.id,
            "user_id": scan.user_id,
            "source_type": scan.source_type,
            "source_id": scan.source_id,
            "source_version": scan.source_version,
            "source_hash": scan.source_hash,
            "snapshot_hash": scan.snapshot_hash,
            "scanner_version": scan.scanner_version,
            "policy_version": scan.policy_version,
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "threats_detected_json": scan.threats_detected_json,
            "key_id": scan.key_id,
            "hmac_signature": scan.hmac_signature,
            "scanned_at": scan.scanned_at,
        }

        self.signer.verify_scan_record(
            expected_user_id=user_id,
            expected_source_type="resume",
            expected_source_id=resume_id,
            expected_source_version=target_ver,
            expected_source_hash=target_hash,
            expected_snapshot_hash=None,
            scan_row=scan_dict,
        )

        override = self.db.get_security_scan_override(user_id=user_id, scan_id=scan.id)
        has_override = override is not None
        override_reason = override.override_reason if override else None

        threats_data = scan.to_dict().get("threats_detected", [])
        threat_count = len(threats_data)

        if scan.classification == ScanClassification.CLEAN:
            return PreflightCheckResult(
                is_allowed=True,
                classification=scan.classification,
                risk_score=scan.risk_score,
                source_type="resume",
                source_id=resume_id,
                source_version=target_ver,
                source_hash=target_hash,
                has_override=has_override,
                override_reason=override_reason,
                threat_count=threat_count,
                summary=f"Clean security scan (Risk: {scan.risk_score:.2f}). Proceeding with {target_action}.",
            )

        if scan.classification == ScanClassification.SUSPICIOUS:
            if target_action in ("external_agent_execution", "automated_submission"):
                raise QuarantinedSourceError(
                    f"Action '{target_action}' blocked: Resume #{resume_id} v{target_ver} is classified as SUSPICIOUS "
                    f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external action-capable agents.",
                    source_type="resume",
                    source_id=resume_id,
                    classification=scan.classification,
                    risk_score=scan.risk_score,
                )
            logger.warning(
                "Resume #%d v%d is SUSPICIOUS (Risk: %.2f). Permitting %s under restricted audit monitoring.",
                resume_id, target_ver, scan.risk_score, target_action,
            )
            return PreflightCheckResult(
                is_allowed=True,
                classification=scan.classification,
                risk_score=scan.risk_score,
                source_type="resume",
                source_id=resume_id,
                source_version=target_ver,
                source_hash=target_hash,
                has_override=has_override,
                override_reason=override_reason,
                threat_count=threat_count,
                summary=f"Suspicious security scan (Risk: {scan.risk_score:.2f}). Permitted with audit warnings.",
            )

        if target_action in ("external_agent_execution", "automated_submission"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' strictly blocked: Resume #{resume_id} v{target_ver} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external agents even with an override.",
                source_type="resume",
                source_id=resume_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        if not has_override:
            raise QuarantinedSourceError(
                f"Action '{target_action}' blocked: Resume #{resume_id} v{target_ver} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}, {threat_count} threats detected). "
                "Candidate review and explicit security override required.",
                source_type="resume",
                source_id=resume_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        logger.info(
            "Permitting %s for QUARANTINED Resume #%d v%d under verified candidate override (Reason: '%s').",
            target_action, resume_id, target_ver, override_reason,
        )
        return PreflightCheckResult(
            is_allowed=True,
            classification=scan.classification,
            risk_score=scan.risk_score,
            source_type="resume",
            source_id=resume_id,
            source_version=target_ver,
            source_hash=target_hash,
            has_override=True,
            override_reason=override_reason,
            threat_count=threat_count,
            summary=f"Quarantined source permitted under candidate override (Reason: {override_reason}).",
        )

    # -------------------------------------------------------------------------
    # CONSOLIDATED PREPARATION PREFLIGHT
    # -------------------------------------------------------------------------

    def check_preparation_security(
        self,
        user_id: int,
        resume_id: Optional[int],
        resume_version_num: Optional[int],
        job_description_id: Optional[int],
        target_action: str = "packet_preparation",
    ) -> Dict[str, PreflightCheckResult]:
        """Runs preflight checks for both resume and job description before document preparation."""
        results: Dict[str, PreflightCheckResult] = {}

        if job_description_id is not None:
            results["job_description"] = self.check_job_description_security(
                user_id=user_id,
                jd_id=job_description_id,
                target_action=target_action,
            )

        if resume_id is not None:
            results["resume"] = self.check_resume_security(
                user_id=user_id,
                resume_id=resume_id,
                version_num=resume_version_num,
                target_action=target_action,
            )

        return results

    def record_candidate_override(
        self,
        user_id: int,
        scan_id: int,
        reason: str,
        actor: str = "candidate",
    ) -> int:
        """Records an explicit, non-empty candidate or admin override for a quarantined source."""
        if not reason or not reason.strip():
            raise ValidationError("Security override reason cannot be empty.")
        return self.db.record_security_scan_override(
            user_id=user_id,
            scan_id=scan_id,
            override_reason=reason.strip(),
            actor_type=actor,
        )
