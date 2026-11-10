"""Centralized Security Preflight and Quarantine Enforcement Engine.

Validates source integrity, verifies HMAC signatures of security scans,
and strictly enforces quarantine restrictions before security-sensitive preparation,
generation, matching, and external agent workflows.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Dict, Optional

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    JobDescriptionNotFoundError,
    QuarantinedSourceError,
    ScanSignatureMismatchError,
    ScanVerificationKeyUnavailableError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.security.legacy_evidence_verifier import LegacyEvidenceVerifier
from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
from src.security.resume_verifier import ResumeIntegrityVerifier, VerifiedResume
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner
from src.utils.canonical_json import canonical_json_hash
from src.utils.logger import setup_logger

logger = setup_logger("SecurityPreflightManager")


# Authoritative legacy exception states accepted by security preflight (Phase 9.1.2.7 Part A)
ACCEPTED_LEGACY_AUDIT_OUTCOMES: frozenset[str] = frozenset({"SUCCESS", "RECONCILED"})


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
        evidence_verifier: Optional[LegacyEvidenceVerifier] = None,
    ):
        self.db = db_manager
        self.key_manager = key_manager or ScanKeyManager(db_manager=db_manager)
        self.signer = SecurityScanSigner(key_manager=self.key_manager)
        self.detector = detector or PromptInjectionDetector()
        self.file_validator = file_validator
        self._evidence_verifier = evidence_verifier

    @property
    def evidence_verifier(self) -> LegacyEvidenceVerifier:
        """Lazily initializes LegacyEvidenceVerifier when required for legacy JD evidence verification (Phase C.0.6)."""
        if self._evidence_verifier is None:
            self._evidence_verifier = LegacyEvidenceVerifier(db_manager=self.db)
        return self._evidence_verifier

    @evidence_verifier.setter
    def evidence_verifier(self, verifier: Optional[LegacyEvidenceVerifier]) -> None:
        self._evidence_verifier = verifier

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

        # 1. Extracted-text integrity check (Phase 9.1.2.1 Part D.1)
        raw_text_clean = (jd.raw_content or "").strip()
        computed_raw_hash = hashlib.sha256(raw_text_clean.encode("utf-8")).hexdigest()
        if computed_raw_hash != jd.content_hash:
            raise SecurityAuthorizationError(
                f"JobDescription #{jd_id} raw content hash tampering detected: "
                f"expected '{jd.content_hash}', computed '{computed_raw_hash}'."
            )

        # 2. Canonical snapshot manifest integrity check (RFC 8785)
        parsed_data = jd.to_dict().get("parsed_data") if hasattr(jd, "to_dict") else None
        if parsed_data is None and isinstance(jd.parsed_data, str) and jd.parsed_data.strip():
            try:
                parsed_data = json.loads(jd.parsed_data)
            except Exception:
                parsed_data = None

        manifest = {
            "user_id": jd.user_id,
            "company_name": (jd.company_name or "").strip(),
            "job_title": (jd.job_title or "").strip(),
            "raw_content_hash": computed_raw_hash,
            "parsed_data": parsed_data,
            "parser_version": jd.parser_version,
            "source_type": jd.source_type,
            "source_url": jd.source_url,
            "original_filename": jd.original_filename,
        }
        computed_snapshot_hash = canonical_json_hash(manifest)
        if jd.snapshot_hash is not None and computed_snapshot_hash != jd.snapshot_hash:
            raise SecurityAuthorizationError(
                f"JobDescription #{jd_id} canonical snapshot tampering detected: "
                f"expected '{jd.snapshot_hash}', computed '{computed_snapshot_hash}'."
            )

        # 3. Uploaded job-description physical binary integrity (Phase 9.1.2.1 Part D.2, Phase 9.1.2.2 Part C, Phase 9.1.2.3 Part A)
        normalized_source_type = (jd.source_type or "").lower().strip()
        is_uploaded = normalized_source_type in ("uploaded_document", "uploaded", "upload")
        has_binary_meta = False

        binary_state = getattr(jd, "binary_integrity_state", None)

        if is_uploaded:
            bin_fields = (jd.storage_filename, jd.file_hash, jd.file_size_bytes, jd.file_format)
            non_null_count = sum(1 for f in bin_fields if f is not None and str(f).strip() != "")
            if 0 < non_null_count < 4:
                raise SecurityAuthorizationError(
                    f"JobDescription #{jd_id} has partially populated binary metadata. "
                    f"Complete metadata (storage_filename, file_hash, file_size_bytes, file_format) is mandatory for uploaded records."
                )

            if binary_state == "LEGACY_TEXT_ONLY":
                if non_null_count != 0:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} claims LEGACY_TEXT_ONLY state but contains populated binary metadata."
                    )

                # Prior signed scan with binary hash cannot be bypassed by legacy state
                if self.db:
                    latest_scan = self.db.get_latest_security_scan(
                        user_id=user_id,
                        source_type="job_description",
                        source_id=jd_id,
                        source_version=1,
                    )
                    if latest_scan and getattr(latest_scan, "source_binary_hash", None) is not None:
                        raise SecurityAuthorizationError(
                            f"JobDescription #{jd_id} cannot be accepted as LEGACY_TEXT_ONLY because an authoritative signed scan "
                            f"exists with binary provenance (hash: {latest_scan.source_binary_hash})."
                        )

                # Durable migration audit record is strictly mandatory for LEGACY_TEXT_ONLY
                if not self.db or not hasattr(self.db, "get_legacy_integrity_exception"):
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} claims LEGACY_TEXT_ONLY state but no authoritative database manager is configured to verify migration audit record."
                    )

                legacy_exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=user_id)
                if not legacy_exc:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} has LEGACY_TEXT_ONLY state without an authoritative legacy integrity exception migration audit record."
                    )

                # Authoritative legacy exception outcome check (Phase 9.1.2.7 Part A)
                if legacy_exc.outcome == "REVERTED":
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} legacy integrity exception was REVERTED during reconciliation audit and cannot be accepted as LEGACY_TEXT_ONLY."
                    )

                if legacy_exc.outcome not in ACCEPTED_LEGACY_AUDIT_OUTCOMES:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} has unapproved legacy integrity exception outcome '{legacy_exc.outcome}'. "
                        f"Accepted outcomes: {sorted(ACCEPTED_LEGACY_AUDIT_OUTCOMES)}."
                    )

                if legacy_exc.assigned_legacy_state != "LEGACY_TEXT_ONLY":
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} legacy integrity exception assigned state '{legacy_exc.assigned_legacy_state}' "
                        "is inconsistent with expected 'LEGACY_TEXT_ONLY'."
                    )

                if legacy_exc.user_id != user_id:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} legacy integrity exception user_id {legacy_exc.user_id} does not match requested user_id {user_id}."
                    )

                if legacy_exc.job_description_id != jd_id:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} legacy integrity exception job_description_id {legacy_exc.job_description_id} does not match requested {jd_id}."
                    )

                # Verify snapshot hash binding
                if not legacy_exc.source_snapshot_hash or (jd.snapshot_hash and legacy_exc.source_snapshot_hash != jd.snapshot_hash):
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} snapshot hash '{jd.snapshot_hash}' does not match grandfathered snapshot hash '{legacy_exc.source_snapshot_hash}'."
                    )

                # Phase 9.1.2.5 Part C & Phase 9.1.2.6 Section 5.3: Verify independent evidence provenance and authenticate artifact
                if not getattr(legacy_exc, "evidence_type", None) or not getattr(legacy_exc, "evidence_reference_id", None):
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} legacy integrity exception lacks required independent evidence proof (evidence_type / evidence_reference_id missing)."
                    )

                attestation = self.db.get_legacy_evidence_attestation(
                    job_description_id=jd_id,
                    user_id=user_id,
                )
                if not attestation:
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} claims LEGACY_TEXT_ONLY state but lacks an authoritative evidence attestation."
                    )

                # Independently verify the evidence artifact
                self.evidence_verifier.verify_attestation(
                    attestation=attestation,
                    user_id=user_id,
                    job_description_id=jd_id,
                    snapshot_hash=jd.snapshot_hash,
                )

                has_binary_meta = False
                logger.info("JobDescription #%d verified as auditable LEGACY_TEXT_ONLY record; proceeding with text scanning.", jd_id)

            elif non_null_count == 4:
                if (jd.file_format or "").lower() not in ("pdf", "docx"):
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} has unsupported file_format '{jd.file_format}'. Must be 'pdf' or 'docx'."
                    )
                jd_dir = self.file_validator.get_user_job_descriptions_dir(user_id)
                jd_file_path = jd_dir / jd.storage_filename
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=user_id,
                    file_path=jd_file_path,
                    expected_hash=jd.file_hash,
                    expected_size=jd.file_size_bytes,
                    expected_format=jd.file_format,
                    is_mandatory=True,
                    resource_desc=f"Uploaded Job Description #{jd_id}",
                )
                has_binary_meta = True
            else:
                # non_null_count == 0 but NOT marked as LEGACY_TEXT_ONLY
                raise SecurityAuthorizationError(
                    f"JobDescription #{jd_id} is an uploaded record missing required binary metadata. "
                    "All-NULL binary metadata is permitted only for auditable historical legacy records with verified migration audit records."
                )
        else:
            # Non-uploaded record (pasted, url, etc.)
            if binary_state not in ("NOT_APPLICABLE", None):
                if binary_state == "LEGACY_TEXT_ONLY":
                    raise SecurityAuthorizationError(
                        f"JobDescription #{jd_id} of source_type '{jd.source_type}' cannot have binary_integrity_state 'LEGACY_TEXT_ONLY'."
                    )
            has_binary_meta = False

        # 4. Retrieve latest scan and verify version freshness (Phase 9.1.2.1 Part E & Phase 9.1.2.2 Part B)
        scan = self.db.get_latest_security_scan(
            user_id=user_id,
            source_type="job_description",
            source_id=jd_id,
            source_version=1,
        )

        is_stale = False
        if scan:
            if scan.classification == ScanClassification.QUARANTINED:
                # Quarantined scans remain permanently in quarantine
                is_stale = False
            elif scan.scanner_version != self.detector.engine_version or scan.policy_version != self.detector.policy_version:
                is_stale = True
                logger.info(
                    "Scan #%d for JobDescription #%d has stale version (scanner: %s vs %s, policy: %s vs %s). Triggering rescan.",
                    scan.id, jd_id, scan.scanner_version, self.detector.engine_version, scan.policy_version, self.detector.policy_version,
                )
            elif scan.classification != ScanClassification.QUARANTINED and has_binary_meta:
                if (
                    getattr(scan, "manifest_version", "v1") != "v2"
                    or getattr(scan, "source_binary_hash", None) != jd.file_hash
                    or getattr(scan, "source_binary_size_bytes", None) != jd.file_size_bytes
                    or getattr(scan, "source_binary_format", None) != jd.file_format
                ):
                    is_stale = True
                    logger.info(
                        "Scan #%d for JobDescription #%d lacks current binary provenance binding. Triggering fresh v2 scan.",
                        scan.id, jd_id,
                    )

        if (not scan) or is_stale:
            # Execute fresh scan on authoritative raw content
            logger.info("Executing fresh security scan for JobDescription #%d (User #%d)...", jd_id, user_id)
            scan_result = self.detector.scan(jd.raw_content)
            manifest_ver = "v2" if has_binary_meta else "v1"
            bin_hash = jd.file_hash if has_binary_meta else None
            bin_size = jd.file_size_bytes if has_binary_meta else None
            bin_fmt = jd.file_format if has_binary_meta else None

            manifest, sig, key_id = self.signer.sign_scan_result(
                user_id=user_id,
                source_type="job_description",
                source_id=jd_id,
                source_version=1,
                source_hash=jd.content_hash,
                snapshot_hash=jd.snapshot_hash,
                scan_result=scan_result,
                manifest_version=manifest_ver,
                source_binary_hash=bin_hash,
                source_binary_size_bytes=bin_size,
                source_binary_format=bin_fmt,
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
                source_binary_hash=bin_hash,
                source_binary_size_bytes=bin_size,
                source_binary_format=bin_fmt,
                manifest_version=manifest_ver,
            )

        # 5. Verify scan record HMAC and integrity
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
            "source_binary_hash": getattr(scan, "source_binary_hash", None),
            "source_binary_size_bytes": getattr(scan, "source_binary_size_bytes", None),
            "source_binary_format": getattr(scan, "source_binary_format", None),
            "manifest_version": getattr(scan, "manifest_version", "v1"),
        }

        self.signer.verify_scan_record(
            expected_user_id=user_id,
            expected_source_type="job_description",
            expected_source_id=jd_id,
            expected_source_version=1,
            expected_source_hash=jd.content_hash,
            expected_snapshot_hash=jd.snapshot_hash,
            scan_row=scan_dict,
            expected_source_binary_hash=jd.file_hash if has_binary_meta else None,
            expected_source_binary_size_bytes=jd.file_size_bytes if has_binary_meta else None,
            expected_source_binary_format=jd.file_format if has_binary_meta else None,
        )

        # Check for candidate override (audit telemetry only)
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
        # Strict processing boundary: Quarantined content can NEVER be used for document generation,
        # matching, packet preparation, export, prefilling, or external execution!
        # Candidate override is append-only audit telemetry for candidate inspection only.
        if target_action in ("external_agent_execution", "automated_submission"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' strictly blocked: Job description #{jd_id} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external agents even with an override.",
                source_type="job_description",
                source_id=jd_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        if target_action not in ("audit_inspection", "candidate_review", "telemetry_view"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' blocked: Job description #{jd_id} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}, {threat_count} threats detected). "
                "Quarantined content cannot be exposed to external agents or used in document generation, matching, preparation, prefilling, export, or external actions.",
                source_type="job_description",
                source_id=jd_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
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
            summary=f"Quarantined source inspected under candidate audit review (Override: {has_override}).",
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
        res_size = v_res.file_size_bytes
        res_format = v_res.file_format

        # 2. Retrieve latest scan and verify version freshness (Phase 9.1.2.1 Part E & Phase 9.1.2.2 Part B)
        scan = self.db.get_latest_security_scan(
            user_id=user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=target_ver,
        )

        is_stale = False
        if scan:
            if scan.classification == ScanClassification.QUARANTINED:
                # Quarantined scans remain permanently in quarantine
                is_stale = False
            elif scan.scanner_version != self.detector.engine_version or scan.policy_version != self.detector.policy_version:
                is_stale = True
                logger.info(
                    "Scan #%d for Resume #%d v%d has stale version (scanner: %s vs %s, policy: %s vs %s). Triggering rescan.",
                    scan.id, resume_id, target_ver, scan.scanner_version, self.detector.engine_version, scan.policy_version, self.detector.policy_version,
                )
            elif getattr(scan, "manifest_version", "v1") != "v2":
                is_stale = True
                logger.info(
                    "Scan #%d for Resume #%d v%d is manifest version '%s' (not 'v2'). Upgrading to v2 with binary provenance.",
                    scan.id, resume_id, target_ver, getattr(scan, "manifest_version", "v1"),
                )
            elif (
                getattr(scan, "source_binary_hash", None) != target_hash
                or getattr(scan, "source_binary_size_bytes", None) != res_size
                or getattr(scan, "source_binary_format", None) != res_format
            ):
                is_stale = True
                logger.info(
                    "Scan #%d for Resume #%d v%d has binary metadata mismatch. Triggering fresh v2 scan.",
                    scan.id, resume_id, target_ver,
                )
            elif scan.source_hash != target_hash:
                is_stale = True

        if (not scan) or is_stale:
            # Execute fresh scan on fresh in-memory parsed text / raw representation
            logger.info("Executing fresh security scan for Resume #%d v%d (User #%d)...", resume_id, target_ver, user_id)
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
                manifest_version="v2",
                source_binary_hash=target_hash,
                source_binary_size_bytes=res_size,
                source_binary_format=res_format,
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
                source_binary_hash=target_hash,
                source_binary_size_bytes=res_size,
                source_binary_format=res_format,
                manifest_version="v2",
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
            "source_binary_hash": getattr(scan, "source_binary_hash", None),
            "source_binary_size_bytes": getattr(scan, "source_binary_size_bytes", None),
            "source_binary_format": getattr(scan, "source_binary_format", None),
            "manifest_version": getattr(scan, "manifest_version", "v1"),
        }

        require_bin = getattr(scan, "manifest_version", "v1") == "v2" or scan.classification != ScanClassification.QUARANTINED
        self.signer.verify_scan_record(
            expected_user_id=user_id,
            expected_source_type="resume",
            expected_source_id=resume_id,
            expected_source_version=target_ver,
            expected_source_hash=target_hash,
            expected_snapshot_hash=None,
            scan_row=scan_dict,
            expected_source_binary_hash=target_hash if require_bin else None,
            expected_source_binary_size_bytes=res_size if require_bin else None,
            expected_source_binary_format=res_format if require_bin else None,
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

        # scan.classification == ScanClassification.QUARANTINED
        # Strict processing boundary: Quarantined content can NEVER be used for document generation,
        # matching, packet preparation, export, prefilling, or external execution!
        # Candidate override is append-only audit telemetry for candidate inspection only.
        if target_action in ("external_agent_execution", "automated_submission"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' strictly blocked: Resume #{resume_id} v{target_ver} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}) and cannot be exposed to external agents even with an override.",
                source_type="resume",
                source_id=resume_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
            )

        if target_action not in ("audit_inspection", "candidate_review", "telemetry_view"):
            raise QuarantinedSourceError(
                f"Action '{target_action}' blocked: Resume #{resume_id} v{target_ver} is QUARANTINED "
                f"(Risk: {scan.risk_score:.2f}, {threat_count} threats detected). "
                "Quarantined content cannot be exposed to external agents or used in document generation, matching, preparation, prefilling, export, or external actions.",
                source_type="resume",
                source_id=resume_id,
                classification=scan.classification,
                risk_score=scan.risk_score,
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
            summary=f"Quarantined resume inspected under candidate audit review (Override: {has_override}).",
        )

    def recover_unverifiable_resume_scan(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        recovery_reason: str = "Historical signing key unavailable",
    ) -> PreflightCheckResult:
        """Executes an authorized append-only scan recovery for an authentic resume whose historical key is lost.

        Enforces:
        1. JIT independent verification of physical binary (ownership, exact version, file hash, size, format).
        2. Strict validation that existing scan failure is VERIFICATION_KEY_UNAVAILABLE (fails closed on signature tampering).
        3. Preserves original scan record untouched (append-only in SQLite).
        4. Preserves sticky quarantine (quarantined resumes remain quarantined).
        5. Performs fresh prompt injection scan on verified source text.
        6. Signs new scan with current active durable key.
        7. Persists new scan row and verifies it immediately.
        """
        # 1. Authoritative JIT binary verification
        verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
        v_res = verifier.verify_and_load_resume(
            user_id=user_id,
            resume_id=resume_id,
            version_num=version_num,
            fresh_parse=True,
        )

        target_ver = v_res.version_num
        target_hash = v_res.file_hash
        res_size = v_res.file_size_bytes
        res_format = v_res.file_format

        # 2. Check existing scan to verify this is genuinely an unavailable historical key situation
        existing_scan = self.db.get_latest_security_scan(
            user_id=user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=target_ver,
        )

        was_quarantined = False
        if existing_scan:
            was_quarantined = (existing_scan.classification == ScanClassification.QUARANTINED)
            scan_dict = {
                "id": existing_scan.id,
                "user_id": existing_scan.user_id,
                "source_type": existing_scan.source_type,
                "source_id": existing_scan.source_id,
                "source_version": existing_scan.source_version,
                "source_hash": existing_scan.source_hash,
                "snapshot_hash": existing_scan.snapshot_hash,
                "scanner_version": existing_scan.scanner_version,
                "policy_version": existing_scan.policy_version,
                "risk_score": existing_scan.risk_score,
                "classification": existing_scan.classification,
                "threats_detected_json": existing_scan.threats_detected_json,
                "key_id": existing_scan.key_id,
                "hmac_signature": existing_scan.hmac_signature,
                "scanned_at": existing_scan.scanned_at,
                "source_binary_hash": getattr(existing_scan, "source_binary_hash", None),
                "source_binary_size_bytes": getattr(existing_scan, "source_binary_size_bytes", None),
                "source_binary_format": getattr(existing_scan, "source_binary_format", None),
                "manifest_version": getattr(existing_scan, "manifest_version", "v1"),
            }
            try:
                self.signer.verify_scan_record(
                    expected_user_id=user_id,
                    expected_source_type="resume",
                    expected_source_id=resume_id,
                    expected_source_version=target_ver,
                    expected_source_hash=target_hash,
                    expected_snapshot_hash=None,
                    scan_row=scan_dict,
                    expected_source_binary_hash=target_hash,
                    expected_source_binary_size_bytes=res_size,
                    expected_source_binary_format=res_format,
                )
                logger.info("Resume #%d v%d scan #%d is already valid; no recovery needed.", resume_id, target_ver, existing_scan.id)
                return self.check_resume_security(user_id=user_id, resume_id=resume_id, version_num=target_ver, verified_resume=v_res)
            except ScanVerificationKeyUnavailableError:
                logger.info(
                    "Resume #%d v%d scan #%d verification key '%s' is unavailable. Proceeding with authorized recovery.",
                    resume_id, target_ver, existing_scan.id, existing_scan.key_id,
                )
            except ScanSignatureMismatchError as e:
                raise SecurityAuthorizationError(
                    f"Cannot recover scan for Resume #{resume_id} v{target_ver}: "
                    f"Signature mismatch detected on scan #{existing_scan.id} with available key. "
                    "Integrity violation cannot be bypassed."
                ) from e

        # 3. Fresh scan on verified text
        text_to_scan = v_res.raw_text if hasattr(v_res, "raw_text") and v_res.raw_text else ""
        if not text_to_scan:
            facts = v_res.parsed_resume
            facts_dict = facts.to_dict() if hasattr(facts, "to_dict") and callable(facts.to_dict) else (facts if isinstance(facts, dict) else {})
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
            text_to_scan = " ".join(parts)

        scan_result = self.detector.scan(text_to_scan)

        # 4. Sticky quarantine enforcement
        if was_quarantined:
            logger.warning("Sticky quarantine enforced on recovered scan for Resume #%d v%d.", resume_id, target_ver)
            from dataclasses import replace
            scan_result = replace(scan_result, classification=ScanClassification.QUARANTINED)

        # 5. Sign with current active durable key
        manifest, sig, key_id = self.signer.sign_scan_result(
            user_id=user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=target_ver,
            source_hash=target_hash,
            snapshot_hash=None,
            scan_result=scan_result,
            manifest_version="v2",
            source_binary_hash=target_hash,
            source_binary_size_bytes=res_size,
            source_binary_format=res_format,
        )

        threats_dicts = [t.to_dict() for t in scan_result.threats_detected]

        # 6. Persist new append-only scan record
        new_scan = self.db.save_security_scan(
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
            source_binary_hash=target_hash,
            source_binary_size_bytes=res_size,
            source_binary_format=res_format,
            manifest_version="v2",
        )

        # 7. Immediately verify new scan record
        new_scan_dict = {
            "id": new_scan.id,
            "user_id": new_scan.user_id,
            "source_type": new_scan.source_type,
            "source_id": new_scan.source_id,
            "source_version": new_scan.source_version,
            "source_hash": new_scan.source_hash,
            "snapshot_hash": new_scan.snapshot_hash,
            "scanner_version": new_scan.scanner_version,
            "policy_version": new_scan.policy_version,
            "risk_score": new_scan.risk_score,
            "classification": new_scan.classification,
            "threats_detected_json": new_scan.threats_detected_json,
            "key_id": new_scan.key_id,
            "hmac_signature": new_scan.hmac_signature,
            "scanned_at": new_scan.scanned_at,
            "source_binary_hash": getattr(new_scan, "source_binary_hash", None),
            "source_binary_size_bytes": getattr(new_scan, "source_binary_size_bytes", None),
            "source_binary_format": getattr(new_scan, "source_binary_format", None),
            "manifest_version": getattr(new_scan, "manifest_version", "v2"),
        }
        self.signer.verify_scan_record(
            expected_user_id=user_id,
            expected_source_type="resume",
            expected_source_id=resume_id,
            expected_source_version=target_ver,
            expected_source_hash=target_hash,
            expected_snapshot_hash=None,
            scan_row=new_scan_dict,
            expected_source_binary_hash=target_hash,
            expected_source_binary_size_bytes=res_size,
            expected_source_binary_format=res_format,
        )

        logger.info(
            "Successfully recovered scan for Resume #%d v%d (User #%d) with new Scan #%d (Key ID: %s, Reason: %s).",
            resume_id, target_ver, user_id, new_scan.id, key_id, recovery_reason,
        )

        return self.check_resume_security(
            user_id=user_id,
            resume_id=resume_id,
            version_num=target_ver,
            target_action="candidate_review",
            verified_resume=v_res,
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
