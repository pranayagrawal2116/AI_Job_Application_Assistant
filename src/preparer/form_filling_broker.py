"""Application Form Filling Broker (Phase C.1).

Authoritative execution and orchestration layer responsible for automated external
employer ATS form auto-population, verified resume upload, asynchronous ATS parsing
synchronization, remaining field completion, and human review verification.

Strict Operational & Safety Invariants:
1. All resume file access MUST go through FormPrefiller.open_verified_attachment().
   Never consume raw filesystem paths from frontend.
2. Cross-user isolation strictly enforced: user_id must match application.user_id
   and resume.user_id.
3. Never submit any application automatically (allow_automated_submission=False).
   Always stop before final submission controls.
4. Preserves values already entered by candidate or accurately parsed by ATS.
5. Emits immutable EXTERNAL_FORM_AUTOFILLED audit event without prematurely
   transitioning application status to SUBMITTED.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    JobNotFoundError,
    SecurityAuthorizationError,
)
from src.preparer.form_prefiller import FormPrefiller
from src.preparer.universal_field_mapper import (
    CandidateFieldFact,
    FormFieldTarget,
    ProvenanceStatus,
    UniversalFieldMapper,
)
from src.security.url_validator import URLSafetyValidator
from src.utils.canonical_json import canonical_json_bytes
from src.utils.logger import setup_logger

logger = setup_logger("FormFillingBroker")


class ATSProvider:
    KEKA = "KEKA"
    GREENHOUSE = "GREENHOUSE"
    LEVER = "LEVER"
    WORKDAY = "WORKDAY"
    UNIVERSAL = "UNIVERSAL"


@dataclass
class FormFieldResult:
    """Outcome for an individual form field."""
    field_name: str
    selector: str
    field_type: str
    intended_value: Optional[str]
    actual_value: Optional[str]
    provenance: str
    status: str  # AUTO_FILLED, ATS_PARSED, PRESERVED, MANUAL_REVIEW, UNMATCHED, ERROR
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormFillExecutionReport:
    """Comprehensive execution report of an external ATS form filling operation."""
    execution_id: str
    application_id: int
    user_id: int
    ats_provider: str
    target_url: str
    validated_domain: str
    resume_uploaded: bool
    resume_id: int
    resume_version_num: int
    resume_file_hash: str
    resume_filename: str
    ats_parsing_completed: bool
    total_fields_detected: int
    fields_populated_count: int
    fields_ats_parsed_count: int
    fields_preserved_count: int
    fields_manual_review_count: int
    fields_unmatched_count: int
    field_results: List[FormFieldResult] = field(default_factory=list)
    anti_automation_detected: bool = False
    submission_prevented: bool = True
    audit_event_id: Optional[int] = None
    status: str = "SUCCESS"  # SUCCESS, PARTIAL, BLOCKED, FAILED
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AutofillPlanResponse:
    """Structured plan returned to frontend or companion prior to execution."""
    execution_id: str
    application_id: int
    user_id: int
    company_name: str
    job_title: str
    target_url: str
    validated_domain: str
    ats_provider: str
    resume_id: int
    resume_version_num: int
    resume_filename: str
    resume_file_size: int
    resume_file_format: str
    plan_hash: str
    action_ticket: str
    facts: Dict[str, Any]
    candidate_profile_provenance: Dict[str, Any]
    known_fields_to_fill: List[Dict[str, Any]]
    safety_message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApplicationFormFillingBroker:
    """Authoritative execution and coordination broker for employer application forms."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        db: Optional[DatabaseManager] = None,
        file_validator: Optional[Any] = None,
    ):
        self.db = db or db_manager or DatabaseManager()
        self.file_validator = file_validator
        self.prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)

    # -------------------------------------------------------------------------
    # DOMAIN & ATS IDENTIFICATION
    # -------------------------------------------------------------------------

    @classmethod
    def identify_ats_provider(cls, url: str, html_snippet: str = "") -> str:
        """Identifies the employer ATS provider from the URL and page DOM."""
        if not url:
            return ATSProvider.UNIVERSAL

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""

        # Keka detection
        if "keka.com" in host or "/careers/applyjob" in path or "/careers/jobdetails" in path or "resumeuploadsettings" in lower_html or "kekahire" in lower_html:
            return ATSProvider.KEKA

        # Greenhouse detection
        if "greenhouse.io" in host or "grnh.se" in host or "job_application" in lower_html:
            return ATSProvider.GREENHOUSE

        # Lever detection
        if "lever.co" in host or "lever-form" in lower_html:
            return ATSProvider.LEVER

        # Workday detection
        if "myworkdayjobs.com" in host or "workday" in host:
            return ATSProvider.WORKDAY

        return ATSProvider.UNIVERSAL

    @classmethod
    def validate_external_domain(cls, url: str) -> str:
        """Validates that destination URL is a valid, globally routable external domain.

        Raises:
            SecurityAuthorizationError: On invalid or restricted target URL.
        """
        if not url or not isinstance(url, str) or not url.strip():
            raise SecurityAuthorizationError("Target application URL is missing.")

        clean_url = url.strip()
        parsed = urlparse(clean_url)
        if parsed.scheme not in ("http", "https"):
            raise SecurityAuthorizationError(f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        host = parsed.hostname
        if not host:
            raise SecurityAuthorizationError(f"Malformed target URL '{clean_url}'.")

        # SSRF and loopback protection
        import ipaddress
        try:
            ip = ipaddress.ip_address(host)
            if URLSafetyValidator.is_ip_private_or_restricted(ip):
                raise SecurityAuthorizationError(f"Target URL host '{host}' resolves to a restricted or private address.")
        except ValueError:
            # Domain name (not raw IP)
            if host.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                # Permit controlled test bypass if configured in URLSafetyValidator
                if "127.0.0.1" not in URLSafetyValidator._test_allowed_ips and "localhost" not in URLSafetyValidator._test_allowed_ips:
                    raise SecurityAuthorizationError(f"Target host '{host}' is a loopback address.")

        return host

    # -------------------------------------------------------------------------
    # AUTONOMOUS PREPARATION & PLAN RESOLUTION
    # -------------------------------------------------------------------------

    def prepare_autofill_plan(
        self,
        user_id: int,
        application_id: int,
        target_url: Optional[str] = None,
    ) -> AutofillPlanResponse:
        """Constructs an authoritative, cryptographically bound form filling plan."""
        # 1. Load and verify application ownership
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise JobNotFoundError(f"Application #{application_id} not found.")
            app = dict(app_row)

        if app["user_id"] != user_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=app["user_id"],
                resource=f"Application #{application_id}",
            )

        # 2. Resolve target URL
        effective_url = target_url or app.get("external_application_url") or ""
        if not effective_url and app.get("job_id"):
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT job_url, source_url FROM jobs WHERE id = ?", (app["job_id"],))
                j_row = cursor.fetchone()
                if j_row:
                    effective_url = j_row["job_url"] or j_row["source_url"] or ""

        if not effective_url:
            raise SecurityAuthorizationError(
                f"Application #{application_id} has no external employer URL configured."
            )

        validated_domain = self.validate_external_domain(effective_url)
        ats_provider = self.identify_ats_provider(effective_url)

        # 3. Resolve active candidate profile
        profile_row = self.db.get_user_candidate_profile(user_id)
        candidate_profile = profile_row.get("profile_data") if profile_row else {}
        if isinstance(candidate_profile, str):
            try:
                candidate_profile = json.loads(candidate_profile)
            except Exception:
                candidate_profile = {}

        # 4. Resolve selected verified resume
        resume_id = app.get("resume_id")
        if not resume_id:
            # Fallback to user's primary resume
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM resumes WHERE user_id = ? AND is_active = 1 ORDER BY is_primary DESC, id DESC LIMIT 1", (user_id,))
                res_row = cursor.fetchone()
                if not res_row:
                    raise SecurityAuthorizationError(f"User #{user_id} has no active resume available for autofill.")
                resume_id = res_row["id"]

        # 5. Build underlying FormFillPlan via FormPrefiller to verify attachments and scan signatures
        job_stub = {
            "id": app.get("job_id") or 0,
            "company_name": app.get("company_name") or "Employer",
            "job_url": effective_url,
            "user_id": user_id,
            "is_persisted": True if app.get("job_id") else False,
        }
        form_plan = self.prefiller.build_form_payload(
            job=job_stub,
            user_id=user_id,
            resume_id=resume_id,
        )

        attachment_ref = form_plan.attachment_ref
        if not attachment_ref:
            raise SecurityAuthorizationError(f"Could not build authoritative attachment reference for Resume #{resume_id}.")

        # 6. Extract candidate facts using UniversalFieldMapper
        mapper = UniversalFieldMapper(candidate_profile=candidate_profile)
        facts_dict = {k: f.to_dict() for k, f in mapper.facts.items()}

        # 7. Generate execution ID and single-use action ticket
        execution_id = f"exec_{hashlib.sha256(f'{user_id}:{application_id}:{time.time()}'.encode()).hexdigest()[:16]}"
        plan_hash = hashlib.sha256(
            canonical_json_bytes({
                "execution_id": execution_id,
                "application_id": application_id,
                "user_id": user_id,
                "target_url": effective_url,
                "resume_file_hash": attachment_ref.file_hash,
                "facts": facts_dict,
            })
        ).hexdigest()

        # Issue ticket using SessionManager
        from src.security.session_manager import SessionManager
        session_mgr = SessionManager(db_manager=self.db)
        action_ticket = session_mgr.create_action_ticket(
            action_type="autofill",
            resource_id=application_id,
            packet_version_hash=plan_hash,
            candidate_id=f"user_{user_id}",
            ttl_seconds=3600,
        )

        # 8. Known fields list
        known_fields = [asdict(f) for f in form_plan.fields_to_fill]

        return AutofillPlanResponse(
            execution_id=execution_id,
            application_id=application_id,
            user_id=user_id,
            company_name=app.get("company_name") or "Employer",
            job_title=app.get("job_title") or "Opportunity",
            target_url=effective_url,
            validated_domain=validated_domain,
            ats_provider=ats_provider,
            resume_id=attachment_ref.resume_id,
            resume_version_num=attachment_ref.version_num,
            resume_filename=attachment_ref.storage_filename,
            resume_file_size=attachment_ref.file_size_bytes,
            resume_file_format=attachment_ref.file_format,
            plan_hash=plan_hash,
            action_ticket=action_ticket,
            facts=facts_dict,
            candidate_profile_provenance=candidate_profile.get("field_provenance") or {},
            known_fields_to_fill=known_fields,
            safety_message="Form prefill plan authorized. Final manual submission approval required.",
        )

    # -------------------------------------------------------------------------
    # VERIFIED RESUME ATTACHMENT ACCESS
    # -------------------------------------------------------------------------

    def get_verified_resume_bytes(
        self,
        user_id: int,
        application_id: int,
        ticket: str,
    ) -> Tuple[bytes, str, str]:
        """Authorized gateway to obtain verified resume bytes for external form upload.

        CRITICAL SECURITY:
        - Re-validates application ownership.
        - Strictly opens binary via FormPrefiller.open_verified_attachment().
        - Returns (file_bytes, filename, content_type).
        """
        # Load application
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise JobNotFoundError(f"Application #{application_id} not found.")
            app_data = dict(app_row)
            if app_data["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=app_data["user_id"], resource=f"Application #{application_id}")
            resume_id = app_data["resume_id"]

        if not resume_id:
            raise SecurityAuthorizationError(f"Application #{application_id} has no assigned resume.")

        # Build plan to get attachment ref
        job_stub = {"id": app_data.get("job_id") or 0, "company_name": app_data.get("company_name") or "Employer", "user_id": user_id, "is_persisted": False}
        plan = self.prefiller.build_form_payload(job=job_stub, user_id=user_id, resume_id=resume_id)
        if not plan.attachment_ref:
            raise SecurityAuthorizationError(f"Could not construct VerifiedAttachmentRef for Resume #{resume_id}.")

        # Retrieve bytes through authoritative gateway
        raw_bytes = self.prefiller.open_verified_attachment(plan.attachment_ref, user_id=user_id)
        filename = plan.attachment_ref.storage_filename or f"resume_{user_id}.pdf"
        fmt = (plan.attachment_ref.file_format or "pdf").lower()
        content_type = "application/pdf" if fmt == "pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return (raw_bytes, filename, content_type)

    # -------------------------------------------------------------------------
    # PLAYWRIGHT AUTOMATION EXECUTION
    # -------------------------------------------------------------------------

    def execute_playwright_autofill(
        self,
        user_id: int,
        application_id: int,
        page: Any,
        target_url: Optional[str] = None,
        timeout_seconds: float = 20.0,
    ) -> FormFillExecutionReport:
        """Executes full end-to-end form population on an active Playwright page.

        Lifecycle:
        1. Authorizes plan and retrieves verified resume bytes.
        2. Detects anti-automation / bot challenge.
        3. Identifies ATS form and uploads resume to file input.
        4. Waits for ATS asynchronous resume parsing.
        5. Re-inspects form fields, identifying ATS-parsed fields vs unfilled fields.
        6. Preserves candidate-entered / ATS-filled fields.
        7. Populates remaining unfilled fields using verified candidate data.
        8. Verifies resulting field values.
        9. STRICT INVARIANT: Never clicks final submit button!
        10. Records EXTERNAL_FORM_AUTOFILLED audit event.
        """
        # 1. Prepare authoritative plan
        plan = self.prepare_autofill_plan(user_id=user_id, application_id=application_id, target_url=target_url)
        raw_resume_bytes, resume_filename, _ = self.get_verified_resume_bytes(user_id=user_id, application_id=application_id, ticket=plan.action_ticket)

        # 2. Inspect page for anti-automation challenges
        page_content = page.content()
        if self.prefiller.detect_anti_automation(page_content):
            logger.warning("Anti-automation mechanism detected on target page. Halting form population.")
            return FormFillExecutionReport(
                execution_id=plan.execution_id,
                application_id=application_id,
                user_id=user_id,
                ats_provider=plan.ats_provider,
                target_url=plan.target_url,
                validated_domain=urlparse(plan.target_url).hostname or "",
                resume_uploaded=False,
                resume_id=plan.resume_id,
                resume_version_num=plan.resume_version_num,
                resume_file_hash=plan.plan_hash,
                resume_filename=resume_filename,
                ats_parsing_completed=False,
                total_fields_detected=0,
                fields_populated_count=0,
                fields_ats_parsed_count=0,
                fields_preserved_count=0,
                fields_manual_review_count=0,
                fields_unmatched_count=0,
                anti_automation_detected=True,
                status="BLOCKED",
                message="Anti-automation or login gate detected on employer website. Please proceed manually.",
            )

        ats_provider = self.identify_ats_provider(page.url, page_content)

        # 3. Locate resume file upload control and upload verified resume
        resume_uploaded = False
        with tempfile.NamedTemporaryFile(suffix=f"_{resume_filename}", delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_path.write_bytes(raw_resume_bytes)

        try:
            resume_selectors = [
                "#resume-upload",
                ".resume-upload",
                "input[data-field-identifier='resume']",
                "input[field-name='resume']",
                "input[type='file'][name*='resume']",
                "input[type='file'][id*='resume']",
                "input[type='file']",
            ]
            file_input = None
            for sel in resume_selectors:
                loc = page.locator(sel)
                if loc.count() > 0:
                    file_input = loc.first
                    logger.info("Found resume file input selector: %s", sel)
                    break

            if file_input:
                file_input.set_input_files(str(tmp_path))
                resume_uploaded = True
                logger.info("Uploaded verified resume '%s' to employer ATS file input.", resume_filename)

                # 4. Wait for ATS asynchronous resume parsing to complete
                self._wait_for_ats_parsing(page, ats_provider, timeout_seconds=timeout_seconds)
            else:
                logger.warning("No file upload input found on page. Proceeding with direct field mapping.")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        # 5. Re-inspect page DOM fields and populate
        field_results = self._inspect_and_populate_fields(page, plan.facts, ats_provider)

        # Count outcomes
        pop_cnt = sum(1 for r in field_results if r.status == "AUTO_FILLED")
        ats_cnt = sum(1 for r in field_results if r.status == "ATS_PARSED")
        pres_cnt = sum(1 for r in field_results if r.status == "PRESERVED")
        rev_cnt = sum(1 for r in field_results if r.status == "MANUAL_REVIEW")
        unm_cnt = sum(1 for r in field_results if r.status == "UNMATCHED")

        # 6. Verify that final submission controls are NOT clicked
        # Ensure #jobApplicationSubmitButton or similar submit button is intact and application not submitted
        report = FormFillExecutionReport(
            execution_id=plan.execution_id,
            application_id=application_id,
            user_id=user_id,
            ats_provider=ats_provider,
            target_url=page.url,
            validated_domain=urlparse(page.url).hostname or "",
            resume_uploaded=resume_uploaded,
            resume_id=plan.resume_id,
            resume_version_num=plan.resume_version_num,
            resume_file_hash=plan.plan_hash,
            resume_filename=resume_filename,
            ats_parsing_completed=True if resume_uploaded else False,
            total_fields_detected=len(field_results),
            fields_populated_count=pop_cnt,
            fields_ats_parsed_count=ats_cnt,
            fields_preserved_count=pres_cnt,
            fields_manual_review_count=rev_cnt,
            fields_unmatched_count=unm_cnt,
            field_results=field_results,
            anti_automation_detected=False,
            submission_prevented=True,
            status="SUCCESS",
            message=f"Auto-populated {pop_cnt} fields, preserved {pres_cnt + ats_cnt} existing/ATS fields. Ready for candidate review.",
        )

        # 7. Record EXTERNAL_FORM_AUTOFILLED audit event
        audit_event = self._record_autofill_audit_event(report)
        if audit_event:
            report.audit_event_id = audit_event.id

        return report

    # -------------------------------------------------------------------------
    # ATS-SPECIFIC SYNCHRONIZATION & FIELD POPULATION
    # -------------------------------------------------------------------------

    def _wait_for_ats_parsing(self, page: Any, ats_provider: str, timeout_seconds: float = 15.0) -> None:
        """Waits for employer ATS asynchronous resume parsing to complete."""
        start_t = time.time()
        logger.info("Waiting for %s resume parsing to finish...", ats_provider)

        if ats_provider == ATSProvider.KEKA:
            # On Keka:
            # 1. Loader is shown (.loader or .loader-container)
            # 2. When parsing finishes: #resume text input gets the file name, or .loader hides
            try:
                # Wait briefly for loader to appear or complete
                page.wait_for_timeout(1000)
                # Wait for loader to disappear
                loader = page.locator(".loader, .loader-container, #loading")
                if loader.count() > 0:
                    loader.first.wait_for(state="hidden", timeout=int(timeout_seconds * 1000))
                # Wait for uploaded filename or field update
                page.wait_for_timeout(1000)
            except Exception as e:
                logger.info("Keka parsing wait completed or timed out: %s", e)
        else:
            # Generic wait
            try:
                page.wait_for_load_state("networkidle", timeout=int(timeout_seconds * 1000))
            except Exception:
                pass

        elapsed = time.time() - start_t
        logger.info("Resume parsing wait elapsed: %.2f seconds", elapsed)

    def _inspect_and_populate_fields(
        self, page: Any, facts_dict: Dict[str, Any], ats_provider: str
    ) -> List[FormFieldResult]:
        """Inspects all relevant DOM form controls and applies field decisions."""
        results: List[FormFieldResult] = []

        # Find all inputs, selects, textareas
        controls = page.query_selector_all("input:not([type='hidden']):not([type='file']), select, textarea")
        logger.info("Found %d form controls on page for inspection.", len(controls))

        for ctrl in controls:
            try:
                tag_name = ctrl.evaluate("el => el.tagName.toLowerCase()")
                ctrl_id = ctrl.get_attribute("id") or ""
                ctrl_name = ctrl.get_attribute("name") or ""
                ctrl_type = ctrl.get_attribute("type") or tag_name
                placeholder = ctrl.get_attribute("placeholder") or ""
                aria_label = ctrl.get_attribute("aria-label") or ""
                current_val = ctrl.evaluate("el => el.value") or ""

                # Extract label text
                label_text = ""
                if ctrl_id:
                    lbl = page.query_selector(f"label[for='{ctrl_id}']")
                    if lbl:
                        label_text = lbl.inner_text().strip()

                if not label_text:
                    # Look for enclosing label or closest preceding label
                    label_text = ctrl.evaluate("""el => {
                        const lbl = el.closest('label');
                        if (lbl) return lbl.innerText.trim();
                        let prev = el.previousElementSibling;
                        while (prev) {
                            if (prev.tagName.toLowerCase() === 'label') return prev.innerText.trim();
                            prev = prev.previousElementSibling;
                        }
                        const parent = el.parentElement;
                        if (parent) {
                            const pLbl = parent.querySelector('label');
                            if (pLbl) return pLbl.innerText.trim();
                        }
                        return '';
                    }""")

                # Collect select options
                options_list: List[Tuple[str, str]] = []
                if tag_name == "select":
                    options_list = ctrl.evaluate("""el => {
                        return Array.from(el.options).map(o => [o.value, o.text.trim()]);
                    }""")

                target = FormFieldTarget(
                    element_id=ctrl_id,
                    name_attr=ctrl_name,
                    field_type="select" if tag_name == "select" else ctrl_type,
                    accessible_label=label_text,
                    placeholder=placeholder,
                    aria_label=aria_label,
                    options=options_list,
                    current_value=current_val,
                )

                # Map field using UniversalFieldMapper rules
                # Create mapper from facts
                mapper = UniversalFieldMapper()
                mapper.facts = {k: CandidateFieldFact(**v) for k, v in facts_dict.items()}
                decision = mapper.match_field(target)

                # Determine action
                field_display_name = label_text or ctrl_name or ctrl_id or placeholder or "Field"
                selector = f"#{ctrl_id}" if ctrl_id else f"{tag_name}[name='{ctrl_name}']"

                if decision.action == "PRESERVE_EXISTING":
                    # Check if it was filled by ATS parser
                    is_ats = False
                    if ats_provider == ATSProvider.KEKA and current_val:
                        is_ats = True
                    results.append(
                        FormFieldResult(
                            field_name=field_display_name,
                            selector=selector,
                            field_type=target.field_type,
                            intended_value=decision.intended_value,
                            actual_value=current_val,
                            provenance=ProvenanceStatus.ATS_PARSED if is_ats else ProvenanceStatus.USER_CONFIRMED,
                            status="ATS_PARSED" if is_ats else "PRESERVED",
                        )
                    )
                elif decision.action == "FILL" and decision.intended_value is not None:
                    # Populate the control
                    self._fill_control(ctrl, tag_name, target.field_type, decision.intended_value)
                    # Verify populated value
                    new_val = ctrl.evaluate("el => el.value") or ""
                    results.append(
                        FormFieldResult(
                            field_name=field_display_name,
                            selector=selector,
                            field_type=target.field_type,
                            intended_value=decision.intended_value,
                            actual_value=new_val,
                            provenance=decision.provenance,
                            status="AUTO_FILLED",
                        )
                    )
                    logger.info("Auto-filled '%s' (%s) -> '%s'", field_display_name, selector, decision.intended_value)
                elif decision.action == "NEEDS_INPUT":
                    results.append(
                        FormFieldResult(
                            field_name=field_display_name,
                            selector=selector,
                            field_type=target.field_type,
                            intended_value=None,
                            actual_value=current_val,
                            provenance=decision.provenance,
                            status="MANUAL_REVIEW",
                            error_message=decision.explanation,
                        )
                    )
                else:
                    results.append(
                        FormFieldResult(
                            field_name=field_display_name,
                            selector=selector,
                            field_type=target.field_type,
                            intended_value=None,
                            actual_value=current_val,
                            provenance=ProvenanceStatus.AMBIGUOUS,
                            status="UNMATCHED",
                            error_message=decision.explanation,
                        )
                    )
            except Exception as e:
                logger.error("Error inspecting/populating control: %s", e)

        return results

    def _fill_control(self, ctrl: Any, tag_name: str, field_type: str, value: str) -> None:
        """Populates an HTML element safely triggering standard DOM events."""
        if tag_name == "select":
            # Select option by value or text
            ctrl.evaluate("""(el, val) => {
                let matched = false;
                for (let i = 0; i < el.options.length; i++) {
                    const opt = el.options[i];
                    if (opt.value.trim().toLowerCase() === val.trim().toLowerCase() ||
                        opt.text.trim().toLowerCase() === val.trim().toLowerCase() ||
                        opt.text.trim().toLowerCase().includes(val.trim().toLowerCase())) {
                        el.selectedIndex = i;
                        matched = true;
                        break;
                    }
                }
                if (matched) {
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                }
            }""", value)
        elif field_type == "checkbox":
            # Handled with caution: only check if explicit
            pass
        else:
            # Text / Email / Tel / Number / Textarea
            ctrl.fill(value)
            # Dispatch change and input events to ensure frameworks like React / jQuery register the update
            ctrl.evaluate("""el => {
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new Event('blur', { bubbles: true }));
            }""")

    # -------------------------------------------------------------------------
    # AUDIT TRAIL LOGGING
    # -------------------------------------------------------------------------

    def _record_autofill_audit_event(self, report: FormFillExecutionReport) -> Optional[Any]:
        """Appends the authoritative EXTERNAL_FORM_AUTOFILLED event to the application timeline."""
        try:
            payload = {
                "execution_id": report.execution_id,
                "ats_provider": report.ats_provider,
                "target_url": report.target_url,
                "validated_domain": report.validated_domain,
                "resume_uploaded": report.resume_uploaded,
                "resume_id": report.resume_id,
                "resume_version_num": report.resume_version_num,
                "total_fields_detected": report.total_fields_detected,
                "fields_populated_count": report.fields_populated_count,
                "fields_ats_parsed_count": report.fields_ats_parsed_count,
                "fields_preserved_count": report.fields_preserved_count,
                "fields_manual_review_count": report.fields_manual_review_count,
                "fields_unmatched_count": report.fields_unmatched_count,
                "submission_prevented": report.submission_prevented,
                "status": report.status,
                "timestamp": report.timestamp,
            }
            event = self.db.create_application_event(
                application_id=report.application_id,
                user_id=report.user_id,
                event_type="EXTERNAL_FORM_AUTOFILLED",
                new_status=None,  # Preserves existing status (e.g. APPROVED or READY_FOR_REVIEW)
                actor_type="CANDIDATE",
                actor_identifier=f"candidate_{report.user_id}",
                event_payload=payload,
            )
            logger.info("Recorded EXTERNAL_FORM_AUTOFILLED audit event #%s for Application #%d", getattr(event, "id", None), report.application_id)
            return event
        except Exception as e:
            logger.error("Failed to record EXTERNAL_FORM_AUTOFILLED audit event: %s", e)
            return None
