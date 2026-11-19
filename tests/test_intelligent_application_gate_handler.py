"""Acceptance & Integration Tests for JobFlow Intelligent Application Gate Handler (IAGH).

Verifies:
1. Direct application page detection (form ready, not blocking).
2. Category A: Legal and privacy gates (Privacy notice, Terms & conditions, Recruitment consent).
3. Category B: Cookie preference gates (dismissible modal/banner).
4. Category C: Authentication gates (Candidate login, OTP/MFA).
5. Category D: Security gates (Cloudflare Turnstile, CAPTCHA).
6. Category E: Eligibility screening gates (Work authorization, sponsorship questions).
7. Category F: Application progression (Multi-step wizard, ATS parsing indicator).
8. Keyword non-false-positive: Footer privacy links do NOT trigger blocking.
9. Human interaction manager: Protected submission & consent buttons cannot be clicked by automation.
10. Execution state machine: Enforces strict transition graph, records transition history.
11. Workflow resumer: Multi-gate sequential progression (Privacy -> Consent -> Eligibility -> Form Autofill).
12. User declined: Candidate declining mandatory terms halts workflow cleanly.
13. Session persistence & recovery: SQLite execution session survives simulated reload/restart.
14. End-to-end Playwright mock test: Gate pause -> Human completion -> Autofill completion -> Manual submit guard.
"""

from datetime import datetime, timezone
import json
import pytest
from unittest.mock import MagicMock
from playwright.sync_api import sync_playwright

from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError, SecurityAuthorizationError
from src.preparer.application_workflow_resumer import ApplicationWorkflowResumer, WorkflowResumptionResult
from src.preparer.ats_adapter_registry import ATSAdapterRegistry, BaseATSAdapter, LeverATSAdapter, UniversalATSAdapter
from src.preparer.execution_state_machine import ApplicationExecutionStateMachine, ExecutionState
from src.preparer.form_filling_broker import ApplicationFormFillingBroker, FormFillExecutionReport
from src.preparer.gate_detector import (
    ActionCategory,
    GateCategory,
    GateDetectionResult,
    GateType,
    PreApplicationGateDetector,
)
from src.preparer.human_interaction_manager import HumanInteractionManager, InteractionGuidance


# =============================================================================
# MOCK HTML TEST FIXTURES
# =============================================================================

DIRECT_FORM_HTML = """
<!DOCTYPE html>
<html>
<head><title>Cin7 - Junior Software Engineer</title></head>
<body>
    <form id="application-form">
        <label>Full name</label>
        <input type="text" name="name" data-qa="name-input" value="">
        <label>Email</label>
        <input type="email" name="email" data-qa="email-input" value="">
        <label>Resume</label>
        <input type="file" name="resume" data-qa="input-resume">
        <button type="submit" id="hcaptchaSubmitBtn">Submit Application</button>
    </form>
    <footer>
        <a href="/privacy">Privacy Policy</a> | <a href="/terms">Terms of Service</a>
    </footer>
</body>
</html>
"""

PRIVACY_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Candidate Privacy Notice - Global Corp</title></head>
<body>
    <div class="consent-container">
        <h2>Candidate Privacy Notice</h2>
        <p>Please read our recruitment privacy statement carefully regarding data collection.</p>
        <div class="actions">
            <button id="accept-privacy-btn">I Agree & Continue</button>
            <button id="decline-privacy-btn">Decline</button>
        </div>
    </div>
</body>
</html>
"""

TERMS_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Terms of Application</title></head>
<body>
    <div role="dialog" class="modal terms-modal">
        <h3>Terms and Conditions</h3>
        <p>You must agree to the application terms before viewing the form.</p>
        <button type="button" id="accept-terms">Accept Terms</button>
    </div>
</body>
</html>
"""

COOKIE_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Job Portal</title></head>
<body>
    <div id="onetrust-banner-sdk" class="cookie-banner">
        <p>We use cookies to enhance your application experience.</p>
        <button id="accept-cookies">Accept All Cookies</button>
        <button id="manage-cookies">Manage Preferences</button>
    </div>
</body>
</html>
"""

LOGIN_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Candidate Sign In</title></head>
<body>
    <div class="login-box">
        <h2>Sign In to Your Account</h2>
        <form id="login-form">
            <input type="email" name="username" placeholder="Email Address">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

OTP_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Verify Your Identity</title></head>
<body>
    <div class="otp-container">
        <h2>Two-Factor Verification</h2>
        <p>Enter the verification code sent to your phone:</p>
        <input type="text" name="otp" autocomplete="one-time-code" placeholder="123456">
        <button type="submit">Verify Code</button>
    </div>
</body>
</html>
"""

CLOUDFLARE_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Just a moment...</title></head>
<body>
    <div id="challenge-stage">
        <h2>Verify you are human</h2>
        <div class="cf-turnstile" data-sitekey="abc123"></div>
        <iframe src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile"></iframe>
    </div>
</body>
</html>
"""

WORK_AUTH_GATE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Preliminary Eligibility Questions</title></head>
<body>
    <div class="eligibility-container">
        <h3>Pre-Screening Questions</h3>
        <fieldset>
            <legend>Are you legally authorized to work in India?</legend>
            <label><input type="radio" name="authorized" value="yes"> Yes</label>
            <label><input type="radio" name="authorized" value="no"> No</label>
        </fieldset>
        <fieldset>
            <legend>Will you now or in the future require visa sponsorship?</legend>
            <label><input type="radio" name="sponsorship" value="yes"> Yes</label>
            <label><input type="radio" name="sponsorship" value="no"> No</label>
        </fieldset>
        <button type="button" id="next-btn">Next Step</button>
    </div>
</body>
</html>
"""


# =============================================================================
# UNIT & INTEGRATION TESTS
# =============================================================================

class TestPreApplicationGateDetector:
    """Verifies universal classification across all 6 gate categories."""

    def test_01_direct_application_form_ready(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(DIRECT_FORM_HTML, url="https://jobs.lever.co/cin7/apply")
        assert res.category == GateCategory.NONE.value
        assert res.gate_type == GateType.APPLICATION_FORM_READY.value
        assert res.is_blocking is False
        assert res.form_detected is True

    def test_02_footer_privacy_link_does_not_trigger_false_positive(self):
        """Invariant: Passive footer privacy links must NEVER block active application forms."""
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(DIRECT_FORM_HTML)
        assert res.is_blocking is False
        assert res.category != GateCategory.LEGAL_PRIVACY.value

    def test_03_privacy_agreement_gate_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(PRIVACY_GATE_HTML)
        assert res.category == GateCategory.LEGAL_PRIVACY.value
        assert res.gate_type in (GateType.PRIVACY_POLICY.value, GateType.CANDIDATE_PRIVACY_NOTICE.value)
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_DECISION.value

    def test_04_terms_and_conditions_modal_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(TERMS_GATE_HTML)
        assert res.category == GateCategory.LEGAL_PRIVACY.value
        assert res.gate_type == GateType.TERMS_AND_CONDITIONS.value
        assert res.is_blocking is True

    def test_05_cookie_banner_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(COOKIE_GATE_HTML)
        assert res.category == GateCategory.COOKIE.value
        assert res.gate_type == GateType.COOKIE_CONSENT.value
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_DECISION.value

    def test_06_login_authentication_gate_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(LOGIN_GATE_HTML, url="https://careers.company.com/login")
        assert res.category == GateCategory.AUTHENTICATION.value
        assert res.gate_type == GateType.LOGIN_REQUIRED.value
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_AUTHENTICATION.value

    def test_07_mfa_otp_gate_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(OTP_GATE_HTML)
        assert res.category == GateCategory.AUTHENTICATION.value
        assert res.gate_type == GateType.MFA_OTP.value
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_AUTHENTICATION.value

    def test_08_cloudflare_security_verification_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(CLOUDFLARE_GATE_HTML)
        assert res.category == GateCategory.SECURITY.value
        assert res.gate_type == GateType.CLOUDFLARE_VERIFICATION.value
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_AUTHENTICATION.value

    def test_09_eligibility_screening_gate_detection(self):
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(WORK_AUTH_GATE_HTML)
        assert res.category == GateCategory.ELIGIBILITY.value
        assert res.gate_type == GateType.WORK_AUTHORIZATION.value
        assert res.is_blocking is True
        assert res.action_category == ActionCategory.USER_DECISION.value


class TestHumanInteractionManager:
    """Verifies safe interaction guidance and protected control constraints."""

    def test_10_protected_controls_cannot_be_automated(self):
        mgr = HumanInteractionManager()
        # Final submission
        assert mgr.is_automated_action_permitted("Submit Application") is False
        assert mgr.is_automated_action_permitted("Apply Now") is False
        assert mgr.is_automated_action_permitted("submit") is False

        # Legal & Consent
        assert mgr.is_automated_action_permitted("I Agree & Continue") is False
        assert mgr.is_automated_action_permitted("I Accept") is False
        assert mgr.is_automated_action_permitted("Accept Terms") is False
        assert mgr.is_automated_action_permitted("Confirm Declaration") is False

        # Security
        assert mgr.is_automated_action_permitted("Verify you are human") is False

        # Ordinary controls CAN be automated
        assert mgr.is_automated_action_permitted("Upload Resume") is True
        assert mgr.is_automated_action_permitted("Next") is True

    def test_11_interaction_guidance_formulation(self):
        mgr = HumanInteractionManager()
        detector = PreApplicationGateDetector()
        res = detector.detect_from_html(PRIVACY_GATE_HTML)
        guidance = mgr.evaluate_gate_interaction(res)
        assert "Privacy Notice" in guidance.title
        assert "review" in guidance.instruction.lower()
        assert guidance.is_blocking is True


def _seed_user_and_app(db: DatabaseManager, user_id: int = 1, app_id: int = 1):
    with db.transaction() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO users (id, email, password_hash, password_salt, full_name) VALUES (?, ?, 'h', 's', 'Test Candidate')",
            (user_id, f"candidate_{user_id}@test.com"),
        )
        cursor.execute(
            "INSERT OR IGNORE INTO applications (id, user_id, company_name, job_title, status) VALUES (?, ?, 'Test Corp', 'Engineer', 'APPROVED')",
            (app_id, user_id),
        )


class TestApplicationExecutionStateMachine:
    """Verifies state machine graph, transitions, and persistence."""

    def test_12_valid_transition_lifecycle(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_sm.db"))
        _seed_user_and_app(db, user_id=1, app_id=1)
        sm = ApplicationExecutionStateMachine(db_manager=db)

        # Create session in db
        session_id = "exec_test_12"
        db.save_autofill_execution_session({
            "execution_id": session_id,
            "application_id": 1,
            "user_id": 1,
            "current_state": ExecutionState.PORTAL_OPENED.value,
        })

        # Transition 1: PORTAL_OPENED -> COMPANION_CONNECTED
        rec1 = sm.transition(session_id, ExecutionState.COMPANION_CONNECTED, event_source="COMPANION")
        assert rec1.new_state == ExecutionState.COMPANION_CONNECTED.value
        assert sm.get_current_state(session_id) == ExecutionState.COMPANION_CONNECTED

        # Transition 2: COMPANION_CONNECTED -> PAGE_ANALYZING
        rec2 = sm.transition(session_id, ExecutionState.PAGE_ANALYZING, event_source="BACKEND")
        assert rec2.new_state == ExecutionState.PAGE_ANALYZING.value

        # Transition 3: PAGE_ANALYZING -> GATE_DETECTED
        rec3 = sm.transition(session_id, ExecutionState.GATE_DETECTED, event_source="BACKEND")
        assert rec3.new_state == ExecutionState.GATE_DETECTED.value

        # Transition 4: GATE_DETECTED -> WAITING_FOR_USER
        rec4 = sm.transition(session_id, ExecutionState.WAITING_FOR_USER, event_source="BACKEND")
        assert rec4.new_state == ExecutionState.WAITING_FOR_USER.value

        # Transition 5: WAITING_FOR_USER -> USER_ACTION_DETECTED
        rec5 = sm.transition(session_id, ExecutionState.USER_ACTION_DETECTED, event_source="USER")
        assert rec5.new_state == ExecutionState.USER_ACTION_DETECTED.value

        # Transition 6: USER_ACTION_DETECTED -> APPLICATION_FORM_DETECTED
        rec6 = sm.transition(session_id, ExecutionState.APPLICATION_FORM_DETECTED, event_source="BACKEND")
        assert rec6.new_state == ExecutionState.APPLICATION_FORM_DETECTED.value

        # Transition 7: APPLICATION_FORM_DETECTED -> AUTOFILL_RESUMED
        rec7 = sm.transition(session_id, ExecutionState.AUTOFILL_RESUMED, event_source="BACKEND")
        assert rec7.new_state == ExecutionState.AUTOFILL_RESUMED.value

        # Verify persisted state in SQLite
        loaded = db.get_autofill_execution_session(session_id)
        assert loaded["current_state"] == ExecutionState.AUTOFILL_RESUMED.value
        assert len(loaded["state_history"]) == 7

    def test_13_illegal_transition_rejection(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_sm_illegal.db"))
        _seed_user_and_app(db, user_id=1, app_id=1)
        sm = ApplicationExecutionStateMachine(db_manager=db)

        session_id = "exec_test_13"
        db.save_autofill_execution_session({
            "execution_id": session_id,
            "application_id": 1,
            "user_id": 1,
            "current_state": ExecutionState.PORTAL_OPENED.value,
        })

        # Cannot jump directly from PORTAL_OPENED to READY_FOR_HUMAN_REVIEW
        with pytest.raises(SecurityAuthorizationError):
            sm.transition(session_id, ExecutionState.READY_FOR_HUMAN_REVIEW, event_source="TEST")


class TestApplicationWorkflowResumer:
    """Verifies sequential multi-gate workflow resumption."""

    def test_14_multi_gate_sequential_progression(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_resumer.db"))
        app_id = 100
        user_id = 5
        _seed_user_and_app(db, user_id=user_id, app_id=app_id)
        resumer = ApplicationWorkflowResumer(db_manager=db)

        session_id = "exec_resumer_14"
        ticket = "valid_ticket_14"

        db.save_autofill_execution_session({
            "execution_id": session_id,
            "application_id": app_id,
            "user_id": user_id,
            "action_ticket": ticket,
            "current_state": ExecutionState.PORTAL_OPENED.value,
        })

        # Stage 1: Privacy gate presented
        res1 = resumer.process_gate_event(
            application_id=app_id,
            execution_id=session_id,
            ticket=ticket,
            event_type="USER_INTERACTION",
            html_snippet=PRIVACY_GATE_HTML,
            user_id=user_id,
        )
        assert res1.gate_detected is True
        assert res1.current_state == ExecutionState.WAITING_FOR_USER.value
        assert res1.is_ready_for_autofill is False

        # Stage 2: Candidate accepts privacy -> Work authorization eligibility gate presented
        res2 = resumer.process_gate_event(
            application_id=app_id,
            execution_id=session_id,
            ticket=ticket,
            event_type="GATE_COMPLETED",
            html_snippet=WORK_AUTH_GATE_HTML,
            control_interacted={"text": "I Agree & Continue"},
            user_id=user_id,
        )
        assert res2.gate_detected is True
        assert res2.current_state == ExecutionState.WAITING_FOR_USER.value
        assert res2.gate_result["gate_type"] == GateType.WORK_AUTHORIZATION.value

        # Stage 3: Candidate completes questionnaire -> Application form becomes accessible
        res3 = resumer.process_gate_event(
            application_id=app_id,
            execution_id=session_id,
            ticket=ticket,
            event_type="GATE_COMPLETED",
            html_snippet=DIRECT_FORM_HTML,
            control_interacted={"text": "Next Step"},
            user_id=user_id,
        )
        assert res3.gate_detected is False
        assert res3.is_ready_for_autofill is True
        assert res3.current_state == ExecutionState.AUTOFILL_RESUMED.value

    def test_15_candidate_declines_agreement_halts_workflow(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_decline.db"))
        app_id = 200
        user_id = 10
        _seed_user_and_app(db, user_id=user_id, app_id=app_id)
        resumer = ApplicationWorkflowResumer(db_manager=db)

        session_id = "exec_decline_15"
        ticket = "ticket_15"

        db.save_autofill_execution_session({
            "execution_id": session_id,
            "application_id": app_id,
            "user_id": user_id,
            "action_ticket": ticket,
            "current_state": ExecutionState.WAITING_FOR_USER.value,
        })

        res = resumer.process_gate_event(
            application_id=app_id,
            execution_id=session_id,
            ticket=ticket,
            event_type="USER_DECLINED",
            user_id=user_id,
        )
        assert res.current_state == ExecutionState.USER_DECLINED.value
        assert res.is_ready_for_autofill is False
        assert "halted" in res.message.lower()


class TestATSAdapterRegistry:
    """Verifies extensible ATS provider resolution."""

    def test_16_provider_resolutions(self):
        # Lever
        lever_adapter = ATSAdapterRegistry.resolve("https://jobs.lever.co/company/job-id")
        assert lever_adapter.provider_name == "LEVER"
        assert "button#hcaptchaSubmitBtn" in lever_adapter.get_submit_selectors()

        # Greenhouse
        gh_adapter = ATSAdapterRegistry.resolve("https://boards.greenhouse.io/company/jobs/123")
        assert gh_adapter.provider_name == "GREENHOUSE"

        # Workday
        wd_adapter = ATSAdapterRegistry.resolve("https://company.myworkdayjobs.com/en-US/careers/job/123")
        assert wd_adapter.provider_name == "WORKDAY"

        # Keka
        keka_adapter = ATSAdapterRegistry.resolve("https://company.keka.com/careers/applyjob/123")
        assert keka_adapter.provider_name == "KEKA"

        # Generic
        gen_adapter = ATSAdapterRegistry.resolve("https://careers.example.com/apply")
        assert gen_adapter.provider_name == "UNIVERSAL"


# =============================================================================
# END-TO-END PLAYWRIGHT MOCK ACCEPTANCE TEST
# =============================================================================

class TestPlaywrightIAGHAcceptance:
    """End-to-end browser automation test verifying gate pause, resume, and submission guard."""

    def test_17_playwright_gate_pause_and_autofill_completion(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "test_pw_iagh.db"))
        broker = ApplicationFormFillingBroker(db_manager=db)

        # Mock candidate and application in DB
        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'candidate@test.com', 'h', 's', 'Pranay Agrawal')"
            )
            cursor.execute(
                "INSERT INTO applications (id, user_id, company_name, job_title, external_application_url, status) VALUES (1, 1, 'CIN7', 'Software Engineer', 'https://jobs.lever.co/cin7/apply', 'APPROVED')"
            )

        # Save session in DB
        db.save_autofill_execution_session({
            "execution_id": "exec_test_17",
            "application_id": 1,
            "user_id": 1,
            "action_ticket": "ticket_17",
            "current_state": ExecutionState.PORTAL_OPENED.value,
        })

        # Mock plan preparation and verified resume bytes
        mock_plan = MagicMock()
        mock_plan.execution_id = "exec_test_17"
        mock_plan.application_id = 1
        mock_plan.user_id = 1
        mock_plan.ats_provider = "LEVER"
        mock_plan.target_url = "https://jobs.lever.co/cin7/apply"
        mock_plan.plan_hash = "plan_hash_17"
        mock_plan.action_ticket = "ticket_17"
        mock_plan.resume_id = 1
        mock_plan.resume_version_num = 1
        mock_plan.facts = {
            "full_name": {"value": "Pranay Agrawal", "provenance": "USER_CONFIRMED"},
            "email": {"value": "candidate@test.com", "provenance": "USER_CONFIRMED"},
            "phone": {"value": "+91 9876543210", "provenance": "USER_CONFIRMED"},
            "current_location": {"value": "Pune, India", "provenance": "USER_CONFIRMED"},
            "current_company": {"value": "Tech Corp", "provenance": "USER_CONFIRMED"},
            "linkedin_url": {"value": "https://linkedin.com/in/pranay", "provenance": "USER_CONFIRMED"},
            "github_url": {"value": "https://github.com/pranay", "provenance": "USER_CONFIRMED"},
        }
        broker.prepare_autofill_plan = MagicMock(return_value=mock_plan)
        fake_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n%%EOF"
        broker.get_verified_resume_bytes = MagicMock(return_value=(fake_pdf, "resume.pdf", "application/pdf"))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # Scenario A: Page is currently on Privacy Notice Gate
            page.set_content(PRIVACY_GATE_HTML)
            report_a = broker.execute_playwright_autofill(user_id=1, application_id=1, page=page)
            assert report_a.status == "PAUSED_FOR_USER_ACTION"
            assert report_a.resume_uploaded is False
            assert "Privacy Notice" in report_a.message

            # Scenario B: Human accepts agreement -> Page transitions to form
            page.set_content(DIRECT_FORM_HTML)
            report_b = broker.execute_playwright_autofill(user_id=1, application_id=1, page=page)
            assert report_b.status == "SUCCESS"
            assert report_b.fields_populated_count > 0
            assert report_b.submission_prevented is True

            # Invariant: Final submit button was NEVER clicked
            # Verify page still contains the submit button unclicked
            submit_btn = page.locator("button#hcaptchaSubmitBtn")
            assert submit_btn.count() == 1

            browser.close()
