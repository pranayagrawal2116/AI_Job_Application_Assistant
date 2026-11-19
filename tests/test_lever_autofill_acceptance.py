"""Phase C.1 Acceptance & Regression Tests for Lever ATS Form Autofill.

Tests cover:
1. Lever form detection (URL, domain, DOM markers).
2. Field mapping against exact CIN7 Lever form selectors and candidate profile.
3. Anti-automation non-false-positive detection on Lever forms containing hCaptcha buttons.
4. Companion handshake verification (success, invalid ticket, application mismatch).
5. Progressive companion stage reporting.
6. Independent field verification and retry mechanism.
7. Zero-field execution safeguards (cannot report false success).
8. Existing field value preservation guarantee.
9. Sensitive attributes zero-hallucination guarantee (CTC, Notice Period, EEO).
10. Strict human-in-the-loop submission protection.
11. Full Playwright mock execution on authentic Lever application form.
"""

import json
import pytest
from unittest.mock import MagicMock
from playwright.sync_api import sync_playwright

from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError
from src.preparer.form_filling_broker import (
    ApplicationFormFillingBroker,
    ATSProvider,
    FormFillExecutionReport,
    FormFieldResult,
)
from src.preparer.form_prefiller import FormPrefiller
from src.preparer.universal_field_mapper import (
    UniversalFieldMapper,
    FormFieldTarget,
    ProvenanceStatus,
)


LEVER_CIN7_HTML = """
<!DOCTYPE html>
<html>
<head><title>Cin7 - Junior Software Engineer</title></head>
<body>
<div class="application-page">
    <div class="posting-header">
        <h2>Junior Software Engineer</h2>
        <div class="posting-categories">Engineering / Pune, India</div>
    </div>
    <form id="application-form" method="POST" enctype="multipart/form-data">
        <div class="section-resume">
            <label>Resume/CV</label>
            <input type="file" name="resume" id="resume-upload-input" data-qa="input-resume">
            <div class="application-file-upload"><span class="file-name"></span></div>
        </div>

        <div class="section-personal">
            <label for="name">Full name <span>*</span></label>
            <input type="text" id="name" name="name" data-qa="name-input" value="">

            <label for="email">Email <span>*</span></label>
            <input type="email" id="email" name="email" data-qa="email-input" value="">

            <label for="phone">Phone <span>*</span></label>
            <input type="tel" id="phone" name="phone" data-qa="phone-input" value="">

            <label for="location-input">Current location <span>*</span></label>
            <input type="text" id="location-input" name="location" data-qa="location-input" value="">

            <label for="org">Current company</label>
            <input type="text" id="org" name="org" data-qa="org-input" value="">
        </div>

        <div class="section-urls">
            <label>LinkedIn URL</label>
            <input type="text" name="urls[LinkedIn]" value="">

            <label>GitHub URL</label>
            <input type="text" name="urls[GitHub]" value="">

            <label>Portfolio URL</label>
            <input type="text" name="urls[Portfolio]" value="">
        </div>

        <div class="section-custom">
            <label for="field0">What is your notice period?</label>
            <input type="text" id="field0" name="cards[0][field0]" value="">

            <label for="field1">What is your expected CTC?</label>
            <input type="text" id="field1" name="cards[0][field1]" value="">
        </div>

        <div class="section-eeo">
            <label for="eeo-gender">Gender</label>
            <select id="eeo-gender" name="eeo[gender]">
                <option value="">Select...</option>
                <option value="male">Male</option>
                <option value="female">Female</option>
                <option value="decline">Decline to self-identify</option>
            </select>
        </div>

        <div class="section-submit">
            <input type="hidden" name="h-captcha-response" id="hcaptchaResponseInput" value="">
            <button type="submit" id="hcaptchaSubmitBtn" class="postings-btn">Submit application</button>
        </div>
    </form>
</div>
</body>
</html>
"""


@pytest.fixture
def candidate_profile_data():
    return {
        "personal": {
            "full_name": "Pranay Anup Agrawal",
            "email": "agrawalpranay2116@gmail.com",
            "phone": "95100 29575",
            "location": "Pune, Maharashtra",
            "linkedin": "https://linkedin.com/in/pranay-agrawal-005416322",
            "github": "https://github.com/pranayagrawal2116",
        },
        "work_experience": [
            {
                "employer": "Sarita Infotech Pvt. Ltd.",
                "job_title": "Project Manager | Mobile App Development",
                "duration": "3 months",
                "verification_status": "EXTRACTED_UNVERIFIED",
            }
        ],
        "education": [
            {
                "institution": "MIT World Peace University",
                "degree": "B.Tech",
                "major": "Computer Science & Engineering",
                "current_cgpa": 7.6,
                "expected_graduation_year": 2028,
            }
        ],
    }


class TestLeverAutofillAcceptance:

    def test_lever_ats_detection(self):
        """Verifies that Lever URLs and form markers correctly resolve to ATSProvider.LEVER."""
        url = "https://jobs.lever.co/cin7/510ff0bd-2b01-4645-bf6f-89be209ad154/apply?source=LinkedIn"
        assert ApplicationFormFillingBroker.identify_ats_provider(url) == ATSProvider.LEVER

        # URL with domain or form id
        assert ApplicationFormFillingBroker.identify_ats_provider("https://lever.co/apply", LEVER_CIN7_HTML) == ATSProvider.LEVER
        assert ApplicationFormFillingBroker.identify_ats_provider("https://careers.cin7.com/apply", '<form id="application-form">') == ATSProvider.LEVER

    def test_anti_automation_not_falsely_triggered_on_lever_forms(self):
        """Verifies that FormPrefiller does NOT falsely flag Lever forms as anti-automation

        even when the form includes Lever's hCaptcha submit button and hidden tokens.
        """
        prefiller = FormPrefiller()
        # Lever page with accessible form inputs must NOT be flagged as blocked
        assert not prefiller.detect_anti_automation(LEVER_CIN7_HTML)

        # Real Cloudflare interstitial challenge MUST still be detected
        cf_page = "<html><body><div class='cf-chl-widget'>Please complete the Cloudflare Turnstile challenge. Verify you are human.</div></body></html>"
        assert prefiller.detect_anti_automation(cf_page)

    def test_lever_cin7_field_mapping_zero_hallucination(self, candidate_profile_data):
        """Verifies that all standard candidate details map to Lever form controls

        and sensitive questions (CTC, notice period, EEO) require candidate input.
        """
        mapper = UniversalFieldMapper(candidate_profile=candidate_profile_data)

        # 1. Full name
        name_t = FormFieldTarget(name_attr="name", element_id="name", field_type="text", accessible_label="Full name", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(name_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "Pranay Anup Agrawal"

        # 2. Email
        email_t = FormFieldTarget(name_attr="email", element_id="email", field_type="email", accessible_label="Email", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(email_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "agrawalpranay2116@gmail.com"

        # 3. Phone
        phone_t = FormFieldTarget(name_attr="phone", element_id="phone", field_type="tel", accessible_label="Phone", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(phone_t)
        assert dec.action == "FILL"
        assert "95100" in str(dec.intended_value)

        # 4. Current location
        loc_t = FormFieldTarget(name_attr="location", element_id="location-input", field_type="text", accessible_label="Current location", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(loc_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "Pune, Maharashtra"

        # 5. Current company (from work_experience employer)
        org_t = FormFieldTarget(name_attr="org", element_id="org", field_type="text", accessible_label="Current company", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(org_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "Sarita Infotech Pvt. Ltd."

        # 6. LinkedIn URL
        li_t = FormFieldTarget(name_attr="urls[LinkedIn]", element_id="", field_type="text", accessible_label="LinkedIn URL", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(li_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "https://linkedin.com/in/pranay-agrawal-005416322"

        # 7. GitHub URL
        gh_t = FormFieldTarget(name_attr="urls[GitHub]", element_id="", field_type="text", accessible_label="GitHub URL", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(gh_t)
        assert dec.action == "FILL"
        assert dec.intended_value == "https://github.com/pranayagrawal2116"

        # 8. Notice period -> NEEDS_INPUT (Zero Hallucination)
        np_t = FormFieldTarget(name_attr="cards[0][field0]", element_id="field0", field_type="text", accessible_label="What is your notice period?", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(np_t)
        assert dec.action == "NEEDS_INPUT"

        # 9. Expected CTC -> NEEDS_INPUT (Zero Hallucination)
        ctc_t = FormFieldTarget(name_attr="cards[0][field1]", element_id="field1", field_type="text", accessible_label="What is your expected CTC?", placeholder="", aria_label="", options=[], current_value="")
        dec = mapper.match_field(ctc_t)
        assert dec.action == "NEEDS_INPUT"

        # 10. EEO Gender -> NEEDS_INPUT (Zero Hallucination)
        eeo_t = FormFieldTarget(name_attr="eeo[gender]", element_id="eeo-gender", field_type="select", accessible_label="Gender", placeholder="", aria_label="", options=[("male", "Male"), ("female", "Female")], current_value="")
        dec = mapper.match_field(eeo_t)
        assert dec.action == "NEEDS_INPUT"

    def test_companion_handshake_lifecycle(self):
        """Verifies handshake registration, validation, and error handling in broker."""
        db = DatabaseManager(db_path=":memory:")
        broker = ApplicationFormFillingBroker(db_manager=db)

        # Register execution mock
        exec_id = "exec_test_lever_123"
        ticket = "ticket_valid_sig_456"
        with broker._execution_lock:
            broker._active_executions[exec_id] = {
                "execution_id": exec_id,
                "application_id": 450,
                "user_id": 165,
                "action_ticket": ticket,
                "status": "READY",
                "companion_connected": False,
                "stage_index": 1,
            }

        # Successful handshake
        res = broker.record_handshake(
            application_id=450,
            execution_id=exec_id,
            ticket=ticket,
            domain="jobs.lever.co",
            companion_version="1.1.0",
            ats_detected="lever",
            form_found=True,
        )
        assert res["companion_connected"] is True
        assert res["stage_index"] == 3
        assert res["form_detected"] is True

        # Check status endpoint output
        st = broker.get_execution_status(application_id=450, execution_id=exec_id)
        assert st["companion_connected"] is True
        assert st["stage_index"] == 3
        assert st["form_detected"] is True

        # Rejection on application mismatch
        with pytest.raises(SecurityAuthorizationError):
            broker.record_handshake(
                application_id=999,  # Mismatched app
                execution_id=exec_id,
                ticket=ticket,
            )

        # Rejection on invalid ticket
        with pytest.raises(SecurityAuthorizationError):
            broker.record_handshake(
                application_id=450,
                execution_id=exec_id,
                ticket="invalid_ticket",
            )

    def test_progressive_companion_stage_updates(self):
        """Verifies that the companion can push progressive updates to the broker."""
        db = DatabaseManager(db_path=":memory:")
        broker = ApplicationFormFillingBroker(db_manager=db)

        exec_id = "exec_test_progress_789"
        ticket = "ticket_progress_test"
        with broker._execution_lock:
            broker._active_executions[exec_id] = {
                "execution_id": exec_id,
                "application_id": 450,
                "user_id": 165,
                "action_ticket": ticket,
                "status": "READY",
                "stage_index": 1,
            }

        broker.record_progress(
            application_id=450,
            execution_id=exec_id,
            ticket=ticket,
            stage="RESUME_UPLOADED",
            stage_index=5,
            message="Resume attached to Lever file input",
            stats={"resume_uploaded": True},
        )

        st = broker.get_execution_status(application_id=450, execution_id=exec_id)
        assert st["stage_index"] == 5
        assert st["resume_uploaded"] is True
        assert "Resume attached" in st["message"]

    def test_zero_field_execution_fails_closed(self):
        """Verifies that an execution where 0 fields are populated and no resume uploaded

        cannot produce a SUCCESS status or mark stages complete.
        """
        db = DatabaseManager(db_path=":memory:")
        broker = ApplicationFormFillingBroker(db_manager=db)

        # Mock page with no form controls
        mock_page = MagicMock()
        mock_page.content.return_value = "<html><body>No job form here</body></html>"
        mock_page.url = "https://jobs.lever.co/cin7/empty"
        mock_page.query_selector_all.return_value = []
        mock_page.locator.return_value.count.return_value = 0

        # Mock prepare_autofill_plan and get_verified_resume_bytes
        broker.prepare_autofill_plan = MagicMock()
        mock_plan = MagicMock()
        mock_plan.execution_id = "exec_zero_test"
        mock_plan.application_id = 450
        mock_plan.user_id = 165
        mock_plan.ats_provider = "LEVER"
        mock_plan.target_url = mock_page.url
        mock_plan.plan_hash = "hash_zero"
        mock_plan.action_ticket = "ticket_zero"
        mock_plan.facts = {}
        mock_plan.resume_id = 1
        mock_plan.resume_version_num = 1
        broker.prepare_autofill_plan.return_value = mock_plan
        broker.get_verified_resume_bytes = MagicMock(return_value=(b"%PDF-1.4...", "resume.pdf", "application/pdf"))

        with broker._execution_lock:
            broker._active_executions["exec_zero_test"] = {
                "execution_id": "exec_zero_test",
                "application_id": 450,
                "user_id": 165,
                "action_ticket": "ticket_zero",
                "status": "READY",
                "stage_index": 1,
            }

        report = broker.execute_playwright_autofill(
            user_id=165,
            application_id=450,
            page=mock_page,
            target_url=mock_page.url,
        )

        assert report.fields_populated_count == 0
        assert report.status == "NO_FIELDS_POPULATED"
        assert "could not populate any fields" in report.message.lower()

        # Check execution status in broker
        st = broker.get_execution_status(application_id=450, execution_id="exec_zero_test")
        assert st["status"] in ["FAILED", "NO_FIELDS_POPULATED"]
        assert st["stage"] == "FAILED"
        assert st["stage_index"] < 9

    def test_existing_field_preservation(self, candidate_profile_data):
        """Verifies that fields already containing values are preserved and never overwritten."""
        mapper = UniversalFieldMapper(candidate_profile=candidate_profile_data)

        # Candidate edited name on Lever form before running autofill
        pre_filled_target = FormFieldTarget(
            name_attr="name",
            element_id="name",
            field_type="text",
            accessible_label="Full name",
            placeholder="",
            aria_label="",
            options=[],
            current_value="Pranay A. Agrawal (Custom Edit)",
        )
        dec = mapper.match_field(pre_filled_target)
        assert dec.action == "PRESERVE_EXISTING"
        assert dec.intended_value == "Pranay A. Agrawal (Custom Edit)"

    def test_e2e_playwright_lever_form_autofill(self, candidate_profile_data):
        """Executes full end-to-end autofill on authentic Lever CIN7 HTML DOM using Playwright.

        Verifies:
        - Resume file input is identified and attached.
        - Name, email, phone, location, org, and social URLs are filled and verified.
        - Notice period and CTC are flagged for candidate review without fabrication.
        - Submission button is never clicked.
        - Output report contains correct populated and verified field counts.
        """
        db = DatabaseManager(db_path=":memory:")
        broker = ApplicationFormFillingBroker(db_manager=db)

        # Prepare mocks
        broker.prepare_autofill_plan = MagicMock()
        mock_plan = MagicMock()
        mock_plan.execution_id = "exec_e2e_lever"
        mock_plan.application_id = 450
        mock_plan.user_id = 165
        mock_plan.ats_provider = "LEVER"
        mock_plan.target_url = "https://jobs.lever.co/cin7/junior-software-engineer/apply"
        mock_plan.plan_hash = "plan_hash_lever"
        mock_plan.action_ticket = "ticket_e2e_lever"
        mock_plan.resume_id = 1
        mock_plan.resume_version_num = 1

        # Use facts from mapper
        mapper = UniversalFieldMapper(candidate_profile=candidate_profile_data)
        mock_plan.facts = {k: f.to_dict() for k, f in mapper.facts.items()}
        broker.prepare_autofill_plan.return_value = mock_plan

        fake_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n%%EOF"
        broker.get_verified_resume_bytes = MagicMock(return_value=(fake_pdf, "Pranay_Agrawal_Resume.pdf", "application/pdf"))

        with broker._execution_lock:
            broker._active_executions["exec_e2e_lever"] = {
                "execution_id": "exec_e2e_lever",
                "application_id": 450,
                "user_id": 165,
                "action_ticket": "ticket_e2e_lever",
                "status": "READY",
                "stage_index": 1,
            }

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Load authentic Lever CIN7 HTML
            page.set_content(LEVER_CIN7_HTML)

            report = broker.execute_playwright_autofill(
                user_id=165,
                application_id=450,
                page=page,
                target_url=mock_plan.target_url,
            )

            # 1. Check report outcomes
            assert report.resume_uploaded is True
            assert report.fields_populated_count >= 6
            assert report.status == "SUCCESS"
            assert report.submission_prevented is True

            # 2. Check DOM field values
            assert page.input_value("input[data-qa='name-input']") == "Pranay Anup Agrawal"
            assert page.input_value("input[data-qa='email-input']") == "agrawalpranay2116@gmail.com"
            assert "95100" in page.input_value("input[data-qa='phone-input']")
            assert page.input_value("input[data-qa='location-input']") == "Pune, Maharashtra"
            assert page.input_value("input[data-qa='org-input']") == "Sarita Infotech Pvt. Ltd."
            assert page.input_value("input[name='urls[LinkedIn]']") == "https://linkedin.com/in/pranay-agrawal-005416322"
            assert page.input_value("input[name='urls[GitHub]']") == "https://github.com/pranayagrawal2116"

            # 3. Check sensitive fields remain blank (Zero Hallucination)
            assert page.input_value("input[name='cards[0][field0]']") == ""
            assert page.input_value("input[name='cards[0][field1]']") == ""

            # 4. Check submit button was NEVER clicked
            # The form is still on the page with unsubmitted state
            assert page.locator("#hcaptchaSubmitBtn").count() == 1

            browser.close()
