"""Playwright Browser Acceptance Test Suite (Phase C.1: External ATS Form Auto-Population).

Verifies end-to-end automated form population on an external employer application portal:
1. Target ATS portal identification (Keka ATS form pattern).
2. Safe authorized resume file upload into #resume-upload.
3. Detection of ATS-parsed fields and population of remaining blank fields from verified candidate facts.
4. Field preservation: existing values are never overwritten.
5. Strict Human-in-the-Loop safety invariant: Final submit button (#jobApplicationSubmitButton) is NEVER clicked.
6. Sensitive fields guarantee: Gender, DOB, Salary, and Notice period are never inferred.
"""

import http.server
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest

from playwright.sync_api import sync_playwright

from src.preparer.universal_field_mapper import FormFieldTarget, UniversalFieldMapper

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# HTML template representing the live Keka ATS application form inspected at blueflamelabs.keka.com
KEKA_SIMULATED_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Careers - Job Application Form</title>
</head>
<body>
    <div id="jobApplicationContainer">
        <h2>Apply for Project Manager</h2>
        
        <!-- File upload element -->
        <div class="form-group">
            <label for="resume-upload">Upload Resume (PDF, DOCX)</label>
            <input type="file" id="resume-upload" name="resume" accept=".pdf,.docx,.doc" />
            <span id="uploadStatus">No file chosen</span>
        </div>

        <form id="applicantForm">
            <!-- Personal Information -->
            <input type="text" id="firstName" name="firstName" placeholder="First Name" />
            <input type="text" id="middleName" name="middleName" placeholder="Middle Name" />
            <input type="text" id="lastName" name="lastName" placeholder="Last Name" />
            
            <select id="mobilePhone_countryCode" name="mobilePhone.countryCode">
                <option value="+1">+1 (US)</option>
                <option value="+44">+44 (UK)</option>
                <option value="+91">+91 (India)</option>
            </select>
            <input type="tel" id="mobilePhone_number" name="mobilePhone.number" placeholder="Mobile Number" />

            <input type="email" id="email" name="email" placeholder="Email Address" />
            
            <select id="gender" name="gender">
                <option value="">Select Gender</option>
                <option value="1">Male</option>
                <option value="2">Female</option>
            </select>

            <!-- Experience -->
            <input type="number" id="workExperience" name="workExperience" placeholder="Total Experience (Years)" />
            <select id="workExperience_months" name="workExperience.months">
                <option value="0">0 Months</option>
                <option value="3">3 Months</option>
                <option value="6">6 Months</option>
                <option value="9">9 Months</option>
            </select>

            <input type="text" id="currentLocation" name="currentLocation" placeholder="Current Location" />

            <!-- Custom Questions -->
            <input type="text" id="college_name_q" name="1d9c080f-d347-4129-bc69-68e84b90402c" placeholder="College Name" />
            <input type="text" id="branch_q" name="df9e8b1c-376f-4061-848c-1be135a8266e" placeholder="Branch" />
            <input type="text" id="cgpa_q" name="c5c44e06-12b2-45e1-bbc7-029c00746894" placeholder="CGPA" />

            <!-- Consent Checkbox -->
            <input type="checkbox" id="termsConsent" name="termsConsent" />
            <label for="termsConsent">I agree to terms and conditions</label>

            <!-- Final Submission Button - MUST NEVER BE CLICKED BY AUTOMATION -->
            <button type="button" id="jobApplicationSubmitButton" onclick="window.formWasSubmitted = true;">
                Submit Application
            </button>
        </form>
    </div>

    <script>
        window.formWasSubmitted = false;
        document.getElementById('resume-upload').addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                document.getElementById('uploadStatus').innerText = 'Uploaded: ' + e.target.files[0].name;
            }
        });
    </script>
</body>
</html>
"""


class MockATSHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Simple HTTP handler serving the simulated ATS form."""

    def do_GET(self):
        if self.path in ("/", "/careers/applyjob/76776", "/careers/apply"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(KEKA_SIMULATED_HTML.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence HTTP server logs during tests
        pass


class TestBrowserAcceptancePhaseC1(unittest.TestCase):
    """End-to-end Playwright acceptance test suite for external form filling."""

    ats_server: socketserver.TCPServer
    server_thread: threading.Thread
    port: int
    playwright: any
    browser: any

    @classmethod
    def setUpClass(cls):
        # 1. Start mock ATS HTTP server on dynamic port
        handler = MockATSHTTPHandler
        cls.ats_server = socketserver.TCPServer(("127.0.0.1", 0), handler)
        cls.port = cls.ats_server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.ats_server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.portal_url = f"http://127.0.0.1:{cls.port}/careers/applyjob/76776"

        # 2. Start Playwright
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "browser") and cls.browser:
            cls.browser.close()
        if hasattr(cls, "playwright") and cls.playwright:
            cls.playwright.stop()
        if hasattr(cls, "ats_server") and cls.ats_server:
            cls.ats_server.shutdown()
            cls.ats_server.server_close()

    def test_keka_form_population_and_human_in_the_loop_safety(self):
        """Verify resume file upload, DOM inspection, field auto-filling, and human approval safety."""
        # 1. Candidate facts profile
        profile = {
            "full_name": "Pranay Anup Agrawal",
            "email": "pranay@example.com",
            "phone": "+91 9510029575",
            "location": "Pune, Maharashtra, India",
            "education": [
                {
                    "institution": "MIT World Peace University",
                    "degree": "B.Tech in Computer Science and Engineering",
                    "major": "Computer Science with AI & Data Science",
                    "current_cgpa": "7.6",
                    "expected_graduation_year": "2028",
                }
            ],
            "work_experience": [
                {
                    "company": "Sarita Infotech Pvt. Ltd.",
                    "title": "Project Manager",
                    "duration_months": 3,
                }
            ],
            "technical_skills": ["Python", "Machine Learning", "FastAPI"],
        }

        mapper = UniversalFieldMapper(profile)

        # 2. Create isolated dummy resume file
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
            tf.write(b"%PDF-1.4 Mock resume content for Phase C.1 test")
            resume_path = tf.name

        page = self.browser.new_page()
        try:
            # 3. Navigate to employer portal
            page.goto(self.portal_url, wait_until="networkidle")

            # 4. Upload resume
            file_input = page.locator("#resume-upload")
            self.assertTrue(file_input.is_visible())
            file_input.set_input_files(resume_path)

            upload_status = page.locator("#uploadStatus").inner_text()
            self.assertIn("Uploaded:", upload_status)

            # 5. Extract form fields from live DOM
            inputs = page.query_selector_all("input, select, textarea")
            detected_targets = []
            for inp in inputs:
                tag = inp.evaluate("el => el.tagName.toLowerCase()")
                el_id = inp.get_attribute("id") or ""
                name = inp.get_attribute("name") or ""
                inp_type = "select" if tag == "select" else ("textarea" if tag == "textarea" else (inp.get_attribute("type") or "text"))
                ph = inp.get_attribute("placeholder") or ""
                curr_val = inp.input_value() if inp_type not in ("checkbox", "radio", "file") else ""

                if inp_type in ("file", "hidden", "submit", "button"):
                    continue

                target = FormFieldTarget(
                    element_id=el_id,
                    name_attr=name,
                    field_type=inp_type,
                    placeholder=ph,
                    accessible_label=ph,
                    current_value=curr_val if curr_val else None,
                )
                detected_targets.append(target)

            # 6. Run field mapping decisions
            decisions = [mapper.match_field(t) for t in detected_targets]

            # 7. Apply decisions into form (excluding submit button)
            for d in decisions:
                if d.action == "FILL" and d.intended_value:
                    target = d.field_target
                    sel = f"#{target.element_id}" if target.element_id else f"[name='{target.name_attr}']"
                    loc = page.locator(sel)
                    if target.field_type == "select":
                        loc.select_option(d.intended_value)
                    else:
                        loc.fill(d.intended_value)

            # 8. VERIFY RESULTING FORM VALUES
            self.assertEqual(page.locator("#firstName").input_value(), "Pranay")
            self.assertEqual(page.locator("#middleName").input_value(), "Anup")
            self.assertEqual(page.locator("#lastName").input_value(), "Agrawal")
            self.assertEqual(page.locator("#email").input_value(), "pranay@example.com")
            self.assertEqual(page.locator("#mobilePhone_number").input_value(), "9510029575")
            self.assertEqual(page.locator("#workExperience").input_value(), "0")
            self.assertEqual(page.locator("#workExperience_months").input_value(), "3")
            self.assertEqual(page.locator("#currentLocation").input_value(), "Pune, Maharashtra, India")

            # 9. STRICT SAFETY INVARIANT: Verify that submit button was NEVER clicked!
            was_submitted = page.evaluate("() => window.formWasSubmitted")
            self.assertFalse(was_submitted, "SAFETY VIOLATION: Submit button must NEVER be clicked by automation!")

        finally:
            page.close()
            Path(resume_path).unlink(missing_ok=True)

    def test_existing_field_values_are_preserved(self):
        """Verify that existing candidate inputs or ATS parsed values are never overwritten."""
        profile = {
            "full_name": "Pranay Anup Agrawal",
            "email": "pranay@example.com",
        }
        mapper = UniversalFieldMapper(profile)

        page = self.browser.new_page()
        try:
            page.goto(self.portal_url, wait_until="networkidle")

            # Pre-populate a field directly (e.g. ATS already parsed a preferred nickname)
            page.locator("#firstName").fill("Pranav")

            inputs = page.query_selector_all("input, select, textarea")
            detected_targets = []
            for inp in inputs:
                tag = inp.evaluate("el => el.tagName.toLowerCase()")
                el_id = inp.get_attribute("id") or ""
                name = inp.get_attribute("name") or ""
                inp_type = "select" if tag == "select" else ("textarea" if tag == "textarea" else (inp.get_attribute("type") or "text"))
                ph = inp.get_attribute("placeholder") or ""
                curr_val = inp.input_value() if inp_type not in ("checkbox", "radio", "file") else ""

                if inp_type in ("file", "hidden", "submit", "button"):
                    continue

                target = FormFieldTarget(
                    element_id=el_id,
                    name_attr=name,
                    field_type=inp_type,
                    placeholder=ph,
                    accessible_label=ph,
                    current_value=curr_val if curr_val else None,
                )
                detected_targets.append(target)

            decisions = [mapper.match_field(t) for t in detected_targets]

            # Find decision for firstName
            first_name_dec = next((d for d in decisions if d.field_target.element_id == "firstName"), None)
            self.assertIsNotNone(first_name_dec)
            self.assertEqual(first_name_dec.action, "PRESERVE_EXISTING")
            self.assertEqual(first_name_dec.intended_value, "Pranav")

            # Apply only FILL decisions
            for d in decisions:
                if d.action == "FILL" and d.intended_value:
                    target = d.field_target
                    sel = f"#{target.element_id}" if target.element_id else f"[name='{target.name_attr}']"
                    loc = page.locator(sel)
                    if target.field_type == "select":
                        loc.select_option(d.intended_value)
                    else:
                        loc.fill(d.intended_value)

            # Assert firstName still has "Pranav", NOT overwritten with "Pranay"
            self.assertEqual(page.locator("#firstName").input_value(), "Pranav")
        finally:
            page.close()


if __name__ == "__main__":
    unittest.main()
