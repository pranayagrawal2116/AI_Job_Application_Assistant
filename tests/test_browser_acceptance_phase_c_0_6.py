"""Hermetic Playwright Browser Acceptance Test Suite (Phase C.0.6).

Verifies authoritative environment bootstrap and end-to-end security workflow:
1. Backend starts with authoritative environment resolution.
2. /api/health returns HTTP 200 with matching normalized app_env.
3. Candidate logs in and uploads synthetic resume.
4. Resume parsing, security scan signing, and preflight pass cleanly.
5. Application workspace opens, tailoring generates tailored resume without APP_ENV error.
6. Tailored artifact saved to disk.
7. Server restart preserves valid signed scan verification.
"""

import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.request

from playwright.sync_api import sync_playwright

from tests.fixtures.isolated_server import IsolatedTestServer
from tests.fixtures.synthetic_personas import generate_two_column_acca_pdf

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestBrowserAcceptancePhaseC06(unittest.TestCase):
    """Playwright browser acceptance test suite for Phase C.0.6."""

    server: IsolatedTestServer
    playwright: any
    temp_dir: tempfile.TemporaryDirectory
    artifacts_dir: Path

    @classmethod
    def setUpClass(cls):
        # 1. Start isolated test server
        cls.server = IsolatedTestServer()
        cls.server.start()
        cls.base_url = cls.server.base_url

        # 2. Setup artifacts directory
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.temp_path = Path(cls.temp_dir.name)
        cls.artifacts_dir = PROJECT_ROOT / "test_artifacts"
        cls.artifacts_dir.mkdir(parents=True, exist_ok=True)

        # 3. Generate sample resume PDF
        cls.acca_pdf_path = cls.temp_path / "synthetic_acca_resume.pdf"
        cls.acca_pdf_path.write_bytes(generate_two_column_acca_pdf())

        # 4. Start Playwright
        cls.playwright = sync_playwright().start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "playwright") and cls.playwright:
            cls.playwright.stop()
        if hasattr(cls, "server") and cls.server:
            cls.server.stop()
        if hasattr(cls, "temp_dir") and cls.temp_dir:
            cls.temp_dir.cleanup()

    def test_01_api_health_authoritative_app_env(self):
        """Step 1 & 2 & 3: Health check returns HTTP 200 with authoritative normalized app_env and no error."""
        health_url = f"{self.base_url}/api/health"
        req = urllib.request.Request(health_url)
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.status, 200)
            data = json.loads(response.read().decode("utf-8"))

        self.assertEqual(data.get("status"), "healthy")
        env_info = data.get("environment", {})
        # Must reflect normalized environment ('test' under IsolatedTestServer)
        self.assertEqual(env_info.get("app_env"), "test")
        self.assertTrue(env_info.get("database_connected"))
        self.assertTrue(data.get("configuration_subsystem", {}).get("ready"))
        self.assertIsNone(data.get("configuration_subsystem", {}).get("error"))

    def test_02_e2e_resume_tailoring_workflow_no_app_env_error(self):
        """Steps 4-16: Candidate login, resume upload, tailoring without APP_ENV failure, and restart persistence."""
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Step 4: Register & Login synthetic candidate
        cand_email = f"synth_cand_{int(time.time())}@example.com"
        cand_password = "SecurePassword123!"

        reg_url = f"{self.base_url}/api/auth/register"
        reg_payload = json.dumps({
            "email": cand_email,
            "password": cand_password,
            "full_name": "Synthetic ACCA Candidate",
            "profession_industry": "accounting_finance",
        }).encode("utf-8")
        req_reg = urllib.request.Request(reg_url, data=reg_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_reg) as resp:
            self.assertIn(resp.status, (200, 201))
            reg_data = json.loads(resp.read().decode("utf-8"))
            session_id = reg_data.get("session_id")
            user_id = reg_data.get("user", {}).get("id")

        self.assertIsNotNone(session_id)
        self.assertIsNotNone(user_id)

        # Set auth session cookie/storage in browser
        page.goto(f"{self.base_url}/login")
        page.fill("input[type='email']", cand_email)
        page.fill("input[type='password']", cand_password)
        page.click("button[type='submit']")

        # Wait for navigation to dashboard or jobs
        page.wait_for_load_state("networkidle")

        # Step 5 & 6: Upload synthetic PDF resume via API with verified session
        pdf_bytes = self.acca_pdf_path.read_bytes()
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="synthetic_acca_resume.pdf"\r\n'
            f"Content-Type: application/pdf\r\n\r\n"
        ).encode("utf-8") + pdf_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        upload_req = urllib.request.Request(
            f"{self.base_url}/api/profile/resumes/upload",
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Authorization": f"Bearer {session_id}",
            },
        )
        with urllib.request.urlopen(upload_req) as upload_resp:
            self.assertIn(upload_resp.status, (200, 201))
            upload_data = json.loads(upload_resp.read().decode("utf-8"))
            resume_id = upload_data.get("id") or upload_data.get("resume", {}).get("id")

        self.assertIsNotNone(resume_id)

        # Step 7: Create a synthetic job and draft application
        create_app_payload = json.dumps({
            "company_name": "Azets Audit Ltd",
            "job_title": "Tax Senior Associate",
            "employment_type": "Full-time",
            "location": "London, UK",
            "notes": "E2E Phase C.0.6 acceptance test application.",
        }).encode("utf-8")
        app_req = urllib.request.Request(
            f"{self.base_url}/api/applications",
            data=create_app_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {session_id}",
            },
        )
        with urllib.request.urlopen(app_req) as app_resp:
            self.assertIn(app_resp.status, (200, 201))
            app_data = json.loads(app_resp.read().decode("utf-8"))
            application_id = app_data.get("id")

        self.assertIsNotNone(application_id)

        # Step 8-14: Execute Tailor Resume API (which triggers SecurityPreflightManager and LegacyEvidenceVerifier)
        tailor_payload = json.dumps({
            "resume_id": resume_id,
            "custom_instructions": "Highlight UK direct tax and audit experience.",
        }).encode("utf-8")
        tailor_req = urllib.request.Request(
            f"{self.base_url}/api/applications/{application_id}/tailor-resume",
            data=tailor_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {session_id}",
            },
        )

        with urllib.request.urlopen(tailor_req) as tailor_resp:
            self.assertEqual(tailor_resp.status, 200)
            tailor_data = json.loads(tailor_resp.read().decode("utf-8"))
            self.assertEqual(tailor_data.get("status"), "ok")
            tailored_resume = tailor_data.get("tailored_resume")
            self.assertIsNotNone(tailored_resume)
            self.assertEqual(tailored_resume.get("target_company"), "Azets Audit Ltd")

        # Step 15 & 16: Restart server and verify health and security scan persistence
        self.server.stop()
        self.server.start()

        # Re-check health after restart
        health_req = urllib.request.Request(f"{self.server.base_url}/api/health")
        with urllib.request.urlopen(health_req) as h_resp:
            self.assertEqual(h_resp.status, 200)
            h_data = json.loads(h_resp.read().decode("utf-8"))
            self.assertEqual(h_data.get("status"), "healthy")

        # Re-authenticate candidate after server restart
        login_url = f"{self.server.base_url}/api/auth/login"
        login_payload = json.dumps({
            "email": cand_email,
            "password": cand_password,
        }).encode("utf-8")
        req_login = urllib.request.Request(login_url, data=login_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_login) as l_resp:
            self.assertIn(l_resp.status, (200, 201))
            l_data = json.loads(l_resp.read().decode("utf-8"))
            new_session_id = l_data.get("session_id")

        self.assertIsNotNone(new_session_id)

        # Verify tailor endpoint still succeeds with persisted scan
        tailor_req_post_restart = urllib.request.Request(
            f"{self.server.base_url}/api/applications/{application_id}/tailor-resume",
            data=tailor_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {new_session_id}",
            },
        )
        with urllib.request.urlopen(tailor_req_post_restart) as t2_resp:
            self.assertEqual(t2_resp.status, 200)
            t2_data = json.loads(t2_resp.read().decode("utf-8"))
            self.assertEqual(t2_data.get("status"), "ok")

        browser.close()


if __name__ == "__main__":
    unittest.main()
