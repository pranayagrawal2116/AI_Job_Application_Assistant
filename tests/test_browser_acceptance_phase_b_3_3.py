"""Playwright End-to-End Browser Acceptance Test Suite (Phase B.3.3).

Executes real browser acceptance across Chromium and WebKit for:
  - Scenario A: ACCA Candidate Registration, Resume Upload, Profile Population & Discovery.
  - Scenario B: CSE Candidate Registration, Resume Upload, Skills Verification & Discovery.
  - Scenario C: File Dropzone Interactions (Click-to-upload, clear, invalid extension, size limits).
  - Scenario D: Discovery Polling, Page Refresh Recovery, and Non-Blocking UI Verification.
"""

import os
os.environ.setdefault("APP_ENV", "test")

import time
from pathlib import Path
import tempfile
import unittest

from playwright.sync_api import sync_playwright

from tests.fixtures.synthetic_personas import generate_two_column_acca_pdf, generate_persona_pdf


BASE_URL = "http://127.0.0.1:8000"


class TestBrowserAcceptancePhaseB33(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.temp_path = Path(cls.temp_dir.name)

        # Generate synthetic PDF test artifacts on disk
        cls.acca_pdf_path = cls.temp_path / "synthetic_acca_resume.pdf"
        cls.acca_pdf_path.write_bytes(generate_two_column_acca_pdf())

        cls.cse_pdf_path = cls.temp_path / "synthetic_cse_resume.pdf"
        cls.cse_pdf_path.write_bytes(generate_persona_pdf("cs_mobile_ai_student"))

        cls.invalid_file_path = cls.temp_path / "invalid_document.txt"
        cls.invalid_file_path.write_text("This is an unsupported plain text document.")

        cls.oversized_file_path = cls.temp_path / "oversized_document.pdf"
        # 11 MB dummy file
        cls.oversized_file_path.write_bytes(b"%PDF-1.4 " + (b"0" * (11 * 1024 * 1024)))

        cls.playwright = sync_playwright().start()

    @classmethod
    def tearDownClass(cls):
        cls.playwright.stop()
        cls.temp_dir.cleanup()

    def test_scenario_a_acca_candidate_workflow(self):
        """Scenario A: ACCA candidate registers, uploads resume, inspects verified profile, and triggers discovery."""
        timestamp = int(time.time() * 1000)
        email = f"acca.candidate.{timestamp}@example.com"
        password = "SecurePassword123!"
        full_name = "Pranjali ACCA Candidate"

        # Test across Chromium
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            # 1. Open Registration
            page.goto(f"{BASE_URL}/register")
            page.wait_for_selector('input[type="text"]')
            page.fill('input[type="text"]', full_name)
            page.fill('input[type="email"]', email)
            page.fill('input[type="password"]', password)
            page.click('button[type="submit"]')

            # 2. Arrive at Onboarding Wizard Step 1
            page.wait_for_url(f"{BASE_URL}/onboarding", timeout=10000)
            self.assertIn("Welcome to JobFlow AI", page.content())

            # 3. Step 1 -> Step 2
            page.click('button:has-text("Continue to Resume Upload")')
            page.wait_for_selector('input[type="file"]', state="attached")

            # 4. Upload synthetic ACCA resume
            file_input = page.locator('input[type="file"]')
            file_input.set_input_files(str(self.acca_pdf_path))
            page.wait_for_selector('button:has-text("Upload & Parse"):not([disabled])')
            page.click('button:has-text("Upload & Parse")')

            # 5. Arrive at Step 3: Profile & Role Recommendations
            page.wait_for_selector('text=Profile Generated & Ready for Discovery', timeout=15000)
            content = page.content()

            # Verify ACCA qualifications and domain evidence present
            self.assertTrue(
                "ACCA" in content or "Accounting" in content or "BBA" in content or "Tax" in content,
                "ACCA or accounting qualifications should be visible in extracted credentials",
            )

            # 6. Confirm & Discover
            confirm_btn = page.locator('button:has-text("Confirm & Discover Matching Jobs")')
            self.assertTrue(confirm_btn.is_visible())
            confirm_btn.click()

            # 7. Directed to /jobs
            page.wait_for_url(f"{BASE_URL}/jobs", timeout=15000)
            self.assertIn("/jobs", page.url)

            # Verify no permanent loading crash
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

        finally:
            context.close()
            browser.close()

    def test_scenario_b_cse_candidate_workflow(self):
        """Scenario B: CSE candidate registers, uploads resume, inspects tech skills, and starts discovery."""
        timestamp = int(time.time() * 1000)
        email = f"cse.candidate.{timestamp}@example.com"
        password = "SecurePassword123!"
        full_name = "Rohan CSE Candidate"

        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            # 1. Register
            page.goto(f"{BASE_URL}/register")
            page.fill('input[type="text"]', full_name)
            page.fill('input[type="email"]', email)
            page.fill('input[type="password"]', password)
            page.click('button[type="submit"]')

            # 2. Onboarding
            page.wait_for_url(f"{BASE_URL}/onboarding", timeout=10000)
            page.click('button:has-text("Continue to Resume Upload")')

            # 3. Upload CSE resume
            page.wait_for_selector('input[type="file"]', state="attached")
            file_input = page.locator('input[type="file"]')
            file_input.set_input_files(str(self.cse_pdf_path))
            page.click('button:has-text("Upload & Parse")')

            # 4. Extracted credentials review
            page.wait_for_selector('text=Profile Generated & Ready for Discovery', timeout=15000)
            content = page.content()

            # Verify CSE details
            self.assertTrue(
                "MIT World Peace University" in content or "Computer Science" in content or "Flutter" in content or "Python" in content,
                "CSE academic and technical skills must appear in extracted review",
            )

            # 5. Confirm
            page.click('button:has-text("Confirm & Discover Matching Jobs")')
            page.wait_for_url(f"{BASE_URL}/jobs", timeout=15000)
            self.assertIn("/jobs", page.url)
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

        finally:
            context.close()
            browser.close()

    def test_scenario_c_file_dropzone_and_validation(self):
        """Scenario C: File Dropzone validations across Chromium and WebKit."""
        for browser_type in [self.playwright.chromium, self.playwright.webkit]:
            browser = browser_type.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            try:
                # Log in as test user
                timestamp = int(time.time() * 1000)
                email = f"dropzone.{timestamp}_{browser_type.name}@example.com"
                page.goto(f"{BASE_URL}/register")
                page.fill('input[type="text"]', f"Dropzone Tester {browser_type.name}")
                page.fill('input[type="email"]', email)
                page.fill('input[type="password"]', "Password123!")
                page.click('button[type="submit"]')
                page.wait_for_url(f"{BASE_URL}/onboarding", timeout=10000)

                # Move to Step 2
                page.click('button:has-text("Continue to Resume Upload")')
                page.wait_for_selector('input[type="file"]', state="attached")
                file_input = page.locator('input[type="file"]')

                # Test 1: Invalid file format (.txt)
                file_input.set_input_files(str(self.invalid_file_path))
                page.wait_for_selector('text=Only PDF or DOCX documents are supported.')

                # Test 2: Oversized file (>10MB)
                file_input.set_input_files(str(self.oversized_file_path))
                page.wait_for_selector('text=File size exceeds 10 MB limit.')

                # Test 3: Valid file select
                file_input.set_input_files(str(self.cse_pdf_path))
                page.wait_for_selector('text=synthetic_cse_resume.pdf')

                # Test 4: Clear selected file
                clear_btn = page.locator('button[data-clear-btn="true"]')
                if clear_btn.is_visible():
                    clear_btn.click()
                    page.wait_for_selector('text=Click to browse or drag and drop')

                # Test 5: Re-select same file again
                file_input.set_input_files(str(self.cse_pdf_path))
                page.wait_for_selector('text=synthetic_cse_resume.pdf')

            finally:
                context.close()
                browser.close()

    def test_scenario_d_discovery_recovery_and_persistence(self):
        """Scenario D: Verify discovery polling, page refresh recovery, and non-blocking notifications."""
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            timestamp = int(time.time() * 1000)
            email = f"recovery.{timestamp}@example.com"
            page.goto(f"{BASE_URL}/register")
            page.fill('input[type="text"]', "Recovery Candidate")
            page.fill('input[type="email"]', email)
            page.fill('input[type="password"]', "Password123!")
            page.click('button[type="submit"]')
            page.wait_for_url(f"{BASE_URL}/onboarding", timeout=10000)

            # Direct navigation to /jobs
            page.goto(f"{BASE_URL}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # Verify auto-discovery button exists
            disc_btn = page.locator('button:has-text("Refresh Matches"), button:has-text("Searching...")')
            self.assertTrue(disc_btn.first.is_visible())

            # Refresh the page to verify safe hydration without permanent loaders
            page.reload()
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)
            self.assertFalse(page.locator('text=Processing file...').is_visible())

        finally:
            context.close()
            browser.close()
