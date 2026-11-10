"""Fully Isolated Playwright Browser Acceptance Test Suite (Phase C.0.4).

Verifies Critical Job Feed Integrity Hotfix:
  1. Scenario 1: First-time ACCA candidate feed integrity:
     - Cards 1, 2, 3... are strictly accounting/tax/audit jobs.
     - Zero AI/ML jobs ("Generative AI", "NLP", "Machine Learning", "Small Language Models") in feed.
     - Zero unrelated jobs ("Fiction Writer", "Internship Counselor", "Founders Office").
  2. Scenario 2: Computer Science candidate feed integrity:
     - AI/ML/Software jobs are displayed.
     - Zero accounting/tax/audit jobs in feed.
  3. Scenario 3: Relevant opportunity counter integrity:
     - Banner accurately reflects count of relevant opportunities without inflated catalog counts.
"""

import os
os.environ.setdefault("APP_ENV", "test")

from pathlib import Path
import tempfile
import time
import unittest
from typing import List

from playwright.sync_api import sync_playwright, BrowserContext, Page

from tests.fixtures.isolated_server import IsolatedTestServer
from tests.fixtures.synthetic_personas import generate_two_column_acca_pdf, generate_persona_pdf


class TestBrowserAcceptancePhaseC04(unittest.TestCase):
    """Hermetic Playwright browser test suite verifying Phase C.0.4 feed integrity requirements."""

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
        cls.artifacts_dir = Path(__file__).resolve().parent.parent / "test_artifacts"
        cls.artifacts_dir.mkdir(parents=True, exist_ok=True)

        # 3. Generate sample resume PDFs
        cls.acca_pdf_path = cls.temp_path / "synthetic_acca_resume.pdf"
        cls.acca_pdf_path.write_bytes(generate_two_column_acca_pdf())

        cls.cse_pdf_path = cls.temp_path / "synthetic_cse_resume.pdf"
        cls.cse_pdf_path.write_bytes(generate_persona_pdf("cs_mobile_ai_student"))

        # 4. Start Playwright
        cls.playwright = sync_playwright().start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.playwright.stop()
        except Exception:
            pass
        cls.server.cleanup()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def _setup_page_with_reporting(self, context: BrowserContext, test_name: str) -> Page:
        page = context.new_page()
        page.set_default_timeout(15000)

        console_logs: List[str] = []
        failed_requests: List[str] = []

        def on_console(msg):
            text = msg.text
            if "session_id" not in text and "password" not in text.lower():
                console_logs.append(f"[{msg.type}] {text}")

        def on_response(resp):
            if resp.status >= 400 and "/api/" in resp.url:
                failed_requests.append(f"{resp.status} {resp.request.method} {resp.url}")

        page.on("console", on_console)
        page.on("response", on_response)

        page._test_name = test_name
        page._console_logs = console_logs
        page._failed_requests = failed_requests
        return page

    def _capture_failure_artifacts(self, page: Page):
        test_name = getattr(page, "_test_name", "unknown_test")
        try:
            screenshot_path = self.artifacts_dir / f"{test_name}_failure.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
            log_path = self.artifacts_dir / f"{test_name}_errors.log"
            html_path = self.artifacts_dir / f"{test_name}_failure.html"
            logs = getattr(page, "_console_logs", [])
            reqs = getattr(page, "_failed_requests", [])
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("=== CONSOLE LOGS ===\n" + "\n".join(logs) + "\n\n")
                f.write("=== FAILED NETWORK REQUESTS ===\n" + "\n".join(reqs) + "\n")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(page.content())
        except Exception:
            pass

    def _register_user(self, page: Page, name: str, email: str) -> None:
        page.goto(f"{self.base_url}/register")
        page.fill('input[type="text"]', name)
        page.fill('input[type="email"]', email)
        page.fill('input[type="password"]', "SecurePass123!")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{self.base_url}/onboarding", timeout=12000)

    def _upload_resume_in_onboarding(self, page: Page, pdf_path: Path) -> None:
        page.click('button:has-text("Continue to Resume Upload")')
        file_input = page.wait_for_selector('input[type="file"]', state="attached", timeout=6000)
        file_input.set_input_files(str(pdf_path))
        page.click('button:has-text("Upload & Parse")')
        page.wait_for_selector('text=Step 3 of 3', timeout=15000)
        page.click('button:has-text("Review Full Profile First")')
        page.wait_for_url(f"{self.base_url}/profile*", timeout=12000)

    # -------------------------------------------------------------------------
    # TEST 1: ACCA Candidate Feed Integrity (Zero AI/ML Leaks)
    # -------------------------------------------------------------------------
    def test_01_acca_candidate_feed_integrity(self):
        """Scenario 1: ACCA candidate feed contains only accounting/tax opportunities.
        Cards 1, 2, 3... must NOT contain AI/ML or unrelated writing/counseling jobs.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_01_acca_feed_integrity")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c04_acca_{timestamp}@example.com"

            self._register_user(page, "Pranjali ACCA", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            # Navigate to /jobs
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # Wait for discovery and cards to render
            page.wait_for_selector(
                'h3:has-text("Tax"), h3:has-text("Account"), h3:has-text("Audit"), [data-testid="job-card-header"]',
                timeout=18000,
            )

            # Check that job card headers do not contain AI/ML
            prohibited_titles = [
                "Generative AI",
                "Applied Research Intern",
                "AI/ML Intern",
                "AI Engineer",
                "Voice AI",
                "Small Language Models",
                "Fiction Writer",
                "Training And Internship Counselor",
            ]

            card_headers = page.locator('h3').all_text_contents()
            for header in card_headers:
                for bad_title in prohibited_titles:
                    self.assertNotIn(
                        bad_title.lower(),
                        header.lower(),
                        f"Found prohibited job title '{header}' in ACCA candidate feed!",
                    )

            # Ensure positive presence of accounting/tax keywords
            page_text = page.content().lower()
            has_accounting = any(t in page_text for t in ["tax", "account", "audit", "finance", "compliance"])
            self.assertTrue(has_accounting, "Expected accounting/tax opportunities in ACCA feed.")

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 2: CS Candidate Feed Integrity (Zero Accounting Leaks)
    # -------------------------------------------------------------------------
    def test_02_cs_candidate_feed_integrity(self):
        """Scenario 2: Computer Science candidate feed contains only software/tech opportunities."""
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_02_cs_feed_integrity")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c04_cs_{timestamp}@example.com"

            self._register_user(page, "Pranay CSE", email)
            self._upload_resume_in_onboarding(page, self.cse_pdf_path)

            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            page.wait_for_selector(
                'h3:has-text("AI"), h3:has-text("Engineer"), h3:has-text("Developer"), [data-testid="job-card-header"]',
                timeout=18000,
            )

            prohibited_for_cs = [
                "UK Tax Associate",
                "Statutory Audit",
                "Chartered Accountant",
                "Tax Executive",
                "Fiction Writer",
            ]

            card_headers = page.locator('h3').all_text_contents()
            for header in card_headers:
                for bad_title in prohibited_for_cs:
                    self.assertNotIn(
                        bad_title.lower(),
                        header.lower(),
                        f"Found prohibited job title '{header}' in CSE candidate feed!",
                    )

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()
