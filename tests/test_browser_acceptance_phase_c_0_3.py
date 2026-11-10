"""Fully Isolated Playwright Browser Acceptance Test Suite (Phase C.0.3).

Verifies Resume-Scoped Job Discovery, First-Visit Skeleton UX & Cross-Industry Job Relevance:
  1. Scenario 1: First-time ACCA candidate journey (Skeletons -> Automatic Discovery -> Pure Accounting Jobs, No AI/ML).
  2. Scenario 2: Resume replacement stale role invalidation (CSE replaced with ACCA on same account).
  3. Scenario 3: Cross-user multi-tenant candidate discovery isolation.
  4. Scenario 4: Cached candidate results without redundant re-discovery on subsequent visits.
  5. Scenario 5: Discovery failure handling (skeletons replaced with error banner and retry button).
  6. Scenario 6: Partial discovery notice banner for restricted/rate-limited external sources.
  7. Scenario 7: Manual search independence from inferred resume career domain.
  8. Scenario 8: No-resume onboarding state (prompts resume upload, never auto-triggers discovery).
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
from src.database.db_manager import DatabaseManager


class TestBrowserAcceptancePhaseC03(unittest.TestCase):
    """Hermetic Playwright browser test suite verifying Phase C.0.3 requirements."""

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
        """Configures a page with network and console listeners for automated failure reporting."""
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
        """Captures screenshot and error logs upon test assertion failure."""
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
        """Helper to register a fresh candidate user."""
        page.goto(f"{self.base_url}/register")
        page.fill('input[type="text"]', name)
        page.fill('input[type="email"]', email)
        page.fill('input[type="password"]', "SecurePass123!")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{self.base_url}/onboarding", timeout=12000)

    def _upload_resume_in_onboarding(self, page: Page, pdf_path: Path) -> None:
        """Helper to complete onboarding resume upload."""
        page.click('button:has-text("Continue to Resume Upload")')
        file_input = page.wait_for_selector('input[type="file"]', state="attached", timeout=6000)
        file_input.set_input_files(str(pdf_path))
        page.click('button:has-text("Upload & Parse")')
        page.wait_for_selector('text=Step 3 of 3', timeout=15000)
        page.click('button:has-text("Review Full Profile First")')
        page.wait_for_url(f"{self.base_url}/profile*", timeout=12000)

    # -------------------------------------------------------------------------
    # TEST 1: First-Time ACCA Candidate Journey & Skeleton UX
    # -------------------------------------------------------------------------
    def test_01_first_time_acca_candidate_journey(self):
        """Scenario 1: ACCA candidate on first visit sees skeletons, automatic discovery triggers,
        and results only contain accounting/tax jobs (strictly rejecting AI/ML).
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_01_first_time_acca")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_acca_{timestamp}@example.com"

            self._register_user(page, "Pranjali ACCA", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            # Navigate to /jobs
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # Verify skeletons or discovery banner appear during initial discovery
            initial_state_found = (
                page.locator('[data-testid="job-card-skeleton"]').count() > 0
                or page.locator('text=Discovery Scraper Running').is_visible()
                or page.locator('text=Scanning LinkedIn').is_visible()
            )
            self.assertTrue(initial_state_found, "Expected skeleton grid or discovery banner on first visit.")

            # Wait for discovery to complete and jobs to render
            page.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit"), [data-testid="job-card-header"]',
                timeout=18000,
            )

            # Skeletons should be gone
            self.assertEqual(page.locator('[data-testid="job-card-skeleton"]').count(), 0)

            # Verify feed contains accounting/tax opportunities
            page_content = page.content()
            self.assertTrue(
                "Tax Associate" in page_content
                or "UK Tax Associate" in page_content
                or "Audit" in page_content
                or "Accountant" in page_content,
                "Expected accounting/finance job in feed.",
            )

            # STRICT NEGATIVE CRITERIA: Feed must NOT contain AI/ML or Python software engineering jobs
            self.assertNotIn("Machine Learning Intern", page_content)
            self.assertNotIn("Artificial Intelligence Intern", page_content)
            self.assertNotIn("Computer Vision Intern", page_content)

            # Suggested career paths chips must show accounting roles
            self.assertTrue(
                "Tax Associate" in page_content
                or "Accounts" in page_content
                or "Stock Auditor" in page_content,
                "Expected suggested roles chips to reflect ACCA career context.",
            )

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 2: Resume Replacement Stale Role Invalidation
    # -------------------------------------------------------------------------
    def test_02_resume_replacement_stale_role_invalidation(self):
        """Scenario 2: When candidate replaces primary resume (CSE -> ACCA),
        old CSE recommendations disappear and roles refresh to accounting.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_02_resume_replacement")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_switch_{timestamp}@example.com"

            # 1. Start with CSE resume
            self._register_user(page, "Alex Switcher", email)
            self._upload_resume_in_onboarding(page, self.cse_pdf_path)

            # 2. Visit /jobs and complete initial CSE discovery
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            page.wait_for_selector(
                'h3:has-text("Junior Software Engineer"), h3:has-text("Junior Project Manager"), h3:has-text("Software Engineer")',
                timeout=18000,
            )
            cse_content = page.content()
            self.assertTrue("Software Engineer" in cse_content or "Project Manager" in cse_content)

            # 3. Replace resume on Profile page with ACCA resume
            page.goto(f"{self.base_url}/profile")
            page.wait_for_selector('h1:has-text("Candidate Profile")', timeout=10000)

            # Click Resume Library tab
            page.click('button:has-text("Resume Library")')
            page.wait_for_timeout(500)

            # Upload ACCA resume
            dropzone_input = page.wait_for_selector('input[type="file"]', state="attached", timeout=8000)
            dropzone_input.set_input_files(str(self.acca_pdf_path))

            # Wait for upload & sync confirmation
            page.wait_for_selector('text=synthetic_acca_resume.pdf', timeout=15000)

            # Set new resume as primary
            set_primary_btn = page.locator('button:has-text("Set Primary")')
            if set_primary_btn.count() > 0:
                set_primary_btn.first.click()
                page.wait_for_timeout(1000)

            # 4. Navigate back to /jobs
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # Wait for updated discovery or jobs refresh
            page.wait_for_timeout(2500)

            # Suggested career roles chips MUST update to accounting roles
            page_content = page.content()
            self.assertTrue(
                "Tax Associate" in page_content
                or "Accounts" in page_content
                or "Stock Auditor" in page_content
                or "Internal Auditor" in page_content,
                f"Expected ACCA suggested roles after resume replacement. Page content: {page_content[:500]}",
            )

            # Old CSE recommendations must NOT be present in active feed
            self.assertNotIn("Junior Software Engineer", page_content)
            self.assertNotIn("Junior Project Manager", page_content)

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 3: Cross-User Multi-Tenant Discovery Isolation
    # -------------------------------------------------------------------------
    def test_03_cross_user_isolation(self):
        """Scenario 3: Candidate Alpha (ACCA) and Candidate Beta (CSE) in separate sessions
        receive strictly isolated recommendations without cross-contamination.
        """
        browser = self.playwright.chromium.launch(headless=True)
        try:
            timestamp = int(time.time() * 1000)

            # Context A: Alpha (Finance)
            context_a = browser.new_context()
            page_a = self._setup_page_with_reporting(context_a, "test_03_alpha")
            self._register_user(page_a, "Alpha Finance", f"alpha_{timestamp}@example.com")
            self._upload_resume_in_onboarding(page_a, self.acca_pdf_path)

            # Context B: Beta (Tech)
            context_b = browser.new_context()
            page_b = self._setup_page_with_reporting(context_b, "test_03_beta")
            self._register_user(page_b, "Beta Tech", f"beta_{timestamp}@example.com")
            self._upload_resume_in_onboarding(page_b, self.cse_pdf_path)

            # Run discovery on /jobs for Alpha
            page_a.goto(f"{self.base_url}/jobs")
            page_a.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit")',
                timeout=25000,
            )
            content_a = page_a.content()

            # Run discovery on /jobs for Beta
            page_b.goto(f"{self.base_url}/jobs")
            page_b.wait_for_selector(
                'h3:has-text("Junior Software Engineer"), h3:has-text("Junior Project Manager"), h3:has-text("Software Engineer")',
                timeout=25000,
            )
            content_b = page_b.content()

            # Verify Alpha only sees finance, not tech
            self.assertTrue("Tax Associate" in content_a or "Audit" in content_a)
            self.assertNotIn("Junior Software Engineer", content_a)

            # Verify Beta only sees tech, not finance
            self.assertTrue("Software Engineer" in content_b or "Project Manager" in content_b)
            self.assertNotIn("UK Tax Associate", content_b)

            context_a.close()
            context_b.close()
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 4: Cached Candidate Results (No Redundant Discovery)
    # -------------------------------------------------------------------------
    def test_04_cached_candidate_results_no_redundant_discovery(self):
        """Scenario 4: Re-visiting /jobs with existing completed discovery run
        immediately displays cached jobs without triggering redundant discovery.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_04_cached_results")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_cached_{timestamp}@example.com"

            self._register_user(page, "Cached Candidate", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            # 1. First visit to /jobs: triggers discovery and completes
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit")',
                timeout=25000,
            )

            # Count discovery runs in SQLite
            db = DatabaseManager(db_path=self.server.db_path)
            with db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                user_id = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM discovery_runs WHERE user_id = ?", (user_id,))
                run_count_initial = cursor.fetchone()[0]

            self.assertGreaterEqual(run_count_initial, 1)

            # 2. Navigate away to dashboard
            page.goto(f"{self.base_url}/dashboard")
            page.wait_for_selector('h1:has-text("Good day")', timeout=10000)

            # 3. Return to /jobs
            page.goto(f"{self.base_url}/jobs")

            # Jobs must be rendered immediately
            page.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit")',
                timeout=5000,
            )

            # Verify no redundant discovery run was created
            with db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM discovery_runs WHERE user_id = ?", (user_id,))
                run_count_after = cursor.fetchone()[0]

            self.assertEqual(run_count_initial, run_count_after, "Discovery was re-triggered redundantly!")

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 5: Discovery Failure Handling & Clean Retry
    # -------------------------------------------------------------------------
    def test_05_discovery_failure_handling(self):
        """Scenario 5: When discovery fails, skeletons disappear and an error banner
        with a retry button is displayed.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_05_discovery_failure")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_failure_{timestamp}@example.com"

            self._register_user(page, "Failure Candidate", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            # Intercept discovery trigger to simulate backend failure
            page.route(
                "**/api/jobs/discovery",
                lambda route: route.fulfill(
                    status=500,
                    content_type="application/json",
                    json={"detail": "Job board rate limit or gateway connection failure."},
                ) if route.request.method == "POST" else route.continue_(),
            )

            # Navigate to /jobs
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # Skeletons should disappear and discovery failed banner should be visible
            page.wait_for_selector('[data-testid="discovery-failed-state"]', timeout=10000)
            self.assertTrue(page.locator('[data-testid="discovery-failed-state"]').is_visible())
            self.assertTrue(page.locator('[data-testid="retry-discovery-btn"]').is_visible())
            self.assertEqual(page.locator('[data-testid="job-card-skeleton"]').count(), 0)

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 6: Partial Discovery Banner
    # -------------------------------------------------------------------------
    def test_06_partial_discovery_banner(self):
        """Scenario 6: When external sources are restricted, partial discovery banner is rendered."""
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_06_partial_discovery")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_partial_{timestamp}@example.com"

            self._register_user(page, "Partial Candidate", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            # Complete initial discovery
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit")',
                timeout=25000,
            )

            # Update discovery run in DB to simulate restricted sources
            db = DatabaseManager(db_path=self.server.db_path)
            with db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                user_id = cursor.fetchone()[0]
                cursor.execute(
                    "UPDATE discovery_runs SET status = 'PARTIAL', restricted_count = 2 WHERE user_id = ?",
                    (user_id,),
                )

            # Refresh /jobs
            page.reload()
            page.wait_for_selector('[data-testid="partial-discovery-banner"]', timeout=10000)
            self.assertTrue(page.locator('[data-testid="partial-discovery-banner"]').is_visible())

            banner_text = page.locator('[data-testid="partial-discovery-banner"]').text_content()
            self.assertIn("Partial Discovery Notice", banner_text)

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 7: Manual Search Independence from Inferred Domain
    # -------------------------------------------------------------------------
    def test_07_manual_search_independent_of_inferred_domain(self):
        """Scenario 7: Candidate manual keyword searches query global catalog without
        overwriting resume-inferred target roles or preferences.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_07_manual_search")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_search_{timestamp}@example.com"

            self._register_user(page, "Search Candidate", email)
            self._upload_resume_in_onboarding(page, self.acca_pdf_path)

            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector(
                'h3:has-text("Tax Associate"), h3:has-text("UK Tax Associate"), h3:has-text("Audit")',
                timeout=25000,
            )

            # Insert a catalog job with Python to search for
            db = DatabaseManager(db_path=self.server.db_path)
            with db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO jobs (id, job_title, company_name, job_url, location, platform, job_description)
                    VALUES (9001, 'Senior Python Engineer', 'Global Pythonics', 'https://example.com/py/9001', 'Remote', 'LinkedIn', 'Python development and Django microservices')
                    """
                )

            # Search for 'Python' in search bar
            search_input = page.wait_for_selector('input[placeholder*="Search by role title"]', timeout=5000)
            search_input.fill("Python")
            page.click('button[type="submit"]:has-text("Search")')

            # Wait for search results
            page.wait_for_selector('h3:has-text("Senior Python Engineer")', timeout=10000)
            self.assertTrue(page.locator('h3:has-text("Senior Python Engineer")').is_visible())

            # Verify 'Search' badge is visible on the manual search result
            self.assertTrue(page.locator('span:has-text("Search")').first.is_visible())

            # Suggested career paths chips MUST still show ACCA roles, not Python
            page_content = page.content()
            self.assertTrue(
                "Tax Associate" in page_content
                or "Stock Auditor" in page_content
                or "Accounts" in page_content,
                "Inferred career paths chips should remain grounded in resume, not corrupted by search query.",
            )

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()

    # -------------------------------------------------------------------------
    # TEST 8: No-Resume Onboarding State
    # -------------------------------------------------------------------------
    def test_08_no_resume_onboarding_state(self):
        """Scenario 8: Fresh candidate navigating to /jobs without an uploaded resume
        sees no-resume onboarding state and discovery is never triggered.
        """
        browser = self.playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = self._setup_page_with_reporting(context, "test_08_no_resume")

        try:
            timestamp = int(time.time() * 1000)
            email = f"c03_noresume_{timestamp}@example.com"

            # Register but do NOT upload resume
            self._register_user(page, "No Resume Candidate", email)

            # Directly navigate to /jobs
            page.goto(f"{self.base_url}/jobs")
            page.wait_for_selector('h1:has-text("Find Opportunities")', timeout=10000)

            # No-resume prompt state must be visible once candidate context resolves
            page.wait_for_selector('[data-testid="no-resume-state"]', timeout=8000)
            self.assertTrue(page.locator('[data-testid="no-resume-state"]').is_visible())

            # Skeletons must now be gone
            self.assertEqual(page.locator('[data-testid="job-card-skeleton"]').count(), 0)

            # Click "Go to My Profile" button
            go_to_profile_btn = page.locator('[data-testid="go-to-profile-btn"]')
            self.assertTrue(go_to_profile_btn.is_visible())
            go_to_profile_btn.click()

            # Verify navigation to /profile
            page.wait_for_url(f"{self.base_url}/profile*", timeout=10000)
            page.wait_for_selector('h1:has-text("Candidate Profile")', state="visible", timeout=10000)
            self.assertTrue(page.locator('h1:has-text("Candidate Profile")').is_visible())

            # Verify discovery run was NEVER created in database
            db = DatabaseManager(db_path=self.server.db_path)
            with db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                user_id = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM discovery_runs WHERE user_id = ?", (user_id,))
                run_count = cursor.fetchone()[0]

            self.assertEqual(run_count, 0, "Discovery run must not be created without a primary resume!")

        except Exception:
            self._capture_failure_artifacts(page)
            raise
        finally:
            context.close()
            browser.close()
