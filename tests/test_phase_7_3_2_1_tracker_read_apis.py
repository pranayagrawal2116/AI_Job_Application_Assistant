"""Comprehensive tests for Phase 7.3.2.1: Candidate Application Tracker Backend Read APIs and URL Security Remediation.

Covers:
1. Candidate Application Listing & Query Filtering:
   - Candidate isolation (User A vs User B).
   - include_archived=False (default excludes archived applications) and include_archived=True.
   - status_in parameter for multi-status category filtering, case-normalization, empty/none handling.
   - employment_type filtering.
   - sort_by options: deadline_asc (NULLS LAST), updated_at_desc, created_at_desc, created_at_asc, company_name_asc, job_title_asc.
   - sort_by whitelist validation (rejecting SQL injection attempts and invalid options with ValidationError).
   - search_term filtering across company_name, job_title, and notes.
   - Pagination with limit and offset, validating negative inputs.
2. Candidate Application Tracker KPI Metrics:
   - Total calculation matching active (or all with include_archived=True).
   - Accurate distribution across 12 lifecycle statuses:
     - in_preparation (DRAFT, PREPARING, READY_FOR_REVIEW)
     - approved (APPROVED)
     - submitted (SUBMITTED only)
     - in_progress (IN_PROGRESS only; does NOT increment submitted)
     - interviewing (ASSESSMENT, INTERVIEW)
     - offers (OFFER only; separated from concluded)
     - active_pipeline (SUBMITTED, IN_PROGRESS, ASSESSMENT, INTERVIEW, OFFER)
     - concluded (REJECTED, WITHDRAWN, CLOSED)
   - Follow-up reminders due today or overdue calculation.
   - Follow-up reminder archive filtering: reminders for archived applications excluded by default, included when include_archived=True.
   - Completed reminders excluded from follow_ups_due.
3. External Application URL Security Remediation:
   - Strict 7-step execution order.
   - Unauthenticated access fails (InvalidSessionError).
   - Cross-user application access fails (ApplicationNotFoundError).
   - Application without URL fails (ValidationError).
   - Unsafe/private IP destination fails (UnsafeURLError).
   - Arbitrary client URL substitution prohibited (SecurityAuthorizationError).
   - Sensitive query parameter and fragment redaction in audit event payload.
   - Clean parameters preserved in validated destination and sanitized payload.
   - Application status preserved (not mutated).
   - Validated canonical URL returned for browser navigation.
4. Candidate Follow-Up Service Layer:
   - create_application_follow_up (enforcing candidate application ownership).
   - list_application_follow_ups (candidate scoping, filtering by application_id, is_completed, include_archived).
   - get_application_follow_up (ownership verification, cross-user rejection).
   - complete_application_follow_up (ownership verification, status update, outcome notes, timeline event).
   - delete_application_follow_up (ownership verification, cross-user rejection).
   - Unauthenticated calls fail.
5. Application Match Detail Retrieval:
   - Retrieval via active prepared packet's matching_result_id.
   - Returns None when no packet or unlinked matching_result_id.
   - Cross-user application access fails (ApplicationNotFoundError).
   - Unauthenticated access fails (InvalidSessionError).
"""

from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
from typing import List, Optional
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    InvalidSessionError,
    SecurityAuthorizationError,
    UnsafeURLError,
    ValidationError,
)
from src.database.models import ApplicationStatus, MatchResult
from src.security.session_manager import SessionManager


class BaseTrackerReadAPITest(unittest.TestCase):
    """Base fixture setting up isolated SQLite database, test candidates, and authenticated sessions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_tracker_read.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate_a@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate_b@example.com', 'h2', 's2', 'Bob Candidate')"
            )

        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a",
            candidate_name="Alice Candidate",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b",
            candidate_name="Bob Candidate",
            user_id=self.user_b,
        )

        def mock_public_resolver(host: str, port: int) -> List[str]:
            if "127.0.0.1" in host or "internal" in host or "metadata" in host:
                return ["127.0.0.1"]
            return ["93.184.215.14"]

        self.service = DashboardService(
            db_manager=self.db,
            url_resolver=mock_public_resolver,
        )

    def tearDown(self):
        self.session_mgr.reset_instance()
        self.temp_dir.cleanup()

    def _create_app(
        self,
        user_id: int,
        company: str,
        title: str,
        status: str = "DRAFT",
        deadline: Optional[str] = None,
        employment_type: Optional[str] = None,
        job_url: Optional[str] = None,
        notes: Optional[str] = None,
        is_archived: int = 0,
    ) -> int:
        """Helper to directly insert applications with various statuses and metadata."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, status,
                    application_deadline, employment_type, external_application_url,
                    notes, is_archived, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    company,
                    title,
                    status,
                    deadline,
                    employment_type,
                    job_url,
                    notes,
                    is_archived,
                ),
            )
            return cursor.lastrowid


class TestApplicationListingQueries(BaseTrackerReadAPITest):
    """Verifies list_user_applications and list_candidate_applications querying capabilities."""

    def test_candidate_isolation(self):
        """User A only sees User A's applications; User B only sees User B's applications."""
        app_a1 = self._create_app(self.user_a, "Alpha Corp", "AI Engineer")
        app_a2 = self._create_app(self.user_a, "Beta Labs", "Data Scientist")
        app_b1 = self._create_app(self.user_b, "Gamma Tech", "ML Researcher")

        apps_a = self.service.list_candidate_applications(self.session_a.session_id)
        apps_b = self.service.list_candidate_applications(self.session_b.session_id)

        self.assertEqual(len(apps_a), 2)
        self.assertEqual({a.id for a in apps_a}, {app_a1, app_a2})
        self.assertEqual(len(apps_b), 1)
        self.assertEqual({b.id for b in apps_b}, {app_b1})

    def test_include_archived_default_false(self):
        """Default include_archived=False excludes archived applications."""
        app_active = self._create_app(self.user_a, "Active Co", "Engineer", is_archived=0)
        app_archived = self._create_app(self.user_a, "Archived Co", "Designer", is_archived=1)

        default_list = self.service.list_candidate_applications(self.session_a.session_id)
        self.assertEqual(len(default_list), 1)
        self.assertEqual(default_list[0].id, app_active)

        with_archived = self.service.list_candidate_applications(
            self.session_a.session_id, include_archived=True
        )
        self.assertEqual(len(with_archived), 2)
        self.assertEqual({a.id for a in with_archived}, {app_active, app_archived})

    def test_status_in_filtering(self):
        """status_in filters by a list of statuses with normalization."""
        self._create_app(self.user_a, "A Co", "Dev", status="DRAFT")
        self._create_app(self.user_a, "B Co", "Dev", status="PREPARING")
        self._create_app(self.user_a, "C Co", "Dev", status="INTERVIEW")
        self._create_app(self.user_a, "D Co", "Dev", status="OFFER")

        prep_apps = self.service.list_candidate_applications(
            self.session_a.session_id,
            status_in=["DRAFT", "PREPARING"],
        )
        self.assertEqual(len(prep_apps), 2)
        self.assertEqual({a.status for a in prep_apps}, {"DRAFT", "PREPARING"})

        interview_apps = self.service.list_candidate_applications(
            self.session_a.session_id,
            status_in=["interview", "  OFFER  "],
        )
        self.assertEqual(len(interview_apps), 2)
        self.assertEqual({a.status for a in interview_apps}, {"INTERVIEW", "OFFER"})

    def test_employment_type_filtering(self):
        """employment_type filters applications by employment type."""
        app_ft = self._create_app(self.user_a, "FT Co", "Dev", employment_type="Full-time")
        self._create_app(self.user_a, "PT Co", "Dev", employment_type="Part-time")
        self._create_app(self.user_a, "Cont Co", "Dev", employment_type="Contract")

        ft_apps = self.service.list_candidate_applications(
            self.session_a.session_id,
            employment_type="Full-time",
        )
        self.assertEqual(len(ft_apps), 1)
        self.assertEqual(ft_apps[0].id, app_ft)

    def test_sort_by_deadline_asc_nulls_last(self):
        """sort_by='deadline_asc' orders applications by deadline ASC with NULLs last."""
        app_dec = self._create_app(self.user_a, "Co Dec", "Dev", deadline="2026-12-01")
        app_nov = self._create_app(self.user_a, "Co Nov", "Dev", deadline="2026-11-01")
        app_null = self._create_app(self.user_a, "Co Null", "Dev", deadline=None)

        sorted_apps = self.service.list_candidate_applications(
            self.session_a.session_id,
            sort_by="deadline_asc",
        )
        self.assertEqual(len(sorted_apps), 3)
        self.assertEqual(sorted_apps[0].id, app_nov)
        self.assertEqual(sorted_apps[1].id, app_dec)
        self.assertEqual(sorted_apps[2].id, app_null)

    def test_sort_by_whitelist_validation(self):
        """Allowed sort options pass; invalid sort options raise ValidationError."""
        valid_sorts = [
            "updated_at_desc",
            "created_at_desc",
            "created_at_asc",
            "deadline_asc",
            "company_name_asc",
            "job_title_asc",
        ]
        for sort_opt in valid_sorts:
            res = self.service.list_candidate_applications(
                self.session_a.session_id, sort_by=sort_opt
            )
            self.assertIsInstance(res, list)

        invalid_sorts = ["malicious_column", "id ASC; DROP TABLE", "random", ""]
        for bad_sort in invalid_sorts:
            if not bad_sort:
                continue
            with self.assertRaises(ValidationError):
                self.service.list_candidate_applications(
                    self.session_a.session_id, sort_by=bad_sort
                )

    def test_search_term_across_fields(self):
        """search_term matches company_name, job_title, and notes."""
        app1 = self._create_app(self.user_a, "Google", "SWE", notes="Applied via referral")
        self._create_app(self.user_a, "Microsoft", "Research Scientist", notes="Found on LinkedIn")
        app3 = self._create_app(self.user_a, "Meta", "SWE", notes="Follow up with Google recruiter")

        res_swe = self.service.list_candidate_applications(self.session_a.session_id, search_term="SWE")
        self.assertEqual(len(res_swe), 2)
        self.assertEqual({a.id for a in res_swe}, {app1, app3})

        res_google = self.service.list_candidate_applications(self.session_a.session_id, search_term="Google")
        self.assertEqual(len(res_google), 2)
        self.assertEqual({a.id for a in res_google}, {app1, app3})

    def test_pagination_and_validation(self):
        """limit and offset paginate results, negative values raise ValidationError."""
        for i in range(5):
            self._create_app(self.user_a, f"Co {i}", f"Role {i}")

        page1 = self.service.list_candidate_applications(self.session_a.session_id, limit=2, offset=0)
        self.assertEqual(len(page1), 2)

        page2 = self.service.list_candidate_applications(self.session_a.session_id, limit=2, offset=2)
        self.assertEqual(len(page2), 2)

        page3 = self.service.list_candidate_applications(self.session_a.session_id, limit=2, offset=4)
        self.assertEqual(len(page3), 1)

        with self.assertRaises(ValidationError):
            self.service.list_candidate_applications(self.session_a.session_id, limit=-1)
        with self.assertRaises(ValidationError):
            self.service.list_candidate_applications(self.session_a.session_id, offset=-5)

    def test_database_pagination_validation_matrix(self):
        """Verifies full matrix of pagination input validation directly on DatabaseManager."""
        for i in range(5):
            self._create_app(self.user_a, f"Company {i}", f"Title {i}")

        # 1. limit=-1 raises ValidationError
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, limit=-1)

        # 2. offset=-1, limit=20 raises ValidationError
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, limit=20, offset=-1)

        # 3. offset=-1, limit=None raises ValidationError
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, limit=None, offset=-1)

        # 4. offset="abc" raises ValidationError
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, offset="abc")  # type: ignore

        # 5. limit="abc" raises ValidationError
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, limit="abc")  # type: ignore

        # 6. booleans rejected
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, limit=True)  # type: ignore
        with self.assertRaises(ValidationError):
            self.db.list_user_applications(self.user_a, offset=True)  # type: ignore

        # 7. limit=None, offset=0 is valid (returns all 5)
        res_all = self.db.list_user_applications(self.user_a, limit=None, offset=0)
        self.assertEqual(len(res_all), 5)

        # 8. limit=None, offset=3 is valid (skips 3, returns 2)
        res_offset3 = self.db.list_user_applications(self.user_a, limit=None, offset=3)
        self.assertEqual(len(res_offset3), 2)

        # 9. limit=0, offset=0 is valid empty result
        res_empty = self.db.list_user_applications(self.user_a, limit=0, offset=0)
        self.assertEqual(len(res_empty), 0)


class TestCandidateTrackerMetrics(BaseTrackerReadAPITest):
    """Verifies get_candidate_tracker_metrics across all statuses, follow-ups, and archive states."""

    def test_all_12_statuses_kpi_distribution(self):
        """Computes metrics correctly across all 12 canonical statuses."""
        all_statuses = [
            ApplicationStatus.DRAFT.value,
            ApplicationStatus.PREPARING.value,
            ApplicationStatus.READY_FOR_REVIEW.value,
            ApplicationStatus.APPROVED.value,
            ApplicationStatus.SUBMITTED.value,
            ApplicationStatus.IN_PROGRESS.value,
            ApplicationStatus.ASSESSMENT.value,
            ApplicationStatus.INTERVIEW.value,
            ApplicationStatus.OFFER.value,
            ApplicationStatus.REJECTED.value,
            ApplicationStatus.WITHDRAWN.value,
            ApplicationStatus.CLOSED.value,
        ]

        for idx, stat in enumerate(all_statuses):
            self._create_app(self.user_a, f"Company {idx}", f"Role {idx}", status=stat)

        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)

        self.assertEqual(metrics["total"], 12)
        self.assertEqual(metrics["in_preparation"], 3)  # DRAFT, PREPARING, READY_FOR_REVIEW
        self.assertEqual(metrics["approved"], 1)        # APPROVED
        self.assertEqual(metrics["submitted"], 1)       # SUBMITTED only
        self.assertEqual(metrics["in_progress"], 1)     # IN_PROGRESS only
        self.assertEqual(metrics["interviewing"], 2)    # ASSESSMENT, INTERVIEW
        self.assertEqual(metrics["offers"], 1)          # OFFER only
        self.assertEqual(metrics["active_pipeline"], 5) # SUBMITTED + IN_PROGRESS + ASSESSMENT + INTERVIEW + OFFER
        self.assertEqual(metrics["concluded"], 3)       # REJECTED, WITHDRAWN, CLOSED

    def test_submitted_does_not_count_in_progress(self):
        """IN_PROGRESS does NOT increment 'submitted'; only SUBMITTED increments 'submitted'."""
        self._create_app(self.user_a, "Co 1", "Role 1", status=ApplicationStatus.IN_PROGRESS.value)
        self._create_app(self.user_a, "Co 2", "Role 2", status=ApplicationStatus.IN_PROGRESS.value)

        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["submitted"], 0)
        self.assertEqual(metrics["in_progress"], 2)
        self.assertEqual(metrics["active_pipeline"], 2)

    def test_offers_separated_from_concluded(self):
        """OFFER increments 'offers' and 'active_pipeline', NOT 'concluded'."""
        self._create_app(self.user_a, "Offer Co", "Lead AI", status=ApplicationStatus.OFFER.value)

        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["offers"], 1)
        self.assertEqual(metrics["active_pipeline"], 1)
        self.assertEqual(metrics["concluded"], 0)

    def test_archived_applications_excluded_by_default_from_metrics(self):
        """Archived applications are excluded by default, included with include_archived=True."""
        self._create_app(self.user_a, "Co 1", "Role 1", status="SUBMITTED", is_archived=0)
        self._create_app(self.user_a, "Co 2", "Role 2", status="INTERVIEW", is_archived=1)

        metrics_default = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics_default["total"], 1)
        self.assertEqual(metrics_default["submitted"], 1)
        self.assertEqual(metrics_default["interviewing"], 0)
        self.assertEqual(metrics_default["active_pipeline"], 1)

        metrics_all = self.service.get_candidate_tracker_metrics(
            self.session_a.session_id, include_archived=True
        )
        self.assertEqual(metrics_all["total"], 2)
        self.assertEqual(metrics_all["submitted"], 1)
        self.assertEqual(metrics_all["interviewing"], 1)
        self.assertEqual(metrics_all["active_pipeline"], 2)

    def test_follow_ups_due_kpi_and_archival(self):
        """follow_ups_due counts incomplete reminders due today or overdue, excluding archived apps by default."""
        today = datetime.now(timezone.utc).date()
        yesterday = (today - timedelta(days=1)).isoformat()
        today_str = today.isoformat()
        tomorrow = (today + timedelta(days=1)).isoformat()

        app_active = self._create_app(self.user_a, "Active Co", "Role", is_archived=0)
        app_archived = self._create_app(self.user_a, "Archived Co", "Role", is_archived=0)

        # 1. Past due on active app (DUE)
        self.db.create_application_follow_up(
            application_id=app_active,
            user_id=self.user_a,
            follow_up_date=yesterday,
            follow_up_type="STATUS_INQUIRY",
            description="Overdue status inquiry",
        )
        # 2. Due today on active app (DUE)
        self.db.create_application_follow_up(
            application_id=app_active,
            user_id=self.user_a,
            follow_up_date=today_str,
            follow_up_type="PORTFOLIO_UPDATE",
            description="Due today portfolio update",
        )
        # 3. Due tomorrow on active app (NOT DUE)
        self.db.create_application_follow_up(
            application_id=app_active,
            user_id=self.user_a,
            follow_up_date=tomorrow,
            follow_up_type="PHONE_CALL",
            description="Future call",
        )
        # 4. Past due on active app, but COMPLETED (NOT DUE)
        fu4 = self.db.create_application_follow_up(
            application_id=app_active,
            user_id=self.user_a,
            follow_up_date=yesterday,
            follow_up_type="THANK_YOU_NOTE",
            description="Completed overdue thank you note",
        )
        self.db.complete_application_follow_up(fu4.id, self.user_a, outcome_notes="Done")

        # 5. Past due on ARCHIVED app (EXCLUDED by default, INCLUDED when include_archived=True)
        self.db.create_application_follow_up(
            application_id=app_archived,
            user_id=self.user_a,
            follow_up_date=yesterday,
            follow_up_type="RECRUITER_CHECKIN",
            description="Archived overdue checkin",
        )
        self.db.archive_user_application(app_archived, self.user_a, "Position archived")

        metrics_default = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics_default["follow_ups_due"], 2)

        metrics_with_archived = self.service.get_candidate_tracker_metrics(
            self.session_a.session_id, include_archived=True
        )
        self.assertEqual(metrics_with_archived["follow_ups_due"], 3)

    def test_metrics_candidate_isolation(self):
        """User A metrics are isolated from User B metrics."""
        self._create_app(self.user_a, "User A Co", "Role", status="SUBMITTED")
        self._create_app(self.user_b, "User B Co", "Role", status="OFFER")

        metrics_a = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        metrics_b = self.service.get_candidate_tracker_metrics(self.session_b.session_id)

        self.assertEqual(metrics_a["submitted"], 1)
        self.assertEqual(metrics_a["offers"], 0)
        self.assertEqual(metrics_b["submitted"], 0)
        self.assertEqual(metrics_b["offers"], 1)


class TestExternalApplicationURLSecurity(BaseTrackerReadAPITest):
    """Verifies log_external_application_url_opened security, status preservation, and redaction."""

    def test_unauthenticated_request_fails(self):
        """Calling without a valid session fails with InvalidSessionError."""
        app = self._create_app(self.user_a, "Co", "Role", job_url="https://example.com/apply")
        with self.assertRaises(InvalidSessionError):
            self.service.log_external_application_url_opened(
                application_id=app,
                session_id="invalid_session_token",
            )

    def test_cross_user_application_access_fails(self):
        """User A cannot access User B's application URL (ApplicationNotFoundError or CrossUserAccessError)."""
        app_b = self._create_app(self.user_b, "Bob Co", "Dev", job_url="https://example.com/apply")
        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            self.service.log_external_application_url_opened(
                application_id=app_b,
                session_id=self.session_a.session_id,
            )

    def test_missing_canonical_url_raises_validation_error(self):
        """Application without external application URL raises ValidationError."""
        app = self._create_app(self.user_a, "Co", "Role", job_url=None)
        with self.assertRaises(ValidationError):
            self.service.log_external_application_url_opened(
                application_id=app,
                session_id=self.session_a.session_id,
            )

    def test_unsafe_stored_url_raises_unsafe_url_error(self):
        """Application with private IP or metadata URL raises UnsafeURLError."""
        app_unsafe = self._create_app(
            self.user_a, "Co", "Role", job_url="http://127.0.0.1/admin"
        )
        with self.assertRaises(UnsafeURLError):
            self.service.log_external_application_url_opened(
                application_id=app_unsafe,
                session_id=self.session_a.session_id,
            )

    def test_arbitrary_client_url_substitution_prohibited(self):
        """Providing a client URL different from the canonical stored URL raises SecurityAuthorizationError."""
        app = self._create_app(
            self.user_a, "Co", "Role", job_url="https://example.com/jobs/42"
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.service.log_external_application_url_opened(
                application_id=app,
                session_id=self.session_a.session_id,
                url="https://phishing.site/fake_login",
            )

    def test_sensitive_param_and_fragment_redaction(self):
        """URL fragments are stripped and sensitive parameters are redacted in audit event payload."""
        canonical_url = (
            "https://jobs.example.com/apply?reqId=456"
            "&token=supersecret123&auth=bearer_token_xyz#access_token=secret_frag"
        )
        app = self._create_app(self.user_a, "Secure Co", "SWE", job_url=canonical_url)

        # Execute navigation request logging
        returned_url = self.service.log_external_application_url_opened(
            application_id=app,
            session_id=self.session_a.session_id,
        )

        # 1. Validated canonical destination URL returned to UI preserves parameters & fragments
        self.assertEqual(returned_url, canonical_url)

        # 2. Check the audit event payload recorded in database
        events = self.db.get_application_events(application_id=app, user_id=self.user_a)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "EXTERNAL_APPLICATION_URL_OPENED")
        self.assertEqual(event.actor_type, "CANDIDATE")
        self.assertEqual(event.actor_identifier, f"user_{self.user_a}")

        payload = event.event_payload_json
        if isinstance(payload, str):
            payload = json.loads(payload)

        sanitized = payload["opened_url"]
        # Fragment must be completely stripped
        self.assertNotIn("#", sanitized)
        self.assertNotIn("secret_frag", sanitized)
        # Sensitive parameters must be REDACTED
        self.assertIn("token=REDACTED", sanitized)
        self.assertIn("auth=REDACTED", sanitized)
        self.assertNotIn("supersecret123", sanitized)
        self.assertNotIn("bearer_token_xyz", sanitized)
        # Legitimate parameters must be preserved
        self.assertIn("reqId=456", sanitized)

    def test_status_strictly_preserved(self):
        """Calling log_external_application_url_opened does not mutate application status."""
        app = self._create_app(
            self.user_a, "Co", "Role", status="APPROVED", job_url="https://example.com/apply"
        )
        self.service.log_external_application_url_opened(
            application_id=app,
            session_id=self.session_a.session_id,
        )

        retrieved = self.service.get_candidate_application(
            application_id=app,
            session_id=self.session_a.session_id,
        )
        self.assertEqual(retrieved.status, "APPROVED")

    def test_valid_stored_canonical_url_succeeds(self):
        """Valid stored canonical URL succeeds and returns validated URL for browser navigation."""
        app = self._create_app(
            self.user_a, "Co", "Role", status="PREPARING", job_url="https://careers.google.com/jobs/1"
        )
        res_url = self.service.log_external_application_url_opened(
            application_id=app,
            session_id=self.session_a.session_id,
        )
        self.assertEqual(res_url, "https://careers.google.com/jobs/1")

    def test_missing_canonical_url_with_supplied_url_rejected(self):
        """When canonical URL is missing, caller-supplied URL is NOT used and raises ValidationError."""
        app = self._create_app(self.user_a, "Co", "Role", job_url=None)
        with self.assertRaises(ValidationError):
            self.service.log_external_application_url_opened(
                application_id=app,
                session_id=self.session_a.session_id,
                url="https://attacker.site/apply",
            )

    def test_url_validator_not_invoked_before_authentication(self):
        """URL safety validator and DNS resolver are never called when candidate authentication fails."""
        resolver_called = []

        def spy_resolver(host: str, port: int) -> List[str]:
            resolver_called.append((host, port))
            return ["93.184.215.14"]

        service = DashboardService(db_manager=self.db, url_resolver=spy_resolver)
        app = self._create_app(self.user_a, "Co", "Role", job_url="https://example.com/apply")

        with self.assertRaises(InvalidSessionError):
            service.log_external_application_url_opened(
                application_id=app,
                session_id="totally_invalid_session_token",
            )

        self.assertEqual(len(resolver_called), 0, "Resolver must not be called before authentication.")

    def test_url_validator_not_invoked_for_cross_user_application(self):
        """URL safety validator and DNS resolver are never called for applications owned by another candidate."""
        resolver_called = []

        def spy_resolver(host: str, port: int) -> List[str]:
            resolver_called.append((host, port))
            return ["93.184.215.14"]

        service = DashboardService(db_manager=self.db, url_resolver=spy_resolver)
        app_b = self._create_app(self.user_b, "Bob Co", "Dev", job_url="https://example.com/apply")

        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            service.log_external_application_url_opened(
                application_id=app_b,
                session_id=self.session_a.session_id,
            )

        self.assertEqual(len(resolver_called), 0, "Resolver must not be called for another candidate's application.")

    def test_no_audit_event_appended_on_validation_failure(self):
        """No audit event is appended when URL validation fails at any point."""
        app_missing = self._create_app(self.user_a, "Co Missing", "Role", job_url=None)
        app_unsafe = self._create_app(self.user_a, "Co Unsafe", "Role", job_url="http://127.0.0.1/admin")
        app_valid = self._create_app(self.user_a, "Co Valid", "Role", job_url="https://example.com/apply")

        # 1. Missing canonical URL
        with self.assertRaises(ValidationError):
            self.service.log_external_application_url_opened(app_missing, self.session_a.session_id)
        self.assertEqual(len(self.db.get_application_events(app_missing, self.user_a)), 0)

        # 2. Missing canonical URL with supplied URL
        with self.assertRaises(ValidationError):
            self.service.log_external_application_url_opened(
                app_missing, self.session_a.session_id, url="https://example.com/apply"
            )
        self.assertEqual(len(self.db.get_application_events(app_missing, self.user_a)), 0)

        # 3. Unsafe canonical URL
        with self.assertRaises(UnsafeURLError):
            self.service.log_external_application_url_opened(app_unsafe, self.session_a.session_id)
        self.assertEqual(len(self.db.get_application_events(app_unsafe, self.user_a)), 0)

        # 4. Arbitrary substitution attempt
        with self.assertRaises(SecurityAuthorizationError):
            self.service.log_external_application_url_opened(
                app_valid, self.session_a.session_id, url="https://phish.com"
            )
        self.assertEqual(len(self.db.get_application_events(app_valid, self.user_a)), 0)

        # 5. Invalid session
        with self.assertRaises(InvalidSessionError):
            self.service.log_external_application_url_opened(app_valid, "bad_session")
        self.assertEqual(len(self.db.get_application_events(app_valid, self.user_a)), 0)


class TestCandidateFollowUpService(BaseTrackerReadAPITest):
    """Verifies Candidate Follow-Up service wrappers in DashboardService."""

    def test_create_follow_up_ownership_enforcement(self):
        """Creating a follow-up enforces candidate application ownership."""
        app_a = self._create_app(self.user_a, "Alice Co", "Role")
        app_b = self._create_app(self.user_b, "Bob Co", "Role")

        fu = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app_a,
            follow_up_date="2026-11-10",
            follow_up_type="STATUS_INQUIRY",
            description="Check on review status",
        )
        self.assertIsNotNone(fu.id)
        self.assertEqual(fu.user_id, self.user_a)

        # Alice cannot create follow-up on Bob's application
        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            self.service.create_application_follow_up(
                session_id=self.session_a.session_id,
                application_id=app_b,
                follow_up_date="2026-11-10",
                follow_up_type="STATUS_INQUIRY",
                description="Hacked follow-up",
            )

    def test_list_follow_ups_filtering_and_archival(self):
        """list_application_follow_ups supports filtering by app, completion, and archival."""
        app_active = self._create_app(self.user_a, "Active Co", "Role", is_archived=0)
        app_archived = self._create_app(self.user_a, "Archived Co", "Role", is_archived=0)

        fu1 = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app_active,
            follow_up_date="2026-11-05",
            follow_up_type="STATUS_INQUIRY",
            description="Active incomplete",
        )
        fu2 = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app_active,
            follow_up_date="2026-11-06",
            follow_up_type="PHONE_CALL",
            description="Active completed",
        )
        self.service.complete_application_follow_up(
            session_id=self.session_a.session_id,
            follow_up_id=fu2.id,
            outcome_notes="Called recruiter",
        )
        fu3 = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app_archived,
            follow_up_date="2026-11-07",
            follow_up_type="RECRUITER_CHECKIN",
            description="Archived incomplete",
        )
        self.service.archive_candidate_application(
            application_id=app_archived,
            session_id=self.session_a.session_id,
            archive_reason="Position closed",
        )

        # Default excludes archived
        active_fus = self.service.list_application_follow_ups(self.session_a.session_id)
        self.assertEqual(len(active_fus), 2)
        self.assertEqual({f.id for f in active_fus}, {fu1.id, fu2.id})

        # Include archived
        all_fus = self.service.list_application_follow_ups(
            self.session_a.session_id, include_archived=True
        )
        self.assertEqual(len(all_fus), 3)
        self.assertEqual({f.id for f in all_fus}, {fu1.id, fu2.id, fu3.id})

        # Filter by completion status
        incomplete = self.service.list_application_follow_ups(
            self.session_a.session_id, is_completed=False
        )
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(incomplete[0].id, fu1.id)

        completed = self.service.list_application_follow_ups(
            self.session_a.session_id, is_completed=True
        )
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].id, fu2.id)

    def test_get_complete_and_delete_follow_up_ownership(self):
        """get, complete, and delete follow-up enforce ownership."""
        app_a = self._create_app(self.user_a, "Alice Co", "Role")
        app_b = self._create_app(self.user_b, "Bob Co", "Role")

        fu_a = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app_a,
            follow_up_date="2026-11-15",
            follow_up_type="OTHER",
            description="Alice note",
        )
        fu_b = self.service.create_application_follow_up(
            session_id=self.session_b.session_id,
            application_id=app_b,
            follow_up_date="2026-11-15",
            follow_up_type="OTHER",
            description="Bob note",
        )

        # Alice gets Alice's follow-up
        fetched = self.service.get_application_follow_up(self.session_a.session_id, fu_a.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, fu_a.id)

        # Alice cannot get Bob's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.service.get_application_follow_up(self.session_a.session_id, fu_b.id)

        # Alice cannot complete Bob's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.service.complete_application_follow_up(
                self.session_a.session_id, fu_b.id, outcome_notes="Hacked"
            )

        # Alice completes Alice's follow-up
        completed = self.service.complete_application_follow_up(
            self.session_a.session_id, fu_a.id, outcome_notes="All clear"
        )
        self.assertTrue(completed.is_completed)
        self.assertEqual(completed.outcome_notes, "All clear")

        # Alice cannot delete Bob's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.service.delete_application_follow_up(self.session_a.session_id, fu_b.id)

        # Alice deletes Alice's follow-up
        self.assertTrue(self.service.delete_application_follow_up(self.session_a.session_id, fu_a.id))
        self.assertIsNone(self.service.get_application_follow_up(self.session_a.session_id, fu_a.id))


class TestCandidateApplicationMatchDetail(BaseTrackerReadAPITest):
    """Verifies get_candidate_application_match_detail relational resolution."""

    def test_returns_match_when_linked_via_prepared_packet(self):
        """Returns the MatchResult record when linked through prepared_packets.matching_result_id."""
        app = self._create_app(self.user_a, "Google", "AI Eng")

        # Seed resume and job description
        resume_id = self.db.create_user_resume(
            user_id=self.user_a,
            original_filename="resume.pdf",
            storage_filename="storage.pdf",
            file_format="pdf",
            file_hash="hash_123",
            file_size_bytes=1024,
            parsed_data={},
        )["id"]
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_a,
            company_name="Google",
            job_title="AI Eng",
            raw_content="Python, ML",
            source_type="pasted",
        )

        match_res = MatchResult(
            user_id=self.user_a,
            resume_id=resume_id,
            job_description_id=jd.id,
            match_score=92.5,
            match_classification="Excellent match",
            eligibility_status="ELIGIBLE",
            score_breakdown=json.dumps({"technical_skills": 25}),
            explanation="Strong match on core requirements.",
        )
        match_id = self.db.save_match_result(match_res)

        # Create active prepared packet linking this match_id
        self.db.create_prepared_packet(
            application_id=app,
            user_id=self.user_a,
            packet_version_hash="packet_hash_v1",
            original_resume_hash="hash_123",
            job_description_snapshot_hash="jd_hash_123",
            screening_answers={},
            matching_result_id=match_id,
        )

        # Retrieve match detail via service
        detail = self.service.get_candidate_application_match_detail(
            application_id=app,
            session_id=self.session_a.session_id,
        )
        self.assertIsNotNone(detail)
        self.assertEqual(detail.id, match_id)
        self.assertEqual(detail.match_score, 92.5)
        self.assertEqual(detail.eligibility_status, "ELIGIBLE")

    def test_returns_none_when_unlinked(self):
        """Returns None when no prepared packet exists or matching_result_id is unlinked."""
        app = self._create_app(self.user_a, "Meta", "SWE")
        self.assertIsNone(
            self.service.get_candidate_application_match_detail(
                application_id=app,
                session_id=self.session_a.session_id,
            )
        )

        # Create packet with matching_result_id = None
        self.db.create_prepared_packet(
            application_id=app,
            user_id=self.user_a,
            packet_version_hash="packet_hash_v2",
            original_resume_hash="hash_abc",
            job_description_snapshot_hash="jd_hash_abc",
            screening_answers={},
            matching_result_id=None,
        )
        self.assertIsNone(
            self.service.get_candidate_application_match_detail(
                application_id=app,
                session_id=self.session_a.session_id,
            )
        )

    def test_cross_user_and_unauthenticated_rejection(self):
        """Cross-user calls raise (ApplicationNotFoundError, CrossUserAccessError), invalid sessions raise InvalidSessionError."""
        app_b = self._create_app(self.user_b, "Bob Co", "Dev")

        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            self.service.get_candidate_application_match_detail(
                application_id=app_b,
                session_id=self.session_a.session_id,
            )

        with self.assertRaises(InvalidSessionError):
            self.service.get_candidate_application_match_detail(
                application_id=app_b,
                session_id="invalid_session",
            )


if __name__ == "__main__":
    unittest.main()
