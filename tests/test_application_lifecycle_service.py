"""Comprehensive tests for Application Lifecycle Core Service Layer (Phase 7.2).

Covers:
1. Candidate application creation with ownership validation (JD, resume, status restrictions).
2. Application retrieval with strict multi-user ownership enforcement (IDOR protection).
3. Candidate application listing with filtering, search, and sorting.
4. Atomic application status transitions with state-machine validation and rollback on error.
5. Concurrency conflict handling and stale-state detection.
6. Generic transition gate protection (APPROVED and SUBMITTED blocked via generic endpoints).
7. Application timeline retrieval and cryptographic event-chain verification.
8. External application URL logging (strictly preserves status, no automated transition).
9. Session security tests (missing, expired, inactive, unbound, and cross-user mismatched sessions).
"""

import os
import sqlite3
import tempfile
import time
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    InvalidSessionError,
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
    SessionExpiredError,
    ValidationError,
)
from src.database.models import ApplicationStatus
from src.security.session_manager import SessionManager


class TestApplicationLifecycleServiceBase(unittest.TestCase):
    """Base fixture creating isolated test database, users, and sessions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_lifecycle.db")
        self.db = DatabaseManager(self.db_path)
        self.service = DashboardService(db_manager=self.db, url_resolver=lambda h, p: ["93.184.215.14"])
        self.session_mgr = SessionManager.get_instance()

        # Seed two distinct candidate users in DB
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'alice@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'bob@example.com', 'h2', 's2', 'Bob Candidate')"
            )

        self.user_a = 1
        self.user_b = 2

        # Establish authenticated sessions
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="alice_user",
            candidate_name="Alice Candidate",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="bob_user",
            candidate_name="Bob Candidate",
            user_id=self.user_b,
        )

    def tearDown(self):
        self.session_mgr.reset_instance()
        self.temp_dir.cleanup()

    def _seed_job_description(self, user_id: int, title: str = "ML Engineer", company: str = "Acme AI") -> int:
        """Helper to create a user-owned job description."""
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name=company,
            job_title=title,
            raw_content="Python, PyTorch, SQL required.",
            source_type="pasted",
        )
        return jd.id

    def _seed_resume(self, user_id: int, filename: str = "resume.pdf") -> int:
        """Helper to create a user-owned resume record."""
        row = self.db.create_user_resume(
            user_id=user_id,
            original_filename=filename,
            storage_filename=filename,
            file_format="pdf",
            file_hash=f"hash_{filename}_{user_id}",
            file_size_bytes=1024,
            parsed_data={"name": "Candidate"},
            is_primary=True,
        )
        return row["id"]


class TestCandidateApplicationCRUD(TestApplicationLifecycleServiceBase):
    """Tests for application creation, retrieval, and listing."""

    def test_create_candidate_application_success(self):
        """Candidate can create an application in DRAFT status with valid inputs."""
        jd_id = self._seed_job_description(self.user_a)
        res_id = self._seed_resume(self.user_a)

        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="DeepTech Inc",
            job_title="Senior AI Researcher",
            job_description_id=jd_id,
            resume_id=res_id,
            status="DRAFT",
            job_url="https://example.com/jobs/101",
            notes="Found via LinkedIn",
        )

        self.assertIsNotNone(app.id)
        self.assertEqual(app.user_id, self.user_a)
        self.assertEqual(app.company_name, "DeepTech Inc")
        self.assertEqual(app.job_title, "Senior AI Researcher")
        self.assertEqual(app.status, ApplicationStatus.DRAFT.value)
        self.assertEqual(app.job_description_id, jd_id)
        self.assertEqual(app.resume_id, res_id)

    def test_create_candidate_application_empty_fields_fail(self):
        """Creating an application with empty company or title fails with ValidationError."""
        with self.assertRaises(ValidationError):
            self.service.create_candidate_application(
                session_id=self.session_a.session_id,
                company_name="",
                job_title="Engineer",
            )
        with self.assertRaises(ValidationError):
            self.service.create_candidate_application(
                session_id=self.session_a.session_id,
                company_name="Company",
                job_title="   ",
            )

    def test_create_application_rejects_unowned_jd_or_resume(self):
        """User A cannot link User B's job description or resume."""
        jd_b = self._seed_job_description(self.user_b)
        res_b = self._seed_resume(self.user_b)

        # User A attempting to link User B's JD
        with self.assertRaises(ValidationError):
            self.service.create_candidate_application(
                session_id=self.session_a.session_id,
                company_name="TechCorp",
                job_title="Developer",
                job_description_id=jd_b,
            )

        # User A attempting to link User B's Resume
        with self.assertRaises(ValidationError):
            self.service.create_candidate_application(
                session_id=self.session_a.session_id,
                company_name="TechCorp",
                job_title="Developer",
                resume_id=res_b,
            )

    def test_create_application_restricts_initial_status(self):
        """Applications can only be created in DRAFT or PREPARING; not APPROVED, SUBMITTED, etc."""
        self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Company 1",
            job_title="Role 1",
            status="PREPARING",
        )

        for forbidden_status in ["APPROVED", "SUBMITTED", "INTERVIEW", "OFFER", "CLOSED"]:
            with self.assertRaises(SecurityAuthorizationError):
                self.service.create_candidate_application(
                    session_id=self.session_a.session_id,
                    company_name="Company 2",
                    job_title="Role 2",
                    status=forbidden_status,
                )

    def test_get_candidate_application_ownership_isolation(self):
        """User A can retrieve their own application; User B cannot (CrossUserAccessError)."""
        app_a = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Alice Corp",
            job_title="Engineer",
        )

        # User A gets own application
        retrieved = self.service.get_candidate_application(
            application_id=app_a.id,
            session_id=self.session_a.session_id,
        )
        self.assertEqual(retrieved.id, app_a.id)

        # User B attempting to retrieve User A's application
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_application(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
            )

    def test_get_nonexistent_application_raises_not_found(self):
        """Retrieving a non-existent application raises ApplicationNotFoundError."""
        with self.assertRaises(ApplicationNotFoundError):
            self.service.get_candidate_application(
                application_id=99999,
                session_id=self.session_a.session_id,
            )

    def test_list_candidate_applications_multi_user_isolation(self):
        """list_candidate_applications only returns the caller's applications."""
        app_a1 = self.service.create_candidate_application(
            session_id=self.session_a.session_id, company_name="Company A1", job_title="Engineer"
        )
        app_a2 = self.service.create_candidate_application(
            session_id=self.session_a.session_id, company_name="Company A2", job_title="Designer"
        )
        app_b1 = self.service.create_candidate_application(
            session_id=self.session_b.session_id, company_name="Company B1", job_title="Manager"
        )

        # User A list
        apps_a = self.service.list_candidate_applications(session_id=self.session_a.session_id)
        self.assertEqual(len(apps_a), 2)
        ids_a = {a.id for a in apps_a}
        self.assertIn(app_a1.id, ids_a)
        self.assertIn(app_a2.id, ids_a)
        self.assertNotIn(app_b1.id, ids_a)

        # User B list
        apps_b = self.service.list_candidate_applications(session_id=self.session_b.session_id)
        self.assertEqual(len(apps_b), 1)
        self.assertEqual(apps_b[0].id, app_b1.id)

    def test_list_candidate_applications_search_and_sorting(self):
        """list_candidate_applications supports search filtering and sorting."""
        self.service.create_candidate_application(
            session_id=self.session_a.session_id, company_name="Zeta Systems", job_title="Data Scientist"
        )
        self.service.create_candidate_application(
            session_id=self.session_a.session_id, company_name="Alpha Tech", job_title="Backend Engineer"
        )

        # Search filter
        search_res = self.service.list_candidate_applications(
            session_id=self.session_a.session_id, search_term="Backend"
        )
        self.assertEqual(len(search_res), 1)
        self.assertEqual(search_res[0].company_name, "Alpha Tech")

        # Sort by company_name
        sorted_res = self.service.list_candidate_applications(
            session_id=self.session_a.session_id, sort_by="company_name"
        )
        self.assertEqual(sorted_res[0].company_name, "Alpha Tech")
        self.assertEqual(sorted_res[1].company_name, "Zeta Systems")


class TestAtomicApplicationTransitions(TestApplicationLifecycleServiceBase):
    """Tests for atomic status transitions, validations, and rollback."""

    def test_valid_sequential_transitions(self):
        """Application transitions sequentially: DRAFT -> PREPARING -> READY_FOR_REVIEW."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Valid Transitions Co",
            job_title="ML Engineer",
            status="DRAFT",
        )
        self.assertEqual(app.status, ApplicationStatus.DRAFT.value)

        # 1. DRAFT -> PREPARING
        t1 = self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
            expected_current_status="DRAFT",
        )
        self.assertEqual(t1.status, ApplicationStatus.PREPARING.value)

        # 2. PREPARING -> READY_FOR_REVIEW
        t2 = self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="READY_FOR_REVIEW",
            expected_current_status="PREPARING",
        )
        self.assertEqual(t2.status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Timeline verification
        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(tl["chain_valid"])
        event_types = [e.event_type for e in tl["events"]]
        self.assertIn("APPLICATION_CREATED", event_types)
        self.assertIn("APPLICATION_PREPARATION_STARTED", event_types)
        self.assertIn("APPLICATION_READY_FOR_REVIEW", event_types)

    def test_invalid_status_transition_rejected(self):
        """Illegal status transition (e.g. DRAFT -> OFFER) is rejected."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Test Corp",
            job_title="Dev",
            status="DRAFT",
        )
        with self.assertRaises(InvalidStatusTransitionError):
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="OFFER",
            )

        # Status must remain DRAFT
        fresh = self.service.get_candidate_application(app.id, self.session_a.session_id)
        self.assertEqual(fresh.status, ApplicationStatus.DRAFT.value)

    def test_stale_expected_status_rejected(self):
        """Transition specifying a stale expected_current_status fails with ValidationError."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Stale Test Co",
            job_title="Engineer",
            status="DRAFT",
        )
        # Advance to PREPARING
        self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
        )

        # Request expecting DRAFT now fails because current is PREPARING
        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="READY_FOR_REVIEW",
                expected_current_status="DRAFT",
            )
        self.assertIn("Stale state conflict", str(ctx.exception))

    def test_generic_transition_to_approved_rejected(self):
        """Transition to APPROVED via generic transition_application_status is rejected."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Gate Test Co",
            job_title="Dev",
            status="DRAFT",
        )
        self.service.transition_application_status(app.id, self.session_a.session_id, "PREPARING")
        self.service.transition_application_status(app.id, self.session_a.session_id, "READY_FOR_REVIEW")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="APPROVED",
            )
        self.assertIn("requires explicit human packet approval", str(ctx.exception))

    def test_generic_transition_to_submitted_rejected(self):
        """Transition to SUBMITTED via generic transition_application_status is rejected."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Gate Test Co 2",
            job_title="Dev",
            status="DRAFT",
        )
        # Manually force status to APPROVED in DB to test transition from APPROVED
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="SUBMITTED",
            )
        self.assertIn("requires candidate manual submission confirmation", str(ctx.exception))

    def test_transition_failure_triggers_complete_database_rollback(self):
        """If event insertion fails during status transition, the status update is rolled back."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Rollback Test Co",
            job_title="Developer",
            status="DRAFT",
        )

        # Trigger on application_events to simulate DB failure
        with self.db.connection() as conn:
            conn.execute("""
                CREATE TRIGGER simulate_trans_failure_trg
                BEFORE INSERT ON application_events
                WHEN NEW.new_status = 'PREPARING'
                BEGIN
                    SELECT RAISE(FAIL, 'Simulated failure during transition event insert');
                END;
            """)

        try:
            with self.assertRaises(sqlite3.IntegrityError):
                self.service.transition_application_status(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    new_status="PREPARING",
                )
        finally:
            with self.db.connection() as conn:
                conn.execute("DROP TRIGGER IF EXISTS simulate_trans_failure_trg")

        # Status in DB must STILL be DRAFT!
        fresh = self.service.get_candidate_application(app.id, self.session_a.session_id)
        self.assertEqual(fresh.status, ApplicationStatus.DRAFT.value)

        # Timeline must have no partial events
        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(tl["chain_valid"])
        event_statuses = [e.new_status for e in tl["events"]]
        self.assertNotIn("PREPARING", event_statuses)

    def test_external_url_opened_logging_preserves_status(self):
        """Opening external application URL emits an audit event but does NOT mutate status."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="URL Logging Co",
            job_title="Frontend Engineer",
            status="DRAFT",
            job_url="https://company.careers/apply/123",
        )

        self.service.log_external_application_url_opened(
            application_id=app.id,
            session_id=self.session_a.session_id,
        )

        # Status MUST still be DRAFT (never automatically advanced to SUBMITTED!)
        fresh = self.service.get_candidate_application(app.id, self.session_a.session_id)
        self.assertEqual(fresh.status, ApplicationStatus.DRAFT.value)

        # Event is recorded
        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        last_evt = tl["events"][-1]
        self.assertEqual(last_evt.event_type, "EXTERNAL_APPLICATION_URL_OPENED")
        self.assertIn("https://company.careers/apply/123", last_evt.event_payload_json)


class TestSessionSecurityAndIdentityResolution(TestApplicationLifecycleServiceBase):
    """Tests for session validation, identity resolution, and attack resistance."""

    def test_missing_session_id_fails(self):
        """None or empty session_id raises InvalidSessionError."""
        with self.assertRaises(InvalidSessionError):
            self.service.resolve_authenticated_candidate(None)
        with self.assertRaises(InvalidSessionError):
            self.service.resolve_authenticated_candidate("")
        with self.assertRaises(InvalidSessionError):
            self.service.resolve_authenticated_candidate("   ")

    def test_unknown_session_id_fails(self):
        """Non-existent session_id raises InvalidSessionError."""
        with self.assertRaises(InvalidSessionError):
            self.service.resolve_authenticated_candidate("sess_nonexistent_12345")

    def test_expired_session_fails(self):
        """Expired session raises SessionExpiredError."""
        sess = self.session_mgr.authenticate_candidate("alice_exp", "Alice Exp", user_id=self.user_a)
        sess.expires_at = time.time() - 60  # expired 60 seconds ago

        with self.assertRaises(SessionExpiredError):
            self.service.resolve_authenticated_candidate(sess.session_id)

    def test_inactive_session_fails(self):
        """Revoked or deactivated session raises InvalidSessionError."""
        sess = self.session_mgr.authenticate_candidate("alice_rev", "Alice Rev", user_id=self.user_a)
        sess.is_active = False

        with self.assertRaises(InvalidSessionError):
            self.service.resolve_authenticated_candidate(sess.session_id)

    def test_unbound_session_fails(self):
        """Session with None user_id raises SecurityAuthorizationError."""
        sess = self.session_mgr.authenticate_candidate("alice_unb", "Alice Unb", user_id=None)
        sess.user_id = None

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.resolve_authenticated_candidate(sess.session_id)
        self.assertIn("Unbound session", str(ctx.exception))

    def test_client_supplied_user_id_mismatch_rejected(self):
        """Providing a client_user_id that differs from session.user_id raises CrossUserAccessError."""
        # session_a belongs to user_a (1). Passing client_user_id=2 (User B) must be rejected
        with self.assertRaises(CrossUserAccessError) as ctx:
            self.service.resolve_authenticated_candidate(
                session_id=self.session_a.session_id,
                client_user_id=self.user_b,
            )
        self.assertIn("Cross-user security violation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
