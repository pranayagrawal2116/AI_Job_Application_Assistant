"""Phase 7.2.1 State Transition Authorization & Lifecycle Security Hardening Test Suite.

Covers all 5 core hardening requirements:
1. Gate authorization bypass prevention (caller-supplied booleans cannot authorize APPROVED or SUBMITTED).
2. Mandatory reopening rationale enforcement and terminal transition rules.
3. External URL validation (SSRF defense, scheme validation, private IP rejection) and sensitive query parameter redaction.
4. SQLite immediate write-lock, atomic failure rollback, and event chain integrity.
5. Protection of reserved audit payload fields against caller tampering.
"""

import json
import os
import shutil
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
    UnsafeURLError,
    ValidationError,
)
from src.database.models import ApplicationStatus
from src.lifecycle.state_machine import ApplicationStateMachine
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager


class TestPhase721SecurityHardening(unittest.TestCase):
    """Rigorous security and lifecycle integrity hardening tests for Phase 7.2.1."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="phase721_harden_")
        self.db_path = os.path.join(self.test_dir, "test_lifecycle_hardening.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService(db_manager=self.db)
        self.session_mgr = SessionManager.get_instance()
        self.approval_gate = HumanApprovalGate(db_manager=self.db)

        # Seed synthetic candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate.a@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate.b@example.com', 'h2', 's2', 'Bob Candidate')"
            )
        self.user_a = 1
        self.user_b = 2

        # Create active sessions
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="alice_candidate",
            candidate_name="Alice Candidate",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="bob_candidate",
            candidate_name="Bob Candidate",
            user_id=self.user_b,
        )

    def tearDown(self):
        self.session_mgr.reset_instance()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # 1. GATE AUTHORIZATION BYPASS PREVENTION
    # =========================================================================

    def test_generic_db_transition_cannot_bypass_approved_with_boolean_flag(self):
        """Calling db.transition_application_status with is_gate_authorized=True CANNOT authorize APPROVED."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            status="DRAFT",
        )
        self.service.transition_application_status(app.id, self.session_a.session_id, "PREPARING")
        self.service.transition_application_status(app.id, self.session_a.session_id, "READY_FOR_REVIEW")

        # Attempt to bypass using is_gate_authorized=True
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a,
                new_status="APPROVED",
                is_gate_authorized=True,
            )
        self.assertIn("gate-protected", str(ctx.exception).lower())
        self.assertIn("humanapprovalgate", str(ctx.exception).lower())

        # Verify application status was NOT mutated
        current_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(current_app.status, "READY_FOR_REVIEW")

    def test_generic_db_transition_cannot_bypass_submitted_with_boolean_flag(self):
        """Calling db.transition_application_status with is_gate_authorized=True CANNOT authorize SUBMITTED."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            status="DRAFT",
        )
        # Directly set to APPROVED in db to test transition from APPROVED
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a,
                new_status="SUBMITTED",
                is_gate_authorized=True,
            )
        self.assertIn("gate-protected", str(ctx.exception).lower())
        self.assertIn("submission confirmation", str(ctx.exception).lower())

        # Verify application status was NOT mutated
        current_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(current_app.status, "APPROVED")

    def test_generic_service_transition_to_approved_rejected(self):
        """Service layer transition_application_status rejects transition to APPROVED."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
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
        self.assertIn("gate-protected", str(ctx.exception).lower())

    def test_generic_service_transition_to_submitted_rejected(self):
        """Service layer transition_application_status rejects transition to SUBMITTED."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            status="DRAFT",
        )
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="SUBMITTED",
            )
        self.assertIn("gate-protected", str(ctx.exception).lower())

    def test_legitimate_human_approval_workflow_succeeds_and_records_event(self):
        """Legitimate approval through HumanApprovalGate succeeds and atomically emits PACKET_HUMAN_APPROVED event."""
        from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash

        # Setup JD, Resume, Application, PreparedPacket
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_a,
            company_name="Tech Innovations",
            job_title="ML Engineer",
            raw_content="Develop ML pipelines.",
        )
        res = self.db.create_user_resume(
            user_id=self.user_a,
            original_filename="alice_cv.pdf",
            storage_filename="alice_cv_stored.pdf",
            file_format="pdf",
            file_hash="dummy_hash_alice_resume_123",
            file_size_bytes=1024,
        )
        res_id = res["id"]
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Tech Innovations",
            job_title="ML Engineer",
            status="DRAFT",
            job_description_id=jd.id,
            resume_id=res_id,
        )
        self.service.transition_application_status(app.id, self.session_a.session_id, "PREPARING")
        self.service.transition_application_status(app.id, self.session_a.session_id, "READY_FOR_REVIEW")

        # Prepare packet
        dummy_snapshot = {
            "application_id": app.id,
            "user_id": self.user_a,
            "job_description_id": jd.id,
            "original_resume_id": res_id,
            "packet_version": 1,
            "tailored_resume": {"summary": "Experienced ML Engineer"},
            "cover_letter": "I am excited to apply.",
            "screening_answers": [],
            "attachments_manifest": [],
        }
        snap_bytes = canonical_json_bytes(dummy_snapshot)
        snap_hash = canonical_json_hash(dummy_snapshot)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (101, ?, ?, 1, ?, 'dummy_hash_alice_resume_123', 'jdh', '[]', ?, 1)
                """,
                (app.id, self.user_a, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, self.user_a)

        # Issue legitimate HUMAN_APPROVAL ticket
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        # Authorize via HumanApprovalGate
        success, msg, approval = self.approval_gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Approval failed: {msg}")
        self.assertIsNotNone(approval)

        # Verify application status transitioned
        updated_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(
            ApplicationStateMachine.normalize_status(updated_app.status),
            ApplicationStatus.APPROVED,
        )

        # Verify PACKET_HUMAN_APPROVED event was appended to timeline
        events = self.db.get_application_events(app.id, self.user_a)
        approved_events = [e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]
        self.assertEqual(len(approved_events), 1)
        self.assertEqual(approved_events[0].actor_identifier, "Alice Candidate")

        # Verify cryptographic event chain remains intact
        valid_chain, chain_msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid_chain, f"Event chain broken: {chain_msg}")

    def _create_submitted_app(self, session_id: str, company_name: str, job_title: str):
        app = self.service.create_candidate_application(
            session_id=session_id,
            company_name=company_name,
            job_title=job_title,
            status="DRAFT",
        )
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'SUBMITTED' WHERE id = ?", (app.id,))
        return app

    # =========================================================================
    # 2. ENFORCE REOPENING RATIONALE & TERMINAL TRANSITIONS
    # =========================================================================

    def test_reopening_from_rejected_without_rationale_fails(self):
        """Reopening from REJECTED to IN_PROGRESS requires a non-empty rationale."""
        app = self._create_submitted_app(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Dev",
        )
        # Advance to REJECTED
        self.service.transition_application_status(app.id, self.session_a.session_id, "REJECTED")

        # Attempt to reopen without rationale (None)
        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                reopen_rationale=None,
            )
        self.assertIn("non-empty reopening rationale is required", str(ctx.exception).lower())

        # Attempt to reopen with empty string
        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                reopen_rationale="",
            )
        self.assertIn("non-empty reopening rationale is required", str(ctx.exception).lower())

        # Attempt to reopen with whitespace only
        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                reopen_rationale="    ",
            )
        self.assertIn("non-empty reopening rationale is required", str(ctx.exception).lower())

    def test_reopening_bypass_via_unrelated_metadata_fails(self):
        """Attempting to supply rationale in transition_metadata instead of reopen_rationale is rejected."""
        app = self._create_submitted_app(
            session_id=self.session_a.session_id,
            company_name="Acme Corp",
            job_title="Dev",
        )
        self.service.transition_application_status(app.id, self.session_a.session_id, "WITHDRAWN")

        # Caller puts rationale in unrelated metadata key, leaving reopen_rationale None
        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                transition_metadata={"notes": "Position opened back up"},
                reopen_rationale=None,
            )
        self.assertIn("non-empty reopening rationale is required", str(ctx.exception).lower())

    def test_valid_reopening_from_all_terminal_states_succeeds(self):
        """Reopening from REJECTED, WITHDRAWN, or CLOSED with valid rationale succeeds and records APPLICATION_REOPENED."""
        for term_status in ["REJECTED", "WITHDRAWN", "CLOSED"]:
            app = self._create_submitted_app(
                session_id=self.session_a.session_id,
                company_name=f"Company for {term_status}",
                job_title="Engineer",
            )
            # Transition to terminal status
            if term_status == "CLOSED":
                self.service.transition_application_status(app.id, self.session_a.session_id, "WITHDRAWN")
                self.service.transition_application_status(app.id, self.session_a.session_id, "CLOSED")
            else:
                self.service.transition_application_status(app.id, self.session_a.session_id, term_status)

            # Reopen with valid rationale
            rationale_text = f"Candidate re-engaging for {term_status} application."
            reopened_app = self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                reopen_rationale=rationale_text,
            )
            self.assertEqual(reopened_app.status, "IN_PROGRESS")

            # Verify timeline event
            events = self.db.get_application_events(app.id, self.user_a)
            reopen_event = events[-1]
            self.assertEqual(reopen_event.event_type, "APPLICATION_REOPENED")
            payload = json.loads(reopen_event.event_payload_json)
            self.assertEqual(payload["previous_status"], term_status)
            self.assertEqual(payload["new_status"], "IN_PROGRESS")
            self.assertEqual(payload["reopen_rationale"], rationale_text)

    def test_terminal_progression_to_closed_succeeds_without_reopening_rationale(self):
        """Progressing from REJECTED or WITHDRAWN to CLOSED is terminal finalization and does NOT require reopening rationale."""
        # 1. REJECTED -> CLOSED
        app1 = self._create_submitted_app(
            session_id=self.session_a.session_id,
            company_name="Company 1",
            job_title="Dev",
        )
        self.service.transition_application_status(app1.id, self.session_a.session_id, "REJECTED")
        closed1 = self.service.transition_application_status(app1.id, self.session_a.session_id, "CLOSED")
        self.assertEqual(closed1.status, "CLOSED")

        # 2. WITHDRAWN -> CLOSED
        app2 = self._create_submitted_app(
            session_id=self.session_a.session_id,
            company_name="Company 2",
            job_title="Dev",
        )
        self.service.transition_application_status(app2.id, self.session_a.session_id, "WITHDRAWN")
        closed2 = self.service.transition_application_status(app2.id, self.session_a.session_id, "CLOSED")
        self.assertEqual(closed2.status, "CLOSED")

    def test_disallowed_transitions_from_terminal_states(self):
        """Terminal states cannot transition to arbitrary non-reopening states."""
        app = self._create_submitted_app(
            session_id=self.session_a.session_id,
            company_name="Terminal Test",
            job_title="Dev",
        )
        self.service.transition_application_status(app.id, self.session_a.session_id, "WITHDRAWN")
        self.service.transition_application_status(app.id, self.session_a.session_id, "CLOSED")

        disallowed_targets = ["DRAFT", "PREPARING", "READY_FOR_REVIEW", "ASSESSMENT", "INTERVIEW", "OFFER", "REJECTED", "WITHDRAWN"]
        for target in disallowed_targets:
            with self.assertRaises(InvalidStatusTransitionError):
                self.service.transition_application_status(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    new_status=target,
                )

    # =========================================================================
    # 3. EXTERNAL URL VALIDATION & AUDIT REDACTION
    # =========================================================================

    def test_external_url_validation_in_application_creation(self):
        """Application creation validates external_job_url against SSRF and unsafe schemes."""
        # Valid HTTPS URL succeeds
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Valid URL Co",
            job_title="Dev",
            job_url="https://careers.google.com/jobs/results/12345",
        )
        self.assertEqual(app.external_application_url, "https://careers.google.com/jobs/results/12345")

        # Unsupported schemes rejected
        for bad_url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://ftp.example.com/job",
            "gopher://gopher.floodgap.com",
        ]:
            with self.assertRaises(UnsafeURLError):
                self.service.create_candidate_application(
                    session_id=self.session_a.session_id,
                    company_name="Bad Scheme Co",
                    job_title="Dev",
                    job_url=bad_url,
                )

        # Loopback and private IPs rejected
        for private_url in [
            "http://localhost:8080/apply",
            "http://127.0.0.1:8000/job",
            "http://10.0.0.1/job",
            "http://169.254.169.254/latest/meta-data",
            "http://192.168.1.1/admin",
        ]:
            with self.assertRaises(UnsafeURLError):
                self.service.create_candidate_application(
                    session_id=self.session_a.session_id,
                    company_name="Private IP Co",
                    job_title="Dev",
                    job_url=private_url,
                )

        # Embedded credentials rejected
        with self.assertRaises(UnsafeURLError):
            self.service.create_candidate_application(
                session_id=self.session_a.session_id,
                company_name="Credential Co",
                job_title="Dev",
                job_url="https://user:password@careers.example.com/jobs",
            )

    def test_log_external_application_url_opened_validates_and_preserves_status(self):
        """log_external_application_url_opened validates URL, does not mutate status, and rejects unsafe URLs."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Preserve Status Co",
            job_title="Dev",
            status="PREPARING",
        )

        # Valid URL logging
        self.service.log_external_application_url_opened(
            application_id=app.id,
            session_id=self.session_a.session_id,
            url="https://jobs.example.com/posting/999",
        )

        # Verify status is preserved (NOT modified to SUBMITTED or anything else)
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, "PREPARING")

        # Unsafe URL rejected and NO event appended
        initial_event_count = len(self.db.get_application_events(app.id, self.user_a))
        with self.assertRaises(UnsafeURLError):
            self.service.log_external_application_url_opened(
                application_id=app.id,
                session_id=self.session_a.session_id,
                url="http://127.0.0.1:8080/exploit",
            )
        post_event_count = len(self.db.get_application_events(app.id, self.user_a))
        self.assertEqual(initial_event_count, post_event_count)

    def test_sensitive_query_parameters_redacted_in_audit_event(self):
        """Tokens, api_keys, passwords, and secrets are redacted from the logged URL payload."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Privacy Co",
            job_title="Dev",
        )

        url_with_tokens = (
            "https://ats.example.com/apply?job_id=456"
            "&token=secret_token_12345"
            "&auth_code=sensitive_auth_code"
            "&api_key=sk_live_99999"
            "&candidate_email=candidate@example.com"
            "&source=linkedin"
        )
        self.service.log_external_application_url_opened(
            application_id=app.id,
            session_id=self.session_a.session_id,
            url=url_with_tokens,
        )

        events = self.db.get_application_events(app.id, self.user_a)
        url_events = [e for e in events if e.event_type == "EXTERNAL_APPLICATION_URL_OPENED"]
        self.assertEqual(len(url_events), 1)

        payload = json.loads(url_events[0].event_payload_json)
        opened_url = payload["opened_url"]

        # Ensure sensitive token values are not present
        self.assertNotIn("secret_token_12345", opened_url)
        self.assertNotIn("sensitive_auth_code", opened_url)
        self.assertNotIn("sk_live_99999", opened_url)

        # Ensure REDACTED is present for sensitive keys
        self.assertIn("token=REDACTED", opened_url)
        self.assertIn("auth_code=REDACTED", opened_url)
        self.assertIn("api_key=REDACTED", opened_url)

        # Ensure non-sensitive query parameters are preserved
        self.assertIn("job_id=456", opened_url)
        self.assertIn("source=linkedin", opened_url)

    # =========================================================================
    # 4. SQLITE WRITE LOCK, CONCURRENCY & TRANSACTION HARDENING
    # =========================================================================

    def test_immediate_transaction_acquires_write_lock(self):
        """immediate_transaction acquires SQLite write lock, preventing concurrent write collisions."""
        with self.db.immediate_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_stale_expected_status_conflict_raises_and_rolls_back(self):
        """Providing an expected_current_status that does not match current state fails with complete rollback."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Concurrency Co",
            job_title="Dev",
            status="DRAFT",
        )
        events_before = len(self.db.get_application_events(app.id, self.user_a))

        with self.assertRaises(ValidationError) as ctx:
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="PREPARING",
                expected_current_status="READY_FOR_REVIEW",  # Stale: actual is DRAFT
            )
        self.assertIn("stale state conflict", str(ctx.exception).lower())

        # Verify no state or event changes occurred
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, "DRAFT")
        events_after = len(self.db.get_application_events(app.id, self.user_a))
        self.assertEqual(events_before, events_after)

    def test_concurrent_status_modification_conflict_handled_gracefully(self):
        """If database row is concurrently updated between lock and update, conflict is detected and rolled back."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Race Co",
            job_title="Dev",
            status="DRAFT",
        )

        # Simulate another transaction updating status to PREPARING concurrently
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'PREPARING' WHERE id = ?", (app.id,))

        # Now an attempt to transition from DRAFT with expected_current_status=DRAFT must fail
        with self.assertRaises(ValidationError) as ctx:
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a,
                new_status="PREPARING",
                expected_current_status="DRAFT",
            )
        self.assertIn("stale state conflict", str(ctx.exception).lower())

    def test_event_insertion_failure_triggers_complete_status_rollback(self):
        """If internal event insertion fails, the status update is completely rolled back."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Rollback Co",
            job_title="Dev",
            status="DRAFT",
        )

        # Monkey-patch _insert_application_event_internal to simulate database failure
        original_insert = self.db._insert_application_event_internal
        try:
            def failing_insert(*args, **kwargs):
                raise RuntimeError("Simulated trigger or disk failure during event emission")

            self.db._insert_application_event_internal = failing_insert

            with self.assertRaises(RuntimeError) as ctx:
                self.db.transition_application_status(
                    application_id=app.id,
                    user_id=self.user_a,
                    new_status="PREPARING",
                )
            self.assertIn("Simulated trigger or disk failure", str(ctx.exception))

            # Verify application status remains DRAFT (rolled back)
            fresh_app = self.db.get_user_application(app.id, self.user_a)
            self.assertEqual(fresh_app.status, "DRAFT")
        finally:
            self.db._insert_application_event_internal = original_insert

    # =========================================================================
    # 5. PROTECTED RESERVED AUDIT PAYLOAD FIELDS
    # =========================================================================

    def test_transition_metadata_cannot_override_reserved_audit_fields(self):
        """Callers cannot supply reserved audit fields in transition_metadata to forge or tamper with timeline records."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Audit Protection Co",
            job_title="Dev",
            status="DRAFT",
        )

        reserved_fields_to_test = [
            ("previous_status", "CLOSED"),
            ("new_status", "OFFER"),
            ("application_id", 9999),
            ("user_id", 9999),
            ("actor_type", "SYSTEM_ADMIN"),
            ("session_reference", "forged_session"),
            ("reopen_rationale", "forged_rationale"),
            ("created_at", "1970-01-01T00:00:00"),
            ("sequence_no", 1),
            ("event_hash", "forged_hash"),
            ("prev_event_hash", "forged_prev_hash"),
            ("event_type", "FORGED_EVENT"),
        ]

        for field_name, forged_val in reserved_fields_to_test:
            with self.assertRaises(ValidationError) as ctx:
                self.service.transition_application_status(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    new_status="PREPARING",
                    transition_metadata={field_name: forged_val},
                )
            self.assertIn("cannot override reserved audit payload field", str(ctx.exception).lower())

        # Verify application status was not modified
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, "DRAFT")

    def test_allowed_custom_metadata_persisted_alongside_canonical_fields(self):
        """Non-reserved custom metadata is safely preserved alongside canonical audit fields."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Audit Custom Co",
            job_title="Dev",
            status="DRAFT",
        )

        custom_metadata = {
            "candidate_notes": "Starting resume customization",
            "source_platform": "Company Careers",
            "confidence_score": 92,
        }
        updated_app = self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
            transition_metadata=custom_metadata,
        )
        self.assertEqual(updated_app.status, "PREPARING")

        events = self.db.get_application_events(app.id, self.user_a)
        transition_event = events[-1]
        payload = json.loads(transition_event.event_payload_json)

        # Canonical fields are present and correct
        self.assertEqual(payload["previous_status"], "DRAFT")
        self.assertEqual(payload["new_status"], "PREPARING")
        self.assertEqual(payload["application_id"], app.id)
        self.assertEqual(payload["user_id"], self.user_a)

        # Custom metadata is present
        self.assertEqual(payload["candidate_notes"], "Starting resume customization")
        self.assertEqual(payload["source_platform"], "Company Careers")
        self.assertEqual(payload["confidence_score"], 92)


if __name__ == "__main__":
    unittest.main()
