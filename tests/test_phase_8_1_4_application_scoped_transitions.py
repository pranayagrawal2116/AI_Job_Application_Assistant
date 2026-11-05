"""Comprehensive regression and verification test suite for Phase 8.1.4:
Application-Scoped Status Transitions & Final Trust-Boundary Remediation.

Tests cover:
- Finding A: Application-scoped status updates & multi-tenant application isolation
- Finding B: Fail-closed legacy approval lookups with strict candidate ownership
- Finding C: Descriptor-relative candidate file verification and traversal hardening
- Finding D: End-to-end regression, audit log scoping, and DashboardService integration
"""

import errno
import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest.mock import MagicMock, patch

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    DatabaseError,
    FileSecurityError,
    InvalidFileFormatError,
    InvalidStatusTransitionError,
    KeyRevokedError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.lifecycle.state_machine import ApplicationStateMachine, ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import KeyRotationManager, SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash

PDF_HEADER = b"%PDF-1.4\n%phase814 test content inside user storage\n"


class BasePhase814TestCase(unittest.TestCase):
    """Shared fixture for Phase 8.1.4 tests."""

    def setUp(self):
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = str(self.base_dir / "test_phase_8_1_4.db")
        self.storage_dir = self.base_dir / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager(
            server_secret=b"test_secret_32_bytes_long_phase814__",
            db_manager=self.db,
        )
        SessionManager._instance = self.session_mgr

        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.gate = HumanApprovalGate(
            db_manager=self.db,
            session_manager=self.session_mgr,
            file_validator=self.file_validator,
        )

        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'cand1@example.com', 'h1', 's1', 'Candidate One')"
            )
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'cand2@example.com', 'h2', 's2', 'Candidate Two')"
            )
        self.user_1 = 1
        self.user_2 = 2

        self.session_1 = self.session_mgr.authenticate_candidate(
            candidate_id="cand_1",
            candidate_name="Candidate One",
            user_id=self.user_1,
        )
        self.session_2 = self.session_mgr.authenticate_candidate(
            candidate_id="cand_2",
            candidate_name="Candidate Two",
            user_id=self.user_2,
        )

        self.user1_dir = self.storage_dir / "1"
        self.user1_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "applications").mkdir(parents=True, exist_ok=True)

        self.user2_dir = self.storage_dir / "2"
        self.user2_dir.mkdir(parents=True, exist_ok=True)
        (self.user2_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user2_dir / "applications").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        SessionManager.reset_instance()
        self.temp_dir.cleanup()

    def _create_verified_application(self, user_id: int, job_id: Optional[int] = None):
        """Helper to create a complete verified application packet."""
        prof = self.db.save_user_candidate_profile(
            user_id=user_id,
            profile_data={
                "full_name": f"Candidate {user_id}",
                "headline": "Software Engineer",
                "technical_skills": ["Python", "SQL"],
            },
        )
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            raw_content="Develop software in Python.",
        )
        user_res_dir = self.storage_dir / str(user_id) / "resumes"
        user_res_dir.mkdir(parents=True, exist_ok=True)
        res_file = user_res_dir / "source.pdf"
        res_file.write_bytes(PDF_HEADER)
        res_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        res_record = self.db.create_user_resume(
            user_id=user_id,
            original_filename="source.pdf",
            storage_filename=str(res_file),
            file_format="pdf",
            file_hash=res_hash,
            file_size_bytes=len(PDF_HEADER),
        )

        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
            resume_id=res_record["id"],
            job_id=job_id,
        )

        user_app_dir = self.storage_dir / str(user_id) / "applications" / str(app.id)
        user_app_dir.mkdir(parents=True, exist_ok=True)

        tailored_file = user_app_dir / "tailored.pdf"
        tailored_file.write_bytes(PDF_HEADER)
        tailored_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        cover_file = user_app_dir / "cover.pdf"
        cover_file.write_bytes(PDF_HEADER)
        cover_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        tailored_doc = GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(tailored_file),
            filename="tailored.pdf",
            file_hash=tailored_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )
        cover_doc = GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(cover_file),
            filename="cover.pdf",
            file_hash=cover_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )

        tailored_model = TailoredResume(
            user_id=user_id,
            target_role="Software Engineer",
            target_company="Acme Corp",
            professional_summary="Engineer with Python skills",
        )
        cover_model = CoverLetter(
            user_id=user_id,
            target_company="Acme Corp",
            target_role="Software Engineer",
            letter_text="Application letter text",
            paragraphs=["Application letter text"],
            file_path=str(cover_file),
        )

        packet = self.gate.prepare_universal_packet(
            user_id=user_id,
            application_id=app.id,
            original_resume_id=res_record["id"],
            original_resume_hash=res_hash,
            tailored_resume=tailored_model,
            tailored_resume_pdf_doc=tailored_doc,
            cover_letter=cover_model,
            cover_letter_pdf_doc=cover_doc,
            qa_packet=ScreeningQAPacket(user_id=user_id, job_description_id=jd.id, questions=[]),
            job_description_snapshot_hash=jd.snapshot_hash,
            candidate_profile_version=prof.get("version"),
            candidate_profile_hash=prof.get("profile_hash"),
        )
        refreshed_app = self.db.get_application_by_id(app.id)
        return refreshed_app, packet, packet.packet_version_hash, jd


# =============================================================================
# FINDING A: APPLICATION-SCOPED STATUS UPDATES & MULTI-TENANT ISOLATION
# =============================================================================

class TestFindingAApplicationScopedStatusUpdates(BasePhase814TestCase):
    """Verifies that status mutations, submissions, and lookups are strictly application-scoped."""

    def test_two_candidates_same_catalog_job_manual_submission(self):
        """When Candidate A submits for Job 555, Candidate B's application remains untouched."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (555, 'Target Co', 'ML Engineer', 'https://target.co/jobs/555', 'lever')"
            )

        app_a, packet_a, snap_hash_a, _ = self._create_verified_application(self.user_1, job_id=555)
        app_b, packet_b, snap_hash_b, _ = self._create_verified_application(self.user_2, job_id=555)

        # Candidate A gets approval and ticket
        ticket_a = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_a.id,
            packet_hash=snap_hash_a,
        )
        succ_a, msg_a, _ = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app_a.id,
            packet_id=packet_a.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket_a,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_a, f"Authorization failed for Candidate A: {msg_a}")

        # Candidate A submits application manually
        sub_ticket_a = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app_a.id,
            packet_hash=snap_hash_a,
        )
        succ_sub, msg_sub = self.gate.record_manual_submission(
            application_id=app_a.id,
            job_id=555,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            submission_ticket=sub_ticket_a,
            packet_version_hash=snap_hash_a,
            submission_notes="Submitted via portal",
        )
        self.assertTrue(succ_sub, f"Submission failed for Candidate A: {msg_sub}")

        # Verify Candidate A is APPLIED
        refreshed_a = self.db.get_application_by_id(app_a.id)
        self.assertIsNotNone(refreshed_a)
        self.assertEqual(refreshed_a.status, ApplicationStatus.APPLIED.value)

        # Verify Candidate B remains in original status (untouched)
        refreshed_b = self.db.get_application_by_id(app_b.id)
        self.assertIsNotNone(refreshed_b)
        self.assertEqual(refreshed_b.status, app_b.status)

        # Verify Candidate B received zero audit logs
        logs_b = self.db.get_application_logs(application_id=app_b.id, user_id=self.user_2)
        self.assertEqual(len(logs_b), 0)

        # Verify Candidate B cannot submit using Candidate A's ticket or approval
        succ_b_hack, msg_b_hack = self.gate.record_manual_submission(
            application_id=app_b.id,
            job_id=555,
            approver_name="Candidate Two",
            session_id=self.session_2.session_id,
            submission_ticket=sub_ticket_a,  # Candidate A's ticket
            packet_version_hash=snap_hash_b,
        )
        self.assertFalse(succ_b_hack)
        self.assertIn("rejected", msg_b_hack.lower())

    def test_order_invariance_candidate_b_inserted_first(self):
        """Order invariance: Candidate B inserted first, Candidate A submitting only touches Candidate A."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (556, 'Target Co', 'Data Scientist', 'https://target.co/jobs/556', 'greenhouse')"
            )

        # Candidate B created first
        app_b, packet_b, snap_hash_b, _ = self._create_verified_application(self.user_2, job_id=556)
        # Candidate A created second
        app_a, packet_a, snap_hash_a, _ = self._create_verified_application(self.user_1, job_id=556)

        self.assertLess(app_b.id, app_a.id)

        # Candidate A gets approval and ticket
        ticket_a = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_a.id,
            packet_hash=snap_hash_a,
        )
        succ_a, msg_a, _ = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app_a.id,
            packet_id=packet_a.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket_a,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_a, f"Authorization failed: {msg_a}")

        sub_ticket_a = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app_a.id,
            packet_hash=snap_hash_a,
        )
        succ_sub, msg_sub = self.gate.record_manual_submission(
            application_id=app_a.id,
            job_id=556,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            submission_ticket=sub_ticket_a,
            packet_version_hash=snap_hash_a,
        )
        self.assertTrue(succ_sub, f"Submission failed: {msg_sub}")

        # Candidate A is APPLIED
        self.assertEqual(self.db.get_application_by_id(app_a.id).status, ApplicationStatus.APPLIED.value)
        # Candidate B is unchanged
        self.assertEqual(self.db.get_application_by_id(app_b.id).status, app_b.status)

    def test_update_application_status_requires_matching_user_id(self):
        """update_application_status fails closed when user_id is missing or mismatched."""
        app, _, _, _ = self._create_verified_application(self.user_1)

        # 1. Missing user_id for candidate-owned application raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx_none:
            self.db.update_application_status(
                application_id=app.id,
                new_status=ApplicationStatus.WITHDRAWN.value,
                user_id=None,
            )
        self.assertIn("requires authenticated user_id", str(ctx_none.exception))

        # 2. Wrong user_id raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx_wrong:
            self.db.update_application_status(
                application_id=app.id,
                new_status=ApplicationStatus.WITHDRAWN.value,
                user_id=self.user_2,
            )
        self.assertIn("is owned by user", str(ctx_wrong.exception).lower())

        # 3. Matching user_id succeeds
        updated = self.db.update_application_status(
            application_id=app.id,
            new_status=ApplicationStatus.WITHDRAWN.value,
            user_id=self.user_1,
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, ApplicationStatus.WITHDRAWN.value)

    def test_get_application_by_job_id_multi_user_ambiguity(self):
        """get_application_by_job_id fails closed when user_id is omitted on multi-user jobs."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (557, 'Target Co', 'Backend Eng', 'https://target.co/jobs/557', 'direct')"
            )

        app1, _, _, _ = self._create_verified_application(self.user_1, job_id=557)
        app2, _, _, _ = self._create_verified_application(self.user_2, job_id=557)

        # Scoped with user 1 returns app1
        res1 = self.db.get_application_by_job_id(job_id=557, user_id=self.user_1)
        self.assertIsNotNone(res1)
        self.assertEqual(res1.id, app1.id)

        # Scoped with user 2 returns app2
        res2 = self.db.get_application_by_job_id(job_id=557, user_id=self.user_2)
        self.assertIsNotNone(res2)
        self.assertEqual(res2.id, app2.id)

        # Without user_id raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.get_application_by_job_id(job_id=557, user_id=None)
        self.assertIn("multiple applications exist", str(ctx.exception).lower())

    def test_get_application_by_job_id_candidate_owned_single_app_requires_user_id(self):
        """Single candidate-owned application resolves properly with scoping and preserves isolation."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (558, 'Target Co', 'QA Lead', 'https://target.co/jobs/558', 'direct')"
            )
        app1, _, _, _ = self._create_verified_application(self.user_1, job_id=558)

        # Scoped with user 1 returns app1
        res1 = self.db.get_application_by_job_id(job_id=558, user_id=self.user_1)
        self.assertIsNotNone(res1)
        self.assertEqual(res1.id, app1.id)

        # Scoped with user 2 returns None (isolated)
        res2 = self.db.get_application_by_job_id(job_id=558, user_id=self.user_2)
        self.assertIsNone(res2)

        # Single app without user_id returns app1 for backwards compatibility
        res_compat = self.db.get_application_by_job_id(job_id=558, user_id=None)
        self.assertIsNotNone(res_compat)
        self.assertEqual(res_compat.id, app1.id)

    def test_get_application_by_id_direct(self):
        """get_application_by_id fetches exact application record."""
        app1, _, _, _ = self._create_verified_application(self.user_1)
        fetched = self.db.get_application_by_id(app1.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, app1.id)
        self.assertEqual(fetched.user_id, self.user_1)

        # Non-existent ID returns None
        self.assertIsNone(self.db.get_application_by_id(999999))

    def test_record_manual_submission_cross_user_rejection(self):
        """Candidate 1 cannot call record_manual_submission on Candidate 2's application."""
        app2, packet2, snap_hash2, _ = self._create_verified_application(self.user_2)

        ticket_1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app2.id,
            packet_hash=snap_hash2,
        )

        succ, msg = self.gate.record_manual_submission(
            application_id=app2.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,  # User 1 session
            submission_ticket=ticket_1,
            packet_version_hash=snap_hash2,
        )
        self.assertFalse(succ)
        self.assertIn("does not belong to authenticated candidate", msg)

    def test_concurrent_status_mutation_rowcount_check(self):
        """If application status changed concurrently, update_application_status fails closed with DatabaseError."""
        app, _, _, _ = self._create_verified_application(self.user_1)

        # Intercept connection cursor so UPDATE executes with cursor.rowcount = 0
        original_conn = self.db.connection

        class MockCursorProxy:
            def __init__(self, real_cursor):
                self._real = real_cursor
                self._simulated_rowcount = None

            @property
            def rowcount(self):
                if self._simulated_rowcount is not None:
                    return self._simulated_rowcount
                return self._real.rowcount

            def __getattr__(self, name):
                return getattr(self._real, name)

            def execute(self, sql, *args, **kwargs):
                res = self._real.execute(sql, *args, **kwargs)
                if "UPDATE applications SET" in sql:
                    # Simulate 0 rows updated due to concurrent modification
                    self._simulated_rowcount = 0
                return res

        class MockConnProxy:
            def __init__(self, real_conn):
                self._real = real_conn

            def __getattr__(self, name):
                return getattr(self._real, name)

            def cursor(self):
                return MockCursorProxy(self._real.cursor())

        from contextlib import contextmanager

        real_transaction = self.db.transaction

        @contextmanager
        def mock_transaction():
            with real_transaction() as conn:
                yield MockConnProxy(conn)

        with patch.object(self.db, "transaction", mock_transaction):
            with self.assertRaises(DatabaseError) as ctx:
                self.db.update_application_status(
                    application_id=app.id,
                    new_status=ApplicationStatus.WITHDRAWN.value,
                    user_id=self.user_1,
                )
            self.assertIn("Possible concurrent modification", str(ctx.exception))

    def test_transactional_rollback_on_audit_failure(self):
        """Status mutation rolls back completely if audit log insertion fails."""
        app, _, _, _ = self._create_verified_application(self.user_1)
        orig_status = app.status

        # Create a trigger that aborts insertion into application_logs
        with self.db.transaction() as conn:
            conn.cursor().execute("""
                CREATE TRIGGER test_fail_audit_insert
                BEFORE INSERT ON application_logs
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated audit log trigger failure');
                END;
            """)

        try:
            with self.assertRaises((DatabaseError, Exception)):
                self.db.update_application_status(
                    application_id=app.id,
                    new_status=ApplicationStatus.WITHDRAWN.value,
                    user_id=self.user_1,
                )

            # Status must remain orig_status due to transaction rollback
            refreshed = self.db.get_application_by_id(app.id)
            self.assertEqual(refreshed.status, orig_status)
        finally:
            with self.db.transaction() as conn:
                conn.cursor().execute("DROP TRIGGER IF EXISTS test_fail_audit_insert")


# =============================================================================
# FINDING B: FAIL-CLOSED LEGACY APPROVAL LOOKUPS
# =============================================================================

class TestFindingBFailClosedLegacyApprovalLookup(BasePhase814TestCase):
    """Verifies that has_valid_human_approval strictly checks candidate ownership on legacy paths."""

    def test_legacy_approval_lookup_rejects_missing_zero_negative_invalid_user_id(self):
        """Candidate-owned legacy approval lookup rejects user_id=None, 0, -1, invalid string, or wrong user."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (600, 'Legacy Co', 'Legacy Role', 'https://legacy.co/600', 'direct')"
            )
            # Create candidate-owned application without packets
            conn.cursor().execute(
                "INSERT INTO applications (id, job_id, user_id, company_name, job_title, status) "
                "VALUES (6001, 600, 1, 'Legacy Co', 'Legacy Role', 'Awaiting Approval')"
            )

        # Record explicit human approval for user 1
        self.db.record_human_approval(
            job_id=600,
            application_id=6001,
            approver_name="Candidate One",
            approver_id="user_1",
            user_id=1,
        )

        # 1. user_id=None -> False
        self.assertFalse(self.db.has_valid_human_approval(job_id=600, user_id=None))

        # 2. user_id=0 -> False
        self.assertFalse(self.db.has_valid_human_approval(job_id=600, user_id=0))

        # 3. user_id=-1 -> False
        self.assertFalse(self.db.has_valid_human_approval(job_id=600, user_id=-1))

        # 4. user_id="invalid" -> False
        self.assertFalse(self.db.has_valid_human_approval(job_id=600, user_id="invalid"))

        # 5. user_id=2 (wrong user) -> False
        self.assertFalse(self.db.has_valid_human_approval(job_id=600, user_id=self.user_2))

        # 6. user_id=1 (matching user) -> True
        self.assertTrue(self.db.has_valid_human_approval(job_id=600, user_id=self.user_1))

    def test_unowned_application_rejects_candidate_user_id(self):
        """Unowned legacy application (user_id IS NULL) rejects candidate user_id."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) "
                "VALUES (601, 'Public Co', 'Public Role', 'https://pub.co/601', 'direct')"
            )

        # Mock query returning unowned legacy application row (user_id=None)
        unowned_app_row = {"id": 6002, "job_id": 601, "user_id": None}

        real_conn = self.db.connection

        class UnownedAppCursorProxy:
            def __init__(self, real_cursor):
                self._real = real_cursor

            def __getattr__(self, name):
                return getattr(self._real, name)

            def fetchall(self):
                # When querying applications for job 601, return the unowned row
                return [unowned_app_row]

            def fetchone(self):
                return {"pkt_count": 0}

        class UnownedConnProxy:
            def __init__(self, real_c):
                self._real = real_c

            def __getattr__(self, name):
                return getattr(self._real, name)

            def cursor(self):
                return UnownedAppCursorProxy(self._real.cursor())

        from contextlib import contextmanager

        @contextmanager
        def mock_conn():
            with real_conn() as c:
                yield UnownedConnProxy(c)

        with patch.object(self.db, "connection", mock_conn):
            # A candidate user_id passed to unowned application fails closed
            self.assertFalse(self.db.has_valid_human_approval(job_id=601, user_id=self.user_1))

        # A non-existent job also fails closed
        self.assertFalse(self.db.has_valid_human_approval(job_id=99999, user_id=self.user_1))

    def test_legacy_fallback_blocked_when_packets_exist(self):
        """Applications with prepared packets must never fall back to legacy approval logs."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)

        # Record human approval in logs, but NO row in application_approvals
        self.db.record_human_approval(
            job_id=app.job_id,
            application_id=app.id,
            approver_name="Candidate One",
            user_id=self.user_1,
        )

        # Because app has prepared_packets, it must NOT fall back to application_logs
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))


# =============================================================================
# FINDING C: DESCRIPTOR-RELATIVE FILE VERIFICATION HARDENING
# =============================================================================

class TestFindingCDescriptorRelativeFileVerification(BasePhase814TestCase):
    """Verifies descriptor-relative traversal, fstat verification, and symlink defenses."""

    def test_descriptor_relative_valid_file_read(self):
        """Valid file inside candidate storage resolves and validates cleanly."""
        target_file = self.user1_dir / "resumes" / "valid_resume.pdf"
        target_file.write_bytes(PDF_HEADER)
        file_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        res_path, content, computed_hash, computed_size = self.file_validator.resolve_and_verify_candidate_file(
            user_id=self.user_1,
            file_path=str(target_file),
            expected_hash=file_hash,
            expected_size=len(PDF_HEADER),
            expected_format="pdf",
        )
        self.assertEqual(content, PDF_HEADER)
        self.assertEqual(computed_size, len(PDF_HEADER))
        self.assertEqual(computed_hash, file_hash)

    def test_descriptor_relative_intermediate_symlink_rejected(self):
        """Intermediate directory symlink within candidate storage is rejected with FileSecurityError."""
        outside_dir = self.base_dir / "outside_dir"
        outside_dir.mkdir(parents=True, exist_ok=True)
        secret_file = outside_dir / "secret.pdf"
        secret_file.write_bytes(PDF_HEADER)

        symlink_dir = self.user1_dir / "symlink_dir"
        symlink_dir.symlink_to(outside_dir)

        fake_target = symlink_dir / "secret.pdf"
        file_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(fake_target),
                expected_hash=file_hash,
                expected_size=len(PDF_HEADER),
                expected_format="pdf",
            )
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_descriptor_relative_final_file_symlink_rejected(self):
        """Final file being a symlink is rejected with FileSecurityError."""
        outside_file = self.base_dir / "outside_file.pdf"
        outside_file.write_bytes(PDF_HEADER)

        symlink_file = self.user1_dir / "resumes" / "symlink_target.pdf"
        symlink_file.symlink_to(outside_file)
        file_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(symlink_file),
                expected_hash=file_hash,
                expected_size=len(PDF_HEADER),
                expected_format="pdf",
            )
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_descriptor_relative_non_regular_file_rejected(self):
        """A directory passed as a file path is rejected by fstat ISREG check."""
        sub_dir = self.user1_dir / "resumes" / "not_a_file"
        sub_dir.mkdir(parents=True, exist_ok=True)

        with self.assertRaises((ValidationError, FileSecurityError)) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(sub_dir),
            )
        self.assertIn("regular file", str(ctx.exception).lower())

    def test_descriptor_relative_toctou_parent_replacement_simulation(self):
        """Descriptor-relative traversal opens dir_fd with O_NOFOLLOW preventing TOCTOU redirect."""
        # Create a deep directory structure
        deep_dir = self.user1_dir / "level1" / "level2"
        deep_dir.mkdir(parents=True, exist_ok=True)
        deep_file = deep_dir / "doc.pdf"
        deep_file.write_bytes(PDF_HEADER)
        file_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        # Normal read passes
        res_path, content, computed_hash, computed_size = self.file_validator.resolve_and_verify_candidate_file(
            user_id=self.user_1,
            file_path=str(deep_file),
            expected_hash=file_hash,
            expected_size=len(PDF_HEADER),
            expected_format="pdf",
        )
        self.assertEqual(content, PDF_HEADER)

        # Replace level1 with a symlink pointing to another location
        evil_dir = self.base_dir / "evil_level1"
        evil_dir.mkdir(parents=True, exist_ok=True)
        (evil_dir / "level2").mkdir(parents=True, exist_ok=True)
        evil_file = evil_dir / "level2" / "doc.pdf"
        evil_file.write_bytes(PDF_HEADER)

        shutil.rmtree(self.user1_dir / "level1")
        (self.user1_dir / "level1").symlink_to(evil_dir)

        # Now attempting to read must be blocked
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(deep_file),
                expected_hash=file_hash,
                expected_size=len(PDF_HEADER),
                expected_format="pdf",
            )
        self.assertTrue(
            "symlink" in str(ctx.exception).lower() or "symbolic link" in str(ctx.exception).lower()
        )


# =============================================================================
# FINDING D: AUDIT SCOPING & DASHBOARD SERVICE INTEGRATION
# =============================================================================

class TestFindingDAuditScopingAndDashboardIntegration(BasePhase814TestCase):
    """Verifies that audit logging and DashboardService transitions are strictly scoped."""

    def test_application_logs_audit_scoping_by_application_and_user(self):
        """get_application_logs strictly isolates records by application_id and user_id."""
        app1, _, _, _ = self._create_verified_application(self.user_1)
        app2, _, _, _ = self._create_verified_application(self.user_2)

        # Update app1
        self.db.update_application_status(
            application_id=app1.id,
            new_status=ApplicationStatus.WITHDRAWN.value,
            user_id=self.user_1,
            notes="Withdrawn User 1",
        )

        # Update app2
        self.db.update_application_status(
            application_id=app2.id,
            new_status=ApplicationStatus.WITHDRAWN.value,
            user_id=self.user_2,
            notes="Withdrawn User 2",
        )

        # App 1 logs only show User 1 events
        logs_1 = self.db.get_application_logs(application_id=app1.id, user_id=self.user_1)
        self.assertTrue(len(logs_1) >= 1)
        for log in logs_1:
            self.assertEqual(log.user_id, self.user_1)
            self.assertEqual(log.application_id, app1.id)

        # App 2 logs only show User 2 events
        logs_2 = self.db.get_application_logs(application_id=app2.id, user_id=self.user_2)
        self.assertTrue(len(logs_2) >= 1)
        for log in logs_2:
            self.assertEqual(log.user_id, self.user_2)
            self.assertEqual(log.application_id, app2.id)

    def test_dashboard_service_scoped_status_updates(self):
        """DashboardService delegates application_id and user_id to db_manager."""
        service = DashboardService(db_manager=self.db)
        app1, _, _, _ = self._create_verified_application(self.user_1)

        succ = service.update_application_status(
            job_id=app1.job_id,
            application_id=app1.id,
            user_id=self.user_1,
            new_status=ApplicationStatus.WITHDRAWN.value,
            notes="Dashboard withdrawn",
        )
        self.assertTrue(succ)
        refreshed = self.db.get_application_by_id(app1.id)
        self.assertEqual(refreshed.status, ApplicationStatus.WITHDRAWN.value)

    def test_dashboard_service_scoped_manual_submission(self):
        """DashboardService.confirm_manual_submission enforces application_id and user_id."""
        service = DashboardService(db_manager=self.db)
        app1, packet1, snap_hash1, _ = self._create_verified_application(self.user_1)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app1.id,
            packet_hash=snap_hash1,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app1.id,
            packet_id=packet1.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )

        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app1.id,
            packet_hash=snap_hash1,
        )

        succ, msg = service.confirm_manual_submission(
            job_id=app1.job_id,
            application_id=app1.id,
            user_id=self.user_1,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            submission_ticket=sub_ticket,
            packet_version_hash=snap_hash1,
            submission_notes="Submitted via DashboardService",
        )
        self.assertTrue(succ, f"DashboardService manual submission failed: {msg}")
        self.assertEqual(self.db.get_application_by_id(app1.id).status, ApplicationStatus.APPLIED.value)


if __name__ == "__main__":
    unittest.main()
