"""tests/test_phase_7_2_2_4_exact_verifier.py

PHASE 7.2.2.4 — EXACT TRUSTED VERIFIER TYPE ENFORCEMENT & SESSION MANAGER CONSISTENCY

Tests:
1. Exact SessionManager type identity enforcement (type(sm) is SessionManager):
   - Constructor rejection of subclasses (even named 'SessionManager').
   - Verification-boundary defense-in-depth rejection of subclasses and proxies.
   - Successful fake verifier cannot create approvals, logs, status transitions, or timeline events.
   - Genuine exact SessionManager operates cleanly.
2. SessionManager identity consistency between HumanApprovalGate and DatabaseManager:
   - Shared instance succeeds.
   - Initially unconfigured DatabaseManager automatically wires HumanApprovalGate's instance.
   - Mismatched genuine instances reject configuration with SecurityAuthorizationError.
   - Forged subclass in DatabaseManager rejects configuration with SecurityAuthorizationError.
   - Forged subclass in HumanApprovalGate rejects configuration with SecurityAuthorizationError.
"""

import os
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    SecurityAuthorizationError,
)
from src.database.models import ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager as RealSessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class FakeSessionManagerSubclass(RealSessionManager):
    """Malicious/spoofed subclass deliberately named 'SessionManager' to attempt bypass."""
    def verify_and_consume_approval_grant(self, grant):
        return True, "Accepted by spoofed verifier subclass"


# Explicitly spoof class name to simulate deliberate evasion attempt
FakeSessionManagerSubclass.__name__ = "SessionManager"


class DuckTypedProxyVerifier:
    """Proxy object implementing verify_and_consume_approval_grant without inheritance."""
    def verify_and_consume_approval_grant(self, grant):
        return True, "Accepted by duck-typed proxy"


class TestPhase7224SubclassVerifierSubstitution(unittest.TestCase):
    """Section 3: Subclass and proxy verifier-substitution regression tests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_exact_verifier.db")
        self.session_mgr = RealSessionManager.get_instance()
        self.db = DatabaseManager(self.db_path, session_manager=self.session_mgr)
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate.one@example.com', 'h1', 's1', 'Candidate One')"
            )
        self.user_a = 1
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_one",
            candidate_name="Candidate One",
            user_id=self.user_a,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_app_and_packet(self, user_id: int, initial_status: str = "READY_FOR_REVIEW"):
        """Helper creating a test job description, resume, application, and prepared packet."""
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            raw_content="Build distributed pipelines with Spark and Python.",
        )
        res = self.db.create_user_resume(
            user_id=user_id,
            original_filename="resume.pdf",
            storage_filename="resume_stored.pdf",
            file_format="pdf",
            file_hash="dummy_hash_resume_abc123",
            file_size_bytes=2048,
        )
        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            status=initial_status,
            job_description_id=jd.id,
            resume_id=res["id"],
        )

        dummy_snapshot = {
            "application_id": app.id,
            "user_id": user_id,
            "job_description_id": jd.id,
            "original_resume_id": res["id"],
            "packet_version": 1,
            "tailored_resume": {"summary": "Experienced Data Engineer"},
            "cover_letter": "I am thrilled to apply for the Lead Data Engineer position.",
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
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, 1, ?, 'dummy_hash_resume_abc123', 'jd_snap_hash', '[]', ?, 1)
                """,
                (app.id, user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, user_id)
        return app, packet, snap_hash

    def _issue_valid_grant(self, app, packet, snap_hash):
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        v_ok, v_msg, auth_grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket,
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=snap_hash,
            approver_name="Candidate One",
        )
        self.assertTrue(v_ok, f"Grant issuance failed: {v_msg}")
        return auth_grant

    def test_subclass_constructor_rejection(self):
        """Test A: DatabaseManager constructor rejects a SessionManager subclass named 'SessionManager'."""
        subclass_inst = FakeSessionManagerSubclass()
        self.assertEqual(type(subclass_inst).__name__, "SessionManager")
        self.assertIsInstance(subclass_inst, RealSessionManager)
        self.assertIsNot(type(subclass_inst), RealSessionManager)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            DatabaseManager(self.db_path, session_manager=subclass_inst)
        self.assertIn("must be an exact SessionManager instance", str(ctx.exception))

    def test_subclass_verification_boundary_rejection(self):
        """Test B: Even if internal _session_manager is deliberately replaced with subclass, boundary rejects it."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash)

        # Force bypass of constructor by directly mutating private reference
        self.db._session_manager = FakeSessionManagerSubclass()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db._authorize_application_packet_atomic(auth_grant=grant)
        self.assertIn("must be an exact SessionManager instance", str(ctx.exception))

    def test_subclass_cannot_authorize_state_mutation(self):
        """Test C: Fake verifier subclass never mutates approvals, logs, status, or timeline events."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash)

        # Inject fake subclass directly
        self.db._session_manager = FakeSessionManagerSubclass()

        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=grant)

        # Verify zero approvals and logs created
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)

        # Status remains untouched
        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, "READY_FOR_REVIEW")

        # Zero PACKET_HUMAN_APPROVED timeline events created
        events = self.db.get_application_events(app.id, self.user_a)
        self.assertEqual(len(events), 1)  # Only APPLICATION_CREATED
        self.assertEqual(events[0].event_type, "APPLICATION_CREATED")
        valid, _ = self.db.verify_application_event_chain(app.id, self.user_a, raise_on_error=True)
        self.assertTrue(valid)

    def test_duck_typed_proxy_verifier_rejected(self):
        """Test: Duck-typed proxy verifier is rejected at constructor and boundary."""
        proxy = DuckTypedProxyVerifier()
        with self.assertRaises(SecurityAuthorizationError):
            DatabaseManager(self.db_path, session_manager=proxy)

        self.db._session_manager = proxy
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash)
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=grant)

    def test_genuine_session_manager_authorizes_successfully(self):
        """Test D: Genuine SessionManager instance with valid registered grant authorizes successfully."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash)

        approval = self.db._authorize_application_packet_atomic(auth_grant=grant)
        self.assertIsNotNone(approval)
        self.assertEqual(approval.application_id, app.id)
        self.assertEqual(approval.packet_id, packet.id)

        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, ApplicationStatus.APPROVED.value)


class TestPhase7224SessionManagerIdentityConsistency(unittest.TestCase):
    """Section 4: Enforce Session Manager Identity Consistency between Gate and DB."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_consistency.db")
        self.session_mgr = RealSessionManager.get_instance()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_shared_instance_succeeds(self):
        """Both components sharing the exact same SessionManager instance succeeds."""
        db = DatabaseManager(self.db_path, session_manager=self.session_mgr)
        gate = HumanApprovalGate(db_manager=db, session_manager=self.session_mgr)

        self.assertIs(gate.session_manager, self.session_mgr)
        self.assertIs(db.session_manager, self.session_mgr)
        self.assertIs(gate.session_manager, db.session_manager)

    def test_db_initially_lacks_instance_wires_genuine_instance(self):
        """DatabaseManager initially lacking an instance has the genuine instance wired by Gate."""
        db = DatabaseManager(self.db_path)
        self.assertIsNone(db._session_manager)

        gate = HumanApprovalGate(db_manager=db, session_manager=self.session_mgr)
        self.assertIs(db._session_manager, self.session_mgr)
        self.assertIs(db.session_manager, self.session_mgr)
        self.assertIs(gate.session_manager, db.session_manager)

    def test_db_configured_with_different_genuine_instance_raises(self):
        """DatabaseManager configured with a different genuine SessionManager raises SecurityAuthorizationError."""
        sm1 = self.session_mgr
        # Create an independent genuine SessionManager instance with distinct secret
        sm2 = RealSessionManager(server_secret=b"independent_genuine_secret_1234567890123456")
        self.assertIsNot(sm1, sm2)
        self.assertIs(type(sm1), RealSessionManager)
        self.assertIs(type(sm2), RealSessionManager)

        db = DatabaseManager(self.db_path, session_manager=sm1)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            HumanApprovalGate(db_manager=db, session_manager=sm2)
        self.assertIn("SessionManager identity mismatch", str(ctx.exception))

    def test_db_configured_with_forged_subclass_raises_in_gate(self):
        """DatabaseManager configured with a forged subclass is rejected by HumanApprovalGate."""
        db = DatabaseManager(self.db_path)
        db._session_manager = FakeSessionManagerSubclass()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            HumanApprovalGate(db_manager=db, session_manager=self.session_mgr)
        self.assertIn("must be an exact SessionManager instance", str(ctx.exception))

    def test_gate_configured_with_forged_subclass_raises(self):
        """HumanApprovalGate configured with a forged subclass is rejected immediately."""
        db = DatabaseManager(self.db_path, session_manager=self.session_mgr)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            HumanApprovalGate(db_manager=db, session_manager=FakeSessionManagerSubclass())
        self.assertIn("HumanApprovalGate.session_manager must be an exact SessionManager instance", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
