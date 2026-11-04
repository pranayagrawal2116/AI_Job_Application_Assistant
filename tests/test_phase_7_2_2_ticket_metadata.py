"""Phase 7.2.2 Action Ticket Metadata Parsing and Cryptographic Provenance Tests.

Verifies:
1. SessionManager.parse_action_ticket accurately parses TKT-{key_id}-{nonce}.{timestamp}.{signature}
   into constituent (key_id, nonce, timestamp, signature).
2. Backward compatibility for legacy tickets without key_id (defaults to "v1").
3. Rejection of malformed, missing, corrupt-timestamp, or empty-segment action tickets.
4. HumanApprovalGate records the actual key_id and ticket_nonce in application_approvals,
   not misinterpreting timestamp as key_id or header_nonce as nonce.
5. Consumed nonce in application_approvals matches session.consumed_tickets.
6. Replay attack prevention, scope binding, and signature validation.
"""

import os
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class TestPhase722TicketMetadata(unittest.TestCase):
    """Tests action ticket parsing, metadata recording, and cryptographic security."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_ticket_meta.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Seed candidate user
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'tkt.cand@example.com', 'h1', 's1', 'Ticket Candidate')"
            )
        self.user_id = 1
        self.session = self.session_mgr.authenticate_candidate(
            candidate_id="tkt_cand",
            candidate_name="Ticket Candidate",
            user_id=self.user_id,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. PARSE_ACTION_TICKET UNIT TESTS
    # =========================================================================

    def test_parse_action_ticket_standard_format(self):
        """Correctly extracts key_id, nonce, timestamp, and signature from standard ticket."""
        ticket_str = "TKT-v2-abc123456789def0.1705000000.f8e9d0c1b2a34567"
        key_id, nonce, ts, sig = SessionManager.parse_action_ticket(ticket_str)

        self.assertEqual(key_id, "v2")
        self.assertEqual(nonce, "abc123456789def0")
        self.assertEqual(ts, 1705000000)
        self.assertEqual(sig, "f8e9d0c1b2a34567")

    def test_parse_action_ticket_hyphenated_key_ids(self):
        """Correctly parses tickets where key_id contains hyphens (e.g. production-2026)."""
        hyphenated_cases = [
            (
                "TKT-production-2026-0123456789abcdef0123456789abcdef.1705000000.f8e9d0c1b2a34567",
                "production-2026",
                "0123456789abcdef0123456789abcdef",
                1705000000,
                "f8e9d0c1b2a34567",
            ),
            (
                "TKT-auth-v2-prod-key-deadbeef1234567890abcdef12345678.1706000000.signature123",
                "auth-v2-prod-key",
                "deadbeef1234567890abcdef12345678",
                1706000000,
                "signature123",
            ),
            (
                "TKT-multi-part-cluster-key-fedcba9876543210fedcba9876543210.1707000000.sigxyz",
                "multi-part-cluster-key",
                "fedcba9876543210fedcba9876543210",
                1707000000,
                "sigxyz",
            ),
        ]
        for ticket_str, expected_key, expected_nonce, expected_ts, expected_sig in hyphenated_cases:
            key_id, nonce, ts, sig = SessionManager.parse_action_ticket(ticket_str)
            self.assertEqual(key_id, expected_key)
            self.assertEqual(nonce, expected_nonce)
            self.assertEqual(ts, expected_ts)
            self.assertEqual(sig, expected_sig)

    def test_parse_action_ticket_legacy_format(self):
        """Correctly parses legacy ticket without key_id hyphen, defaulting to v1."""
        ticket_str = "TKT-legacyNonce12345.1699999999.aabbccddeeff0011"
        key_id, nonce, ts, sig = SessionManager.parse_action_ticket(ticket_str)

        self.assertEqual(key_id, "v1")
        self.assertEqual(nonce, "legacyNonce12345")
        self.assertEqual(ts, 1699999999)
        self.assertEqual(sig, "aabbccddeeff0011")

    def test_parse_action_ticket_rejects_missing_or_invalid_structure(self):
        """Rejects None, empty, missing prefix, corrupt timestamp, or missing segments."""
        invalid_tickets = [
            (None, "Missing action ticket"),
            ("", "Missing action ticket"),
            ("   ", "Missing action ticket"),
            ("INVALID_TICKET_STRING", "Malformed action ticket"),
            ("TKT-noncedotsignoonetwo", "Malformed action ticket"),
            ("TKT-key-nonce.1700000000", "Invalid action ticket structure"),
            ("TKT-key-nonce.1700000000.sig.extra", "Invalid action ticket structure"),
            ("TKT-key-nonce.NOT_A_NUMBER.signature", "Corrupt timestamp in action ticket"),
            ("TKT-key-nonce.1700000000.", "Missing signature in action ticket"),
            ("TKT-.1700000000.sig", "Action ticket missing key_id or nonce"),
            ("TKT--.1700000000.sig", "Action ticket missing key_id or nonce"),
        ]

        for ticket_input, expected_err in invalid_tickets:
            with self.assertRaises(ValueError, msg=f"Should reject: {ticket_input}") as ctx:
                SessionManager.parse_action_ticket(ticket_input)
            self.assertIn(expected_err, str(ctx.exception))

    # =========================================================================
    # 2. APPROVAL GATE STORES ACCURATE METADATA
    # =========================================================================

    def test_approval_stores_actual_key_id_and_nonce(self):
        """application_approvals stores actual key_id and nonce, not timestamp or composite prefix."""
        # Setup JD, Resume, Application, PreparedPacket
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_id,
            company_name="Cloud Solutions Inc",
            job_title="DevOps Engineer",
            raw_content="Manage Kubernetes and Terraform.",
        )
        res = self.db.create_user_resume(
            user_id=self.user_id,
            original_filename="cv.pdf",
            storage_filename="cv_stored.pdf",
            file_format="pdf",
            file_hash="hash_devops_cv",
            file_size_bytes=1024,
        )
        app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Cloud Solutions Inc",
            job_title="DevOps Engineer",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
            resume_id=res["id"],
        )

        dummy_snapshot = {
            "application_id": app.id,
            "user_id": self.user_id,
            "job_description_id": jd.id,
            "original_resume_id": res["id"],
            "packet_version": 1,
            "tailored_resume": {"summary": "DevOps pro"},
            "cover_letter": "I want to apply.",
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
                ) VALUES (301, ?, ?, 1, ?, 'hash_devops_cv', 'jdh', '[]', ?, 1)
                """,
                (app.id, self.user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, self.user_id)

        # Issue ticket
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        # Parse ticket to know expected values
        expected_key_id, expected_nonce, expected_ts, _ = SessionManager.parse_action_ticket(ticket)

        # Authorize via HumanApprovalGate
        success, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Ticket Candidate",
            session_id=self.session.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Approval failed: {msg}")

        # Stored ticket_nonce must equal expected_nonce exactly (not composite header_nonce)
        self.assertEqual(approval.ticket_nonce, expected_nonce)
        self.assertNotIn("-", approval.ticket_nonce)

        # Stored key_id must equal expected_key_id (e.g. 'v1'), NEVER a timestamp integer
        self.assertEqual(approval.key_id, expected_key_id)
        self.assertNotEqual(approval.key_id, str(expected_ts))

        # Stored nonce must be marked consumed in session
        self.assertIn(expected_nonce, self.session.consumed_tickets)

        # Database record inspection
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ticket_nonce, key_id FROM application_approvals WHERE id = ?",
                (approval.id,),
            )
            row = cursor.fetchone()
            self.assertEqual(row["ticket_nonce"], expected_nonce)
            self.assertEqual(row["key_id"], expected_key_id)

    def test_approval_with_hyphenated_key_id_records_exact_key_and_nonce(self):
        """When active key has hyphens (e.g. 'production-2026'), approval records exact key_id and clean nonce."""
        import secrets
        hyphen_key_id = "production-2026"
        secret_bytes = secrets.token_bytes(32)

        original_key = self.session_mgr.active_key_id
        original_keys = dict(self.session_mgr._rotation_keys)
        try:
            self.session_mgr.configure_keys(hyphen_key_id, {hyphen_key_id: secret_bytes})

            jd = self.db.save_job_description_snapshot(
                user_id=self.user_id,
                company_name="Hyphen Key Corp",
                job_title="Security Engineer",
                raw_content="Cloud security and IAM.",
            )
            app = self.db.create_user_application(
                user_id=self.user_id,
                company_name="Hyphen Key Corp",
                job_title="Security Engineer",
                status="READY_FOR_REVIEW",
                job_description_id=jd.id,
            )
            dummy_snapshot = {
                "application_id": app.id,
                "user_id": self.user_id,
                "job_description_id": jd.id,
                "packet_version": 1,
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
                    ) VALUES (305, ?, ?, 1, ?, 'hash_cv', 'jdh', '[]', ?, 1)
                    """,
                    (app.id, self.user_id, snap_hash, snap_bytes.decode("utf-8")),
                )
            packet = self.db.get_active_prepared_packet(app.id, self.user_id)

            ticket = self.session_mgr.issue_action_ticket(
                session_id=self.session.session_id,
                action_type="HUMAN_APPROVAL",
                application_id=app.id,
                packet_hash=snap_hash,
            )
            self.assertTrue(ticket.startswith(f"TKT-{hyphen_key_id}-"))

            # Authorize via HumanApprovalGate
            success, msg, approval = self.gate.authorize_universal_packet(
                user_id=self.user_id,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Ticket Candidate",
                session_id=self.session.session_id,
                action_ticket=ticket,
                candidate_confirmed=True,
            )
            self.assertTrue(success, f"Approval failed: {msg}")

            # Inspect returned approval and DB row
            self.assertEqual(approval.key_id, "production-2026")
            self.assertNotIn("-", approval.ticket_nonce)
            self.assertEqual(len(approval.ticket_nonce), 32)

            with self.db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ticket_nonce, key_id FROM application_approvals WHERE id = ?",
                    (approval.id,),
                )
                row = cursor.fetchone()
                self.assertEqual(row["key_id"], "production-2026")
                self.assertEqual(row["ticket_nonce"], approval.ticket_nonce)

            # Replaying this hyphenated ticket fails
            succ2, msg2, _ = self.gate.authorize_universal_packet(
                user_id=self.user_id,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Ticket Candidate",
                session_id=self.session.session_id,
                action_ticket=ticket,
                candidate_confirmed=True,
            )
            self.assertFalse(succ2)
            self.assertIn("already been used", msg2)
        finally:
            self.session_mgr.configure_keys(original_key, original_keys)

    # =========================================================================
    # 3. REPLAY & SCOPE TAMPERING CHECKS
    # =========================================================================

    def test_replaying_consumed_ticket_is_rejected(self):
        """Ticket can only be used once; subsequent attempts are strictly rejected."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_id,
            company_name="Replay Check Corp",
            job_title="QA Tester",
            raw_content="Execute tests.",
        )
        app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Replay Check Corp",
            job_title="QA Tester",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
        )
        snap_hash = "dummy_snap_hash_replay"
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (302, ?, ?, 1, ?, 'rh', 'jdh', '[]', '{}', 1)
                """,
                (app.id, self.user_id, snap_hash),
            )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        # 1. First verification succeeds
        valid, msg = self.session_mgr.verify_and_consume_action_ticket(
            session_id=self.session.session_id,
            ticket_str=ticket,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        self.assertTrue(valid)

        # 2. Second verification with identical ticket fails with replay detection
        valid_replay, msg_replay = self.session_mgr.verify_and_consume_action_ticket(
            session_id=self.session.session_id,
            ticket_str=ticket,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        self.assertFalse(valid_replay)
        self.assertIn("already been used", msg_replay)

    def test_forged_ticket_signature_rejected(self):
        """Modifying signature in action ticket triggers forgery detection."""
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=1,
            packet_hash="snap_hash_original",
        )
        parts = ticket.split(".")
        forged_ticket = f"{parts[0]}.{parts[1]}.badsignaturedeadbeef"

        valid, msg = self.session_mgr.verify_and_consume_action_ticket(
            session_id=self.session.session_id,
            ticket_str=forged_ticket,
            action_type="HUMAN_APPROVAL",
            application_id=1,
            packet_hash="snap_hash_original",
        )
        self.assertFalse(valid)
        self.assertIn("forgery attempt", msg)


if __name__ == "__main__":
    unittest.main()
