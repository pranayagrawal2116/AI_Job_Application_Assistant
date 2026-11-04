"""Comprehensive tests for Phase 7.3.2.2: Application Lifecycle Timeline & Read-Only Approved Packet Review.

Covers:
1. Workstream A — Application Lifecycle Timeline:
   - Authenticated candidate timeline retrieval.
   - Session authentication rejection (missing, invalid, expired, unbound).
   - Cross-user application isolation (ApplicationNotFoundError).
   - Missing application handling.
   - Authoritative chronological sequence ordering preservation.
   - Valid event chain reporting ("Audit hash-chain consistency verified").
   - Tampered event payload detection ("Audit hash-chain inconsistency detected").
   - Broken hash linkage detection ("Audit hash-chain inconsistency detected").
   - Non-mutating read-only guarantee.

2. Workstream B — Historical Prepared Packet Review:
   - Candidate-scoped packet revision listing.
   - Cross-user and cross-application packet isolation.
   - Historical inactive revision visibility and identification.
   - Active revision identification.
   - Stable reverse chronological ordering (latest revision first).
   - Legacy packet identification (is_legacy=True).
   - Missing packet history handled cleanly.
   - Non-mutating listing guarantee.

3. Workstream C — Packet Detail & Approval Provenance:
   - Candidate-scoped packet detail retrieval.
   - Cross-user packet detail rejection.
   - Cross-application packet detail rejection.
   - Historical inactive packet read-only integrity evaluation without requiring active status.
   - Tampered canonical snapshot detection.
   - Incorrect packet version hash detection.
   - Exact approval provenance (matching exact packet ID, version hash, application ID).
   - Isolation from application status 'APPROVED' when exact packet approval is absent.
   - Consumed and unconsumed approval state accuracy.
   - Non-fabrication of missing approvals and legacy metadata.
   - Non-mutating detail inspection guarantee.

4. Workstream D — Secure PDF/DOCX Packet Document Download:
   - Mandatory 14-step authorization sequence.
   - Valid PDF retrieval with correct MIME type and sanitized filename.
   - Valid DOCX retrieval with correct MIME type and sanitized filename.
   - Unauthenticated and cross-user download rejection.
   - Cross-application packet download rejection.
   - Missing document on disk handling (FileNotFoundError).
   - Missing authoritative hash in manifest rejection (SecurityAuthorizationError).
   - Tampered file bytes on disk rejection (hash mismatch).
   - Unsupported document extension/type rejection (ValidationError).
   - File extension/content magic bytes mismatch rejection (InvalidFileFormatError).
   - Absolute path substitution escaping candidate sandbox rejection.
   - Path traversal ('..') rejection.
   - Symlink escape rejection.
   - Non-mutating download guarantee.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    InvalidFileFormatError,
    InvalidSessionError,
    SecurityAuthorizationError,
    SessionExpiredError,
    ValidationError,
)
from src.database.models import PreparedPacket
from src.security.session_manager import SessionManager


class BaseTimelinePacketReviewTest(unittest.TestCase):
    """Base fixture setting up isolated SQLite database, test candidates, and authenticated sessions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_timeline_packet.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
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

        # Isolated storage base for documents
        self.storage_base = Path(self.temp_dir.name) / "users"
        self.user_a_storage = self.storage_base / str(self.user_a)
        self.user_b_storage = self.storage_base / str(self.user_b)
        self.user_a_storage.mkdir(parents=True, exist_ok=True)
        self.user_b_storage.mkdir(parents=True, exist_ok=True)

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.storage_base,
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
    ) -> int:
        """Helper to directly insert an application."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (user_id, company, title, status),
            )
            return cursor.lastrowid

    def _create_packet(
        self,
        application_id: int,
        user_id: int,
        version_num: int = 1,
        is_active: bool = True,
        snapshot_payload: Optional[Dict[str, Any]] = None,
        tailored_resume_path: Optional[str] = None,
        tailored_resume_hash: Optional[str] = None,
        cover_letter_path: Optional[str] = None,
        cover_letter_hash: Optional[str] = None,
        attachments_manifest: Optional[List[Dict[str, Any]]] = None,
        is_legacy: bool = False,
    ) -> PreparedPacket:
        """Helper to insert a prepared packet revision."""
        if is_legacy:
            canonical_snapshot_json = None
            packet_version_hash = "legacy_packet_hash_" + hashlib.sha256(f"{application_id}_{version_num}".encode()).hexdigest()[:16]
        else:
            payload = snapshot_payload or {
                "application_id": application_id,
                "user_id": user_id,
                "packet_version": version_num,
                "tailored_resume": {"name": "Alice Candidate", "summary": "Sample summary"},
                "cover_letter": {"letter_text": "Sample letter text"},
                "screening_questions": [],
                "attachments_manifest": attachments_manifest or [],
            }
            canonical_snapshot_json = json.dumps(payload, sort_keys=True)
            packet_version_hash = hashlib.sha256(canonical_snapshot_json.encode("utf-8")).hexdigest()

        pkt = self.db.create_prepared_packet(
            application_id=application_id,
            user_id=user_id,
            version_num=version_num,
            packet_version_hash=packet_version_hash,
            original_resume_hash="resume_hash_123",
            job_description_snapshot_hash="jd_hash_123",
            screening_answers=[],
            canonical_snapshot_json=canonical_snapshot_json,
            tailored_resume_path=tailored_resume_path,
            tailored_resume_hash=tailored_resume_hash,
            cover_letter_path=cover_letter_path,
            cover_letter_hash=cover_letter_hash,
            attachments_manifest=attachments_manifest,
        )
        if not is_active:
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE prepared_packets SET is_active_revision = 0 WHERE id = ?",
                    (pkt.id,),
                )
            pkt.is_active_revision = False
        return pkt

    def _record_approval(
        self,
        application_id: int,
        packet_id: int,
        user_id: int,
        packet_version_hash: str,
        approver_name: str = "Alice Candidate",
        is_consumed: bool = False,
    ) -> int:
        """Helper to directly record an application approval."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, key_id, approver_name, session_id,
                    approved_at, is_consumed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                """,
                (
                    application_id,
                    packet_id,
                    user_id,
                    packet_version_hash,
                    f"nonce_{packet_id}_{user_id}",
                    "test_key_1",
                    approver_name,
                    self.session_a.session_id,
                    1 if is_consumed else 0,
                ),
            )
            return cursor.lastrowid


# =============================================================================
# 1. TIMELINE TESTS
# =============================================================================

class TestApplicationLifecycleTimeline(BaseTimelinePacketReviewTest):
    """Tests for Workstream A: Candidate Application Lifecycle Timeline & Event Chain Verification."""

    def test_authenticated_candidate_timeline_retrieval(self):
        """Authenticated candidate can retrieve their application timeline with verified event chain."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Google",
            job_title="Software Engineer",
            status="DRAFT",
        )
        self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
            expected_current_status="DRAFT",
        )

        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertEqual(tl["application_id"], app.id)
        self.assertEqual(tl["user_id"], self.user_a)
        self.assertTrue(tl["chain_valid"])
        self.assertIn("Audit hash-chain consistency verified", tl["verification_message"])
        self.assertIn("2 events cryptographically linked", tl["verification_message"])
        self.assertEqual(len(tl["events"]), 2)
        self.assertEqual(tl["events"][0].event_type, "APPLICATION_CREATED")
        self.assertEqual(tl["events"][1].event_type, "APPLICATION_PREPARATION_STARTED")

    def test_missing_session_rejected(self):
        """None or empty session_id is rejected."""
        app_id = self._create_app(self.user_a, "Apple", "SWE")
        with self.assertRaises((InvalidSessionError, SecurityAuthorizationError)):
            self.service.get_application_timeline(app_id, "")
        with self.assertRaises((InvalidSessionError, SecurityAuthorizationError)):
            self.service.get_application_timeline(app_id, None)

    def test_invalid_session_rejected(self):
        """Unrecognized session_id is rejected."""
        app_id = self._create_app(self.user_a, "Apple", "SWE")
        with self.assertRaises(InvalidSessionError):
            self.service.get_application_timeline(app_id, "invalid_session_uuid_123")

    def test_expired_session_rejected(self):
        """Expired session is rejected."""
        app_id = self._create_app(self.user_a, "Apple", "SWE")
        # Expire session_a
        sess = self.session_mgr.get_session(self.session_a.session_id)
        sess.expires_at = datetime.now(timezone.utc).timestamp() - 100

        with self.assertRaises(SessionExpiredError):
            self.service.get_application_timeline(app_id, self.session_a.session_id)

    def test_unbound_session_rejected(self):
        """Session with unlinked user_id is rejected."""
        app_id = self._create_app(self.user_a, "Apple", "SWE")
        sess = self.session_mgr.get_session(self.session_a.session_id)
        sess.user_id = None

        with self.assertRaises((InvalidSessionError, SecurityAuthorizationError)):
            self.service.get_application_timeline(app_id, self.session_a.session_id)

    def test_cross_user_application_access_rejected(self):
        """Candidate A cannot retrieve Candidate B's application timeline."""
        app_b = self._create_app(self.user_b, "Stripe", "Backend Engineer")
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_application_timeline(app_b, self.session_a.session_id)

    def test_missing_application_handled(self):
        """Non-existent application_id raises ApplicationNotFoundError."""
        with self.assertRaises(ApplicationNotFoundError):
            self.service.get_application_timeline(999999, self.session_a.session_id)

    def test_events_retain_chronological_sequence_ordering(self):
        """Events are strictly ordered ascending by sequence_no with attribution preserved."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Netflix",
            job_title="Systems Engineer",
            status="DRAFT",
        )
        self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
            expected_current_status="DRAFT",
        )
        self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="READY_FOR_REVIEW",
            expected_current_status="PREPARING",
        )

        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertEqual(len(tl["events"]), 3)
        self.assertEqual([e.sequence_no for e in tl["events"]], [1, 2, 3])
        for evt in tl["events"]:
            self.assertEqual(evt.actor_type, "CANDIDATE")
            self.assertEqual(evt.actor_identifier, f"user_{self.user_a}")
            self.assertEqual(evt.application_id, app.id)

    def test_valid_event_chain_reports_valid(self):
        """Untampered timeline explicitly reports valid chain consistency."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Meta",
            job_title="ML Engineer",
            status="DRAFT",
        )
        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(tl["chain_valid"])
        self.assertTrue(tl["verification_message"].startswith("Audit hash-chain consistency verified"))

    def test_modified_event_payload_detected(self):
        """Tampered event payload in SQLite is immediately detected as chain inconsistency."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Amazon",
            job_title="DevOps",
            status="DRAFT",
        )
        # Directly tamper with event payload in database by dropping trigger
        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET event_payload_json = ? WHERE application_id = ?",
                (json.dumps({"tampered": True}), app.id),
            )
            conn.commit()

        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertFalse(tl["chain_valid"])
        self.assertTrue(tl["verification_message"].startswith("Audit hash-chain inconsistency detected"))
        self.assertIn("Event tamper detected", tl["verification_message"])

    def test_broken_hash_linkage_detected(self):
        """Broken predecessor hash link is detected as chain inconsistency."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Uber",
            job_title="Data Engineer",
            status="DRAFT",
        )
        self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="PREPARING",
            expected_current_status="DRAFT",
        )
        # Break hash linkage on event 2 by dropping trigger
        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET previous_event_hash = 'BROKEN_LINK' WHERE sequence_no = 2",
            )
            conn.commit()

        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertFalse(tl["chain_valid"])
        self.assertTrue(tl["verification_message"].startswith("Audit hash-chain inconsistency detected"))
        self.assertIn("Broken hash linkage", tl["verification_message"])

    def test_timeline_reads_are_strictly_non_mutating(self):
        """Reading the timeline repeatedly does not mutate application status or append events."""
        app = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Databricks",
            job_title="Cloud Engineer",
            status="DRAFT",
        )

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM application_events WHERE application_id = ?", (app.id,))
            initial_count = cursor.fetchone()["c"]

        # Call get_application_timeline multiple times
        for _ in range(5):
            tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
            self.assertTrue(tl["chain_valid"])

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM application_events WHERE application_id = ?", (app.id,))
            final_count = cursor.fetchone()["c"]
            cursor.execute("SELECT status FROM applications WHERE id = ?", (app.id,))
            final_status = cursor.fetchone()["status"]

        self.assertEqual(initial_count, final_count)
        self.assertEqual(final_status, "DRAFT")


# =============================================================================
# 2. PACKET LISTING TESTS
# =============================================================================

class TestCandidatePacketListing(BaseTimelinePacketReviewTest):
    """Tests for Workstream B.1: Candidate-Scoped Historical Prepared Packet Listing."""

    def test_candidate_can_list_own_packet_revisions(self):
        """Candidate can list all revisions of prepared packets for their application."""
        app_id = self._create_app(self.user_a, "Microsoft", "SWE")
        p1 = self._create_packet(app_id, self.user_a, version_num=1, is_active=False)
        p2 = self._create_packet(app_id, self.user_a, version_num=2, is_active=True)

        packets = self.service.list_candidate_prepared_packets(app_id, self.session_a.session_id)
        self.assertEqual(len(packets), 2)
        # Ordered latest revision first (version 2, then 1)
        self.assertEqual(packets[0]["version_num"], 2)
        self.assertEqual(packets[0]["packet_id"], p2.id)
        self.assertTrue(packets[0]["is_active_revision"])
        self.assertEqual(packets[1]["version_num"], 1)
        self.assertEqual(packets[1]["packet_id"], p1.id)
        self.assertFalse(packets[1]["is_active_revision"])

    def test_cross_user_packet_listing_rejected(self):
        """Candidate A attempting to list packets for Candidate B's application is rejected."""
        app_b = self._create_app(self.user_b, "Apple", "iOS Dev")
        self._create_packet(app_b, self.user_b, version_num=1)

        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.list_candidate_prepared_packets(app_b, self.session_a.session_id)

    def test_cross_application_packets_never_mixed(self):
        """Packets from another application owned by the same user are never returned."""
        app_1 = self._create_app(self.user_a, "Corp 1", "Dev")
        app_2 = self._create_app(self.user_a, "Corp 2", "Dev")
        self._create_packet(app_1, self.user_a, version_num=1)
        self._create_packet(app_2, self.user_a, version_num=1)

        packets_1 = self.service.list_candidate_prepared_packets(app_1, self.session_a.session_id)
        self.assertEqual(len(packets_1), 1)
        self.assertEqual(packets_1[0]["application_id"], app_1)

    def test_historical_inactive_revisions_remain_visible(self):
        """Historical inactive revisions remain visible with is_active_revision=False."""
        app_id = self._create_app(self.user_a, "Figma", "Design Technologist")
        self._create_packet(app_id, self.user_a, version_num=1, is_active=False)
        self._create_packet(app_id, self.user_a, version_num=2, is_active=False)
        self._create_packet(app_id, self.user_a, version_num=3, is_active=True)

        packets = self.service.list_candidate_prepared_packets(app_id, self.session_a.session_id)
        self.assertEqual(len(packets), 3)
        self.assertTrue(packets[0]["is_active_revision"])
        self.assertFalse(packets[1]["is_active_revision"])
        self.assertFalse(packets[2]["is_active_revision"])

    def test_legacy_packets_identified_correctly(self):
        """Legacy packets without canonical snapshot are identified with is_legacy=True."""
        app_id = self._create_app(self.user_a, "Legacy Corp", "Maintainer")
        self._create_packet(app_id, self.user_a, version_num=1, is_legacy=True)
        self._create_packet(app_id, self.user_a, version_num=2, is_legacy=False)

        packets = self.service.list_candidate_prepared_packets(app_id, self.session_a.session_id)
        self.assertEqual(len(packets), 2)
        # Rev 2 is first (not legacy)
        self.assertFalse(packets[0]["is_legacy"])
        # Rev 1 is second (legacy)
        self.assertTrue(packets[1]["is_legacy"])

    def test_missing_packet_history_returns_empty_list(self):
        """Application without prepared packets returns an empty list cleanly."""
        app_id = self._create_app(self.user_a, "Brand New Co", "Engineer")
        packets = self.service.list_candidate_prepared_packets(app_id, self.session_a.session_id)
        self.assertEqual(packets, [])

    def test_listing_packets_strictly_non_mutating(self):
        """Listing packet revisions does not modify any packet, application, or approval records."""
        app_id = self._create_app(self.user_a, "Clean Co", "Architect")
        p = self._create_packet(app_id, self.user_a, version_num=1)

        # Multiple listings
        for _ in range(3):
            pkts = self.service.list_candidate_prepared_packets(app_id, self.session_a.session_id)
            self.assertEqual(len(pkts), 1)

        # Verify DB untouched
        packet_db = self.db.get_prepared_packet(p.id, self.user_a)
        self.assertEqual(packet_db.version_num, 1)
        self.assertTrue(packet_db.is_active_revision)


# =============================================================================
# 3. PACKET DETAIL & APPROVAL PROVENANCE TESTS
# =============================================================================

class TestCandidatePacketDetailAndApproval(BaseTimelinePacketReviewTest):
    """Tests for Workstream B.2 & C: Packet Detail Retrieval, Historical Integrity & Approval Provenance."""

    def test_candidate_retrieves_own_packet_detail(self):
        """Candidate can retrieve their own packet detail with complete metadata and valid integrity."""
        app_id = self._create_app(self.user_a, "Scale AI", "AI Trainer")
        pkt = self._create_packet(app_id, self.user_a, version_num=1)

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertEqual(detail["packet_id"], pkt.id)
        self.assertEqual(detail["application_id"], app_id)
        self.assertEqual(detail["user_id"], self.user_a)
        self.assertTrue(detail["integrity_valid"])
        self.assertEqual(detail["verification_message"], "Packet integrity verified.")
        self.assertFalse(detail["approval"]["is_approved"])

    def test_cross_user_packet_detail_rejected(self):
        """Candidate A attempting to view Candidate B's packet raises CrossUserAccessError."""
        app_b = self._create_app(self.user_b, "Secret Co", "Research Scientist")
        pkt_b = self._create_packet(app_b, self.user_b, version_num=1)

        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_prepared_packet(app_b, pkt_b.id, self.session_a.session_id)

    def test_cross_application_packet_detail_rejected(self):
        """Requesting a packet with the wrong application_id owned by same candidate raises SecurityAuthorizationError."""
        app_1 = self._create_app(self.user_a, "App One", "Dev")
        app_2 = self._create_app(self.user_a, "App Two", "Dev")
        pkt_1 = self._create_packet(app_1, self.user_a, version_num=1)

        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_prepared_packet(app_2, pkt_1.id, self.session_a.session_id)

    def test_tampered_canonical_snapshot_fails_integrity(self):
        """Tampered snapshot JSON fails read-only integrity verification."""
        app_id = self._create_app(self.user_a, "Security First", "Security Analyst")
        pkt = self._create_packet(app_id, self.user_a, version_num=1)

        # Directly tamper with stored canonical snapshot JSON
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                (json.dumps({"tampered": True}), pkt.id),
            )

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertFalse(detail["integrity_valid"])
        self.assertIn("Integrity check failed", detail["verification_message"])
        self.assertIn("Possible tampering detected", detail["verification_message"])

    def test_incorrect_packet_hash_fails_integrity(self):
        """Tampered packet_version_hash fails read-only integrity verification."""
        app_id = self._create_app(self.user_a, "Integrity Co", "QA")
        pkt = self._create_packet(app_id, self.user_a, version_num=1)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE prepared_packets SET packet_version_hash = 'TAMPERED_HASH' WHERE id = ?",
                (pkt.id,),
            )

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertFalse(detail["integrity_valid"])
        self.assertIn("Integrity check failed", detail["verification_message"])

    def test_historical_inactive_packet_integrity_evaluated_without_requiring_active_status(self):
        """Historical inactive revision with intact snapshot passes read-only integrity check without being active."""
        app_id = self._create_app(self.user_a, "Archive Co", "Lead")
        p1 = self._create_packet(app_id, self.user_a, version_num=1, is_active=False)

        detail = self.service.get_candidate_prepared_packet(app_id, p1.id, self.session_a.session_id)
        self.assertTrue(detail["integrity_valid"])
        self.assertFalse(detail["is_active_revision"])
        self.assertEqual(detail["verification_message"], "Packet integrity verified.")

    def test_approval_shown_only_when_exact_packet_and_hash_match(self):
        """Approval details are attached ONLY when packet_id and version hash match the approval record."""
        app_id = self._create_app(self.user_a, "Governed Inc", "VP Engineering")
        p1 = self._create_packet(app_id, self.user_a, version_num=1, is_active=False)
        p2 = self._create_packet(app_id, self.user_a, version_num=2, is_active=True)

        # Record approval for p1 ONLY
        self._record_approval(
            application_id=app_id,
            packet_id=p1.id,
            user_id=self.user_a,
            packet_version_hash=p1.packet_version_hash,
            approver_name="Alice Candidate",
        )

        # Detail for p1 must show approved
        d1 = self.service.get_candidate_prepared_packet(app_id, p1.id, self.session_a.session_id)
        self.assertTrue(d1["approval"]["is_approved"])
        self.assertEqual(d1["approval"]["approver_name"], "Alice Candidate")

        # Detail for p2 must NOT show approved (even though application is same!)
        d2 = self.service.get_candidate_prepared_packet(app_id, p2.id, self.session_a.session_id)
        self.assertFalse(d2["approval"]["is_approved"])
        self.assertIsNone(d2["approval"]["approval_id"])

    def test_consumed_and_unconsumed_approval_states(self):
        """Approval record consumption state is accurately reported."""
        app_id = self._create_app(self.user_a, "State Co", "Engineer")
        p = self._create_packet(app_id, self.user_a, version_num=1)
        appr_id = self._record_approval(
            application_id=app_id,
            packet_id=p.id,
            user_id=self.user_a,
            packet_version_hash=p.packet_version_hash,
            is_consumed=False,
        )

        detail = self.service.get_candidate_prepared_packet(app_id, p.id, self.session_a.session_id)
        self.assertTrue(detail["approval"]["is_approved"])
        self.assertFalse(detail["approval"]["is_consumed"])

        # Mark consumed
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE application_approvals SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (appr_id,),
            )

        detail_consumed = self.service.get_candidate_prepared_packet(app_id, p.id, self.session_a.session_id)
        self.assertTrue(detail_consumed["approval"]["is_approved"])
        self.assertTrue(detail_consumed["approval"]["is_consumed"])

    def test_missing_approval_not_fabricated(self):
        """Application in status 'APPROVED' does NOT fabricate an approval for unapproved packet."""
        app_id = self._create_app(self.user_a, "Status Mismatch Co", "Engineer", status="APPROVED")
        p = self._create_packet(app_id, self.user_a, version_num=1)

        detail = self.service.get_candidate_prepared_packet(app_id, p.id, self.session_a.session_id)
        self.assertFalse(detail["approval"]["is_approved"])
        self.assertIsNone(detail["approval"]["approval_id"])

    def test_legacy_packet_detail_handling(self):
        """Legacy packet reports is_legacy=True, integrity_valid=False, and clear limitation message."""
        app_id = self._create_app(self.user_a, "Legacy Systems", "Maintainer")
        p_legacy = self._create_packet(app_id, self.user_a, version_num=1, is_legacy=True)

        detail = self.service.get_candidate_prepared_packet(app_id, p_legacy.id, self.session_a.session_id)
        self.assertTrue(detail["is_legacy"])
        self.assertFalse(detail["integrity_valid"])
        self.assertIn("Legacy packet record", detail["verification_message"])

    def test_packet_review_strictly_non_mutating(self):
        """Inspecting packet detail never alters approvals, application status, or packet state."""
        app_id = self._create_app(self.user_a, "Read Only Co", "Auditor")
        p = self._create_packet(app_id, self.user_a, version_num=1)
        self._record_approval(
            application_id=app_id,
            packet_id=p.id,
            user_id=self.user_a,
            packet_version_hash=p.packet_version_hash,
            is_consumed=False,
        )

        for _ in range(3):
            d = self.service.get_candidate_prepared_packet(app_id, p.id, self.session_a.session_id)
            self.assertTrue(d["integrity_valid"])
            self.assertFalse(d["approval"]["is_consumed"])

        # Check DB unchanged
        appr = self.db.get_packet_approval(p.id, self.user_a)
        self.assertFalse(appr.is_consumed)

    def test_no_internal_path_exposure_in_packet_detail(self):
        """Packet detail sanitizes attachments manifest and exposes no internal server paths."""
        app_id = self._create_app(self.user_a, "Sanitize Co", "Security Engineer")
        internal_path = str(self.user_a_storage / "super_secret_internal_dir" / "resume.pdf")
        manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "candidate_resume.pdf",
                "stored_filename": "secret_internal_resume.pdf",
                "format": "PDF",
                "size_bytes": 1024,
                "file_hash": "a" * 64,
                "file_path": internal_path,
                "storage_root": "/var/data/private",
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=manifest)

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertTrue(detail["integrity_valid"])
        self.assertEqual(len(detail["attachments_manifest"]), 1)
        entry = detail["attachments_manifest"][0]

        # Verify disallowed keys are not present
        self.assertNotIn("file_path", entry)
        self.assertNotIn("storage_root", entry)
        self.assertNotIn("stored_filename", entry)

        # Verify allowed keys are present
        self.assertEqual(entry["artifact_type"], "tailored_resume_pdf")
        self.assertEqual(entry["filename"], "candidate_resume.pdf")
        self.assertEqual(entry["format"], "PDF")
        self.assertEqual(entry["size_bytes"], 1024)
        self.assertEqual(entry["file_hash"], "a" * 64)
        self.assertTrue(entry["document_available"])

        # Verify serialized packet dictionary contains no internal filesystem paths
        serialized = json.dumps(detail)
        self.assertNotIn(internal_path, serialized)
        self.assertNotIn("super_secret_internal_dir", serialized)
        self.assertNotIn("/var/data/private", serialized)

    def test_tampered_non_legacy_packet_does_not_fallback_to_db_columns(self):
        """Tampered non-legacy packet does NOT fall back to trusting detached/mutable DB columns."""
        app_id = self._create_app(self.user_a, "Tamper Target", "Engineer")
        pkt = self._create_packet(
            app_id,
            self.user_a,
            version_num=1,
            tailored_resume_path="/some/fake/path.pdf",
            tailored_resume_hash="resume_hash_fallback",
            cover_letter_path="/some/fake/cl.pdf",
            cover_letter_hash="cl_hash_fallback",
            attachments_manifest=[{
                "artifact_type": "tailored_resume_pdf",
                "filename": "fake.pdf",
                "format": "PDF",
                "file_hash": "hash1",
                "file_path": "/some/path",
            }],
        )

        # Tamper the canonical snapshot JSON
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                (json.dumps({"tampered": True, "malicious": "content"}), pkt.id),
            )

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertFalse(detail["integrity_valid"])
        self.assertIn("Integrity check failed", detail["verification_message"])
        # Assert materials are NOT loaded from detached DB columns
        self.assertEqual(detail["tailored_resume"], {})
        self.assertEqual(detail["cover_letter"], {})
        self.assertEqual(detail["screening_questions"], [])
        self.assertEqual(detail["attachments_manifest"], [])
        self.assertFalse(any(detail["documents_available"].values()))


# =============================================================================
# 4. SECURE PDF/DOCX DOWNLOAD TESTS
# =============================================================================

class TestCandidatePacketDocumentDownload(BaseTimelinePacketReviewTest):
    """Tests for Workstream D: Secure PDF/DOCX Packet Document Retrieval & 14-Step Authorization."""

    def setUp(self):
        super().setUp()
        # Setup application-specific directories
        self.app_a_dir = self.user_a_storage / "applications" / "1"
        self.app_a_dir.mkdir(parents=True, exist_ok=True)

        # Create valid PDF fixture
        self.pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        self.pdf_hash = hashlib.sha256(self.pdf_bytes).hexdigest()
        self.pdf_path = self.app_a_dir / "tailored_resume.pdf"
        self.pdf_path.write_bytes(self.pdf_bytes)

        # Create valid DOCX fixture
        self.docx_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00test_docx_data"
        self.docx_hash = hashlib.sha256(self.docx_bytes).hexdigest()
        self.docx_path = self.app_a_dir / "cover_letter.docx"
        self.docx_path.write_bytes(self.docx_bytes)

        # Build sample attachments manifest
        self.manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "Alice_Resume.pdf",
                "stored_filename": "tailored_resume.pdf",
                "format": "PDF",
                "size_bytes": len(self.pdf_bytes),
                "file_hash": self.pdf_hash,
                "file_path": str(self.pdf_path),
            },
            {
                "artifact_type": "cover_letter_docx",
                "filename": "Alice_Cover_Letter.docx",
                "stored_filename": "cover_letter.docx",
                "format": "DOCX",
                "size_bytes": len(self.docx_bytes),
                "file_hash": self.docx_hash,
                "file_path": str(self.docx_path),
            },
        ]

    def test_valid_pdf_download(self):
        """Candidate can download their valid PDF with correct MIME type and sanitized filename."""
        app_id = self._create_app(self.user_a, "Tech Giant", "Staff SWE")
        pkt = self._create_packet(
            app_id,
            self.user_a,
            version_num=1,
            attachments_manifest=self.manifest,
        )

        file_bytes, filename, mime_type = self.service.get_candidate_packet_document(
            application_id=app_id,
            packet_id=pkt.id,
            document_type="tailored_resume_pdf",
            session_id=self.session_a.session_id,
        )
        self.assertEqual(file_bytes, self.pdf_bytes)
        self.assertEqual(filename, "Alice_Resume.pdf")
        self.assertEqual(mime_type, "application/pdf")

    def test_valid_docx_download(self):
        """Candidate can download their valid DOCX with correct MIME type and sanitized filename."""
        app_id = self._create_app(self.user_a, "Enterprise Co", "Director")
        pkt = self._create_packet(
            app_id,
            self.user_a,
            version_num=1,
            attachments_manifest=self.manifest,
        )

        file_bytes, filename, mime_type = self.service.get_candidate_packet_document(
            application_id=app_id,
            packet_id=pkt.id,
            document_type="cover_letter_docx",
            session_id=self.session_a.session_id,
        )
        self.assertEqual(file_bytes, self.docx_bytes)
        self.assertEqual(filename, "Alice_Cover_Letter.docx")
        self.assertEqual(mime_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    def test_unauthenticated_download_rejected(self):
        """Invalid or expired session is rejected before file access."""
        app_id = self._create_app(self.user_a, "Target Co", "SWE")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        with self.assertRaises(InvalidSessionError):
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id="bad_session_token",
            )

    def test_cross_user_download_rejected(self):
        """Candidate A cannot download Candidate B's documents."""
        app_b = self._create_app(self.user_b, "Bob Corp", "Lead")
        pkt_b = self._create_packet(app_b, self.user_b, version_num=1, attachments_manifest=self.manifest)

        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_packet_document(
                application_id=app_b,
                packet_id=pkt_b.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_cross_application_packet_download_rejected(self):
        """Downloading a document specifying the wrong application_id owned by same candidate is rejected."""
        app_1 = self._create_app(self.user_a, "App 1", "Dev")
        app_2 = self._create_app(self.user_a, "App 2", "Dev")
        pkt_1 = self._create_packet(app_1, self.user_a, version_num=1, attachments_manifest=self.manifest)

        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_packet_document(
                application_id=app_2,
                packet_id=pkt_1.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_missing_document_on_disk_handled(self):
        """Document listed in manifest that does not exist on disk raises FileNotFoundError."""
        app_id = self._create_app(self.user_a, "Ghost Co", "Dev")
        missing_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "missing.pdf",
                "format": "PDF",
                "file_hash": "somehash",
                "file_path": str(self.app_a_dir / "nonexistent.pdf"),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=missing_manifest)

        with self.assertRaises(FileNotFoundError):
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_missing_authoritative_hash_rejected(self):
        """Document entry lacking an authoritative integrity hash is rejected."""
        app_id = self._create_app(self.user_a, "NoHash Co", "Dev")
        no_hash_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "nohash.pdf",
                "format": "PDF",
                "file_hash": None,
                "file_path": str(self.pdf_path),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=no_hash_manifest)

        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_tampered_file_bytes_rejected(self):
        """File bytes modified on disk (SHA-256 mismatch with manifest) are rejected."""
        app_id = self._create_app(self.user_a, "Tamper Target", "Dev")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        # Alter the file on disk
        self.pdf_path.write_bytes(b"%PDF-1.4\nTAMPERED CONTENT\n%%EOF")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("integrity verification failed", str(ctx.exception).lower())

    def test_unsupported_document_type_rejected(self):
        """Requesting unsupported types (.sh, .exe, scripts) raises ValidationError."""
        app_id = self._create_app(self.user_a, "Script Target", "Dev")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        for bad_type in ["script_sh", "executable_exe", "payload.py", "../../../etc/passwd"]:
            with self.assertRaises(ValidationError):
                self.service.get_candidate_packet_document(
                    application_id=app_id,
                    packet_id=pkt.id,
                    document_type=bad_type,
                    session_id=self.session_a.session_id,
                )

    def test_extension_content_mismatch_rejected(self):
        """File with .pdf extension lacking %PDF- magic bytes raises InvalidFileFormatError."""
        app_id = self._create_app(self.user_a, "Fake PDF Co", "Dev")
        fake_pdf_path = self.app_a_dir / "fake.pdf"
        fake_pdf_bytes = b"NOT_A_REAL_PDF_JUST_PLAIN_TEXT"
        fake_pdf_path.write_bytes(fake_pdf_bytes)
        fake_hash = hashlib.sha256(fake_pdf_bytes).hexdigest()

        fake_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "fake.pdf",
                "format": "PDF",
                "file_hash": fake_hash,
                "file_path": str(fake_pdf_path),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=fake_manifest)

        with self.assertRaises(InvalidFileFormatError):
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_absolute_path_substitution_rejected(self):
        """Metadata containing an absolute path outside candidate sandbox is rejected."""
        app_id = self._create_app(self.user_a, "Escape Target", "Dev")
        other_path = self.user_b_storage / "bobs_secret.pdf"
        other_path.write_bytes(self.pdf_bytes)

        escape_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "escaped.pdf",
                "format": "PDF",
                "file_hash": self.pdf_hash,
                "file_path": str(other_path),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=escape_manifest)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("escapes candidate", str(ctx.exception))

    def test_path_traversal_rejected(self):
        """Metadata containing '..' path traversal is rejected."""
        app_id = self._create_app(self.user_a, "Traversal Target", "Dev")
        traversal_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "traversal.pdf",
                "format": "PDF",
                "file_hash": self.pdf_hash,
                "file_path": str(self.app_a_dir / ".." / ".." / "2" / "bobs_secret.pdf"),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=traversal_manifest)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("traversal detected", str(ctx.exception).lower())

    def test_symlink_escape_rejected(self):
        """Symlink inside candidate sandbox pointing outside sandbox is rejected."""
        app_id = self._create_app(self.user_a, "Symlink Target", "Dev")
        external_target = Path(self.temp_dir.name) / "external_secret.pdf"
        external_target.write_bytes(self.pdf_bytes)

        symlink_path = self.app_a_dir / "symlink_escape.pdf"
        try:
            os.symlink(str(external_target), str(symlink_path))
        except OSError:
            self.skipTest("Symlinks not supported on this filesystem.")

        symlink_manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "symlink.pdf",
                "format": "PDF",
                "file_hash": self.pdf_hash,
                "file_path": str(symlink_path),
            }
        ]
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=symlink_manifest)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("escapes candidate", str(ctx.exception))

    def test_download_strictly_non_mutating(self):
        """Document download does not alter application, packet, or approval state."""
        app_id = self._create_app(self.user_a, "Non Mutating Download", "Auditor")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)
        self._record_approval(
            application_id=app_id,
            packet_id=pkt.id,
            user_id=self.user_a,
            packet_version_hash=pkt.packet_version_hash,
            is_consumed=False,
        )

        for _ in range(3):
            file_bytes, _, _ = self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
            self.assertEqual(file_bytes, self.pdf_bytes)

        # Check DB state
        app_db = self.db.get_user_application(app_id, self.user_a)
        self.assertEqual(app_db.status, "DRAFT")
        appr_db = self.db.get_packet_approval(pkt.id, self.user_a)
        self.assertFalse(appr_db.is_consumed)

    def test_legacy_packet_download_rejected(self):
        """Legacy packet lacking canonical snapshot is rejected with SecurityAuthorizationError."""
        app_id = self._create_app(self.user_a, "Legacy Co", "Dev")
        p_legacy = self._create_packet(app_id, self.user_a, version_num=1, is_legacy=True)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=p_legacy.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("legacy packet record lacks a verifiable canonical snapshot", str(ctx.exception).lower())

    def test_snapshot_tampering_during_download_rejected(self):
        """Tampering canonical snapshot after creation fails closed with SecurityAuthorizationError before reading disk."""
        app_id = self._create_app(self.user_a, "Tamper Co", "Dev")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        # Tamper snapshot in database
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                (json.dumps({"tampered": True}), pkt.id),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("integrity verification failed", str(ctx.exception).lower())

    def test_detached_manifest_fallback_rejected(self):
        """Detached attachments_manifest_json in DB is rejected if snapshot manifest is empty or omitted."""
        app_id = self._create_app(self.user_a, "Detached Co", "Dev")
        # Create packet with empty attachments_manifest in snapshot, but detached DB column populated
        payload = {
            "application_id": app_id,
            "user_id": self.user_a,
            "packet_version": 1,
            "tailored_resume": {"name": "Alice Candidate"},
            "cover_letter": {"letter_text": "Sample text"},
            "screening_questions": [],
            "attachments_manifest": [],  # Empty in snapshot
        }
        pkt = self._create_packet(
            app_id,
            self.user_a,
            version_num=1,
            snapshot_payload=payload,
            attachments_manifest=self.manifest,  # Populates packet.attachments_manifest_json column
            tailored_resume_path=str(self.pdf_path),
            tailored_resume_hash=self.pdf_hash,
        )

        # Download must raise FileNotFoundError because canonical snapshot manifest is authoritative
        with self.assertRaises(FileNotFoundError):
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )

    def test_tampered_manifest_rejected(self):
        """Modifying manifest entry inside snapshot causes version hash mismatch and download failure."""
        app_id = self._create_app(self.user_a, "Manifest Tamper Co", "Dev")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        # Read snapshot payload, alter the manifest file_path, and write back without updating version hash
        snapshot = json.loads(pkt.canonical_snapshot_json)
        snapshot["attachments_manifest"][0]["file_path"] = str(self.docx_path)
        tampered_json = json.dumps(snapshot, sort_keys=True)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                (tampered_json, pkt.id),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("integrity verification failed", str(ctx.exception).lower())

    def test_invalid_snapshot_json_rejected(self):
        """Malformed or non-dict JSON in canonical_snapshot_json fails both detail and download."""
        app_id = self._create_app(self.user_a, "Malformed JSON Co", "Dev")
        pkt = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=self.manifest)

        # Case A: Malformed syntax
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = '{malformed: true' WHERE id = ?",
                (pkt.id,),
            )

        detail = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertFalse(detail["integrity_valid"])
        self.assertIn("Integrity check failed", detail["verification_message"])

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("integrity verification failed", str(ctx.exception).lower())

        # Case B: Valid JSON but not a dictionary (e.g. list)
        list_json = json.dumps(["not", "a", "dict"])
        list_hash = hashlib.sha256(list_json.encode("utf-8")).hexdigest()
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ?, packet_version_hash = ? WHERE id = ?",
                (list_json, list_hash, pkt.id),
            )

        detail_list = self.service.get_candidate_prepared_packet(app_id, pkt.id, self.session_a.session_id)
        self.assertFalse(detail_list["integrity_valid"])
        self.assertIn("Canonical snapshot structure is invalid", detail_list["verification_message"])

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=pkt.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("Canonical snapshot structure is invalid", str(ctx.exception))

    def test_document_format_mismatch_rejected(self):
        """Cross-checks requested document_type, manifest format, extension, and magic bytes."""
        app_id = self._create_app(self.user_a, "Mismatch Co", "Dev")

        # 1. DOCX requested with PDF manifest format
        mismatch_manifest_1 = [
            {
                "artifact_type": "cover_letter_docx",
                "filename": "cover.pdf",
                "format": "PDF",  # Conflicts with cover_letter_docx requirement of DOCX
                "file_hash": self.pdf_hash,
                "file_path": str(self.pdf_path),
            }
        ]
        p1 = self._create_packet(app_id, self.user_a, version_num=1, attachments_manifest=mismatch_manifest_1)
        with self.assertRaises(ValidationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=p1.id,
                document_type="cover_letter_docx",
                session_id=self.session_a.session_id,
            )
        self.assertIn("format mismatch", str(ctx.exception).lower())

        # 2. PDF requested with DOCX manifest format
        mismatch_manifest_2 = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "resume.docx",
                "format": "DOCX",  # Conflicts with tailored_resume_pdf requirement of PDF
                "file_hash": self.docx_hash,
                "file_path": str(self.docx_path),
            }
        ]
        p2 = self._create_packet(app_id, self.user_a, version_num=2, attachments_manifest=mismatch_manifest_2)
        with self.assertRaises(ValidationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=p2.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("format mismatch", str(ctx.exception).lower())

        # 3. DOCX manifest format with .pdf file path extension
        fake_ext_pdf = self.app_a_dir / "fake_ext.pdf"
        fake_ext_pdf.write_bytes(self.docx_bytes)
        fake_ext_pdf_hash = hashlib.sha256(self.docx_bytes).hexdigest()
        mismatch_manifest_3 = [
            {
                "artifact_type": "cover_letter_docx",
                "filename": "cover.docx",
                "format": "DOCX",
                "file_hash": fake_ext_pdf_hash,
                "file_path": str(fake_ext_pdf),  # .pdf extension conflicts with DOCX format
            }
        ]
        p3 = self._create_packet(app_id, self.user_a, version_num=3, attachments_manifest=mismatch_manifest_3)
        with self.assertRaises(ValidationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=p3.id,
                document_type="cover_letter_docx",
                session_id=self.session_a.session_id,
            )
        self.assertIn("conflicts with file extension", str(ctx.exception).lower())

        # 4. PDF manifest format with .docx file path extension
        fake_ext_docx = self.app_a_dir / "fake_ext.docx"
        fake_ext_docx.write_bytes(self.pdf_bytes)
        fake_ext_docx_hash = hashlib.sha256(self.pdf_bytes).hexdigest()
        mismatch_manifest_4 = [
            {
                "artifact_type": "tailored_resume_pdf",
                "filename": "resume.pdf",
                "format": "PDF",
                "file_hash": fake_ext_docx_hash,
                "file_path": str(fake_ext_docx),  # .docx extension conflicts with PDF format
            }
        ]
        p4 = self._create_packet(app_id, self.user_a, version_num=4, attachments_manifest=mismatch_manifest_4)
        with self.assertRaises(ValidationError) as ctx:
            self.service.get_candidate_packet_document(
                application_id=app_id,
                packet_id=p4.id,
                document_type="tailored_resume_pdf",
                session_id=self.session_a.session_id,
            )
        self.assertIn("conflicts with file extension", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
