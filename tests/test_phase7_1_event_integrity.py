"""Phase 7.1 Event Integrity Tests: Canonical JSON Hashing, Monotonic Sequence Numbers, Hash Chain Linkage, and Tamper Detection."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import EventIntegrityError
from src.database.models import ApplicationStatus
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class TestPhase71EventIntegrity(unittest.TestCase):
    """Verifies cryptographic hash chain integrity, canonical JSON hashing, and tamper detection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_events.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('tester@example.com', 'h', 's', 'Tester')"
            )
            self.user_id = cursor.lastrowid

        self.app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Timeline Corp",
            job_title="Software Architect",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_canonical_json_hashing_determinism(self):
        """RFC 8785 canonical JSON hashing is deterministic regardless of Python dictionary key insertion order."""
        dict_1 = {"z_key": 100, "a_key": "first", "nested": {"b": True, "a": None}}
        dict_2 = {"nested": {"a": None, "b": True}, "a_key": "first", "z_key": 100}

        bytes_1 = canonical_json_bytes(dict_1)
        bytes_2 = canonical_json_bytes(dict_2)
        self.assertEqual(bytes_1, bytes_2, "Canonical bytes must be identical regardless of key order.")

        hash_1 = canonical_json_hash(dict_1)
        hash_2 = canonical_json_hash(dict_2)
        self.assertEqual(hash_1, hash_2, "Canonical hashes must be identical.")

    def test_event_chain_sequence_monotonicity_and_hash_linkage(self):
        """Events are appended with strictly monotonic sequences (1, 2, 3...) and valid hash linkage."""
        # Initial event sequence 1 was created on app creation
        events_1 = self.db.get_application_events(self.app.id, self.user_id)
        self.assertEqual(len(events_1), 1)
        self.assertEqual(events_1[0].sequence_no, 1)
        self.assertEqual(events_1[0].previous_event_hash, "GENESIS")
        self.assertTrue(len(events_1[0].event_hash) == 64)

        # Append sequence 2
        evt_2 = self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="RESUME_TAILORED",
            previous_status=ApplicationStatus.DRAFT.value,
            new_status=ApplicationStatus.PREPARING.value,
            actor_type="CANDIDATE",
            event_payload={"tailored_sections": ["skills", "experience"]},
        )
        self.assertEqual(evt_2.sequence_no, 2)
        self.assertEqual(evt_2.previous_event_hash, events_1[0].event_hash)

        # Append sequence 3
        evt_3 = self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="COVER_LETTER_GENERATED",
            previous_status=ApplicationStatus.PREPARING.value,
            new_status=ApplicationStatus.READY_FOR_REVIEW.value,
            actor_type="CANDIDATE",
            event_payload={"tone": "Professional & Direct"},
        )
        self.assertEqual(evt_3.sequence_no, 3)
        self.assertEqual(evt_3.previous_event_hash, evt_2.event_hash)

        # Append sequence 4
        evt_4 = self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="APPLICATION_APPROVED",
            previous_status=ApplicationStatus.READY_FOR_REVIEW.value,
            new_status=ApplicationStatus.APPROVED.value,
            actor_type="CANDIDATE",
            event_payload={"approved_by": "tester@example.com"},
        )
        self.assertEqual(evt_4.sequence_no, 4)
        self.assertEqual(evt_4.previous_event_hash, evt_3.event_hash)

        # Full chain validation
        is_valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertTrue(is_valid, msg)
        self.assertIn("All 4 events verified successfully", msg)

    def test_tamper_detection_on_event_payload_modification(self):
        """Direct manipulation of stored event_payload_json breaks chain verification."""
        # Append an event
        self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="DOC_UPLOADED",
            event_payload={"filename": "original.pdf"},
        )

        events = self.db.get_application_events(self.app.id, self.user_id)
        target_id = events[1].id

        # Directly tamper the database by disabling trigger and modifying event_payload_json
        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET event_payload_json = '{\"filename\": \"tampered.pdf\"}' WHERE id = ?",
                (target_id,),
            )
            conn.commit()

        # Verification must detect tamper
        is_valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertFalse(is_valid)
        self.assertIn("Event tamper detected", msg)

        # With raise_on_error=True, raises EventIntegrityError
        with self.assertRaises(EventIntegrityError) as ctx:
            self.db.verify_application_event_chain(self.app.id, self.user_id, raise_on_error=True)
        self.assertIn("Event tamper detected", str(ctx.exception))

    def test_tamper_detection_on_broken_hash_linkage(self):
        """Direct manipulation of previous_event_hash breaks chain verification."""
        self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="EVENT_B",
        )
        self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="EVENT_C",
        )

        events = self.db.get_application_events(self.app.id, self.user_id)
        target_id = events[2].id

        # Tamper previous_event_hash
        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET previous_event_hash = 'FORGED_PREVIOUS_HASH' WHERE id = ?",
                (target_id,),
            )
            conn.commit()

        is_valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertFalse(is_valid)
        self.assertIn("Broken hash linkage", msg)

    def test_tamper_detection_on_sequence_discontinuity(self):
        """Direct insertion with a sequence gap is detected by chain verification."""
        # App has event 1. Insert sequence 3 directly.
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO application_events (
                    application_id, user_id, sequence_no, event_type,
                    actor_identifier, previous_event_hash, event_hash
                ) VALUES (?, ?, 3, 'GAP_EVENT', 'tester', 'GENESIS', 'hash')
                """,
                (self.app.id, self.user_id),
            )

        is_valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertFalse(is_valid)
        self.assertIn("Sequence discontinuity: expected sequence 2, found 3", msg)

    def test_append_only_trigger_prevents_in_place_edits(self):
        """The SQLite trigger trg_prevent_application_events_update prevents in-place UPDATE."""
        events = self.db.get_application_events(self.app.id, self.user_id)
        first_evt_id = events[0].id

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE application_events SET event_type = 'OVERWRITTEN' WHERE id = ?",
                    (first_evt_id,),
                )
        self.assertIn("application_events records are append-only and cannot be updated", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
