"""Phase 7.1 Multi-User Ownership & IDOR Protection Tests: Cross-User Isolation across Applications, Events, Confirmations, and Follow-ups."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError, UserNotFoundError
from src.database.models import ApplicationStatus, FollowUpType, SubmissionChannel


class TestPhase71Ownership(unittest.TestCase):
    """Verifies strict multi-user ownership enforcement and IDOR defense across all Phase 7 entities."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_ownership.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('alice@test.com', 'h1', 's1', 'Alice')"
            )
            self.user_a_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('bob@test.com', 'h2', 's2', 'Bob')"
            )
            self.user_b_id = cursor.lastrowid

        # Seed JD and Resume for User A
        self.jd_a = self.db.save_job_description_snapshot(
            user_id=self.user_a_id,
            company_name="Alpha Corp",
            job_title="ML Engineer",
            raw_content="Alpha ML posting.",
        )
        self.res_a = self.db.create_user_resume(
            user_id=self.user_a_id,
            original_filename="alice_cv.pdf",
            storage_filename="alice_cv.pdf",
            file_format="pdf",
            file_hash="hash_alice_res",
            file_size_bytes=1024,
        )

        # Seed JD and Resume for User B
        self.jd_b = self.db.save_job_description_snapshot(
            user_id=self.user_b_id,
            company_name="Beta Corp",
            job_title="Data Scientist",
            raw_content="Beta Data posting.",
        )
        self.res_b = self.db.create_user_resume(
            user_id=self.user_b_id,
            original_filename="bob_cv.pdf",
            storage_filename="bob_cv.pdf",
            file_format="pdf",
            file_hash="hash_bob_res",
            file_size_bytes=2048,
        )

        # Create applications for User A and User B
        self.app_a = self.db.create_user_application(
            user_id=self.user_a_id,
            company_name="Alpha Corp",
            job_title="ML Engineer",
            job_description_id=self.jd_a.id,
            resume_id=self.res_a["id"],
        )
        self.app_b = self.db.create_user_application(
            user_id=self.user_b_id,
            company_name="Beta Corp",
            job_title="Data Scientist",
            job_description_id=self.jd_b.id,
            resume_id=self.res_b["id"],
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cross_user_resource_association_rejected_on_application_create(self):
        """User A cannot link User B's Job Description or Resume to an application."""
        # User A attempts to link User B's JD
        with self.assertRaises(CrossUserAccessError):
            self.db.create_user_application(
                user_id=self.user_a_id,
                company_name="Malicious Co",
                job_title="Intruder",
                job_description_id=self.jd_b.id,
            )

        # User A attempts to link User B's Resume
        with self.assertRaises(CrossUserAccessError):
            self.db.create_user_application(
                user_id=self.user_a_id,
                company_name="Malicious Co",
                job_title="Intruder",
                resume_id=self.res_b["id"],
            )

    def test_cross_user_application_access_rejected(self):
        """User A cannot access User B's application via get_user_application."""
        with self.assertRaises(CrossUserAccessError):
            self.db.get_user_application(self.app_b.id, user_id=self.user_a_id)

    def test_cross_user_event_operations_rejected(self):
        """User A cannot append events to or view events from User B's application."""
        # Append event to User B's application
        with self.assertRaises(CrossUserAccessError):
            self.db.create_application_event(
                application_id=self.app_b.id,
                user_id=self.user_a_id,
                event_type="UNAUTHORIZED_EVENT",
            )

        # View events from User B's application
        with self.assertRaises(CrossUserAccessError):
            self.db.get_application_events(
                application_id=self.app_b.id,
                user_id=self.user_a_id,
            )

    def test_cross_user_submission_confirmation_rejected(self):
        """User A cannot confirm submission for User B's application or link User B's packet."""
        # Create packet for User B
        pkt_b = self.db.create_prepared_packet(
            application_id=self.app_b.id,
            user_id=self.user_b_id,
            packet_version_hash="packet_hash_b",
            original_resume_hash="res_hash_b",
            job_description_snapshot_hash="jd_hash_b",
            screening_answers={},
        )

        # Case 1: User A confirms submission for User B's application
        with self.assertRaises(CrossUserAccessError):
            self.db.create_submission_confirmation(
                application_id=self.app_b.id,
                user_id=self.user_a_id,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

        # Case 2: User A confirms submission for User A's application, but links User B's packet
        with self.assertRaises(CrossUserAccessError):
            self.db.create_submission_confirmation(
                application_id=self.app_a.id,
                user_id=self.user_a_id,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                packet_id=pkt_b.id,
            )

        # Case 3: User A attempts to view User B's confirmation
        self.db.create_submission_confirmation(
            application_id=self.app_b.id,
            user_id=self.user_b_id,
            submission_channel=SubmissionChannel.EMAIL.value,
        )
        with self.assertRaises(CrossUserAccessError):
            self.db.get_submission_confirmation(
                application_id=self.app_b.id,
                user_id=self.user_a_id,
            )

    def test_cross_user_follow_up_operations_rejected(self):
        """User A cannot create, view, complete, or delete User B's follow-ups."""
        # Create follow-up for User B
        fu_b = self.db.create_application_follow_up(
            application_id=self.app_b.id,
            user_id=self.user_b_id,
            follow_up_date="2026-12-15",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Inquire about interview status",
        )

        # Case 1: User A creates follow-up on User B's application
        with self.assertRaises(CrossUserAccessError):
            self.db.create_application_follow_up(
                application_id=self.app_b.id,
                user_id=self.user_a_id,
                follow_up_date="2026-12-15",
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="Malicious follow-up",
            )

        # Case 2: User A views User B's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.db.get_application_follow_up(fu_b.id, user_id=self.user_a_id)

        # Case 3: User A completes User B's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.db.complete_application_follow_up(fu_b.id, user_id=self.user_a_id)

        # Case 4: User A deletes User B's follow-up
        with self.assertRaises(CrossUserAccessError):
            self.db.delete_application_follow_up(fu_b.id, user_id=self.user_a_id)

    def test_cross_user_application_archive_rejected(self):
        """User A cannot archive User B's application."""
        with self.assertRaises(CrossUserAccessError):
            self.db.archive_user_application(self.app_b.id, user_id=self.user_a_id)

    def test_invalid_user_id_raises_user_not_found(self):
        """Non-existent user IDs raise UserNotFoundError."""
        with self.assertRaises(UserNotFoundError):
            self.db.create_user_application(
                user_id=99999,
                company_name="Ghost Corp",
                job_title="Ghost Role",
            )

    def test_direct_sqlite_composite_foreign_key_rejection(self):
        """Direct SQL insertion with mismatched composite FKs must be rejected by SQLite engine."""
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                # Attempt to insert event for User A with User B's user_id
                conn.execute(
                    """
                    INSERT INTO application_events (
                        application_id, user_id, sequence_no, event_type,
                        actor_identifier, previous_event_hash, event_hash
                    ) VALUES (?, ?, 2, 'TAMPER_EVENT', 'intruder', 'GENESIS', 'H1')
                    """,
                    (self.app_a.id, self.user_b_id),
                )

    def test_user_deletion_cleans_user_data_and_leaves_other_user_intact(self):
        """Account erasure for User A removes User A's data cleanly while User B's applications, events, and follow-ups remain intact."""
        # Create follow-up and confirmation for User A
        self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a_id,
            follow_up_date="2026-11-20",
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            description="Send thank you note",
        )
        self.db.create_submission_confirmation(
            application_id=self.app_a.id,
            user_id=self.user_a_id,
            submission_channel=SubmissionChannel.LINKEDIN.value,
        )

        # Create follow-up and confirmation for User B
        self.db.create_application_follow_up(
            application_id=self.app_b.id,
            user_id=self.user_b_id,
            follow_up_date="2026-11-25",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Check status",
        )
        self.db.create_submission_confirmation(
            application_id=self.app_b.id,
            user_id=self.user_b_id,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
        )

        # Delete User A's account data
        deleted = self.db.delete_user_account_data(self.user_a_id)
        self.assertTrue(deleted)

        # Verify User A's application, events, follow-ups, and confirmations are gone
        self.assertIsNone(self.db.get_user_by_id(self.user_a_id))
        self.assertEqual(len(self.db.list_user_applications(self.user_a_id)), 0)
        self.assertEqual(len(self.db.list_application_follow_ups(self.user_a_id)), 0)
        self.assertEqual(len(self.db.list_submission_confirmations(self.user_a_id)), 0)

        # Verify User B's application, events, follow-ups, and confirmations are 100% intact
        app_b_fresh = self.db.get_user_application(self.app_b.id, self.user_b_id)
        self.assertIsNotNone(app_b_fresh)
        self.assertEqual(app_b_fresh.status, ApplicationStatus.SUBMITTED.value)

        events_b = self.db.get_application_events(self.app_b.id, self.user_b_id)
        self.assertGreaterEqual(len(events_b), 2)  # APPLICATION_CREATED + SUBMISSION_CONFIRMED + FOLLOW_UP_SCHEDULED

        follow_ups_b = self.db.list_application_follow_ups(self.user_b_id)
        self.assertEqual(len(follow_ups_b), 1)

        confs_b = self.db.list_submission_confirmations(self.user_b_id)
        self.assertEqual(len(confs_b), 1)


if __name__ == "__main__":
    unittest.main()
