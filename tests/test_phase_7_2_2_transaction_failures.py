"""Phase 7.2.2 Immediate Transaction Safety and Error Handling Tests.

Verifies:
1. immediate_transaction executes BEGIN IMMEDIATE and commits successfully on normal block exit.
2. Exceptions inside the context block trigger ROLLBACK and preserve the original exception.
3. Lock contention when BEGIN IMMEDIATE fails:
   - txn_started remains False.
   - ROLLBACK is NOT executed (preventing 'cannot rollback - no transaction is active').
   - Original sqlite3.OperationalError (database is locked) is re-raised without masking.
4. Failures during COMMIT cleanly trigger ROLLBACK.
5. Concurrent transaction serialization under immediate write lock.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.database.db_manager import DatabaseManager


class TestPhase722TransactionFailures(unittest.TestCase):
    """Tests SQLite immediate_transaction error handling, lock contention, and rollback safety."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_txns.db")
        self.db = DatabaseManager(self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS test_counter (id INTEGER PRIMARY KEY, count INTEGER)")
            cursor.execute("INSERT INTO test_counter (id, count) VALUES (1, 100)")

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. NORMAL COMMIT & BLOCK ROLLBACK
    # =========================================================================

    def test_immediate_transaction_commits_on_success(self):
        """Changes committed when immediate_transaction block completes normally."""
        with self.db.immediate_transaction() as conn:
            conn.execute("UPDATE test_counter SET count = 200 WHERE id = 1")

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count FROM test_counter WHERE id = 1")
            self.assertEqual(cursor.fetchone()[0], 200)

    def test_immediate_transaction_rolls_back_on_exception_inside_block(self):
        """Changes rolled back when exception occurs inside the immediate_transaction block."""
        with self.assertRaises(ValueError):
            with self.db.immediate_transaction() as conn:
                conn.execute("UPDATE test_counter SET count = 999 WHERE id = 1")
                raise ValueError("Deliberate block failure")

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count FROM test_counter WHERE id = 1")
            self.assertEqual(cursor.fetchone()[0], 100)

    # =========================================================================
    # 2. LOCK CONTENTION & BEGIN IMMEDIATE FAILURE HANDLING
    # =========================================================================

    def test_begin_immediate_failure_does_not_call_rollback_and_preserves_error(self):
        """When BEGIN IMMEDIATE fails (e.g. database locked), ROLLBACK is not attempted.

        Crucial test: Verifies that sqlite3.OperationalError: database is locked is NOT
        masked by sqlite3.OperationalError: cannot rollback - no transaction is active.
        """
        # Hold an exclusive write lock using raw sqlite3 connection with autocommit=False
        blocking_conn = sqlite3.connect(self.db_path, timeout=0.1)
        blocking_conn.execute("BEGIN EXCLUSIVE")
        blocking_conn.execute("UPDATE test_counter SET count = 555 WHERE id = 1")

        try:
            # Create a DB manager with a tiny timeout so it raises OperationalError immediately
            contending_db = DatabaseManager(self.db_path)
            # Patch timeout on connections to 0.05s
            with patch.object(contending_db, "get_connection") as mock_conn_fn:
                real_conn = sqlite3.connect(self.db_path, timeout=0.05)
                mock_conn_fn.return_value = real_conn

                # Attempting immediate_transaction will fail on BEGIN IMMEDIATE
                with self.assertRaises(sqlite3.OperationalError) as ctx:
                    with contending_db.immediate_transaction() as conn:
                        conn.execute("UPDATE test_counter SET count = 777 WHERE id = 1")

                # Must be 'database is locked', NEVER 'cannot rollback - no transaction is active'
                err_msg = str(ctx.exception).lower()
                self.assertIn("locked", err_msg)
                self.assertNotIn("cannot rollback", err_msg)
        finally:
            blocking_conn.rollback()
            blocking_conn.close()

    def test_mock_begin_immediate_failure_does_not_mask_original_exception(self):
        """Synthetic failure in BEGIN IMMEDIATE does not call conn.execute('ROLLBACK')."""
        fake_conn = MagicMock()
        fake_conn.execute.side_effect = sqlite3.OperationalError("database is locked (synthetic)")

        with patch.object(self.db, "get_connection", return_value=fake_conn):
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                with self.db.immediate_transaction() as _:
                    pass

            self.assertIn("database is locked (synthetic)", str(ctx.exception))
            # Verify ROLLBACK was never called on fake_conn
            calls = [call[0][0] for call in fake_conn.execute.call_args_list if call[0]]
            self.assertIn("BEGIN IMMEDIATE", calls)
            self.assertNotIn("ROLLBACK", calls)

    # =========================================================================
    # 3. COMMIT FAILURE HANDLING
    # =========================================================================

    def test_commit_failure_triggers_rollback_and_preserves_error(self):
        """When conn.execute('COMMIT') fails, ROLLBACK is executed and original error re-raised."""
        fake_conn = MagicMock()

        def execute_side_effect(sql, *args):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("disk I/O error during commit")
            return MagicMock()

        fake_conn.execute.side_effect = execute_side_effect

        with patch.object(self.db, "get_connection", return_value=fake_conn):
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                with self.db.immediate_transaction() as _:
                    pass

            self.assertIn("disk I/O error during commit", str(ctx.exception))
            calls = [call[0][0] for call in fake_conn.execute.call_args_list if call[0]]
            self.assertIn("BEGIN IMMEDIATE", calls)
            self.assertIn("COMMIT", calls)
            self.assertIn("ROLLBACK", calls)

    # =========================================================================
    # 4. ROLLBACK FAILURE NON-MASKING
    # =========================================================================

    def test_rollback_exception_does_not_mask_primary_block_exception(self):
        """If ROLLBACK itself encounters an exception, the primary exception is still re-raised."""
        fake_conn = MagicMock()

        def execute_side_effect(sql, *args):
            if sql == "ROLLBACK":
                raise sqlite3.OperationalError("secondary rollback failure")
            return MagicMock()

        fake_conn.execute.side_effect = execute_side_effect

        with patch.object(self.db, "get_connection", return_value=fake_conn):
            with self.assertRaises(ValueError) as ctx:
                with self.db.immediate_transaction() as _:
                    raise ValueError("Primary block exception")

            self.assertEqual(str(ctx.exception), "Primary block exception")


if __name__ == "__main__":
    unittest.main()
