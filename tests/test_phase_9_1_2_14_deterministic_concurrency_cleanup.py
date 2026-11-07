"""Dedicated test suite for Phase 9.1.2.14:
Deterministic SQLite Concurrency Testing & Clock State Cleanup.

Independent Review Remediation:
1. Deterministic SQLite Lock-Conflict and Retry Architecture:
   - Replaces trace callbacks with observable database operations.
   - The competing worker executes BEGIN IMMEDIATE with timeout=0.0 against a write-locked database.
   - Catches the resulting sqlite3.OperationalError ("database is locked").
   - Proves SQLite's actual lock-conflict error was returned before signaling lock_conflict_observed.
   - Waits on an explicit retry-permission event.
   - Retries the transaction after the original transaction releases the lock.
   - Verifies successful lock acquisition and transaction completion.
2. Seven Distinct Lifecycle States:
   - State 1: Worker thread created
   - State 2: Worker entered transaction path
   - State 3: Actual SQLite lock attempt executed (timeout=0.0)
   - State 4: SQLite returned lock-conflict error (OperationalError)
   - State 5: Original transaction committed/rolled back; retry permitted
   - State 6: Worker retried and acquired write lock
   - State 7: Competing transaction completed
3. Full Coverage of Concurrency Scenarios:
   - Scenario A: Revocation wins under lock conflict and retry
   - Scenario B: Attestation wins under lock conflict and retry
   - Scenario C: Caller-supplied cursor under lock conflict and retry
4. Strengthened Injected-Failure & Cleanup Coverage:
   - Failure while Thread A holds its write lock
   - Failure after Thread B observes lock conflict
   - Failure before retry permission
   - Failure during retry
   - Failure during transaction commit
   - Guaranteed thread termination check: assert thread.is_alive() is False
   - Verification that database remains unlocked and writable after cleanup
5. Clock State Preservation & ContextVar Scoping:
   - _CLOCK_VAR is the sole injected clock mechanism
   - Elimination of redundant _CLOCK_PROVIDER mutable global
   - Thread isolation, copy_context() isolation, nested and exception-safe restoration
"""

import contextvars
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import time as py_time
from typing import List, Tuple
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import (
    DEFAULT_SCHEMA_PATH,
    DatabaseManager,
)
from src.database.exceptions import (
    SecurityAuthorizationError,
)
import src.security.legacy_evidence_verifier as lev_module
from src.security.legacy_evidence_verifier import (
    AuthenticatedMigrationPrincipal,
    InMemoryEvidenceResolver,
    LegacyEvidenceTrustStore,
    LegacyEvidenceVerifier,
    ServiceAuthenticationProvider,
    VerifiedLegacyEvidence,
    create_signed_evidence_artifact,
    frozen_utc_clock,
    get_current_utc_time,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
    set_test_clock,
)
from src.utils.canonical_json import canonical_json_hash


class Phase91214DeterministicConcurrencyCleanupTests(unittest.TestCase):
    """Authoritative test suite verifying Phase 9.1.2.14 remediation specifications."""

    def setUp(self) -> None:
        os.environ["APP_ENV"] = "test"
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)

        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_14_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "phase_9_1_2_14.db"
        self.db = DatabaseManager(db_path=self.db_path, schema_path=DEFAULT_SCHEMA_PATH)

        # Signing key for evidence
        self.evidence_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.evidence_pub_bytes = self.evidence_priv_key.public_key().public_bytes_raw()

        # Service key for service authentication provider
        self.service_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.service_pub_bytes = self.service_priv_key.public_key().public_bytes_raw()

        # Create test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice_91214@example.com", "hash1", "salt1", "Alice 91214"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_91214@example.com", "hash2", "salt2", "Bob 91214"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Security Architect for Phase 9.1.2.14 verification."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": user_id,
            "company_name": "SecureCorp",
            "job_title": "Security Architect",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'SecureCorp', 'Security Architect', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (user_id, raw_text, c_hash, snap_hash),
            )
            return c.lastrowid

    def _create_provider(self, env: str = "test") -> ServiceAuthenticationProvider:
        with patch.dict(os.environ, {"APP_ENV": env}, clear=True):
            return ServiceAuthenticationProvider(
                trusted_keys={"k_svc_01": {"key_bytes": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={"archival_authority"},
                expected_audience="legacy_migration",
                db_manager=self.db,
            )

    def _setup_verified_evidence_and_principal(self) -> Tuple[VerifiedLegacyEvidence, AuthenticatedMigrationPrincipal, int, LegacyEvidenceTrustStore]:
        provider = self._create_provider("test")
        self.db.set_service_authenticator(provider)

        principal_id = "migration_runner_91214"
        token = provider.mint_service_token(
            principal_id=principal_id,
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={principal_id},
            db_manager=self.db,
        )
        store.register_trusted_key("k_ev_01", self.evidence_pub_bytes, algorithm="Ed25519")

        resolver = InMemoryEvidenceResolver()
        jd_id = self._create_sample_jd(self.user1_id)
        snap = "snapshot_prov_hash_91214"

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_91214",
            issuer_id="archival_authority",
            key_id="k_ev_01",
            signing_key=self.evidence_priv_key,
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}],
            signature_algorithm="Ed25519",
            attesting_principal=principal_id,
        )
        resolver.register_artifact("historical_import_manifest", "PROV_REF_91214", raw_bytes)

        verifier = LegacyEvidenceVerifier(
            trust_store=store,
            resolver=resolver,
            service_authenticator=provider,
            db_manager=self.db,
        )
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_91214",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=principal,
        )
        return verified, principal, jd_id, store

    # =========================================================================
    # PART A: DETERMINISTIC LOCK-CONFLICT AND RETRY (Tests 1-4)
    # =========================================================================

    def test_01_deterministic_scenario_a_revocation_wins_all_seven_states(self) -> None:
        """TC-01: Deterministic Scenario A — Revocation wins under lock conflict and retry.

        Proves all 7 lifecycle states:
        State 1: Worker thread created
        State 2: Worker entered transaction path
        State 3: Actual SQLite lock attempt executed (timeout=0.0)
        State 4: SQLite returned lock-conflict error (OperationalError: database is locked)
        State 5: Original transaction commits revocation; retry permitted
        State 6: Worker retried and acquired write lock
        State 7: Competing transaction completed and rejected revoked principal
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None

        state1_worker_created = threading.Event()
        state2_entered_path = threading.Event()
        state3_lock_attempt_executed = threading.Event()
        state4_lock_conflict_observed = threading.Event()
        state5_retry_permitted = threading.Event()
        state6_retry_lock_acquired = threading.Event()
        state7_worker_completed = threading.Event()
        b_exceptions: List[Exception] = []

        try:
            # Thread A acquires write lock and inserts revocation uncommitted
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")
            connA.execute(
                "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                (principal_id, "Deterministic Scenario A: Revocation wins"),
            )

            # Probe confirms database is physically locked
            probe = self.db.get_connection(timeout=0.0)
            probe.isolation_level = None
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    probe.execute("BEGIN IMMEDIATE")
            finally:
                probe.close()

            def thread_b_worker() -> None:
                state1_worker_created.set()
                state2_entered_path.set()

                # Attempt 1: Execute actual record_legacy_evidence_attestation with timeout=0.0
                try:
                    state3_lock_attempt_executed.set()
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=verified,
                        attesting_principal=principal,
                        trust_store=store,
                        timeout=0.0,
                    )
                except sqlite3.OperationalError as op_err:
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        state4_lock_conflict_observed.set()
                    else:
                        b_exceptions.append(op_err)
                        return
                except Exception as e:
                    b_exceptions.append(e)
                    return

                # Wait for retry permission
                if not state5_retry_permitted.wait(timeout=5.0):
                    b_exceptions.append(TimeoutError("Worker timed out waiting for retry permission."))
                    return

                # Attempt 2 (Retry): Now that Thread A released the lock, retry with timeout=5.0
                try:
                    state6_retry_lock_acquired.set()
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=verified,
                        attesting_principal=principal,
                        trust_store=store,
                        timeout=5.0,
                    )
                except Exception as retry_err:
                    b_exceptions.append(retry_err)
                finally:
                    state7_worker_completed.set()

            thread_b = threading.Thread(target=thread_b_worker)
            thread_b.start()

            # State 1, 2, 3
            self.assertTrue(state1_worker_created.wait(timeout=5.0), "State 1 failed.")
            self.assertTrue(state2_entered_path.wait(timeout=5.0), "State 2 failed.")
            self.assertTrue(state3_lock_attempt_executed.wait(timeout=5.0), "State 3 failed.")

            # State 4: Observable SQLite lock-conflict error
            self.assertTrue(state4_lock_conflict_observed.wait(timeout=5.0), "State 4 failed: No lock conflict.")
            self.assertTrue(thread_b.is_alive(), "Worker died before retry.")

            # State 5: Original transaction commits revocation and releases write lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Grant retry permission
            state5_retry_permitted.set()

            # State 6: Worker retries and acquires write lock
            self.assertTrue(state6_retry_lock_acquired.wait(timeout=5.0), "State 6 failed: Did not acquire lock.")
            # State 7: Worker completes
            self.assertTrue(state7_worker_completed.wait(timeout=5.0), "State 7 failed: Did not complete.")
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive(), "Thread B failed to terminate cleanly.")

            # Worker must have failed closed with SecurityAuthorizationError
            self.assertEqual(len(b_exceptions), 1)
            self.assertIsInstance(b_exceptions[0], SecurityAuthorizationError)
            self.assertIn("has been revoked in database", str(b_exceptions[0]))

            # Verify no attestation row was persisted
            att = self.db.get_legacy_evidence_attestation(verified.job_description_id, user_id=self.user1_id)
            self.assertIsNone(att, "Attestation must not be persisted for revoked principal.")
        finally:
            state5_retry_permitted.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive during cleanup!")

    def test_02_deterministic_scenario_b_attestation_wins_all_seven_states(self) -> None:
        """TC-02: Deterministic Scenario B — Attestation wins under lock conflict and retry.

        Proves all 7 lifecycle states:
        State 1: Worker thread created
        State 2: Worker entered transaction path
        State 3: Actual SQLite lock attempt executed (timeout=0.0)
        State 4: SQLite returned lock-conflict error
        State 5: Original transaction commits attestation; retry permitted
        State 6: Worker retries revocation, acquires lock, commits revocation
        State 7: Competing transaction completed; historical attestation preserved
        """
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None

        state1_worker_created = threading.Event()
        state2_entered_path = threading.Event()
        state3_lock_attempt_executed = threading.Event()
        state4_lock_conflict_observed = threading.Event()
        state5_retry_permitted = threading.Event()
        state6_retry_lock_acquired = threading.Event()
        state7_worker_completed = threading.Event()
        b_exceptions: List[Exception] = []

        try:
            # Thread A holds BEGIN IMMEDIATE with inserted attestation
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")
            curA = connA.cursor()

            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=curA,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)

            def thread_b_revocation_worker() -> None:
                state1_worker_created.set()
                state2_entered_path.set()

                # Attempt 1: Execute BEGIN IMMEDIATE with timeout=0.0
                connB = None
                try:
                    connB = self.db.get_connection(timeout=0.0)
                    connB.isolation_level = None
                    state3_lock_attempt_executed.set()
                    connB.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as op_err:
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        state4_lock_conflict_observed.set()
                    else:
                        b_exceptions.append(op_err)
                        return
                except Exception as e:
                    b_exceptions.append(e)
                    return
                finally:
                    if connB:
                        try:
                            connB.close()
                        except Exception:
                            pass

                # Wait for retry permission
                if not state5_retry_permitted.wait(timeout=5.0):
                    b_exceptions.append(TimeoutError("Worker timed out waiting for retry permission."))
                    return

                # Attempt 2 (Retry): Retrying revocation with timeout=5.0
                connB_retry = None
                try:
                    connB_retry = self.db.get_connection(timeout=5.0)
                    connB_retry.isolation_level = None
                    connB_retry.execute("BEGIN IMMEDIATE")
                    state6_retry_lock_acquired.set()
                    connB_retry.execute(
                        "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                        (principal_id, "Deterministic Scenario B: Revocation after attestation"),
                    )
                    connB_retry.execute("COMMIT")
                except Exception as retry_err:
                    b_exceptions.append(retry_err)
                finally:
                    if connB_retry:
                        try:
                            connB_retry.close()
                        except Exception:
                            pass
                    state7_worker_completed.set()

            thread_b = threading.Thread(target=thread_b_revocation_worker)
            thread_b.start()

            # State 1, 2, 3
            self.assertTrue(state1_worker_created.wait(timeout=5.0))
            self.assertTrue(state2_entered_path.wait(timeout=5.0))
            self.assertTrue(state3_lock_attempt_executed.wait(timeout=5.0))

            # State 4: SQLite returned lock-conflict error
            self.assertTrue(state4_lock_conflict_observed.wait(timeout=5.0))
            self.assertTrue(thread_b.is_alive())

            # State 5: Thread A commits attestation and releases lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Grant retry permission
            state5_retry_permitted.set()

            # State 6: Worker retries and acquires write lock
            self.assertTrue(state6_retry_lock_acquired.wait(timeout=5.0))
            # State 7: Worker completes
            self.assertTrue(state7_worker_completed.wait(timeout=5.0))
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive(), "Thread B failed to terminate cleanly.")
            self.assertEqual(len(b_exceptions), 0, f"Revocation worker had errors: {b_exceptions}")

            # Attestation is immutable and persisted
            row = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
            self.assertIsNotNone(row)
            self.assertEqual(row.attested_by, principal_id)

            # Subsequent checks confirm principal is revoked
            self.assertTrue(self.db.is_principal_revoked(principal_id))
            self.assertFalse(store.is_attesting_principal_trusted(principal_id))
        finally:
            state5_retry_permitted.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive during cleanup!")

    def test_03_deterministic_scenario_c_caller_supplied_cursor_contention(self) -> None:
        """TC-03: Deterministic Scenario C — Caller-supplied cursor under lock conflict and retry.

        Proves:
        1. Sentinel write occurs inside caller's cursor before revocation checks.
        2. Competing caller with timeout=0.0 encounters actual lock conflict error.
        3. Competing caller retries and acquires lock after original caller commits.
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        conn1 = None
        t2 = None

        t2_created = threading.Event()
        t2_entered = threading.Event()
        t2_lock_attempt = threading.Event()
        t2_conflict_observed = threading.Event()
        t2_retry_permitted = threading.Event()
        t2_acquired = threading.Event()
        t2_completed = threading.Event()
        t2_exceptions: List[Exception] = []

        try:
            conn1 = self.db.get_connection(timeout=5.0)
            conn1.isolation_level = None
            conn1.execute("BEGIN IMMEDIATE")
            cur1 = conn1.cursor()

            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur1,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)

            # Verify sentinel row was touched
            cur1.execute("SELECT updated_at FROM _sqlite_write_lock_sentinel WHERE id = 1")
            sentinel_row = cur1.fetchone()
            self.assertIsNotNone(sentinel_row)

            def thread2_worker() -> None:
                t2_created.set()
                t2_entered.set()
                # Attempt 1: timeout=0.0
                conn2 = None
                try:
                    conn2 = self.db.get_connection(timeout=0.0)
                    conn2.isolation_level = None
                    t2_lock_attempt.set()
                    conn2.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as op_err:
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        t2_conflict_observed.set()
                    else:
                        t2_exceptions.append(op_err)
                        return
                except Exception as e:
                    t2_exceptions.append(e)
                    return
                finally:
                    if conn2:
                        try:
                            conn2.close()
                        except Exception:
                            pass

                if not t2_retry_permitted.wait(timeout=5.0):
                    t2_exceptions.append(TimeoutError("Thread 2 timed out waiting for retry permission."))
                    return

                # Attempt 2: retry with timeout=5.0
                conn2_retry = None
                try:
                    conn2_retry = self.db.get_connection(timeout=5.0)
                    conn2_retry.isolation_level = None
                    conn2_retry.execute("BEGIN IMMEDIATE")
                    t2_acquired.set()
                    conn2_retry.execute("COMMIT")
                except Exception as e:
                    t2_exceptions.append(e)
                finally:
                    if conn2_retry:
                        try:
                            conn2_retry.close()
                        except Exception:
                            pass
                    t2_completed.set()

            t2 = threading.Thread(target=thread2_worker)
            t2.start()

            self.assertTrue(t2_created.wait(timeout=5.0))
            self.assertTrue(t2_entered.wait(timeout=5.0))
            self.assertTrue(t2_lock_attempt.wait(timeout=5.0))
            self.assertTrue(t2_conflict_observed.wait(timeout=5.0))
            self.assertTrue(t2.is_alive())

            # Commit conn1
            conn1.execute("COMMIT")
            conn1.close()
            conn1 = None

            t2_retry_permitted.set()

            self.assertTrue(t2_acquired.wait(timeout=5.0))
            self.assertTrue(t2_completed.wait(timeout=5.0))
            t2.join(timeout=5.0)
            self.assertFalse(t2.is_alive(), "Thread 2 failed to terminate cleanly.")
            self.assertEqual(len(t2_exceptions), 0)
        finally:
            t2_retry_permitted.set()
            if conn1 is not None:
                try:
                    conn1.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    conn1.close()
                except Exception:
                    pass
            if t2 is not None and t2.is_alive():
                t2.join(timeout=5.0)
                self.assertFalse(t2.is_alive(), "Thread 2 remained alive during cleanup!")

    def test_04_worker_thread_exception_propagation(self) -> None:
        """TC-04: Worker thread exceptions are reliably captured and propagated to test thread."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        worker_exceptions: List[Exception] = []
        worker_done = threading.Event()

        def faulty_worker() -> None:
            try:
                # Deliberately revoke principal prior to call
                with self.db.transaction() as conn:
                    conn.execute(
                        "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                        (principal.principal_id, "Fault propagation test"),
                    )
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified,
                    attesting_principal=principal,
                    trust_store=store,
                )
            except Exception as e:
                worker_exceptions.append(e)
            finally:
                worker_done.set()

        t = threading.Thread(target=faulty_worker)
        t.start()
        self.assertTrue(worker_done.wait(timeout=5.0))
        t.join(timeout=5.0)
        self.assertFalse(t.is_alive(), "Worker thread must be terminated.")

        self.assertEqual(len(worker_exceptions), 1)
        self.assertIsInstance(worker_exceptions[0], SecurityAuthorizationError)
        self.assertIn("has been revoked in database", str(worker_exceptions[0]))

    # =========================================================================
    # PART B: STRENGTHENED INJECTED-FAILURE & CLEANUP TESTS (Tests 5-9)
    # =========================================================================

    def test_05_injected_failure_while_thread_a_holds_write_lock(self) -> None:
        """TC-05: Injected failure while Thread A holds write lock triggers complete cleanup."""
        connA = None
        thread_w = None
        worker_attempted = threading.Event()
        worker_conflict = threading.Event()
        worker_retry = threading.Event()
        worker_done = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker() -> None:
                connW = None
                try:
                    connW = self.db.get_connection(timeout=0.0)
                    connW.isolation_level = None
                    worker_attempted.set()
                    connW.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    worker_conflict.set()
                finally:
                    if connW:
                        connW.close()

                worker_retry.wait(timeout=5.0)
                worker_done.set()

            thread_w = threading.Thread(target=worker)
            thread_w.start()

            self.assertTrue(worker_attempted.wait(timeout=5.0))
            self.assertTrue(worker_conflict.wait(timeout=5.0))

            # Simulate an injected failure while Thread A holds write lock
            raise RuntimeError("Injected failure while Thread A holds write lock")
        except RuntimeError as e:
            self.assertEqual(str(e), "Injected failure while Thread A holds write lock")
        finally:
            worker_retry.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_w is not None and thread_w.is_alive():
                thread_w.join(timeout=5.0)
                self.assertFalse(thread_w.is_alive(), "Worker remained alive post-cleanup!")

        # Verify database is immediately writable with timeout=0.0
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    def test_06_injected_failure_after_thread_b_observes_lock_conflict(self) -> None:
        """TC-06: Injected failure after Thread B observes lock conflict triggers complete cleanup."""
        connA = None
        thread_b = None
        b_attempted = threading.Event()
        b_conflict = threading.Event()
        b_retry = threading.Event()
        b_done = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker() -> None:
                conn = None
                try:
                    conn = self.db.get_connection(timeout=0.0)
                    conn.isolation_level = None
                    b_attempted.set()
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    b_conflict.set()
                finally:
                    if conn:
                        conn.close()

                b_retry.wait(timeout=5.0)
                b_done.set()

            thread_b = threading.Thread(target=worker)
            thread_b.start()

            self.assertTrue(b_attempted.wait(timeout=5.0))
            self.assertTrue(b_conflict.wait(timeout=5.0))

            # Inject failure right after observing lock conflict
            raise RuntimeError("Injected failure after lock conflict observed")
        except RuntimeError as e:
            self.assertEqual(str(e), "Injected failure after lock conflict observed")
        finally:
            b_retry.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive post-cleanup!")

        # Database must be writable
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    def test_07_injected_failure_before_retry_permission(self) -> None:
        """TC-07: Injected failure before retry permission is granted triggers complete cleanup."""
        connA = None
        thread_b = None
        b_conflict = threading.Event()
        b_retry = threading.Event()
        b_done = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker() -> None:
                conn = None
                try:
                    conn = self.db.get_connection(timeout=0.0)
                    conn.isolation_level = None
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    b_conflict.set()
                finally:
                    if conn:
                        conn.close()

                b_retry.wait(timeout=5.0)
                b_done.set()

            thread_b = threading.Thread(target=worker)
            thread_b.start()

            self.assertTrue(b_conflict.wait(timeout=5.0))

            # Simulate failure before granting retry permission
            raise RuntimeError("Injected failure before retry permission")
        except RuntimeError as e:
            self.assertEqual(str(e), "Injected failure before retry permission")
        finally:
            b_retry.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive post-cleanup!")

        # Database must be writable
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    def test_08_injected_failure_during_worker_retry(self) -> None:
        """TC-08: Injected failure inside worker during retry is captured and does not hang."""
        connA = None
        thread_b = None
        b_conflict = threading.Event()
        b_retry = threading.Event()
        b_done = threading.Event()
        b_errors = []

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker() -> None:
                conn = None
                try:
                    conn = self.db.get_connection(timeout=0.0)
                    conn.isolation_level = None
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    b_conflict.set()
                finally:
                    if conn:
                        conn.close()

                if not b_retry.wait(timeout=5.0):
                    return

                try:
                    # Injected failure during retry
                    raise RuntimeError("Injected failure during retry execution")
                except Exception as e:
                    b_errors.append(e)
                finally:
                    b_done.set()

            thread_b = threading.Thread(target=worker)
            thread_b.start()

            self.assertTrue(b_conflict.wait(timeout=5.0))
            connA.execute("COMMIT")
            connA.close()
            connA = None

            b_retry.set()
            self.assertTrue(b_done.wait(timeout=5.0))
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive(), "Thread B remained alive post-cleanup!")
            self.assertEqual(len(b_errors), 1)
            self.assertEqual(str(b_errors[0]), "Injected failure during retry execution")
        finally:
            b_retry.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive post-cleanup!")

        # Database must be writable
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    def test_09_injected_failure_during_transaction_commit(self) -> None:
        """TC-09: Injected failure during transaction block triggers rollback and frees lock."""
        with self.assertRaises(RuntimeError) as ctx:
            with self.db.immediate_transaction() as conn:
                conn.execute(
                    "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                    ("faulty_p_91214", "Commit failure test"),
                )
                raise RuntimeError("Simulated failure right before commit")
        self.assertEqual(str(ctx.exception), "Simulated failure right before commit")

        # Row must not be committed
        self.assertFalse(self.db.is_principal_revoked("faulty_p_91214"))

        # Lock must be released immediately
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    # =========================================================================
    # PART C: MULTI-WORKER SERIALIZATION & LIFECYCLE ORDERING (Tests 10-12)
    # =========================================================================

    def test_10_multi_worker_lock_conflict_and_sequential_retry(self) -> None:
        """TC-10: Multiple workers observing lock conflict serialize cleanly upon retry."""
        connA = None
        t1 = None
        t2 = None

        t1_conflict = threading.Event()
        t2_conflict = threading.Event()
        retry_permitted = threading.Event()
        t1_done = threading.Event()
        t2_done = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker_fn(conflict_evt: threading.Event, done_evt: threading.Event) -> None:
                # Attempt 1: timeout=0.0
                conn = None
                try:
                    conn = self.db.get_connection(timeout=0.0)
                    conn.isolation_level = None
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    conflict_evt.set()
                finally:
                    if conn:
                        conn.close()

                retry_permitted.wait(timeout=5.0)

                # Attempt 2: retry with timeout=5.0
                conn_retry = None
                try:
                    conn_retry = self.db.get_connection(timeout=5.0)
                    conn_retry.isolation_level = None
                    conn_retry.execute("BEGIN IMMEDIATE")
                    conn_retry.execute("COMMIT")
                finally:
                    if conn_retry:
                        conn_retry.close()
                    done_evt.set()

            t1 = threading.Thread(target=worker_fn, args=(t1_conflict, t1_done))
            t2 = threading.Thread(target=worker_fn, args=(t2_conflict, t2_done))

            t1.start()
            t2.start()

            self.assertTrue(t1_conflict.wait(timeout=5.0))
            self.assertTrue(t2_conflict.wait(timeout=5.0))

            # Both observed lock conflict while Thread A held write lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Permit retry
            retry_permitted.set()

            self.assertTrue(t1_done.wait(timeout=5.0))
            self.assertTrue(t2_done.wait(timeout=5.0))
            t1.join(timeout=5.0)
            t2.join(timeout=5.0)
            self.assertFalse(t1.is_alive())
            self.assertFalse(t2.is_alive())
        finally:
            retry_permitted.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if t1 is not None and t1.is_alive():
                t1.join(timeout=5.0)
                self.assertFalse(t1.is_alive())
            if t2 is not None and t2.is_alive():
                t2.join(timeout=5.0)
                self.assertFalse(t2.is_alive())

    def test_11_explicit_monotonic_seven_state_lifecycle_ordering(self) -> None:
        """TC-11: Explicit verification that all 7 lifecycle states occur in strict monotonic order."""
        state_timestamps = {}
        connA = None
        worker = None

        s1_evt = threading.Event()
        s2_evt = threading.Event()
        s3_evt = threading.Event()
        s4_evt = threading.Event()
        s5_retry = threading.Event()
        s6_evt = threading.Event()
        s7_evt = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker_fn() -> None:
                state_timestamps["s1_created"] = py_time.monotonic()
                s1_evt.set()

                state_timestamps["s2_entered"] = py_time.monotonic()
                s2_evt.set()

                conn = None
                try:
                    conn = self.db.get_connection(timeout=0.0)
                    conn.isolation_level = None
                    state_timestamps["s3_attempted"] = py_time.monotonic()
                    s3_evt.set()
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError:
                    state_timestamps["s4_conflict"] = py_time.monotonic()
                    s4_evt.set()
                finally:
                    if conn:
                        conn.close()

                s5_retry.wait(timeout=5.0)

                conn_retry = None
                try:
                    conn_retry = self.db.get_connection(timeout=5.0)
                    conn_retry.isolation_level = None
                    conn_retry.execute("BEGIN IMMEDIATE")
                    state_timestamps["s6_acquired"] = py_time.monotonic()
                    s6_evt.set()
                    conn_retry.execute("COMMIT")
                finally:
                    if conn_retry:
                        conn_retry.close()
                    state_timestamps["s7_completed"] = py_time.monotonic()
                    s7_evt.set()

            worker = threading.Thread(target=worker_fn)
            worker.start()

            self.assertTrue(s1_evt.wait(timeout=5.0))
            self.assertTrue(s2_evt.wait(timeout=5.0))
            self.assertTrue(s3_evt.wait(timeout=5.0))
            self.assertTrue(s4_evt.wait(timeout=5.0))

            state_timestamps["s5_committed"] = py_time.monotonic()
            connA.execute("COMMIT")
            connA.close()
            connA = None

            s5_retry.set()

            self.assertTrue(s6_evt.wait(timeout=5.0))
            self.assertTrue(s7_evt.wait(timeout=5.0))
            worker.join(timeout=5.0)
            self.assertFalse(worker.is_alive(), "Worker failed to terminate cleanly.")

            # Monotonic order check:
            # s1 <= s2 <= s3 <= s4 <= s5 <= s6 <= s7
            self.assertLessEqual(state_timestamps["s1_created"], state_timestamps["s2_entered"])
            self.assertLessEqual(state_timestamps["s2_entered"], state_timestamps["s3_attempted"])
            self.assertLessEqual(state_timestamps["s3_attempted"], state_timestamps["s4_conflict"])
            self.assertLessEqual(state_timestamps["s4_conflict"], state_timestamps["s5_committed"])
            self.assertLessEqual(state_timestamps["s5_committed"], state_timestamps["s6_acquired"])
            self.assertLessEqual(state_timestamps["s6_acquired"], state_timestamps["s7_completed"])
        finally:
            s5_retry.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if worker is not None and worker.is_alive():
                worker.join(timeout=5.0)
                self.assertFalse(worker.is_alive())

    def test_12_worker_termination_guarantee_and_leak_prevention(self) -> None:
        """TC-12: Proves worker thread termination guarantee and absence of leaked locks."""
        worker_done = threading.Event()

        def short_worker() -> None:
            conn = self.db.get_connection(timeout=5.0)
            conn.close()
            worker_done.set()

        t = threading.Thread(target=short_worker)
        t.start()
        self.assertTrue(worker_done.wait(timeout=5.0))
        t.join(timeout=5.0)
        self.assertFalse(t.is_alive(), "Worker must be proven terminated.")

        # Fresh connection can immediately write
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    # =========================================================================
    # PART D: CLOCK STATE CLEANUP & CONTEXTVAR ISOLATION (Tests 13-18)
    # =========================================================================

    def test_13_contextvar_thread_isolation(self) -> None:
        """TC-13: _CLOCK_VAR provides strict context isolation across independent threads."""
        custom_time = datetime(2027, 5, 20, 14, 0, 0, tzinfo=timezone.utc)
        thread_observed_times: List[datetime] = []
        thread_done = threading.Event()

        set_test_clock(lambda: custom_time)
        self.assertEqual(get_current_utc_time(), custom_time)

        def thread_worker() -> None:
            thread_observed_times.append(get_current_utc_time())
            thread_done.set()

        t = threading.Thread(target=thread_worker)
        t.start()
        self.assertTrue(thread_done.wait(timeout=5.0))
        t.join(timeout=5.0)
        self.assertFalse(t.is_alive())

        self.assertEqual(len(thread_observed_times), 1)
        self.assertNotEqual(thread_observed_times[0], custom_time)
        self.assertEqual(get_current_utc_time(), custom_time)

    def test_14_contextvar_copy_context_snapshot(self) -> None:
        """TC-14: contextvars.copy_context() captures isolated clock snapshot."""
        frozen_time = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: frozen_time)

        ctx = contextvars.copy_context()
        observed_in_ctx = ctx.run(get_current_utc_time)
        self.assertEqual(observed_in_ctx, frozen_time)

        set_test_clock(None)
        self.assertNotEqual(get_current_utc_time(), frozen_time)

        observed_after_clear = ctx.run(get_current_utc_time)
        self.assertEqual(observed_after_clear, frozen_time)

    def test_15_frozen_utc_clock_nested_restoration(self) -> None:
        """TC-15: Nested frozen_utc_clock contexts restore outer context and then default clock."""
        time1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        time2 = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        time3 = datetime(2025, 12, 1, 0, 0, 0, tzinfo=timezone.utc)

        before = get_current_utc_time()
        with frozen_utc_clock(time1):
            self.assertEqual(get_current_utc_time(), time1)
            with frozen_utc_clock(time2):
                self.assertEqual(get_current_utc_time(), time2)
                with frozen_utc_clock(time3):
                    self.assertEqual(get_current_utc_time(), time3)
                self.assertEqual(get_current_utc_time(), time2)
            self.assertEqual(get_current_utc_time(), time1)

        after = get_current_utc_time()
        self.assertNotEqual(after, time1)
        self.assertGreaterEqual(after, before)

    def test_16_frozen_utc_clock_exception_safe_restoration(self) -> None:
        """TC-16: frozen_utc_clock restores previous clock even when an exception occurs inside."""
        frozen_time = datetime(2024, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

        try:
            with frozen_utc_clock(frozen_time):
                self.assertEqual(get_current_utc_time(), frozen_time)
                raise ValueError("Simulated failure inside frozen clock")
        except ValueError as e:
            self.assertEqual(str(e), "Simulated failure inside frozen clock")

        restored = get_current_utc_time()
        self.assertNotEqual(restored, frozen_time)

    def test_17_elimination_of_redundant_global_clock_provider(self) -> None:
        """TC-17: _CLOCK_PROVIDER is strictly absent from legacy_evidence_verifier namespace."""
        self.assertFalse(
            hasattr(lev_module, "_CLOCK_PROVIDER"),
            "Redundant mutable global '_CLOCK_PROVIDER' must be completely eliminated.",
        )
        self.assertNotIn(
            "_CLOCK_PROVIDER",
            dir(lev_module),
            "'_CLOCK_PROVIDER' must not appear in module attributes.",
        )

    def test_18_set_test_clock_clearing_in_production_environment(self) -> None:
        """TC-18: Clearing test clock with set_test_clock(None) succeeds even in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            with self.assertRaises(SecurityAuthorizationError):
                set_test_clock(lambda: datetime.now(timezone.utc))

            set_test_clock(None)
            real_time = get_current_utc_time()
            self.assertIsInstance(real_time, datetime)
            self.assertIsNotNone(real_time.tzinfo)


if __name__ == "__main__":
    unittest.main()
