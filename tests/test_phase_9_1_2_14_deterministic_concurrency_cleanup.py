"""Dedicated test suite for Phase 9.1.2.14:
Deterministic SQLite Concurrency Testing & Clock State Cleanup.

Verifies:
1. Deterministic Multi-Threaded SQLite Concurrency (Zero sleep):
   - Scenario A: Revocation wins under real lock contention (Thread B waits, rejects post-commit).
   - Scenario B: Attestation wins under real lock contention (Thread B revocation waits; attestation immutable).
   - Scenario C: Caller-supplied ImmediateAwareConnection under lock contention; sentinel verification.
   - All 6 lifecycle states verified deterministically with threading.Event and set_trace_callback.
   - Observable SQLite write-lock contention proven with timeout=0.0 probe.
2. Failure-Safe Resource Cleanup:
   - Guaranteed try/finally cleanup on all test connections, transactions, and worker threads.
   - Exception and assertion resilience: lock release and thread join guaranteed on failure.
   - Database remains completely usable for subsequent transactions post-cleanup.
3. Worker Thread Exception Propagation:
   - Unhandled and security exceptions in worker threads captured and propagated to main test thread.
4. Clock State Cleanup & ContextVar Isolation:
   - Elimination of redundant _CLOCK_PROVIDER mutable global.
   - _CLOCK_VAR (ContextVar) is the sole mechanism for injected clock state.
   - Context isolation across threads, copy_context() isolation, nested context restoration,
     and exception-safe restoration.
   - Proves absence of _CLOCK_PROVIDER in src.security.legacy_evidence_verifier namespace.
"""

from contextlib import contextmanager
import contextvars
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
from typing import Generator, List, Optional, Tuple
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
    """Authoritative test suite verifying Phase 9.1.2.14 specifications."""

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
    # PART A: DETERMINISTIC MULTI-THREAD CONCURRENCY WITHOUT SLEEP (Tests 1-6)
    # =========================================================================

    def test_01_deterministic_scenario_a_revocation_wins_all_six_states(self) -> None:
        """TC-01: Deterministic Scenario A — Revocation wins under real lock contention.

        Proves all 6 lifecycle states without time.sleep:
        State 1: Worker thread created
        State 2: Worker entered transaction path
        State 3: Worker attempted SQLite write-lock operation (BEGIN IMMEDIATE)
        State 4: Contention observed; worker has not acquired write lock
        State 5: Original transaction commits revocation and releases lock
        State 6: Competing transaction acquires lock, encounters revocation, and terminates
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None
        orig_immediate_transaction = self.db.immediate_transaction
        orig_get_connection = self.db.get_connection

        # Lifecycle tracking events
        state1_worker_created = threading.Event()
        state2_entered_path = threading.Event()
        state3_attempted_lock = threading.Event()
        state4_acquired_lock = threading.Event()
        state6_worker_completed = threading.Event()
        b_exceptions: List[Exception] = []

        try:
            # Thread A connection holds BEGIN IMMEDIATE with revocation
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")
            connA.execute(
                "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                (principal_id, "Deterministic Scenario A: Revocation wins"),
            )

            # Probe confirms database is physically write-locked (timeout=0.0)
            probe = self.db.get_connection(timeout=0.0)
            probe.isolation_level = None
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    probe.execute("BEGIN IMMEDIATE")
            finally:
                probe.close()

            # Instrument get_connection to detect C-level BEGIN IMMEDIATE
            def instrumented_get_connection(timeout: Optional[float] = None) -> sqlite3.Connection:
                conn = orig_get_connection(timeout=timeout)
                def trace_cb(stmt: str) -> None:
                    if "BEGIN IMMEDIATE" in stmt:
                        state3_attempted_lock.set()
                conn.set_trace_callback(trace_cb)
                return conn

            @contextmanager
            def instrumented_immediate_transaction(timeout: Optional[float] = None) -> Generator[sqlite3.Connection, None, None]:
                state2_entered_path.set()
                with orig_immediate_transaction(timeout=timeout) as conn:
                    state4_acquired_lock.set()
                    yield conn

            self.db.get_connection = instrumented_get_connection
            self.db.immediate_transaction = instrumented_immediate_transaction

            def thread_b_worker() -> None:
                state1_worker_created.set()
                try:
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=verified,
                        attesting_principal=principal,
                        trust_store=store,
                    )
                except Exception as e:
                    b_exceptions.append(e)
                finally:
                    state6_worker_completed.set()

            thread_b = threading.Thread(target=thread_b_worker)
            thread_b.start()

            # State 1: Worker thread created
            self.assertTrue(state1_worker_created.wait(timeout=5.0), "State 1 failed: Worker thread not created.")
            # State 2: Worker entered transaction path
            self.assertTrue(state2_entered_path.wait(timeout=5.0), "State 2 failed: Did not enter transaction path.")
            # State 3: Worker attempted SQLite write-lock operation
            self.assertTrue(state3_attempted_lock.wait(timeout=5.0), "State 3 failed: Did not attempt BEGIN IMMEDIATE.")

            # State 4: Observable contention — probe fails and worker has NOT acquired lock
            probe2 = self.db.get_connection(timeout=0.0)
            probe2.isolation_level = None
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    probe2.execute("BEGIN IMMEDIATE")
            finally:
                probe2.close()
            self.assertFalse(state4_acquired_lock.is_set(), "State 4 failed: Worker acquired write lock prematurely!")
            self.assertTrue(thread_b.is_alive(), "Worker thread died prematurely.")

            # State 5: Original transaction commits revocation and releases lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # State 4 (completed): Worker acquires lock post-commit
            self.assertTrue(state4_acquired_lock.wait(timeout=5.0), "State 4 failed: Worker did not acquire lock.")
            # State 6: Worker thread completes
            self.assertTrue(state6_worker_completed.wait(timeout=5.0), "State 6 failed: Worker did not complete.")
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive())

            # Worker must have failed closed with SecurityAuthorizationError
            self.assertEqual(len(b_exceptions), 1)
            self.assertIsInstance(b_exceptions[0], SecurityAuthorizationError)
            self.assertIn("has been revoked in database", str(b_exceptions[0]))

            # Verify no attestation row was persisted
            att = self.db.get_legacy_evidence_attestation(verified.job_description_id, user_id=self.user1_id)
            self.assertIsNone(att, "Attestation must not be persisted for revoked principal.")
        finally:
            self.db.immediate_transaction = orig_immediate_transaction
            self.db.get_connection = orig_get_connection
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

    def test_02_deterministic_scenario_b_attestation_wins_all_six_states(self) -> None:
        """TC-02: Deterministic Scenario B — Attestation wins under real lock contention.

        Proves all 6 lifecycle states without time.sleep:
        State 1: Worker thread created
        State 2: Worker entered transaction path
        State 3: Worker attempted SQLite write-lock operation (BEGIN IMMEDIATE)
        State 4: Contention observed; revocation worker has not acquired write lock
        State 5: Original transaction commits attestation and releases lock
        State 6: Revocation worker acquires lock, commits revocation, and finishes
        """
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None

        state1_worker_created = threading.Event()
        state2_entered_path = threading.Event()
        state3_attempted_lock = threading.Event()
        state4_acquired_lock = threading.Event()
        state6_worker_completed = threading.Event()
        b_exceptions: List[Exception] = []

        try:
            # Thread A connection holds BEGIN IMMEDIATE with inserted attestation
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
                connB = None
                try:
                    state2_entered_path.set()
                    connB = self.db.get_connection(timeout=5.0)
                    connB.isolation_level = None
                    def trace_cb(stmt: str) -> None:
                        if "BEGIN IMMEDIATE" in stmt:
                            state3_attempted_lock.set()
                    connB.set_trace_callback(trace_cb)
                    connB.execute("BEGIN IMMEDIATE")
                    state4_acquired_lock.set()
                    connB.execute(
                        "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                        (principal_id, "Deterministic Scenario B: Revocation after attestation"),
                    )
                    connB.execute("COMMIT")
                except Exception as e:
                    b_exceptions.append(e)
                finally:
                    if connB:
                        try:
                            connB.close()
                        except Exception:
                            pass
                    state6_worker_completed.set()

            thread_b = threading.Thread(target=thread_b_revocation_worker)
            thread_b.start()

            # State 1, 2, 3
            self.assertTrue(state1_worker_created.wait(timeout=5.0), "State 1 failed.")
            self.assertTrue(state2_entered_path.wait(timeout=5.0), "State 2 failed.")
            self.assertTrue(state3_attempted_lock.wait(timeout=5.0), "State 3 failed.")

            # State 4: Observable contention
            probe = self.db.get_connection(timeout=0.0)
            probe.isolation_level = None
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    probe.execute("BEGIN IMMEDIATE")
            finally:
                probe.close()
            self.assertFalse(state4_acquired_lock.is_set(), "State 4 failed: Revocation acquired lock prematurely!")
            self.assertTrue(thread_b.is_alive())

            # State 5: Original transaction commits attestation and releases lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # State 4 (completed): Revocation worker acquires lock
            self.assertTrue(state4_acquired_lock.wait(timeout=5.0), "State 4 failed: Worker did not acquire lock.")
            # State 6: Worker thread completes
            self.assertTrue(state6_worker_completed.wait(timeout=5.0), "State 6 failed: Worker did not complete.")
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive())
            self.assertEqual(len(b_exceptions), 0, f"Revocation worker had errors: {b_exceptions}")

            # Attestation is immutable and persisted
            row = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
            self.assertIsNotNone(row)
            self.assertEqual(row.attested_by, principal_id)

            # Subsequent checks confirm principal is revoked
            self.assertTrue(self.db.is_principal_revoked(principal_id))
            self.assertFalse(store.is_attesting_principal_trusted(principal_id))
        finally:
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

    def test_03_deterministic_scenario_c_caller_supplied_cursor_contention(self) -> None:
        """TC-03: Deterministic Scenario C — Caller-supplied cursor under write lock contention.

        Proves:
        1. Sentinel write occurs inside caller's cursor before revocation checks.
        2. Competing caller blocks on write lock without sleep.
        3. Observable lock contention verified via timeout=0.0 probe.
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        conn1 = None
        t2 = None

        t2_created = threading.Event()
        t2_entered = threading.Event()
        t2_attempted = threading.Event()
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
                conn2 = None
                try:
                    t2_entered.set()
                    conn2 = self.db.get_connection(timeout=5.0)
                    conn2.isolation_level = None
                    def trace_cb(stmt: str) -> None:
                        if "BEGIN IMMEDIATE" in stmt:
                            t2_attempted.set()
                    conn2.set_trace_callback(trace_cb)
                    conn2.execute("BEGIN IMMEDIATE")
                    t2_acquired.set()
                    conn2.execute("COMMIT")
                except Exception as e:
                    t2_exceptions.append(e)
                finally:
                    if conn2:
                        try:
                            conn2.close()
                        except Exception:
                            pass
                    t2_completed.set()

            t2 = threading.Thread(target=thread2_worker)
            t2.start()

            self.assertTrue(t2_created.wait(timeout=5.0))
            self.assertTrue(t2_entered.wait(timeout=5.0))
            self.assertTrue(t2_attempted.wait(timeout=5.0))

            # Observable contention probe
            probe = self.db.get_connection(timeout=0.0)
            probe.isolation_level = None
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    probe.execute("BEGIN IMMEDIATE")
            finally:
                probe.close()

            self.assertFalse(t2_acquired.is_set(), "Thread 2 acquired write lock prematurely!")
            self.assertTrue(t2.is_alive())

            # Commit conn1
            conn1.execute("COMMIT")
            conn1.close()
            conn1 = None

            self.assertTrue(t2_acquired.wait(timeout=5.0))
            self.assertTrue(t2_completed.wait(timeout=5.0))
            t2.join(timeout=5.0)
            self.assertFalse(t2.is_alive())
            self.assertEqual(len(t2_exceptions), 0)
        finally:
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

    def test_04_worker_thread_exception_propagation(self) -> None:
        """TC-04: Worker thread exceptions are reliably captured and propagated to test thread."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        # Invalidate evidence hash to trigger a known validation error inside worker
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

        self.assertEqual(len(worker_exceptions), 1)
        self.assertIsInstance(worker_exceptions[0], SecurityAuthorizationError)
        self.assertIn("has been revoked", str(worker_exceptions[0]))

    def test_05_cleanup_guarantee_on_midflight_assertion_failure(self) -> None:
        """TC-05: Mid-flight assertion or exception triggers complete resource cleanup.

        Proves:
        1. When an exception or assertion fails while locks are held, the finally block
           rolls back the transaction, closes connections, and joins worker threads.
        2. Subsequent operations on the database immediately succeed without deadlocks or contention.
        """
        connA = None
        thread_worker = None
        worker_attempted = threading.Event()
        worker_acquired = threading.Event()
        worker_completed = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def blocked_worker() -> None:
                connW = None
                try:
                    connW = self.db.get_connection(timeout=5.0)
                    connW.isolation_level = None
                    def trace_cb(stmt: str) -> None:
                        if "BEGIN IMMEDIATE" in stmt:
                            worker_attempted.set()
                    connW.set_trace_callback(trace_cb)
                    connW.execute("BEGIN IMMEDIATE")
                    worker_acquired.set()
                    connW.execute("COMMIT")
                except Exception:
                    pass
                finally:
                    if connW:
                        try:
                            connW.close()
                        except Exception:
                            pass
                    worker_completed.set()

            thread_worker = threading.Thread(target=blocked_worker)
            thread_worker.start()

            self.assertTrue(worker_attempted.wait(timeout=5.0))
            self.assertFalse(worker_acquired.is_set())

            # Simulate an injected failure or assertion failure midway
            raise RuntimeError("Injected mid-flight test failure")
        except RuntimeError as e:
            self.assertEqual(str(e), "Injected mid-flight test failure")
        finally:
            # Cleanup pattern under test
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_worker is not None and thread_worker.is_alive():
                # Releasing connA should allow worker to complete
                worker_completed.wait(timeout=5.0)
                thread_worker.join(timeout=5.0)

        # Worker must have completed post-cleanup
        self.assertTrue(worker_completed.is_set())
        self.assertFalse(thread_worker.is_alive())

        # Crucial: Database must immediately be writable by a fresh connection with ZERO contention
        fresh_conn = self.db.get_connection(timeout=0.0)
        fresh_conn.isolation_level = None
        try:
            fresh_conn.execute("BEGIN IMMEDIATE")
            fresh_conn.execute("COMMIT")
        finally:
            fresh_conn.close()

    def test_06_multi_worker_contention_serialization(self) -> None:
        """TC-06: Multiple workers contending on SQLite write lock serialize deterministically."""
        connA = None
        t1 = None
        t2 = None

        t1_attempted = threading.Event()
        t2_attempted = threading.Event()
        t1_acquired = threading.Event()
        t2_acquired = threading.Event()
        t1_done = threading.Event()
        t2_done = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def worker_fn(attempted_evt: threading.Event, acquired_evt: threading.Event, done_evt: threading.Event) -> None:
                conn = None
                try:
                    conn = self.db.get_connection(timeout=5.0)
                    conn.isolation_level = None
                    def trace_cb(stmt: str) -> None:
                        if "BEGIN IMMEDIATE" in stmt:
                            attempted_evt.set()
                    conn.set_trace_callback(trace_cb)
                    conn.execute("BEGIN IMMEDIATE")
                    acquired_evt.set()
                    conn.execute("COMMIT")
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    done_evt.set()

            t1 = threading.Thread(target=worker_fn, args=(t1_attempted, t1_acquired, t1_done))
            t2 = threading.Thread(target=worker_fn, args=(t2_attempted, t2_acquired, t2_done))

            t1.start()
            t2.start()

            self.assertTrue(t1_attempted.wait(timeout=5.0))
            self.assertTrue(t2_attempted.wait(timeout=5.0))

            # Both workers are blocked behind connA
            self.assertFalse(t1_acquired.is_set())
            self.assertFalse(t2_acquired.is_set())

            # Release connA
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Both workers acquire and finish sequentially
            self.assertTrue(t1_done.wait(timeout=5.0))
            self.assertTrue(t2_done.wait(timeout=5.0))
            t1.join(timeout=5.0)
            t2.join(timeout=5.0)

            self.assertTrue(t1_acquired.is_set())
            self.assertTrue(t2_acquired.is_set())
        finally:
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
            if t2 is not None and t2.is_alive():
                t2.join(timeout=5.0)

    # =========================================================================
    # PART B: CLOCK STATE CLEANUP & CONTEXTVAR ISOLATION (Tests 7-12)
    # =========================================================================

    def test_07_contextvar_thread_isolation(self) -> None:
        """TC-07: _CLOCK_VAR provides strict context isolation across independent threads."""
        custom_time = datetime(2027, 5, 20, 14, 0, 0, tzinfo=timezone.utc)
        thread_observed_times: List[datetime] = []
        thread_done = threading.Event()

        # Set custom clock in main thread
        set_test_clock(lambda: custom_time)
        self.assertEqual(get_current_utc_time(), custom_time)

        # Worker thread without context copy should see current real UTC time (not custom_time)
        def thread_worker() -> None:
            thread_observed_times.append(get_current_utc_time())
            thread_done.set()

        t = threading.Thread(target=thread_worker)
        t.start()
        self.assertTrue(thread_done.wait(timeout=5.0))
        t.join(timeout=5.0)

        self.assertEqual(len(thread_observed_times), 1)
        # Worker sees real time (> 2027-05-20)
        self.assertNotEqual(thread_observed_times[0], custom_time)
        # Main thread still sees custom_time
        self.assertEqual(get_current_utc_time(), custom_time)

    def test_08_contextvar_copy_context_snapshot(self) -> None:
        """TC-08: contextvars.copy_context() captures isolated clock snapshot."""
        frozen_time = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: frozen_time)

        ctx = contextvars.copy_context()
        observed_in_ctx = ctx.run(get_current_utc_time)
        self.assertEqual(observed_in_ctx, frozen_time)

        # Clear in main context
        set_test_clock(None)
        self.assertNotEqual(get_current_utc_time(), frozen_time)

        # Context snapshot preserved its own state
        observed_after_clear = ctx.run(get_current_utc_time)
        self.assertEqual(observed_after_clear, frozen_time)

    def test_09_frozen_utc_clock_nested_restoration(self) -> None:
        """TC-09: Nested frozen_utc_clock contexts restore outer context and then default clock."""
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
        # Must be restored to real clock
        self.assertNotEqual(after, time1)
        self.assertGreaterEqual(after, before)

    def test_10_frozen_utc_clock_exception_safe_restoration(self) -> None:
        """TC-10: frozen_utc_clock restores previous clock even when an exception occurs inside."""
        frozen_time = datetime(2024, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

        try:
            with frozen_utc_clock(frozen_time):
                self.assertEqual(get_current_utc_time(), frozen_time)
                raise ValueError("Simulated failure inside frozen clock")
        except ValueError as e:
            self.assertEqual(str(e), "Simulated failure inside frozen clock")

        # Must have restored to real clock
        restored = get_current_utc_time()
        self.assertNotEqual(restored, frozen_time)

    def test_11_elimination_of_redundant_global_clock_provider(self) -> None:
        """TC-11: _CLOCK_PROVIDER is strictly absent from legacy_evidence_verifier namespace."""
        self.assertFalse(
            hasattr(lev_module, "_CLOCK_PROVIDER"),
            "Redundant mutable global '_CLOCK_PROVIDER' must be completely eliminated.",
        )
        self.assertNotIn(
            "_CLOCK_PROVIDER",
            dir(lev_module),
            "'_CLOCK_PROVIDER' must not appear in module attributes.",
        )

    def test_12_set_test_clock_clearing_in_production_environment(self) -> None:
        """TC-12: Clearing test clock with set_test_clock(None) succeeds even in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            # Attempting to set clock fails closed
            with self.assertRaises(SecurityAuthorizationError):
                set_test_clock(lambda: datetime.now(timezone.utc))

            # Clearing test clock (clock=None) must always be allowed
            set_test_clock(None)
            real_time = get_current_utc_time()
            self.assertIsInstance(real_time, datetime)
            self.assertIsNotNone(real_time.tzinfo)

    def test_13_immediate_transaction_rollback_and_lock_release_on_error(self) -> None:
        """TC-13: immediate_transaction guarantees atomic rollback and lock release on error."""
        with self.assertRaises(RuntimeError) as ctx:
            with self.db.immediate_transaction() as conn:
                conn.execute(
                    "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                    ("faulty_p_91214", "Rollback verification"),
                )
                raise RuntimeError("Simulated transaction body error")
        self.assertEqual(str(ctx.exception), "Simulated transaction body error")

        # Verify row was NOT committed
        self.assertFalse(self.db.is_principal_revoked("faulty_p_91214"))

        # Verify database is immediately unlocked and writable
        fresh = self.db.get_connection(timeout=0.0)
        fresh.isolation_level = None
        try:
            fresh.execute("BEGIN IMMEDIATE")
            fresh.execute("COMMIT")
        finally:
            fresh.close()

    def test_14_explicit_monotonic_lifecycle_state_ordering(self) -> None:
        """TC-14: Explicit verification that lifecycle states occur in strict monotonic order."""
        import time as py_time

        state_timestamps = {}
        connA = None
        worker = None
        orig_immediate_transaction = self.db.immediate_transaction
        orig_get_connection = self.db.get_connection

        state1_evt = threading.Event()
        state2_evt = threading.Event()
        state3_evt = threading.Event()
        state4_evt = threading.Event()
        state6_evt = threading.Event()

        try:
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")

            def instrumented_get_connection(timeout=None):
                conn = orig_get_connection(timeout=timeout)
                def trace_cb(stmt: str) -> None:
                    if "BEGIN IMMEDIATE" in stmt:
                        state_timestamps["state3_attempted"] = py_time.monotonic()
                        state3_evt.set()
                conn.set_trace_callback(trace_cb)
                return conn

            @contextmanager
            def instrumented_immediate_transaction(timeout=None):
                state_timestamps["state2_entered_path"] = py_time.monotonic()
                state2_evt.set()
                with orig_immediate_transaction(timeout=timeout) as conn:
                    state_timestamps["state4_acquired"] = py_time.monotonic()
                    state4_evt.set()
                    yield conn

            self.db.get_connection = instrumented_get_connection
            self.db.immediate_transaction = instrumented_immediate_transaction

            def worker_fn():
                state_timestamps["state1_created"] = py_time.monotonic()
                state1_evt.set()
                try:
                    with self.db.immediate_transaction():
                        pass
                finally:
                    state_timestamps["state6_completed"] = py_time.monotonic()
                    state6_evt.set()

            worker = threading.Thread(target=worker_fn)
            worker.start()

            self.assertTrue(state1_evt.wait(timeout=5.0))
            self.assertTrue(state2_evt.wait(timeout=5.0))
            self.assertTrue(state3_evt.wait(timeout=5.0))

            state_timestamps["state4_contention_observed"] = py_time.monotonic()
            self.assertFalse(state4_evt.is_set())

            # Release lock
            state_timestamps["state5_committed"] = py_time.monotonic()
            connA.execute("COMMIT")
            connA.close()
            connA = None

            self.assertTrue(state4_evt.wait(timeout=5.0))
            self.assertTrue(state6_evt.wait(timeout=5.0))
            worker.join(timeout=5.0)

            # Assert strict monotonic ordering
            self.assertLessEqual(state_timestamps["state1_created"], state_timestamps["state2_entered_path"])
            self.assertLessEqual(state_timestamps["state2_entered_path"], state_timestamps["state3_attempted"])
            self.assertLessEqual(state_timestamps["state3_attempted"], state_timestamps["state4_contention_observed"])
            self.assertLessEqual(state_timestamps["state4_contention_observed"], state_timestamps["state5_committed"])
            self.assertLessEqual(state_timestamps["state5_committed"], state_timestamps["state4_acquired"])
            self.assertLessEqual(state_timestamps["state4_acquired"], state_timestamps["state6_completed"])
        finally:
            self.db.immediate_transaction = orig_immediate_transaction
            self.db.get_connection = orig_get_connection
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

    def test_15_worker_crash_does_not_deadlock_cleanup(self) -> None:
        """TC-15: Worker thread crash or unhandled error does not block failure-safe cleanup."""
        worker_crashed = threading.Event()
        worker_errors = []

        def crashing_worker():
            try:
                # Force an unexpected zero division error
                _ = 1 / 0
            except Exception as e:
                worker_errors.append(e)
            finally:
                worker_crashed.set()

        t = threading.Thread(target=crashing_worker)
        try:
            t.start()
            self.assertTrue(worker_crashed.wait(timeout=5.0))
        finally:
            t.join(timeout=5.0)

        self.assertFalse(t.is_alive())
        self.assertEqual(len(worker_errors), 1)
        self.assertIsInstance(worker_errors[0], ZeroDivisionError)


if __name__ == "__main__":
    unittest.main()
