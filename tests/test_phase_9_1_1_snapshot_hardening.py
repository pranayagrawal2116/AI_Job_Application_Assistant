"""Phase 9.1.1 Tests: Job Description Binary Integrity, Hash Validation & Transactional Snapshot Hardening.

Verifies:
1. Binary metadata persistence (file_hash, file_size_bytes, file_format) on document upload.
2. Pasted and URL job descriptions leave binary metadata NULL.
3. Historical records with NULL binary metadata load without regression.
4. Independent calculation and validation of caller-supplied content_hash.
5. Independent calculation and validation of caller-supplied canonical RFC 8785 snapshot_hash.
6. Immediate transaction write-lock and in-transaction duplicate detection.
7. Strict linear revision lineage (superseding inactive parent rejected; active child branching rejected).
8. Cross-user isolation during superseding (CrossUserAccessError).
9. Partial unique index enforcement at SQLite level (idx_job_descriptions_unique_active_child).
10. Atomic rollback on superseding failure.
11. Binary metadata inheritance across revision lineage.
12. Concurrency-safe superseding under simultaneous thread execution.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest

from docx import Document
from reportlab.pdfgen import canvas

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ConcurrencyConflictError,
    CrossUserAccessError,
    DuplicateJobDescriptionError,
    JobDescriptionNotFoundError,
    ValidationError,
)
from src.security.auth import AuthManager
from src.utils.canonical_json import canonical_json_hash


class TestPhase911SnapshotHardening(unittest.TestCase):
    """Test suite for Phase 9.1.1 snapshot integrity and transactional hardening."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snapshot_hardening.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        self.user_1 = self.auth.register(
            email="candidate1@example.com",
            password="StrongPassword123!",
            full_name="Candidate One",
        )
        self.user_2 = self.auth.register(
            email="candidate2@example.com",
            password="StrongPassword123!",
            full_name="Candidate Two",
        )

        self.user_1_dir = Path(self.temp_dir.name) / "users" / str(self.user_1.id) / "job_descriptions"
        self.user_1_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_sample_pdf(self, lines: list[str]) -> bytes:
        """Helper generating a valid PDF with extractable text using reportlab."""
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        y = 750
        for line in lines:
            c.drawString(50, y, line)
            y -= 25
        c.save()
        return buf.getvalue()

    def _create_sample_docx(self, paragraphs: list[str]) -> bytes:
        """Helper generating a valid DOCX with python-docx."""
        doc = Document()
        for p in paragraphs:
            doc.add_paragraph(p)
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    # -------------------------------------------------------------------------
    # 1. Binary Metadata Persistence on Upload
    # -------------------------------------------------------------------------

    def test_binary_metadata_persisted_on_pdf_upload(self):
        """Uploading a PDF securely persists file_hash, file_size_bytes, and file_format."""
        pdf_bytes = self._create_sample_pdf([
            "Company: SecureCore Systems",
            "Job Title: Senior Cryptographic Engineer",
            "Responsibilities:",
            "- Implement post-quantum cryptographic primitives.",
            "Requirements:",
            "- 5+ years of experience in systems cryptography.",
            "- Proficient in Rust, C, and Python.",
        ])

        expected_hash = hashlib.sha256(pdf_bytes).hexdigest()
        expected_size = len(pdf_bytes)

        jd = self.db.upload_user_job_description(
            user_id=self.user_1.id,
            file_bytes=pdf_bytes,
            original_filename="Crypto_Engineer_JD.pdf",
            user_base_dir=self.user_1_dir,
        )

        # In-memory dataclass verification
        self.assertEqual(jd.file_hash, expected_hash)
        self.assertEqual(jd.file_size_bytes, expected_size)
        self.assertEqual(jd.file_format, "pdf")
        self.assertEqual(jd.source_type, "upload")

        # Database raw SQL verification
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT file_hash, file_size_bytes, file_format, storage_filename FROM job_descriptions WHERE id = ?",
                (jd.id,),
            )
            row = cursor.fetchone()
            self.assertEqual(row["file_hash"], expected_hash)
            self.assertEqual(row["file_size_bytes"], expected_size)
            self.assertEqual(row["file_format"], "pdf")
            self.assertTrue(row["storage_filename"].endswith(".pdf"))

    def test_binary_metadata_persisted_on_docx_upload(self):
        """Uploading a DOCX securely persists file_hash, file_size_bytes, and file_format."""
        docx_bytes = self._create_sample_docx([
            "Company: CloudScale AI",
            "Job Title: Machine Learning Infrastructure Engineer",
            "Responsibilities:",
            "- Scale distributed training pipelines on Kubernetes.",
            "Requirements:",
            "- 3+ years experience with PyTorch and distributed training.",
        ])

        expected_hash = hashlib.sha256(docx_bytes).hexdigest()
        expected_size = len(docx_bytes)

        jd = self.db.upload_user_job_description(
            user_id=self.user_1.id,
            file_bytes=docx_bytes,
            original_filename="ML_Infra_Job.docx",
            user_base_dir=self.user_1_dir,
        )

        self.assertEqual(jd.file_hash, expected_hash)
        self.assertEqual(jd.file_size_bytes, expected_size)
        self.assertEqual(jd.file_format, "docx")

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT file_hash, file_size_bytes, file_format FROM job_descriptions WHERE id = ?",
                (jd.id,),
            )
            row = cursor.fetchone()
            self.assertEqual(row["file_hash"], expected_hash)
            self.assertEqual(row["file_size_bytes"], expected_size)
            self.assertEqual(row["file_format"], "docx")

    # -------------------------------------------------------------------------
    # 2. Pasted and URL Snapshots Leave Binary Metadata NULL
    # -------------------------------------------------------------------------

    def test_pasted_and_url_snapshots_have_null_binary_metadata(self):
        """Pasted and URL job descriptions leave file_hash, file_size_bytes, and file_format as None."""
        pasted_jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Acme Health",
            job_title="Clinical Data Analyst",
            raw_content="Responsibilities: Analyze patient health records. Requirements: SQL, Python.",
            source_type="pasted",
        )

        self.assertIsNone(pasted_jd.file_hash)
        self.assertIsNone(pasted_jd.file_size_bytes)
        self.assertIsNone(pasted_jd.file_format)

        url_jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="FinTech Corp",
            job_title="Backend Developer",
            raw_content="Responsibilities: Develop REST APIs. Requirements: Go, PostgreSQL.",
            source_type="url",
            source_url="https://jobs.fintechcorp.example/backend",
        )

        self.assertIsNone(url_jd.file_hash)
        self.assertIsNone(url_jd.file_size_bytes)
        self.assertIsNone(url_jd.file_format)

        # Raw SQL check
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT file_hash, file_size_bytes, file_format FROM job_descriptions WHERE id IN (?, ?)",
                (pasted_jd.id, url_jd.id),
            )
            rows = cursor.fetchall()
            for r in rows:
                self.assertIsNone(r["file_hash"])
                self.assertIsNone(r["file_size_bytes"])
                self.assertIsNone(r["file_format"])

    # -------------------------------------------------------------------------
    # 3. Historical Record Backward Compatibility
    # -------------------------------------------------------------------------

    def test_historical_records_with_null_binary_metadata_readability(self):
        """Records created without binary columns can be read cleanly into JobDescription."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash,
                    snapshot_hash, parsed_data, is_active
                ) VALUES (?, 'pasted', 'Legacy Corp', 'Legacy Role', 'Content text', 'hash123', 'snap123', '{}', 1)
                """,
                (self.user_1.id,),
            )
            legacy_id = cursor.lastrowid

        jd = self.db.get_job_description(legacy_id, user_id=self.user_1.id)
        self.assertIsNotNone(jd)
        self.assertIsNone(jd.file_hash)
        self.assertIsNone(jd.file_size_bytes)
        self.assertIsNone(jd.file_format)
        d = jd.to_dict()
        self.assertIn("file_hash", d)
        self.assertIsNone(d["file_hash"])

    # -------------------------------------------------------------------------
    # 4. Caller-Supplied Hash Validation
    # -------------------------------------------------------------------------

    def test_caller_supplied_content_hash_validation(self):
        """Matching content_hash succeeds; mismatched content_hash raises ValidationError."""
        raw_text = "Universal Data Engineering posting at Global Systems."
        computed_hash = hashlib.sha256(raw_text.strip().encode("utf-8")).hexdigest()

        # Valid matching content_hash succeeds
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Global Systems",
            job_title="Data Engineer",
            raw_content=raw_text,
            content_hash=computed_hash,
        )
        self.assertEqual(jd.content_hash, computed_hash)

        # Tampered content_hash is rejected
        with self.assertRaises(ValidationError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Global Systems",
                job_title="Senior Data Engineer",
                raw_content="Different job text for senior role.",
                content_hash="bad_tampered_content_hash",
            )
        self.assertIn("Supplied content_hash", str(ctx.exception))
        self.assertIn("does not match computed hash", str(ctx.exception))

    def test_caller_supplied_snapshot_hash_validation(self):
        """Matching RFC 8785 snapshot_hash succeeds; mismatched snapshot_hash raises ValidationError."""
        raw_text = "Security Analyst posting at Cyber Watch."
        raw_hash = hashlib.sha256(raw_text.strip().encode("utf-8")).hexdigest()
        company = "Cyber Watch"
        title = "Security Analyst"
        parsed = {"certifications_required": ["CISSP"]}

        manifest = {
            "user_id": self.user_1.id,
            "company_name": company,
            "job_title": title,
            "raw_content_hash": raw_hash,
            "parsed_data": parsed,
            "parser_version": "1.0.0",
            "source_type": "pasted",
            "source_url": None,
            "original_filename": None,
        }
        valid_snap_hash = canonical_json_hash(manifest)

        # Valid matching snapshot_hash succeeds
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name=company,
            job_title=title,
            raw_content=raw_text,
            parsed_data=parsed,
            snapshot_hash=valid_snap_hash,
        )
        self.assertEqual(jd.snapshot_hash, valid_snap_hash)

        # Tampered snapshot_hash is rejected
        with self.assertRaises(ValidationError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Cyber Watch",
                job_title="Junior Analyst",
                raw_content="Different analyst posting content.",
                snapshot_hash="forged_rfc8785_snapshot_hash",
            )
        self.assertIn("Supplied snapshot_hash", str(ctx.exception))
        self.assertIn("does not match computed canonical manifest hash", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Deduplication Inside Immediate Transaction
    # -------------------------------------------------------------------------

    def test_duplicate_active_snapshot_prevention_inside_transaction(self):
        """Attempting to ingest identical content for the same user raises DuplicateJobDescriptionError."""
        text = "Staff Architect role at Tech Giants."
        self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Tech Giants",
            job_title="Staff Architect",
            raw_content=text,
        )

        with self.assertRaises(DuplicateJobDescriptionError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Tech Giants",
                job_title="Staff Architect",
                raw_content=text,
            )
        self.assertIn("already exists", str(ctx.exception))

    def test_cross_user_duplicate_independence(self):
        """Distinct users can ingest identical job postings without duplicate collision."""
        shared_text = "Shared public job description text across multiple candidates."
        jd1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Public Agency",
            job_title="Project Lead",
            raw_content=shared_text,
        )
        jd2 = self.db.save_job_description_snapshot(
            user_id=self.user_2.id,
            company_name="Public Agency",
            job_title="Project Lead",
            raw_content=shared_text,
        )
        self.assertNotEqual(jd1.id, jd2.id)
        self.assertEqual(jd1.content_hash, jd2.content_hash)
        self.assertEqual(jd1.user_id, self.user_1.id)
        self.assertEqual(jd2.user_id, self.user_2.id)

    # -------------------------------------------------------------------------
    # 6. Revision Lineage & Superseding Rules
    # -------------------------------------------------------------------------

    def test_superseding_inactive_parent_rejected(self):
        """Attempting to supersede an inactive parent record raises ValidationError."""
        parent = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Nexus Cloud",
            job_title="Site Reliability Engineer",
            raw_content="Parent SRE posting.",
        )

        # Deactivate parent manually
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET is_active = 0 WHERE id = ?",
                (parent.id,),
            )

        with self.assertRaises(ValidationError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Nexus Cloud",
                job_title="SRE Lead",
                raw_content="Revision SRE posting.",
                supersedes_job_description_id=parent.id,
            )
        self.assertIn("already inactive", str(ctx.exception))

    def test_superseding_parent_with_existing_active_child_rejected(self):
        """A parent cannot have multiple active children (branching prohibited)."""
        parent = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Nexus Cloud",
            job_title="Database Administrator",
            raw_content="DBA posting content.",
        )

        # Create child 1 (supersedes parent)
        child_1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Nexus Cloud",
            job_title="Senior DBA",
            raw_content="Senior DBA revised posting.",
            supersedes_job_description_id=parent.id,
        )
        self.assertTrue(child_1.is_active)

        # If parent was somehow reactivated, attempting to create a second active child is rejected
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET is_active = 1 WHERE id = ?",
                (parent.id,),
            )

        with self.assertRaises(ValidationError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Nexus Cloud",
                job_title="Principal DBA",
                raw_content="Principal DBA revised posting.",
                supersedes_job_description_id=parent.id,
            )
        self.assertIn("an active child revision already exists", str(ctx.exception))

    def test_partial_unique_index_enforces_single_active_child_at_sqlite_level(self):
        """idx_job_descriptions_unique_active_child rejects duplicate active children at database layer."""
        parent = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Index Test Corp",
            job_title="Software Engineer",
            raw_content="Software Engineer posting.",
        )

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            # First active child
            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash,
                    supersedes_job_description_id, is_active
                ) VALUES (?, 'pasted', 'Index Test Corp', 'Rev 1', 'Content 1', 'h1', ?, 1)
                """,
                (self.user_1.id, parent.id),
            )

            # Second active child fails SQLite unique constraint
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    """
                    INSERT INTO job_descriptions (
                        user_id, source_type, company_name, job_title, raw_content, content_hash,
                        supersedes_job_description_id, is_active
                    ) VALUES (?, 'pasted', 'Index Test Corp', 'Rev 2', 'Content 2', 'h2', ?, 1)
                    """,
                    (self.user_1.id, parent.id),
                )

        # An inactive child CAN coexist under the partial index
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash,
                    supersedes_job_description_id, is_active
                ) VALUES (?, 'pasted', 'Index Test Corp', 'Rev Inactive', 'Content Inactive', 'h3', ?, 0)
                """,
                (self.user_1.id, parent.id),
            )

    def test_cross_user_supersedes_rejected(self):
        """User 2 cannot supersede User 1's job description snapshot."""
        parent = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Alpha Corp",
            job_title="Security Lead",
            raw_content="Alpha Corp job content.",
        )

        with self.assertRaises(CrossUserAccessError):
            self.db.save_job_description_snapshot(
                user_id=self.user_2.id,
                company_name="Alpha Corp",
                job_title="Security Lead",
                raw_content="Alpha Corp user 2 content.",
                supersedes_job_description_id=parent.id,
            )

    def test_nonexistent_parent_raises_not_found(self):
        """Superseding a non-existent job description raises JobDescriptionNotFoundError."""
        with self.assertRaises(JobDescriptionNotFoundError):
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Alpha Corp",
                job_title="Role",
                raw_content="Content",
                supersedes_job_description_id=999999,
            )

    # -------------------------------------------------------------------------
    # 7. Metadata Inheritance Across Revisions
    # -------------------------------------------------------------------------

    def test_metadata_inheritance_on_update_snapshot(self):
        """update_job_description_snapshot inherits binary metadata from uploaded parent."""
        pdf_bytes = self._create_sample_pdf([
            "Company: BioMed Analytics",
            "Job Title: Bioinformatician",
            "Responsibilities: Analyze genomic sequence variants.",
            "Requirements: Python, R, Nextflow.",
        ])

        parent_jd = self.db.upload_user_job_description(
            user_id=self.user_1.id,
            file_bytes=pdf_bytes,
            original_filename="BioMed_Bioinfo.pdf",
            user_base_dir=self.user_1_dir,
        )
        self.assertIsNotNone(parent_jd.file_hash)
        self.assertEqual(parent_jd.file_format, "pdf")

        # Update parsed data
        revised_jd = self.db.update_job_description_snapshot(
            user_id=self.user_1.id,
            jd_id=parent_jd.id,
            updated_parsed_data={"min_years_experience": 4.0, "mandatory_skills": ["Python", "Nextflow"]},
            new_job_title="Senior Bioinformatician",
        )

        self.assertEqual(revised_jd.supersedes_job_description_id, parent_jd.id)
        self.assertEqual(revised_jd.file_hash, parent_jd.file_hash)
        self.assertEqual(revised_jd.file_size_bytes, parent_jd.file_size_bytes)
        self.assertEqual(revised_jd.file_format, parent_jd.file_format)
        self.assertEqual(revised_jd.storage_filename, parent_jd.storage_filename)

        # Parent is now inactive
        parent_fresh = self.db.get_job_description(parent_jd.id, user_id=self.user_1.id)
        self.assertFalse(parent_fresh.is_active)
        self.assertTrue(revised_jd.is_active)

    # -------------------------------------------------------------------------
    # 8. Concurrency Safety
    # -------------------------------------------------------------------------

    def test_concurrent_supersede_attempts_race_safety(self):
        """Simultaneous attempts to supersede the same parent succeed at most once."""
        parent = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Concurrency Corp",
            job_title="Platform Engineer",
            raw_content="Base platform engineer job description text.",
        )

        results = []
        errors = []

        def worker(worker_id: int):
            try:
                child = self.db.save_job_description_snapshot(
                    user_id=self.user_1.id,
                    company_name="Concurrency Corp",
                    job_title=f"Platform Engineer v{worker_id}",
                    raw_content=f"Base platform engineer job description text variant {worker_id}.",
                    supersedes_job_description_id=parent.id,
                )
                results.append(child)
            except (ValidationError, ConcurrencyConflictError, sqlite3.OperationalError, sqlite3.IntegrityError) as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(worker, i) for i in range(5)]
            for f in futures:
                f.result()

        # Exactly 1 worker must succeed
        self.assertEqual(len(results), 1, f"Expected exactly 1 success, got {len(results)}. Errors: {errors}")
        self.assertEqual(len(errors), 4)

        # In DB, exactly 1 active child exists
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM job_descriptions WHERE supersedes_job_description_id = ? AND is_active = 1",
                (parent.id,),
            )
            count = cursor.fetchone()["cnt"]
            self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()

