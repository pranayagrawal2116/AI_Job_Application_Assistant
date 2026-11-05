"""Comprehensive regression and verification test suite for Phase 8.1.5:
Secure Descriptor-Relative File Validation Compatibility Across Python Versions.

Tests cover:
- Finding A: Accurate capability detection across Python 3.11 (Linux) and Python 3.13 (macOS/Linux)
- Finding B: Secure descriptor-relative traversal, metadata inspection without symlink following,
             reliable descriptor closure in finally blocks, and fail-closed defense without unsafe fallback
- Finding C: Preservation of application security, approval lookups, and multi-tenant isolation
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
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    CrossUserAccessError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.lifecycle.state_machine import ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import SessionManager

PDF_HEADER = b"%PDF-1.4\n%phase815 test content for descriptor-relative compatibility\n"


class BasePhase815TestCase(unittest.TestCase):
    """Shared fixture for Phase 8.1.5 tests."""

    def setUp(self):
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = str(self.base_dir / "test_phase_8_1_5.db")
        self.storage_dir = self.base_dir / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager(
            server_secret=b"test_secret_32_bytes_long_phase815__",
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

        self.user1_dir = self.storage_dir / "1"
        self.user1_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "applications").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        SessionManager.reset_instance()
        self.temp_dir.cleanup()


# =============================================================================
# FINDING A: DESCRIPTOR-RELATIVE CAPABILITY DETECTION & INSPECTION
# =============================================================================

class TestDescriptorRelativeCapabilityDetection(BasePhase815TestCase):
    """Verifies that platform capabilities are accurately detected without false negatives."""

    def test_actual_runtime_capabilities_detected(self):
        """Live environment correctly detects descriptor-relative validation support."""
        is_supported = FileSecurityValidator.supports_descriptor_relative_validation()
        # On POSIX (macOS, Linux), this must be True
        if hasattr(os, "O_NOFOLLOW") and os.open in getattr(os, "supports_dir_fd", set()):
            self.assertTrue(
                is_supported,
                "supports_descriptor_relative_validation() returned False on a POSIX system supporting dir_fd and O_NOFOLLOW."
            )

    def test_actual_descriptor_relative_stat_nofollow_on_file_dir_symlink(self):
        """Live metadata inspection distinguishes regular files, directories, and symlinks without following."""
        sub_dir = self.user1_dir / "test_sub"
        sub_dir.mkdir(parents=True, exist_ok=True)

        target_file = sub_dir / "real_file.pdf"
        target_file.write_bytes(PDF_HEADER)

        symlink_file = sub_dir / "link_file.pdf"
        symlink_file.symlink_to(target_file)

        symlink_dir = self.user1_dir / "link_sub"
        symlink_dir.symlink_to(sub_dir)

        root_fd = os.open(str(self.user1_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            # 1. Directory inspection
            st_dir = FileSecurityValidator._descriptor_relative_stat_nofollow("test_sub", root_fd)
            self.assertTrue(stat.S_ISDIR(st_dir.st_mode))
            self.assertFalse(stat.S_ISLNK(st_dir.st_mode))

            # 2. Directory symlink inspection (must report ISLNK, NOT ISDIR)
            st_dir_link = FileSecurityValidator._descriptor_relative_stat_nofollow("link_sub", root_fd)
            self.assertTrue(stat.S_ISLNK(st_dir_link.st_mode))
            self.assertFalse(stat.S_ISDIR(st_dir_link.st_mode))

            sub_fd = os.open("test_sub", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0), dir_fd=root_fd)
            try:
                # 3. Regular file inspection
                st_file = FileSecurityValidator._descriptor_relative_stat_nofollow("real_file.pdf", sub_fd)
                self.assertTrue(stat.S_ISREG(st_file.st_mode))
                self.assertFalse(stat.S_ISLNK(st_file.st_mode))

                # 4. File symlink inspection (must report ISLNK, NOT ISREG)
                st_file_link = FileSecurityValidator._descriptor_relative_stat_nofollow("link_file.pdf", sub_fd)
                self.assertTrue(stat.S_ISLNK(st_file_link.st_mode))
                self.assertFalse(stat.S_ISREG(st_file_link.st_mode))
            finally:
                os.close(sub_fd)
        finally:
            os.close(root_fd)

    def test_python_3_11_simulated_capability_environment(self):
        """Simulates Linux Python 3.11 environment where os.stat supports dir_fd/follow_symlinks but os.lstat is NOT in supports_dir_fd."""
        # Simulated supports sets: os.lstat removed from supports_dir_fd
        mock_supports_dir_fd = {os.open, os.stat}
        mock_supports_follow_symlinks = {os.stat}

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            # Capability detection must be True
            self.assertTrue(
                FileSecurityValidator.supports_descriptor_relative_validation(),
                "Python 3.11 Linux capability check failed: os.stat(dir_fd, follow_symlinks=False) was not recognized."
            )

            # Metadata inspection must work and use os.stat with follow_symlinks=False
            root_fd = os.open(str(self.user1_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                target_file = self.user1_dir / "resumes" / "test_p311.pdf"
                target_file.write_bytes(PDF_HEADER)

                st = FileSecurityValidator._descriptor_relative_stat_nofollow("resumes", root_fd)
                self.assertTrue(stat.S_ISDIR(st.st_mode))

                # Full candidate file validation under simulated Python 3.11
                res_path, content, computed_hash, computed_size = self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(target_file),
                    expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                    expected_size=len(PDF_HEADER),
                    expected_format="pdf",
                )
                self.assertEqual(content, PDF_HEADER)
                self.assertEqual(computed_size, len(PDF_HEADER))
            finally:
                os.close(root_fd)

    def test_python_3_13_simulated_capability_environment(self):
        """Simulates Python 3.13 environment where both os.lstat and os.stat are in supports_dir_fd."""
        mock_supports_dir_fd = {os.open, os.stat, os.lstat}
        mock_supports_follow_symlinks = {os.stat}

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            self.assertTrue(FileSecurityValidator.supports_descriptor_relative_validation())

            target_file = self.user1_dir / "resumes" / "test_p313.pdf"
            target_file.write_bytes(PDF_HEADER)

            res_path, content, _, _ = self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(target_file),
                expected_format="pdf",
            )
            self.assertEqual(content, PDF_HEADER)

    def test_missing_open_dir_fd_fails_closed(self):
        """When os.open does not support dir_fd, validation fails closed with informative error."""
        mock_supports_dir_fd = {os.stat}  # os.open missing
        mock_supports_follow_symlinks = {os.stat}

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            self.assertFalse(FileSecurityValidator.supports_descriptor_relative_validation())

            target_file = self.user1_dir / "resumes" / "test.pdf"
            target_file.write_bytes(PDF_HEADER)

            with self.assertRaises(FileSecurityError) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(target_file),
                )
            self.assertIn("not supported on this platform", str(ctx.exception))
            self.assertIn("os.open(dir_fd)", str(ctx.exception))

    def test_missing_nofollow_metadata_inspection_fails_closed(self):
        """When platform cannot inspect metadata without following symlinks, validation fails closed."""
        mock_supports_dir_fd = {os.open}  # Neither os.stat nor os.lstat in supports_dir_fd
        mock_supports_follow_symlinks = set()

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            self.assertFalse(FileSecurityValidator.supports_descriptor_relative_validation())

            target_file = self.user1_dir / "resumes" / "test.pdf"
            target_file.write_bytes(PDF_HEADER)

            with self.assertRaises(FileSecurityError) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(target_file),
                )
            self.assertIn("not supported on this platform", str(ctx.exception))
            self.assertIn("descriptor-relative nofollow stat", str(ctx.exception))

    def test_missing_o_nofollow_flag_fails_closed(self):
        """When O_NOFOLLOW is missing on the platform, validation fails closed."""
        with patch.object(os, "O_NOFOLLOW", None, create=False):
            if hasattr(os, "O_NOFOLLOW"):
                # Use delattr inside patch context if patch.object doesn't remove it
                delattr(os, "O_NOFOLLOW")

            self.assertFalse(FileSecurityValidator.supports_descriptor_relative_validation())

            target_file = self.user1_dir / "resumes" / "test.pdf"
            target_file.write_bytes(PDF_HEADER)

            with self.assertRaises(FileSecurityError) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(target_file),
                )
            self.assertIn("not supported on this platform", str(ctx.exception))


# =============================================================================
# FINDING B: SECURE DESCRIPTOR CLOSURE & TRAVERSAL INTEGRITY
# =============================================================================

class TestSecureDescriptorClosureAndTraversal(BasePhase815TestCase):
    """Verifies that descriptors are never leaked on success or failure, and traversal remains secure."""

    def test_all_descriptors_closed_on_success(self):
        """Every directory and file descriptor opened during validation is closed on success."""
        target_file = self.user1_dir / "resumes" / "close_test.pdf"
        target_file.write_bytes(PDF_HEADER)

        opened_fds: Set[int] = set()
        closed_fds: Set[int] = set()

        real_open = os.open
        real_close = os.close

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.add(fd)
            return fd

        def track_close(fd):
            closed_fds.add(fd)
            return real_close(fd)

        mock_supports = set(os.supports_dir_fd) | {track_open}

        with patch.object(os, "open", side_effect=track_open), \
             patch.object(os, "close", side_effect=track_close), \
             patch.object(os, "supports_dir_fd", mock_supports):
            res_path, content, _, _ = self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(target_file),
                expected_format="pdf",
            )

        self.assertEqual(content, PDF_HEADER)
        self.assertTrue(len(opened_fds) >= 2)  # At least root_fd + dir_fd + file_fd
        self.assertEqual(
            opened_fds,
            closed_fds,
            f"Descriptor leak detected on success! Unclosed FDs: {opened_fds - closed_fds}"
        )

    def test_all_descriptors_closed_on_failure(self):
        """Every descriptor opened during validation is closed when an error occurs."""
        target_file = self.user1_dir / "resumes" / "fail_close_test.pdf"
        target_file.write_bytes(PDF_HEADER)

        opened_fds: Set[int] = set()
        closed_fds: Set[int] = set()

        real_open = os.open
        real_close = os.close

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.add(fd)
            return fd

        def track_close(fd):
            closed_fds.add(fd)
            return real_close(fd)

        mock_supports = set(os.supports_dir_fd) | {track_open}

        with patch.object(os, "open", side_effect=track_open), \
             patch.object(os, "close", side_effect=track_close), \
             patch.object(os, "supports_dir_fd", mock_supports):
            with self.assertRaises(ValidationError):
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(target_file),
                    expected_hash="0000000000000000000000000000000000000000000000000000000000000000",  # Mismatch
                    expected_format="pdf",
                )

        self.assertTrue(len(opened_fds) >= 2)
        self.assertEqual(
            opened_fds,
            closed_fds,
            f"Descriptor leak detected on failure! Unclosed FDs: {opened_fds - closed_fds}"
        )

    def test_all_descriptors_closed_on_symlink_detection(self):
        """When a symlink is detected at any level, all opened parent descriptors are closed."""
        outside_dir = self.base_dir / "outside"
        outside_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "symlink_dir").symlink_to(outside_dir)

        fake_target = self.user1_dir / "symlink_dir" / "secret.pdf"

        opened_fds: Set[int] = set()
        closed_fds: Set[int] = set()

        real_open = os.open
        real_close = os.close

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.add(fd)
            return fd

        def track_close(fd):
            closed_fds.add(fd)
            return real_close(fd)

        mock_supports = set(os.supports_dir_fd) | {track_open}

        with patch.object(os, "open", side_effect=track_open), \
             patch.object(os, "close", side_effect=track_close), \
             patch.object(os, "supports_dir_fd", mock_supports):
            with self.assertRaises(FileSecurityError):
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(fake_target),
                )

        self.assertTrue(len(opened_fds) >= 1)  # At least root_fd
        self.assertEqual(
            opened_fds,
            closed_fds,
            f"Descriptor leak detected on symlink detection! Unclosed FDs: {opened_fds - closed_fds}"
        )

    def test_intermediate_symlink_rejected_in_python_3_11_mode(self):
        """Under simulated Python 3.11 (os.stat follow_symlinks=False), intermediate symlinks are rejected."""
        mock_supports_dir_fd = {os.open, os.stat}
        mock_supports_follow_symlinks = {os.stat}

        outside_dir = self.base_dir / "outside_p311"
        outside_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "sym_dir_p311").symlink_to(outside_dir)

        fake_target = self.user1_dir / "sym_dir_p311" / "doc.pdf"

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):
            with self.assertRaises(FileSecurityError) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(fake_target),
                )
            self.assertTrue("symlink" in str(ctx.exception).lower() or "symbolic link" in str(ctx.exception).lower())

    def test_final_file_symlink_rejected_in_python_3_11_mode(self):
        """Under simulated Python 3.11, target file symlinks are rejected."""
        mock_supports_dir_fd = {os.open, os.stat}
        mock_supports_follow_symlinks = {os.stat}

        outside_file = self.base_dir / "outside_target.pdf"
        outside_file.write_bytes(PDF_HEADER)

        symlink_target = self.user1_dir / "resumes" / "link_p311.pdf"
        symlink_target.symlink_to(outside_file)

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):
            with self.assertRaises(FileSecurityError) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(symlink_target),
                )
            self.assertTrue("symlink" in str(ctx.exception).lower() or "symbolic link" in str(ctx.exception).lower())

    def test_directory_rejected_as_file_in_python_3_11_mode(self):
        """Under simulated Python 3.11, directories passed as files are rejected."""
        mock_supports_dir_fd = {os.open, os.stat}
        mock_supports_follow_symlinks = {os.stat}

        sub_dir = self.user1_dir / "resumes" / "nested_dir"
        sub_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):
            with self.assertRaises((ValidationError, FileSecurityError)) as ctx:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=self.user_1,
                    file_path=str(sub_dir),
                )
            self.assertIn("regular file", str(ctx.exception).lower())

    def test_parent_directory_replacement_toctou_defense(self):
        """Replacing a parent directory with a symlink after traversal cannot redirect the verified open descriptor."""
        deep_dir = self.user1_dir / "safe_dir"
        deep_dir.mkdir(parents=True, exist_ok=True)
        deep_file = deep_dir / "valid.pdf"
        deep_file.write_bytes(PDF_HEADER)

        # Baseline read succeeds
        res_path, content, _, _ = self.file_validator.resolve_and_verify_candidate_file(
            user_id=self.user_1,
            file_path=str(deep_file),
            expected_format="pdf",
        )
        self.assertEqual(content, PDF_HEADER)

        # Replace parent directory with symlink to outside
        evil_dir = self.base_dir / "evil_dir"
        evil_dir.mkdir(parents=True, exist_ok=True)
        evil_file = evil_dir / "valid.pdf"
        evil_file.write_bytes(PDF_HEADER)

        shutil.rmtree(deep_dir)
        deep_dir.symlink_to(evil_dir)

        # Subsequent attempt to access through replaced parent directory must fail
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(deep_file),
            )
        self.assertTrue("symlink" in str(ctx.exception).lower() or "symbolic link" in str(ctx.exception).lower())


# =============================================================================
# FINDING C: PRESERVATION OF APPROVAL SECURITY & MULTI-TENANT ISOLATION
# =============================================================================

class TestPreservationOfApprovalSecurityAndIsolation(BasePhase815TestCase):
    """Verifies that approval verification and multi-tenant isolation remain fully intact
    under descriptor-relative file validation in both Python 3.11 and 3.13 modes.
    """

    def _create_complete_verified_application(self, user_id: int):
        """Creates a fully consistent candidate application with valid files and hashes."""
        prof = self.db.save_user_candidate_profile(
            user_id=user_id,
            profile_data={
                "full_name": f"Candidate {user_id}",
                "headline": "Lead Data Engineer",
                "technical_skills": ["Python", "Spark", "SQL"],
            },
        )

        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            raw_content="Build distributed pipelines with Spark and Python.",
        )

        user_res_dir = self.storage_dir / str(user_id) / "resumes"
        user_res_dir.mkdir(parents=True, exist_ok=True)
        res_file = user_res_dir / "original_source.pdf"
        res_file.write_bytes(PDF_HEADER)
        res_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        res_record = self.db.create_user_resume(
            user_id=user_id,
            original_filename="original_source.pdf",
            storage_filename=str(res_file),
            file_format="pdf",
            file_hash=res_hash,
            file_size_bytes=len(PDF_HEADER),
        )

        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
            resume_id=res_record["id"],
        )

        user_app_dir = self.storage_dir / str(user_id) / "applications" / str(app.id)
        user_app_dir.mkdir(parents=True, exist_ok=True)

        tailored_file = user_app_dir / "tailored_resume.pdf"
        tailored_file.write_bytes(PDF_HEADER)
        tailored_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        cover_file = user_app_dir / "cover_letter.pdf"
        cover_file.write_bytes(PDF_HEADER)
        cover_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        tailored_doc = GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(tailored_file),
            filename="tailored_resume.pdf",
            file_hash=tailored_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )
        cover_doc = GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(cover_file),
            filename="cover_letter.pdf",
            file_hash=cover_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )

        tailored_model = TailoredResume(
            user_id=user_id,
            target_role="Lead Data Engineer",
            target_company="Apex Global Technologies",
            professional_summary="Experienced Data Engineer with Spark and Python",
        )
        cover_model = CoverLetter(
            user_id=user_id,
            target_company="Apex Global Technologies",
            target_role="Lead Data Engineer",
            letter_text="I am thrilled to apply for the Lead Data Engineer position.",
            paragraphs=["I am thrilled to apply for the Lead Data Engineer position."],
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

        session = self.session_mgr.authenticate_candidate(
            candidate_id=f"cand_{user_id}",
            candidate_name=f"Candidate {user_id}",
            user_id=user_id,
        )

        return app, packet, packet.packet_version_hash, jd, session

    def test_end_to_end_packet_verification_and_approval_live(self):
        """End-to-end packet verification and human authorization succeed with descriptor-relative validation."""
        app, packet, snap_hash, jd, session = self._create_complete_verified_application(self.user_1)

        # 1. Packet verification succeeds
        valid, msg, verified_pkt = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertTrue(valid, f"Verification failed: {msg}")
        self.assertIsNotNone(verified_pkt)

        # 2. Issue action ticket and authorize
        ticket = self.session_mgr.issue_action_ticket(
            session_id=session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ, auth_msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=session.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Authorization failed: {auth_msg}")
        self.assertIsNotNone(approval)

    def test_end_to_end_packet_verification_simulated_python_3_11(self):
        """End-to-end packet verification and authorization succeed under simulated Linux Python 3.11 capabilities."""
        app, packet, snap_hash, jd, session = self._create_complete_verified_application(self.user_1)

        mock_supports_dir_fd = {os.open, os.stat}
        mock_supports_follow_symlinks = {os.stat}

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            valid, msg, verified_pkt = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
            self.assertTrue(valid, f"Python 3.11 mode packet verification failed: {msg}")

            ticket = self.session_mgr.issue_action_ticket(
                session_id=session.session_id,
                action_type="HUMAN_APPROVAL",
                application_id=app.id,
                packet_hash=snap_hash,
            )
            succ, auth_msg, approval = self.gate.authorize_universal_packet(
                user_id=self.user_1,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Candidate One",
                session_id=session.session_id,
                action_ticket=ticket,
                candidate_confirmed=True,
            )
            self.assertTrue(succ, f"Python 3.11 mode authorization failed: {auth_msg}")
            self.assertIsNotNone(approval)

    def test_packet_verification_fails_closed_when_capability_missing(self):
        """When descriptor-relative capability is absent, packet verification fails closed gracefully."""
        app, packet, snap_hash, jd, session = self._create_complete_verified_application(self.user_1)

        # Simulate missing os.open(dir_fd)
        mock_supports_dir_fd = {os.stat}
        mock_supports_follow_symlinks = {os.stat}

        with patch.object(os, "supports_dir_fd", mock_supports_dir_fd), \
             patch.object(os, "supports_follow_symlinks", mock_supports_follow_symlinks):

            valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
            self.assertFalse(valid)
            self.assertIn("Descriptor-relative path validation with O_NOFOLLOW is not supported", msg)

    def test_tampered_attachment_file_rejected_during_packet_verification(self):
        """Altering a file on disk causes packet verification to fail with SHA-256 hash mismatch."""
        app, packet, snap_hash, jd, session = self._create_complete_verified_application(self.user_1)

        # Alter tailored resume on disk
        user_app_dir = self.storage_dir / str(self.user_1) / "applications" / str(app.id)
        tailored_file = user_app_dir / "tailored_resume.pdf"
        tailored_file.write_bytes(PDF_HEADER + b"\n%tampered extra bytes\n")

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("does not match expected hash", msg)

    def test_cross_user_file_reference_rejected_during_packet_verification(self):
        """Packet pointing to another candidate's private file is rejected via storage boundary containment."""
        app1, packet1, snap1, jd1, sess1 = self._create_complete_verified_application(self.user_1)
        app2, packet2, snap2, jd2, sess2 = self._create_complete_verified_application(self.user_2)

        # Point user 1's packet tailored resume path to user 2's file
        user2_tailored = self.storage_dir / str(self.user_2) / "applications" / str(app2.id) / "tailored_resume.pdf"

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET tailored_resume_path = ? WHERE id = ?",
                (str(user2_tailored), packet1.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet1.id, self.user_1)
        self.assertFalse(valid)
        self.assertTrue("containment" in msg.lower() or "violation" in msg.lower() or "failed" in msg.lower())


if __name__ == "__main__":
    unittest.main()
