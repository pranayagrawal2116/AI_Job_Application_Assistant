#!/usr/bin/env python3
"""Local Resume Acceptance Test Suite (Phase B.3.3).

Validates end-to-end extraction and career inference against reference resumes:
  - Mode 1 (Real Files): Specified via --acca-path and --cse-path, or environment variables
                         ACCA_RESUME_PATH and CSE_RESUME_PATH. Missing files cause non-zero exit.
  - Mode 2 (Synthetic):  Activated with --synthetic, running in-memory generated synthetic
                         ACCA and CSE persona documents for CI and hermetic regression.

This script logs cryptographic SHA-256 hashes for audit provenance without hardcoding or
leaking candidate personal identity information (PII) into git history.
"""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.preparer.resume_parser import ResumeParser
from src.preparer.career_role_inferencer import CareerRoleInferencer


def compute_file_hash(path: Path) -> str:
    """Computes SHA-256 hex digest of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_acca_assertions(parser: ResumeParser, inferencer: CareerRoleInferencer, pdf_bytes_or_path) -> Tuple[bool, List[Tuple[str, bool]]]:
    """Evaluates 16 explicit assertions against an ACCA / Accounting candidate document."""
    if isinstance(pdf_bytes_or_path, (str, Path)):
        parsed = parser.parse_file(Path(pdf_bytes_or_path))
    else:
        parsed = parser.parse_bytes(pdf_bytes_or_path, "pdf")

    inferred = inferencer.infer_roles_from_resume(parsed)

    assertions = [
        ("1. Candidate identity extracted", bool(parsed.full_name and len(parsed.full_name.split()) >= 2)),
        ("2. Email extracted", bool(parsed.email and "@" in parsed.email)),
        ("3. Phone extracted", bool(parsed.phone and len(parsed.phone.strip()) >= 7)),
        ("4. LinkedIn profile URL extracted", bool(parsed.linkedin_url and "linkedin.com/in/" in parsed.linkedin_url)),
        ("5. Education extracted (>= 2 degrees/qualifications)", len(parsed.education) >= 2),
        ("6. BBA degree recognized", any("bba" in e.degree.lower() for e in parsed.education)),
        ("7. BBA CGPA verified", any(e.cgpa is not None and e.cgpa > 7.0 for e in parsed.education if "bba" in e.degree.lower())),
        ("8. Secondary/HSC qualification percentage verified", any(e.percentage is not None and e.percentage > 85.0 for e in parsed.education)),
        ("9. ACCA professional qualification recognized", any("acca" in c.name.lower() for c in parsed.certifications)),
        ("10. Work Experience entries extracted (>= 2)", len(parsed.work_experience) >= 2),
        ("11. ACCA PER records extracted (>= 4)", len(parsed.per_experience) >= 4),
        ("12. Tax domain skills extracted", any("tax" in s.lower() for s in parsed.technical_skills)),
        ("13. Audit domain skills extracted", any("audit" in s.lower() for s in parsed.technical_skills)),
        ("14. Accounting software tools recognized", any(t.lower() in ["xero", "digita", "fyi", "approvalmax", "coreplan", "microsoft office suite", "excel"] for t in parsed.tools_and_software)),
        ("15. Multiple professional languages extracted", len(parsed.languages) >= 2),
        ("16. Accounting/finance career recommendations without intern hallucination", (
            any(any(k in r.lower() for k in ["tax", "account", "audit", "financial"]) for r in inferred.suggested_roles)
            and not any(bool(re.search(r"\bintern\b", r, re.IGNORECASE)) for r in inferred.suggested_roles)
        )),
    ]

    all_passed = all(res for _, res in assertions)
    return all_passed, assertions


def run_cse_assertions(parser: ResumeParser, inferencer: CareerRoleInferencer, pdf_bytes_or_path) -> Tuple[bool, List[Tuple[str, bool]]]:
    """Evaluates 16 explicit assertions against a Computer Science & Engineering candidate document."""
    if isinstance(pdf_bytes_or_path, (str, Path)):
        parsed = parser.parse_file(Path(pdf_bytes_or_path))
    else:
        parsed = parser.parse_bytes(pdf_bytes_or_path, "pdf")

    inferred = inferencer.infer_roles_from_resume(parsed)

    assertions = [
        ("1. Candidate identity extracted", bool(parsed.full_name and len(parsed.full_name.split()) >= 2)),
        ("2. Email and phone extracted", bool(parsed.email and "@" in parsed.email and parsed.phone)),
        ("3. Academic institution recognized (MIT WPU / University)", any("mit" in e.institution.lower() or "university" in e.institution.lower() for e in parsed.education)),
        ("4. B.Tech Computer Science and Engineering degree recognized", any("b.tech" in e.degree.lower() or "computer science" in (e.major or "").lower() for e in parsed.education)),
        ("5. AI and Data Science specialization verified", any("artificial intelligence" in (e.major or "").lower() or "data science" in (e.major or "").lower() for e in parsed.education)),
        ("6. Academic CGPA verified (>= 7.5)", any(e.cgpa is not None and e.cgpa >= 7.5 for e in parsed.education)),
        ("7. Expected graduation year verified (2028)", any(e.expected_graduation_year == 2028 for e in parsed.education)),
        ("8. Work experience extracted", len(parsed.work_experience) >= 1),
        ("9. Technical projects extracted", len(parsed.projects) >= 1),
        ("10. Flutter framework skill recognized", any("flutter" in s.lower() for s in parsed.technical_skills)),
        ("11. Python programming skill recognized", any("python" in s.lower() for s in parsed.technical_skills)),
        ("12. Dart programming skill recognized", any("dart" in s.lower() for s in parsed.technical_skills)),
        ("13. Mobile / Android development evidence", any("android" in s.lower() or "mobile" in s.lower() for s in parsed.technical_skills) or any("mobile" in w.role.lower() for w in parsed.work_experience)),
        ("14. Healthcare software project evidence (ABDM / Chatbot)", any(any(k in p.title.lower() for k in ["abdm", "medical", "healthcare", "chatbot", "patient"]) for p in parsed.projects)),
        ("15. Profession-specific career recommendations (Software/AI/Mobile)", any(any(k in r.lower() for k in ["software", "ai", "machine learning", "flutter", "developer", "project manager"]) for r in inferred.suggested_roles)),
        ("16. No irrelevant finance or ACCA recommendations", not any(any(k in r.lower() for k in ["tax", "accountant", "auditor", "acca"]) for r in inferred.suggested_roles)),
    ]

    all_passed = all(res for _, res in assertions)
    return all_passed, assertions


def main():
    parser = argparse.ArgumentParser(description="JobFlow AI Strict Local Resume Acceptance Suite")
    parser.add_argument("--acca-path", type=Path, default=None, help="Path to ACCA reference PDF")
    parser.add_argument("--cse-path", type=Path, default=None, help="Path to CSE reference PDF")
    parser.add_argument("--synthetic", action="store_true", help="Run test suite against generated synthetic personas")
    args = parser.parse_args()

    engine_parser = ResumeParser()
    engine_inferencer = CareerRoleInferencer()

    print("\n" + "=" * 75)
    print("JOBFLOW AI — PHASE B.3.3 LOCAL RESUME ACCEPTANCE TEST SUITE")
    print("=" * 75)

    if args.synthetic:
        print("\nMODE: Hermetic Synthetic Persona Validation")
        from tests.fixtures.synthetic_personas import generate_two_column_acca_pdf, generate_persona_pdf

        print("\n[TEST A] Generating & Evaluating Synthetic ACCA Candidate...")
        acca_bytes = generate_two_column_acca_pdf()
        h = hashlib.sha256(acca_bytes).hexdigest()
        print(f"  [PROVENANCE] Synthetic ACCA Document SHA-256: {h[:16]}...{h[-8:]}")
        parsed_acca = engine_parser.parse_bytes(acca_bytes, "pdf")
        inferred_acca = engine_inferencer.infer_roles_from_resume(parsed_acca)
        synthetic_acca_assertions = [
            ("1. Candidate identity extracted", bool(parsed_acca.full_name)),
            ("2. Email and contact info extracted", bool(parsed_acca.email and parsed_acca.phone)),
            ("3. BBA degree recognized", any("bba" in e.degree.lower() for e in parsed_acca.education)),
            ("4. BBA CGPA verified (~7.69)", any(e.cgpa is not None and abs(e.cgpa - 7.69) < 0.1 for e in parsed_acca.education)),
            ("5. ACCA professional qualification recognized", any("acca" in c.name.lower() for c in (parsed_acca.certifications + parsed_acca.professional_qualifications))),
            ("6. Work experience entries extracted", len(parsed_acca.work_experience) >= 2),
            ("7. Tax/accounting domain skills extracted", any(any(k in s.lower() for k in ["tax", "audit", "account", "vat"]) for s in (parsed_acca.technical_skills + parsed_acca.professional_skills))),
            ("8. Accounting/finance career recommendations without intern hallucination", (
                any(any(k in r.lower() for k in ["tax", "account", "audit", "financial"]) for r in inferred_acca.suggested_roles)
                and not any(bool(re.search(r"\bintern\b", r, re.IGNORECASE)) for r in inferred_acca.suggested_roles)
            )),
        ]
        acca_ok = all(r for _, r in synthetic_acca_assertions)
        for desc, res in synthetic_acca_assertions:
            print(f"  [{'PASS' if res else 'FAIL'}] {desc}")
        print(f"  Result: {sum(1 for _, r in synthetic_acca_assertions if r)}/8 Synthetic ACCA assertions passed.")

        print("\n[TEST B] Generating & Evaluating Synthetic CSE Candidate...")
        cse_bytes = generate_persona_pdf("cs_mobile_ai_student")
        h_cse = hashlib.sha256(cse_bytes).hexdigest()
        print(f"  [PROVENANCE] Synthetic CSE Document SHA-256: {h_cse[:16]}...{h_cse[-8:]}")
        parsed_cse = engine_parser.parse_bytes(cse_bytes, "pdf")
        inferred_cse = engine_inferencer.infer_roles_from_resume(parsed_cse)
        synthetic_cse_assertions = [
            ("1. Candidate identity extracted", bool(parsed_cse.full_name)),
            ("2. Email and phone extracted", bool(parsed_cse.email and parsed_cse.phone)),
            ("3. Academic institution recognized (MIT World Peace University)", any("mit" in e.institution.lower() for e in parsed_cse.education)),
            ("4. B.Tech Computer Science degree recognized", any("b.tech" in e.degree.lower() for e in parsed_cse.education)),
            ("5. Expected graduation year verified (2028)", any(e.expected_graduation_year == 2028 for e in parsed_cse.education)),
            ("6. Academic CGPA verified (7.6)", any(e.cgpa is not None and abs(e.cgpa - 7.6) < 0.1 for e in parsed_cse.education)),
            ("7. Work experience extracted (Sarita Infotech)", any("sarita" in w.employer.lower() for w in parsed_cse.work_experience)),
            ("8. Technical skills extracted (Flutter, Dart, Python)", any("flutter" in s.lower() or "python" in s.lower() for s in parsed_cse.technical_skills)),
            ("9. Technical projects extracted (Chatbot / ABDM)", any(any(k in p.title.lower() for k in ["chatbot", "abdm"]) for p in parsed_cse.projects)),
            ("10. Software career recommendations without finance leakage", (
                any(any(k in r.lower() for k in ["software", "developer", "project manager", "data"]) for r in inferred_cse.suggested_roles)
                and not any(any(k in r.lower() for k in ["tax", "accountant", "auditor", "acca"]) for r in inferred_cse.suggested_roles)
            )),
        ]
        cse_ok = all(r for _, r in synthetic_cse_assertions)
        for desc, res in synthetic_cse_assertions:
            print(f"  [{'PASS' if res else 'FAIL'}] {desc}")
        print(f"  Result: {sum(1 for _, r in synthetic_cse_assertions if r)}/10 Synthetic CSE assertions passed.")

        overall = acca_ok and cse_ok
        print("\n" + "=" * 75)
        print(f"FINAL SYNTHETIC ACCEPTANCE: {'PASSED (18/18 ASSERTIONS)' if overall else 'FAILED'}")
        print("=" * 75 + "\n")
        sys.exit(0 if overall else 1)

    # Real File Mode: Explicit path or environment variable required
    acca_path = args.acca_path or (Path(os.environ["ACCA_RESUME_PATH"]) if "ACCA_RESUME_PATH" in os.environ else None)
    cse_path = args.cse_path or (Path(os.environ["CSE_RESUME_PATH"]) if "CSE_RESUME_PATH" in os.environ else None)

    # Fail closed with exit code 1 if files are missing
    if not acca_path or not acca_path.is_file():
        print("\n[FATAL ERROR] ACCA reference file not found or not provided.")
        print("Please provide --acca-path <path> or set ACCA_RESUME_PATH environment variable.")
        print("Alternatively, pass --synthetic to execute hermetic persona acceptance.")
        sys.exit(1)

    if not cse_path or not cse_path.is_file():
        print("\n[FATAL ERROR] CSE reference file not found or not provided.")
        print("Please provide --cse-path <path> or set CSE_RESUME_PATH environment variable.")
        print("Alternatively, pass --synthetic to execute hermetic persona acceptance.")
        sys.exit(1)

    print("\nMODE: Real Reference Resume Document Acceptance")
    acca_hash = compute_file_hash(acca_path)
    cse_hash = compute_file_hash(cse_path)
    print(f"  [PROVENANCE] ACCA Reference File: {acca_path.name} | SHA-256: {acca_hash[:16]}...{acca_hash[-8:]}")
    print(f"  [PROVENANCE] CSE Reference File:  {cse_path.name}  | SHA-256: {cse_hash[:16]}...{cse_hash[-8:]}")

    print("\n[TEST A] Evaluating Real ACCA Reference Document...")
    acca_ok, acca_assertions = run_acca_assertions(engine_parser, engine_inferencer, acca_path)
    for desc, res in acca_assertions:
        print(f"  [{'PASS' if res else 'FAIL'}] {desc}")
    print(f"  Result: {sum(1 for _, r in acca_assertions if r)}/16 ACCA assertions passed.")

    print("\n[TEST B] Evaluating Real CSE Reference Document...")
    cse_ok, cse_assertions = run_cse_assertions(engine_parser, engine_inferencer, cse_path)
    for desc, res in cse_assertions:
        print(f"  [{'PASS' if res else 'FAIL'}] {desc}")
    print(f"  Result: {sum(1 for _, r in cse_assertions if r)}/16 CSE assertions passed.")

    overall = acca_ok and cse_ok
    print("\n" + "=" * 75)
    print(f"FINAL REAL RESUME ACCEPTANCE: {'ALL 32 ASSERTIONS PASSED (16/16 ACCA, 16/16 CSE)' if overall else 'ACCEPTANCE FAILED'}")
    print("=" * 75 + "\n")
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
