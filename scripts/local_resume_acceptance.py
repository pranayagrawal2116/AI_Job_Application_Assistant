#!/usr/bin/env python3
"""Local Resume Acceptance Test Suite (Phase B.3.2).

Validates end-to-end extraction and career inference against reference resumes:
  - Test A: Real ACCA / Accounting Resume
  - Test B: Real CSE / AI & Data Science Resume

This script inspects files locally without committing them, copying them into the repository,
or leaking candidate personal information into git history.

Usage:
    python3 scripts/local_resume_acceptance.py
    python3 scripts/local_resume_acceptance.py --acca-path /path/to/acca.pdf --cse-path /path/to/cse.pdf
"""

import argparse
import re
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.preparer.resume_parser import ResumeParser
from src.preparer.career_role_inferencer import CareerRoleInferencer


def run_acceptance_tests(acca_path: Path, cse_path: Path) -> bool:
    parser = ResumeParser()
    inferencer = CareerRoleInferencer()
    all_passed = True

    print("\n" + "=" * 70)
    print("JOBFLOW AI — PHASE B.3.2 LOCAL RESUME ACCEPTANCE TEST")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # TEST A: ACCA / Finance Resume
    # -------------------------------------------------------------------------
    print("\n[TEST A] Evaluating Real ACCA / Finance Resume...")
    if not acca_path.is_file():
        print(f"  [SKIP] ACCA reference file not found at: {acca_path}")
        print("  Pass --acca-path to test with a local file.")
    else:
        try:
            parsed_acca = parser.parse_file(acca_path)
            inferred_acca = inferencer.infer_roles_from_resume(parsed_acca)

            assertions = [
                ("Candidate name extracted", bool(parsed_acca.full_name and len(parsed_acca.full_name.split()) >= 2)),
                ("Email extracted", "@" in parsed_acca.email),
                ("Phone extracted", bool(parsed_acca.phone)),
                ("LinkedIn URL extracted", "linkedin.com/in/" in parsed_acca.linkedin_url),
                ("Education extracted (BBA & HSC)", len(parsed_acca.education) >= 2),
                ("BBA degree found", any("bba" in e.degree.lower() for e in parsed_acca.education)),
                ("BBA CGPA verified (7.69)", any(e.cgpa == 7.69 for e in parsed_acca.education if "bba" in e.degree.lower())),
                ("HSC percentage verified (93.8%)", any(e.percentage == 93.8 for e in parsed_acca.education)),
                ("ACCA Qualification recognized", any("acca" in c.name.lower() for c in parsed_acca.certifications)),
                ("Work Experience entries extracted (>= 2)", len(parsed_acca.work_experience) >= 2),
                ("ACCA PER entries extracted (>= 4)", len(parsed_acca.per_experience) >= 4),
                ("Tax / Audit domain skills extracted", any("tax" in s.lower() or "audit" in s.lower() for s in parsed_acca.technical_skills)),
                ("Accounting tools recognized", any(t.lower() in ["xero", "digita", "fyi", "approvalmax", "coreplan", "microsoft office suite"] for t in parsed_acca.tools_and_software)),
                ("Languages extracted (English, Hindi, Gujarati)", len(parsed_acca.languages) >= 3),
                ("Career role inference: accounting/finance domain", any(r in ["Tax Associate", "Internal Auditor", "Accountant", "Accounts Executive", "Financial Analyst", "Audit Associate", "Audit Senior"] for r in inferred_acca.suggested_roles)),
                ("No hallucinated intern titles for ACCA member", not any(bool(re.search(r"\bintern\b", r, re.IGNORECASE)) for r in inferred_acca.suggested_roles)),
            ]

            test_a_passed = True
            for desc, result in assertions:
                status = "PASS" if result else "FAIL"
                if not result:
                    test_a_passed = False
                    all_passed = False
                print(f"  [{status}] {desc}")

            print(f"  Summary: {'All ACCA assertions passed!' if test_a_passed else 'Some ACCA assertions failed.'}")
            print(f"  Roles inferred: {inferred_acca.suggested_roles[:4]}")
        except Exception as e:
            print(f"  [ERROR] ACCA Acceptance failed with exception: {e}")
            all_passed = False

    # -------------------------------------------------------------------------
    # TEST B: CSE / AI & Data Science Resume
    # -------------------------------------------------------------------------
    print("\n[TEST B] Evaluating Real CSE / AI & Data Science Resume...")
    if not cse_path.is_file():
        print(f"  [SKIP] CSE reference file not found at: {cse_path}")
        print("  Pass --cse-path to test with a local file.")
    else:
        try:
            parsed_cse = parser.parse_file(cse_path)
            inferred_cse = inferencer.infer_roles_from_resume(parsed_cse)

            assertions = [
                ("Candidate name extracted", bool(parsed_cse.full_name and len(parsed_cse.full_name.split()) >= 2)),
                ("Email extracted", "@" in parsed_cse.email and "." in parsed_cse.email),
                ("Phone extracted", bool(parsed_cse.phone)),
                ("Location extracted", bool(parsed_cse.location)),
                ("GitHub profile link extracted", "github.com/" in parsed_cse.github_url),
                ("LinkedIn profile link extracted", "linkedin.com/in/" in parsed_cse.linkedin_url),
                ("Education extracted (B.Tech)", len(parsed_cse.education) >= 1 and any("b.tech" in e.degree.lower() or "bachelor" in e.degree.lower() for e in parsed_cse.education)),
                ("CGPA verified (7.6)", any(e.cgpa == 7.6 for e in parsed_cse.education)),
                ("Graduation year verified (2028)", any(e.expected_graduation_year == 2028 for e in parsed_cse.education)),
                ("Work Experience extracted", len(parsed_cse.work_experience) >= 1),
                ("Projects extracted", len(parsed_cse.projects) >= 1),
                ("Tech skills extracted (Flutter, Python, Dart)", any(any(k in s.lower() for k in ["flutter", "python", "dart", "c++", "javascript"]) for s in parsed_cse.technical_skills)),
                ("Career role inference: software/AI domain", any(any(k in r.lower() for k in ["software", "ai", "machine learning", "flutter", "developer", "data", "project"]) for r in inferred_cse.suggested_roles)),
            ]

            test_b_passed = True
            for desc, result in assertions:
                status = "PASS" if result else "FAIL"
                if not result:
                    test_b_passed = False
                    all_passed = False
                print(f"  [{status}] {desc}")

            print(f"  Summary: {'All CSE assertions passed!' if test_b_passed else 'Some CSE assertions failed.'}")
            print(f"  Roles inferred: {inferred_cse.suggested_roles[:4]}")
        except Exception as e:
            print(f"  [ERROR] CSE Acceptance failed with exception: {e}")
            all_passed = False

    print("\n" + "=" * 70)
    print(f"FINAL ACCEPTANCE STATUS: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 70 + "\n")
    return all_passed


def main():
    parser = argparse.ArgumentParser(description="JobFlow AI Local Resume Acceptance CLI")
    parser.add_argument(
        "--acca-path",
        type=Path,
        default=Path("/Users/pranay/Downloads/Pranjali Agrawal Resume.pdf"),
        help="Path to ACCA reference resume PDF",
    )
    parser.add_argument(
        "--cse-path",
        type=Path,
        default=PROJECT_ROOT / "data" / "resumes" / "Pranay_Agrawal_Resume.pdf",
        help="Path to CSE reference resume PDF",
    )
    args = parser.parse_args()

    success = run_acceptance_tests(args.acca_path, args.cse_path)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
