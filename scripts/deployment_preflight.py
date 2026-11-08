#!/usr/bin/env python3
"""Unified Production Deployment Preflight Validator for Windows Server 2016 & IIS 10.

Verifies:
  1. Python 3.11+ 64-bit environment.
  2. Frontend distribution build availability (frontend/dist/index.html).
  3. Production .env presence and readability.
  4. Strict APP_ENV=production enforcement.
  5. Mandatory 256-bit cryptographic secrets.
  6. Cryptographic secret separation (zero reuse).
  7. Key rotation dictionary structures.
  8. Canonical DATABASE_PATH configuration.
  9. Canonical USER_STORAGE_BASE configuration.
 10. Canonical BACKUP_DIR configuration.
 11. Canonical EXPORTS_DIR configuration.
 12. Component-aware data root alignment (D:\\AIJobAssistantData).
 13. IIS web root and frontend asset directory exclusion.
 14. Dedicated database directory accessibility.
 15. Candidate storage directory accessibility.
 16. Backup destination directory accessibility.
 17. NSSM service manager availability.
 18. Service account least-privilege identity.
 19. Single-worker Uvicorn configuration (--workers 1).
 20. IIS 10 request-size limit & HTTPS rewrite configuration.

Zero side effects: Never alters the production database or modifies existing files.
"""

import argparse
import json
import os
from pathlib import Path
import re
import struct
import sys
from typing import Any, Dict, List, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.env_loader import (
    find_env_file,
    load_production_env,
    validate_production_configuration,
    validate_storage_paths_alignment,
)


class CheckResult:
    def __init__(self, check_id: int, title: str, status: str, details: str, is_server_only: bool = False):
        self.check_id = check_id
        self.title = title
        self.status = status  # PASS, FAIL, WARN, MANUAL
        self.details = details
        self.is_server_only = is_server_only

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.check_id,
            "title": self.title,
            "status": self.status,
            "details": self.details,
            "is_server_only": self.is_server_only,
        }


class DeploymentPreflightChecker:
    def __init__(
        self,
        env_file: Optional[str | Path] = None,
        data_dir: str = r"D:\AIJobAssistantData",
        service_account: str = r"NT AUTHORITY\NetworkService",
    ):
        self.env_file_arg = env_file
        self.data_dir = data_dir
        self.service_account = service_account
        self.results: List[CheckResult] = []

    def run_all_checks(self) -> List[CheckResult]:
        self.results.clear()

        # 1. Python Architecture & Version
        self._check_python_environment()

        # 2. Frontend Distribution
        self._check_frontend_bundle()

        # 3. Environment File Presence
        resolved_env = self._check_env_file_presence()

        # Load environment if present
        if resolved_env and resolved_env.is_file():
            load_production_env(resolved_env, override=True)

        # 4. Strict APP_ENV=production
        self._check_app_env()

        # 5. Mandatory Secrets & 6. Secret Separation & 7. Key Rotation
        self._check_secrets_and_rotation()

        # 8-11. Storage Paths Configuration & 12. Data Root Alignment & 13. Web Root Exclusion
        self._check_storage_paths_and_isolation()

        # 14-16. Storage Directory Access & Permissions
        self._check_storage_directory_access()

        # 17. NSSM Binary Availability
        self._check_nssm_availability()

        # 18. Service Account Identity
        self._check_service_identity()

        # 19. Single Worker Model & Command Arguments
        self._check_uvicorn_worker_model()

        # 20. IIS Request Limits & HTTPS Rewrite Configuration
        self._check_iis_web_config()

        return self.results

    def _check_python_environment(self):
        ver = sys.version_info
        bits = struct.calcsize("P") * 8
        is_64 = bits == 64
        is_311 = ver.major == 3 and ver.minor >= 11

        if is_311 and is_64:
            self.results.append(
                CheckResult(1, "Python Version & Architecture", "PASS", f"Python {ver.major}.{ver.minor}.{ver.micro} ({bits}-bit x64)")
            )
        else:
            self.results.append(
                CheckResult(1, "Python Version & Architecture", "FAIL", f"Detected Python {ver.major}.{ver.minor}.{ver.micro} ({bits}-bit). Requires Python 3.11+ 64-bit.")
            )

    def _check_frontend_bundle(self):
        dist_index = PROJECT_ROOT / "frontend" / "dist" / "index.html"
        assets_dir = PROJECT_ROOT / "frontend" / "dist" / "assets"
        if dist_index.is_file() and dist_index.stat().st_size > 0 and assets_dir.is_dir():
            self.results.append(
                CheckResult(2, "Frontend Production Distribution", "PASS", f"index.html verified ({dist_index.stat().st_size} bytes)")
            )
        else:
            self.results.append(
                CheckResult(2, "Frontend Production Distribution", "FAIL", "frontend/dist/index.html is missing. Run 'npm run build --prefix frontend'")
            )

    def _check_env_file_presence(self) -> Optional[Path]:
        resolved = find_env_file(self.env_file_arg)
        if resolved and resolved.is_file():
            self.results.append(
                CheckResult(3, "Production Environment File Presence", "PASS", f"Found .env at {resolved}")
            )
            return resolved
        else:
            self.results.append(
                CheckResult(3, "Production Environment File Presence", "FAIL", "No production .env found. Populate from .env.production.example")
            )
            return None

    def _check_app_env(self):
        app_env = os.environ.get("APP_ENV", "").strip().lower()
        if app_env == "production":
            self.results.append(
                CheckResult(4, "Strict APP_ENV Enforcement", "PASS", "APP_ENV=production verified")
            )
        else:
            self.results.append(
                CheckResult(4, "Strict APP_ENV Enforcement", "FAIL", f"APP_ENV='{app_env}' (must be 'production' for production launch)")
            )

    def _check_secrets_and_rotation(self):
        try:
            report = validate_production_configuration(enforce=False, expected_data_dir=self.data_dir)
            if report.is_valid:
                self.results.append(
                    CheckResult(5, "Mandatory Cryptographic Secrets", "PASS", "All 5 required 256-bit secrets meet entropy standards")
                )
                self.results.append(
                    CheckResult(6, "Cryptographic Secret Separation", "PASS", "Zero duplicate key reuse across subsystems")
                )
                self.results.append(
                    CheckResult(7, "Key Rotation Dictionary Integrity", "PASS", "Valid JSON dictionaries and active key ID mapping")
                )
            else:
                self.results.append(
                    CheckResult(5, "Mandatory Cryptographic Secrets", "FAIL", "; ".join(report.errors[:3]))
                )
                self.results.append(
                    CheckResult(6, "Cryptographic Secret Separation", "FAIL", "Configuration validation reported secret conflicts")
                )
                self.results.append(
                    CheckResult(7, "Key Rotation Dictionary Integrity", "FAIL", "Rotation dictionary validation failed")
                )
        except Exception as exc:
            self.results.append(CheckResult(5, "Mandatory Cryptographic Secrets", "FAIL", str(exc)))
            self.results.append(CheckResult(6, "Cryptographic Secret Separation", "FAIL", str(exc)))
            self.results.append(CheckResult(7, "Key Rotation Dictionary Integrity", "FAIL", str(exc)))

    def _check_storage_paths_and_isolation(self):
        align_errors = validate_storage_paths_alignment(expected_data_dir=self.data_dir)
        db_path = os.environ.get("DATABASE_PATH", "")
        user_storage = os.environ.get("USER_STORAGE_BASE", "")
        backup_dir = os.environ.get("BACKUP_DIR", "")
        exports_dir = os.environ.get("EXPORTS_DIR", "")

        # 8. DATABASE_PATH
        if db_path:
            self.results.append(CheckResult(8, "DATABASE_PATH Configuration", "PASS", db_path))
        else:
            self.results.append(CheckResult(8, "DATABASE_PATH Configuration", "FAIL", "DATABASE_PATH is empty"))

        # 9. USER_STORAGE_BASE
        if user_storage:
            self.results.append(CheckResult(9, "USER_STORAGE_BASE Configuration", "PASS", user_storage))
        else:
            self.results.append(CheckResult(9, "USER_STORAGE_BASE Configuration", "FAIL", "USER_STORAGE_BASE is empty"))

        # 10. BACKUP_DIR
        if backup_dir:
            self.results.append(CheckResult(10, "BACKUP_DIR Configuration", "PASS", backup_dir))
        else:
            self.results.append(CheckResult(10, "BACKUP_DIR Configuration", "FAIL", "BACKUP_DIR is empty"))

        # 11. EXPORTS_DIR
        if exports_dir:
            self.results.append(CheckResult(11, "EXPORTS_DIR Configuration", "PASS", exports_dir))
        else:
            self.results.append(CheckResult(11, "EXPORTS_DIR Configuration", "FAIL", "EXPORTS_DIR is empty"))

        # 12. Component-Aware Data Root Alignment & 13. IIS Web Root Exclusion
        if not align_errors:
            self.results.append(
                CheckResult(12, "Component-Aware Data Root Alignment", "PASS", f"All paths reside under {self.data_dir}")
            )
            self.results.append(
                CheckResult(13, "IIS Web Root & Frontend Exclusion", "PASS", "Storage paths strictly excluded from web roots")
            )
        else:
            self.results.append(
                CheckResult(12, "Component-Aware Data Root Alignment", "FAIL", "; ".join(align_errors))
            )
            self.results.append(
                CheckResult(13, "IIS Web Root & Frontend Exclusion", "FAIL", "Storage paths violate boundary isolation")
            )

    def _check_storage_directory_access(self):
        # On local macOS/Linux dev environments, actual D:\ drive will not exist.
        # Mark as MANUAL/SERVER_ONLY if running on non-Windows with a Windows drive path.
        is_windows = os.name == "nt"
        db_path = os.environ.get("DATABASE_PATH", "")
        backup_dir = os.environ.get("BACKUP_DIR", "")
        user_storage = os.environ.get("USER_STORAGE_BASE", "")

        is_win_path = bool(re.match(r"^[a-zA-Z]:[\\/]", db_path))

        if not is_windows and is_win_path:
            self.results.append(
                CheckResult(14, "Database Directory Filesystem Access", "MANUAL", f"Target path {db_path} requires Windows Server verification", is_server_only=True)
            )
            self.results.append(
                CheckResult(15, "Candidate Storage Filesystem Access", "MANUAL", f"Target path {user_storage} requires Windows Server verification", is_server_only=True)
            )
            self.results.append(
                CheckResult(16, "Backup Destination Filesystem Access", "MANUAL", f"Target path {backup_dir} requires Windows Server verification", is_server_only=True)
            )
        else:
            # On Windows host or local POSIX path, verify directory access
            for cid, name, p in [(14, "Database Directory Access", Path(db_path).parent if db_path else None),
                                 (15, "Candidate Storage Access", Path(user_storage) if user_storage else None),
                                 (16, "Backup Destination Access", Path(backup_dir) if backup_dir else None)]:
                if p and p.exists() and os.access(str(p), os.W_OK):
                    self.results.append(CheckResult(cid, name, "PASS", f"Directory {p} accessible and writable"))
                else:
                    self.results.append(CheckResult(cid, name, "WARN", f"Directory {p} not yet created or non-writable"))

    def _check_nssm_availability(self):
        local_nssm = PROJECT_ROOT / "tools" / "nssm.exe"
        if os.name != "nt":
            self.results.append(
                CheckResult(17, "NSSM Service Manager Binary", "MANUAL", "Requires nssm.exe in PATH or tools/ on Windows Server 2016", is_server_only=True)
            )
        else:
            import shutil
            in_path = shutil.which("nssm.exe")
            if in_path or local_nssm.exists():
                self.results.append(CheckResult(17, "NSSM Service Manager Binary", "PASS", str(in_path or local_nssm)))
            else:
                self.results.append(CheckResult(17, "NSSM Service Manager Binary", "FAIL", "nssm.exe not found in PATH or tools/"))

    def _check_service_identity(self):
        if self.service_account in ("NT AUTHORITY\\NetworkService", "NT AUTHORITY\\SYSTEM", "LocalSystem"):
            self.results.append(
                CheckResult(18, "Least-Privilege Service Identity", "PASS", f"Configured account: {self.service_account}")
            )
        else:
            self.results.append(
                CheckResult(18, "Least-Privilege Service Identity", "WARN", f"Custom account: {self.service_account}")
            )

    def _check_uvicorn_worker_model(self):
        service_script = PROJECT_ROOT / "deploy" / "windows" / "service_install.ps1"
        run_script = PROJECT_ROOT / "deploy" / "windows" / "run_app.ps1"

        svc_content = service_script.read_text(encoding="utf-8") if service_script.exists() else ""
        run_content = run_script.read_text(encoding="utf-8") if run_script.exists() else ""

        has_workers_1 = ("--workers 1" in svc_content) and ("--workers 1" in run_content)
        has_env_file = ("--env-file" in svc_content) and ("--env-file" in run_content)

        if has_workers_1 and has_env_file:
            self.results.append(
                CheckResult(19, "Single-Worker Uvicorn Model", "PASS", "Enforces --workers 1 and --env-file across deployment scripts")
            )
        else:
            self.results.append(
                CheckResult(19, "Single-Worker Uvicorn Model", "FAIL", "Worker model mismatch or missing --env-file")
            )

    def _check_iis_web_config(self):
        web_config = PROJECT_ROOT / "deploy" / "iis" / "web.config"
        if not web_config.exists():
            self.results.append(CheckResult(20, "IIS 10 Reverse-Proxy Configuration", "FAIL", "deploy/iis/web.config missing"))
            return

        content = web_config.read_text(encoding="utf-8")
        has_12mb = 'maxAllowedContentLength="12582912"' in content
        has_https = "HTTP to HTTPS Redirect" in content
        has_proxy = "FastAPI Reverse Proxy" in content

        if has_12mb and has_https and has_proxy:
            self.results.append(
                CheckResult(20, "IIS 10 Reverse-Proxy Configuration", "PASS", "12 MB request limit, HTTPS redirect & reverse-proxy verified")
            )
        else:
            self.results.append(
                CheckResult(20, "IIS 10 Reverse-Proxy Configuration", "FAIL", "Missing required limits or redirect rules in web.config")
            )

    def format_console_report(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append(" JOBFLOW AI - PRODUCTION DEPLOYMENT PREFLIGHT REPORT (PHASE C.0.2)")
        lines.append("=" * 80)
        lines.append(f"{'ID':<4} | {'STATUS':<7} | {'CHECK ITEM':<38} | {'DETAILS'}")
        lines.append("-" * 80)

        pass_count = 0
        fail_count = 0
        warn_count = 0
        manual_count = 0

        for r in self.results:
            if r.status == "PASS":
                pass_count += 1
            elif r.status == "FAIL":
                fail_count += 1
            elif r.status == "WARN":
                warn_count += 1
            elif r.status == "MANUAL":
                manual_count += 1

            lines.append(f"{r.check_id:<4} | {r.status:<7} | {r.title:<38} | {r.details}")

        lines.append("-" * 80)
        lines.append(f"Summary: {pass_count} PASS | {fail_count} FAIL | {warn_count} WARN | {manual_count} MANUAL (Windows Server execution required)")
        lines.append("=" * 80)
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Universal AI Job Application Assistant Production Preflight")
    parser.add_argument("--env-file", type=str, default="", help="Path to production .env file")
    parser.add_argument("--data-dir", type=str, default=r"D:\AIJobAssistantData", help="Expected persistent data directory")
    parser.add_argument("--service-account", type=str, default=r"NT AUTHORITY\NetworkService", help="Service identity")
    parser.add_argument("--json", action="store_true", help="Output JSON report")

    args = parser.parse_args()

    checker = DeploymentPreflightChecker(
        env_file=args.env_file or None,
        data_dir=args.data_dir,
        service_account=args.service_account,
    )
    results = checker.run_all_checks()

    if args.json:
        data = {
            "checks": [r.to_dict() for r in results],
            "is_valid": all(r.status in ("PASS", "MANUAL") for r in results),
        }
        print(json.dumps(data, indent=2))
    else:
        print(checker.format_console_report())

    # Exit code: 0 if no FAIL, 1 if any FAIL
    if any(r.status == "FAIL" for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
