#!/usr/bin/env python3
"""Production Secret Key Generator Utility for JobFlow AI.

Generates cryptographically strong 256-bit (64-character) hexadecimal keys
using Python's standard library `secrets` module for Windows Server 2016 production deployment.

Usage:
    python scripts/generate_production_secrets.py
    python scripts/generate_production_secrets.py --write-env
"""

import argparse
from pathlib import Path
import secrets
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_key_pair(key_name: str) -> tuple[str, str]:
    """Generates a 64-hex-character cryptographically secure token."""
    return key_name, secrets.token_hex(32)


def main():
    parser = argparse.ArgumentParser(
        description="Generate cryptographically strong 256-bit hex keys for JobFlow AI production .env"
    )
    parser.add_argument(
        "--write-env",
        action="store_true",
        help="Write generated secrets into .env if .env does not already exist.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Custom output file path for generated secrets.",
    )
    args = parser.parse_args()

    action_ticket_key = secrets.token_hex(32)
    security_scan_key = secrets.token_hex(32)
    session_secret_key = secrets.token_hex(32)
    password_reset_pepper = secrets.token_hex(32)
    audit_log_pepper = secrets.token_hex(32)

    config_lines = [
        "# =====================================================================",
        "# Generated Production Secrets (Do NOT commit to version control!)",
        "# =====================================================================",
        "APP_ENV=production",
        "LOG_LEVEL=INFO",
        "",
        "# Dedicated Production File Storage Paths (Outside IIS Web Root)",
        "DATABASE_PATH=D:\\AIJobAssistantData\\database\\job_assistant.db",
        "USER_STORAGE_BASE=D:\\AIJobAssistantData\\users",
        "BACKUP_DIR=D:\\AIJobAssistantData\\backups",
        "EXPORTS_DIR=D:\\AIJobAssistantData\\exports",
        "",
        "# Cryptographic Keys (256-bit hex)",
        f"SESSION_SECRET_KEY={session_secret_key}",
        f"PASSWORD_RESET_PEPPER={password_reset_pepper}",
        f"AUDIT_LOG_PEPPER={audit_log_pepper}",
        "",
        "# Action Ticket Signing & Key Rotation",
        "ACTION_TICKET_ACTIVE_KEY_ID=prod_v1",
        f"ACTION_TICKET_SECRET_KEY={action_ticket_key}",
        f'ACTION_TICKET_ROTATION_KEYS={{"prod_v1":"{action_ticket_key}"}}',
        "",
        "# Security Scan Verification & Key Rotation",
        "SECURITY_SCAN_ACTIVE_KEY_ID=scan_prod_v1",
        f"SECURITY_SCAN_SIGNING_KEY={security_scan_key}",
        f'SECURITY_SCAN_ROTATION_KEYS={{"scan_prod_v1":"{security_scan_key}"}}',
        "",
        "# Safety & Anti-Automation Policies",
        "ALLOW_AUTOMATED_SUBMISSION=false",
        "RESPECT_ROBOTS_TXT=true",
        "HEADLESS=true",
        "",
        "# Legacy Evidence Policy",
        "LEGACY_EVIDENCE_POLICY=production",
        "LEGACY_EVIDENCE_TRUSTED_KEYS={}",
        "LEGACY_EVIDENCE_TRUSTED_ISSUERS=[]",
        "LEGACY_EVIDENCE_TRUSTED_PRINCIPALS=[]",
        "LEGACY_EVIDENCE_REVOKED_KEYS=[]",
        "LEGACY_EVIDENCE_REVOKED_PRINCIPALS=[]",
    ]

    output_content = "\n".join(config_lines) + "\n"

    target_file = None
    if args.output:
        target_file = Path(args.output).resolve()
    elif args.write_env:
        target_file = PROJECT_ROOT / ".env"

    if target_file:
        if target_file.exists():
            print(f"ERROR: Destination file '{target_file}' already exists. Refusing to overwrite.", file=sys.stderr)
            sys.exit(1)
        target_file.write_text(output_content, encoding="utf-8")
        print(f"[OK] Successfully wrote generated production secrets to: {target_file}")
    else:
        print(output_content)


if __name__ == "__main__":
    main()
