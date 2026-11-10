"""Authoritative Production Environment Loading & Security Validation Module.

Enforces zero-trust production environment configuration:
1. Loads .env prior to application module initialization.
2. Validates cryptographic 256-bit hexadecimal keys with entropy and placeholder checks.
3. Enforces cryptographic key separation (distinct keys across subsystems).
4. Verifies absolute persistent storage paths outside the IIS web root.
5. Strictly enforces human-in-the-loop and anti-automation safety flags.
6. Emits safe diagnostic logs without exposing secret values or key material.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv

from src.utils.logger import setup_logger

logger = setup_logger("ProductionConfig")

# Known insecure placeholder patterns that must never be accepted in production
INSECURE_PLACEHOLDER_SUBSTRINGS: Set[str] = {
    "generate_and_insert",
    "replace_with",
    "replace_this",
    "placeholder",
    "change_me",
    "your_secret",
    "secret_key_here",
    "example",
    "dummy",
    "default",
    "test_secret",
}

# Default development pepper from auth.py that must be rejected in production
DEFAULT_DEV_PEPPER = "6f8e7d6c5b4a392817263544556677889900aabbccddeeff0011223344556677"

# Substrings indicating forbidden web roots or frontend public asset directories
FORBIDDEN_STORAGE_SUBSTRINGS: List[str] = [
    "inetpub/wwwroot",
    "deploy/iis",
    "frontend/dist",
    "frontend/public",
]


def canonicalize_path_components(path: str | Path) -> tuple[str, List[str]]:
    """Canonicalizes a Windows or POSIX path into (root_specifier, list_of_lowercase_parts),
    resolving '.' and '..' segments logically without requiring filesystem access.
    """
    raw = str(path).strip()
    if not raw:
        return "", []

    # Detect Windows drive letter (e.g. C:\ or c:/)
    win_drive = re.match(r"^([a-zA-Z]):[\\/](.*)", raw)
    if win_drive:
        root_spec = win_drive.group(1).upper() + ":\\"
        remainder = win_drive.group(2)
        sep = re.compile(r"[\\/]+")
    elif raw.startswith(r"\\") or raw.startswith("//"):
        # UNC path \\server\share\...
        unc_match = re.match(r"^[\\/]{2}([^\\/]+)[\\/]([^\\/]+)(?:[\\/](.*))?", raw)
        if unc_match:
            root_spec = f"\\\\{unc_match.group(1).lower()}\\{unc_match.group(2).lower()}\\"
            remainder = unc_match.group(3) or ""
            sep = re.compile(r"[\\/]+")
        else:
            root_spec = "\\\\"
            remainder = raw.lstrip("\\/")
            sep = re.compile(r"[\\/]+")
    elif raw.startswith("/") or raw.startswith("\\"):
        root_spec = "/"
        remainder = raw.lstrip("/\\")
        sep = re.compile(r"[\\/]+")
    else:
        root_spec = ""
        remainder = raw
        sep = re.compile(r"[\\/]+")

    raw_segments = [s for s in sep.split(remainder) if s]
    parts: List[str] = []
    for s in raw_segments:
        s_clean = s.strip()
        if not s_clean or s_clean == ".":
            continue
        if s_clean == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append("..")
        else:
            parts.append(s_clean.lower())

    return root_spec, parts


def is_forbidden_path(parts: List[str]) -> tuple[bool, str]:
    """Detects whether path parts intersect with forbidden web root or frontend directory sequences."""
    forbidden_sequences = [
        (["inetpub", "wwwroot"], "IIS web root (inetpub/wwwroot)"),
        (["deploy", "iis"], "IIS deployment configuration (deploy/iis)"),
        (["frontend", "dist"], "frontend distribution bundle (frontend/dist)"),
        (["frontend", "public"], "frontend public assets (frontend/public)"),
    ]
    for seq, desc in forbidden_sequences:
        seq_len = len(seq)
        for i in range(len(parts) - seq_len + 1):
            if parts[i : i + seq_len] == seq:
                return True, desc
    return False, ""


def is_path_contained_in_root(child: str | Path, root: str | Path) -> bool:
    """Returns True if and only if child is logically contained within root.
    Handles Windows drive letters, case-insensitivity, canonical component hierarchy,
    and prevents traversal escapes.
    """
    c_root, c_parts = canonicalize_path_components(child)
    r_root, r_parts = canonicalize_path_components(root)

    if not c_root or not r_root:
        return False

    if c_root.upper() != r_root.upper():
        return False

    if ".." in c_parts or ".." in r_parts:
        return False

    if len(c_parts) < len(r_parts):
        return False

    return c_parts[: len(r_parts)] == r_parts


class ProductionConfigurationError(ValueError, RuntimeError):
    """Raised when production configuration fails preflight validation."""
    pass


@dataclass
class KeyValidationStatus:
    name: str
    is_present: bool = False
    is_valid_format: bool = False
    entropy_score: int = 0
    error_message: Optional[str] = None


@dataclass
class ProductionValidationReport:
    app_env: str
    is_production: bool
    is_valid: bool
    database_path: Optional[str] = None
    user_storage_base: Optional[str] = None
    backup_dir: Optional[str] = None
    exports_dir: Optional[str] = None
    key_statuses: Dict[str, KeyValidationStatus] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_safe_summary(self) -> Dict[str, Any]:
        """Returns a sanitized summary safe for logging and health checks."""
        return {
            "app_env": self.app_env,
            "is_production": self.is_production,
            "is_valid": self.is_valid,
            "database_configured": bool(self.database_path),
            "user_storage_configured": bool(self.user_storage_base),
            "backup_dir_configured": bool(self.backup_dir),
            "exports_dir_configured": bool(self.exports_dir),
            "keys_validated": {
                k: {"present": v.is_present, "format_ok": v.is_valid_format}
                for k, v in self.key_statuses.items()
            },
            "error_count": len(self.errors),
        }


def get_project_root() -> Path:
    """Resolves the canonical project root directory."""
    return Path(__file__).resolve().parent.parent.parent


def find_env_file(explicit_path: Optional[str | Path] = None) -> Optional[Path]:
    """Finds the effective environment file in order of priority:
    1. Explicit path argument.
    2. ENV_FILE environment variable.
    3. Project root .env.

    Never falls back to .env.example or sample template files.
    """
    if explicit_path:
        p = Path(explicit_path).resolve()
        if p.name.endswith(".example"):
            logger.warning("Ignoring example environment file '%s'; .env.example cannot be used as an active environment.", p)
            return None
        if p.is_file():
            return p
        return None

    env_var_path = os.environ.get("ENV_FILE")
    if env_var_path and str(env_var_path).strip():
        p = Path(env_var_path.strip())
        if not p.is_absolute():
            p_cwd = (Path.cwd() / p).resolve()
            p_root = (get_project_root() / p).resolve()
            if p_cwd.is_file():
                p = p_cwd
            elif p_root.is_file():
                p = p_root
            else:
                p = p.resolve()
        else:
            p = p.resolve()

        if p.name.endswith(".example"):
            logger.warning("Ignoring example environment file in ENV_FILE '%s'.", p)
            return None
        if p.is_file():
            return p
        return None

    root_env = get_project_root() / ".env"
    if root_env.is_file():
        return root_env

    return None


def load_production_env(
    env_path: Optional[str | Path] = None,
    override: bool = False,
) -> Optional[Path]:
    """Loads environment variables from .env into os.environ before module initialization.

    Args:
        env_path: Explicit path to the .env file.
        override: Whether to override existing environment variables (default False).

    Returns:
        Path to loaded .env file, or None if no file was found.
    """
    resolved_path = find_env_file(env_path)
    if resolved_path and resolved_path.is_file():
        load_dotenv(dotenv_path=resolved_path, override=override)
        logger.info("Loaded environment variables from: %s", resolved_path)
        return resolved_path

    logger.debug("No .env file found; using ambient process environment variables.")
    return None


def _check_hex_secret(name: str, value: Optional[str]) -> KeyValidationStatus:
    """Validates that a secret is a 256-bit hexadecimal string (64 hex characters)
    with sufficient entropy and no predictable placeholder patterns.
    """
    status = KeyValidationStatus(name=name)
    if not value or not str(value).strip():
        status.error_message = f"{name} is missing or empty."
        return status

    clean_val = str(value).strip()
    status.is_present = True
    val_lower = clean_val.lower()

    # 1. Known placeholder pattern detection
    for placeholder in INSECURE_PLACEHOLDER_SUBSTRINGS:
        if placeholder in val_lower:
            status.error_message = f"{name} contains an insecure default placeholder substring."
            return status

    # 2. Development default pepper check
    if val_lower == DEFAULT_DEV_PEPPER.lower():
        status.error_message = f"{name} uses the known development default pepper."
        return status

    # 3. Exact 64 hex characters (256 bits)
    if len(clean_val) != 64 or not re.match(r"^[0-9a-fA-F]{64}$", clean_val):
        status.error_message = (
            f"{name} must be exactly 64 hexadecimal characters (256-bit entropy). Got length {len(clean_val)}."
        )
        return status
    if val_lower == DEFAULT_DEV_PEPPER.lower():
        status.error_message = f"{name} uses the known development default pepper."
        return status

    # 4. Low entropy / repeated character check
    unique_chars = len(set(val_lower))
    status.entropy_score = unique_chars
    if unique_chars < 12:
        status.error_message = (
            f"{name} has dangerously low entropy (only {unique_chars} distinct characters in 64 hex digits)."
        )
        return status

    # 5. Trivial sequential patterns check (e.g. 0123456789abcdef... or 12345678...)
    sequential_samples = ["0123456789abcdef", "fedcba9876543210", "1234567890123456"]
    for seq in sequential_samples:
        if seq in val_lower:
            status.error_message = f"{name} contains predictable sequential characters."
            return status

    status.is_valid_format = True
    return status


def validate_production_configuration(
    env_dict: Optional[Dict[str, str]] = None,
    enforce: bool = True,
    expected_data_dir: Optional[str | Path] = None,
) -> ProductionValidationReport:
    """Validates the effective production configuration against strict production standards.

    Checks:
    - APP_ENV == "production"
    - Required 256-bit hex signing and authentication secrets
    - Cryptographic key separation (no duplicate secret reuse across subsystems)
    - Rotation key configuration integrity
    - Absolute persistent storage paths on dedicated drives outside web root
    - Storage path alignment with dedicated data directory (if specified)
    - Strict human-in-the-loop and anti-automation governance flags

    Args:
        env_dict: Optional dictionary of environment variables (defaults to os.environ).
        enforce: If True and APP_ENV == "production", raises ProductionConfigurationError on failure.
        expected_data_dir: Optional root directory that storage paths must reside within.

    Returns:
        ProductionValidationReport detailing validation outcomes.
    """
    env = env_dict if env_dict is not None else os.environ

    app_env = env.get("APP_ENV", "development").strip().lower()
    is_prod = app_env == "production"

    report = ProductionValidationReport(
        app_env=app_env,
        is_production=is_prod,
        is_valid=True,
    )

    # In development or test, return clean report without strict production failures
    if not is_prod:
        report.is_valid = True
        return report

    # -------------------------------------------------------------------------
    # 1. Cryptographic Secrets Validation
    # -------------------------------------------------------------------------
    mandatory_secrets = [
        "ACTION_TICKET_SECRET_KEY",
        "SECURITY_SCAN_SIGNING_KEY",
        "SESSION_SECRET_KEY",
        "PASSWORD_RESET_PEPPER",
        "AUDIT_LOG_PEPPER",
    ]

    validated_secret_values: Dict[str, str] = {}

    for sec_name in mandatory_secrets:
        sec_val = env.get(sec_name)
        status = _check_hex_secret(sec_name, sec_val)
        report.key_statuses[sec_name] = status
        if not status.is_valid_format:
            report.errors.append(status.error_message or f"{sec_name} validation failed.")
            report.is_valid = False
        else:
            validated_secret_values[sec_name] = str(sec_val).strip().lower()

    # Cryptographic Key Separation: Ensure mandatory keys are distinct
    seen_keys: Dict[str, str] = {}
    for sec_name, val in validated_secret_values.items():
        if val in seen_keys:
            conflict_name = seen_keys[val]
            report.errors.append(
                f"Cryptographic key reuse violation: {sec_name} must not be identical to {conflict_name}."
            )
            report.is_valid = False
        else:
            seen_keys[val] = sec_name

    # -------------------------------------------------------------------------
    # 2. Key Rotation Dictionaries
    # -------------------------------------------------------------------------
    # Action Ticket Rotation
    action_active_id = env.get("ACTION_TICKET_ACTIVE_KEY_ID", "v1").strip()
    action_rot_raw = env.get("ACTION_TICKET_ROTATION_KEYS")
    if action_rot_raw and action_rot_raw.strip():
        try:
            action_rot = json.loads(action_rot_raw)
            if not isinstance(action_rot, dict):
                report.errors.append("ACTION_TICKET_ROTATION_KEYS must be a JSON dictionary of key_id -> hex_key.")
                report.is_valid = False
            else:
                if action_active_id not in action_rot:
                    report.errors.append(
                        f"ACTION_TICKET_ACTIVE_KEY_ID '{action_active_id}' is missing from ACTION_TICKET_ROTATION_KEYS."
                    )
                    report.is_valid = False
                for rk_id, rk_val in action_rot.items():
                    rk_status = _check_hex_secret(f"ACTION_TICKET_ROTATION_KEYS[{rk_id}]", rk_val)
                    if not rk_status.is_valid_format:
                        report.errors.append(rk_status.error_message or f"Rotation key '{rk_id}' is invalid.")
                        report.is_valid = False
        except (json.JSONDecodeError, ValueError) as exc:
            report.errors.append(f"ACTION_TICKET_ROTATION_KEYS is not valid JSON: {exc}")
            report.is_valid = False

    # Security Scan Rotation
    scan_active_id = env.get("SECURITY_SCAN_ACTIVE_KEY_ID", "scan_v1").strip()
    scan_rot_raw = env.get("SECURITY_SCAN_ROTATION_KEYS")
    if scan_rot_raw and scan_rot_raw.strip():
        try:
            scan_rot = json.loads(scan_rot_raw)
            if not isinstance(scan_rot, dict):
                report.errors.append("SECURITY_SCAN_ROTATION_KEYS must be a JSON dictionary of key_id -> hex_key.")
                report.is_valid = False
            else:
                if scan_active_id not in scan_rot:
                    report.errors.append(
                        f"SECURITY_SCAN_ACTIVE_KEY_ID '{scan_active_id}' is missing from SECURITY_SCAN_ROTATION_KEYS."
                    )
                    report.is_valid = False
                for sk_id, sk_val in scan_rot.items():
                    sk_status = _check_hex_secret(f"SECURITY_SCAN_ROTATION_KEYS[{sk_id}]", sk_val)
                    if not sk_status.is_valid_format:
                        report.errors.append(sk_status.error_message or f"Scan rotation key '{sk_id}' is invalid.")
                        report.is_valid = False
        except (json.JSONDecodeError, ValueError) as exc:
            report.errors.append(f"SECURITY_SCAN_ROTATION_KEYS is not valid JSON: {exc}")
            report.is_valid = False

    # -------------------------------------------------------------------------
    # 3. Persistent Storage Paths & Directory Isolation
    # -------------------------------------------------------------------------
    path_configs = [
        ("DATABASE_PATH", env.get("DATABASE_PATH") or env.get("SQLITE_DB_PATH")),
        ("USER_STORAGE_BASE", env.get("USER_STORAGE_BASE") or env.get("USER_DATA_DIR")),
        ("BACKUP_DIR", env.get("BACKUP_DIR")),
        ("EXPORTS_DIR", env.get("EXPORTS_DIR")),
    ]

    for p_name, p_val in path_configs:
        if not p_val or not str(p_val).strip():
            report.errors.append(f"Production setting {p_name} must be explicitly configured.")
            report.is_valid = False
            continue

        clean_path = str(p_val).strip()
        p_obj = Path(clean_path)

        # Require absolute path (supports POSIX absolute /... or Windows absolute C:\...)
        is_abs = p_obj.is_absolute() or bool(re.match(r"^[a-zA-Z]:[\\/]", clean_path))
        if not is_abs:
            report.errors.append(f"{p_name} must be an absolute path outside the web root (got '{clean_path}').")
            report.is_valid = False
            continue

        # Phase C.0.2: Component-aware canonical containment & forbidden location checks
        _, c_parts = canonicalize_path_components(clean_path)
        is_bad, bad_reason = is_forbidden_path(c_parts)
        if is_bad:
            report.errors.append(
                f"{p_name} ('{clean_path}') must not be located inside {bad_reason}."
            )
            report.is_valid = False

        if ".." in c_parts:
            report.errors.append(
                f"{p_name} ('{clean_path}') contains illegal relative directory traversal (..)."
            )
            report.is_valid = False

        if expected_data_dir:
            if not is_path_contained_in_root(clean_path, expected_data_dir):
                report.errors.append(
                    f"{p_name} ('{clean_path}') is not canonically contained within expected data directory '{expected_data_dir}'."
                )
                report.is_valid = False

        # Check directory existence or creatability on native platform
        can_check_fs = (os.name == "nt") or (not bool(re.match(r"^[a-zA-Z]:[\\/]", clean_path)))

        if p_name == "DATABASE_PATH":
            report.database_path = clean_path
            if can_check_fs:
                try:
                    p_obj.parent.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    report.warnings.append(f"Cannot verify parent directory for {p_name}: {exc}")
        elif p_name == "USER_STORAGE_BASE":
            report.user_storage_base = clean_path
            if can_check_fs:
                try:
                    p_obj.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    report.warnings.append(f"Cannot verify directory for {p_name}: {exc}")
        elif p_name == "BACKUP_DIR":
            report.backup_dir = clean_path
            if can_check_fs:
                try:
                    p_obj.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    report.warnings.append(f"Cannot verify directory for {p_name}: {exc}")
        elif p_name == "EXPORTS_DIR":
            report.exports_dir = clean_path
            if can_check_fs:
                try:
                    p_obj.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    report.warnings.append(f"Cannot verify directory for {p_name}: {exc}")

    # -------------------------------------------------------------------------
    # 4. Strict Safety & Anti-Automation Flags
    # -------------------------------------------------------------------------
    auto_sub = env.get("ALLOW_AUTOMATED_SUBMISSION", "false").strip().lower()
    if auto_sub in ("true", "1", "yes", "on"):
        report.errors.append(
            "CRITICAL SAFETY VIOLATION: ALLOW_AUTOMATED_SUBMISSION must be false in production."
        )
        report.is_valid = False

    robots = env.get("RESPECT_ROBOTS_TXT", "true").strip().lower()
    if robots not in ("true", "1", "yes", "on"):
        report.errors.append(
            "COMPLIANCE VIOLATION: RESPECT_ROBOTS_TXT must be true in production."
        )
        report.is_valid = False

    # -------------------------------------------------------------------------
    # 5. Diagnostic Logging and Enforcement
    # -------------------------------------------------------------------------
    if not report.is_valid:
        error_list = "; ".join(report.errors)
        logger.critical("Production configuration validation FAILED with %d error(s): %s", len(report.errors), error_list)
        if enforce:
            raise ProductionConfigurationError(
                f"Production configuration preflight failed ({len(report.errors)} errors): {error_list}"
            )
    else:
        logger.info(
            "Production configuration validation PASSED. All %d mandatory secrets and paths verified.",
            len(mandatory_secrets),
        )

    return report


def validate_storage_paths_alignment(
    env_dict: Optional[Dict[str, str]] = None,
    expected_data_dir: Optional[str | Path] = None,
) -> List[str]:
    """Validates that all configured persistent storage paths are outside web roots
    and optionally aligned with the dedicated data root directory.

    Args:
        env_dict: Optional dictionary of environment variables (defaults to os.environ).
        expected_data_dir: Optional root directory that all storage paths must reside within.

    Returns:
        List of error descriptions (empty if all paths are valid).
    """
    env = env_dict if env_dict is not None else os.environ
    errors: List[str] = []

    path_configs = [
        ("DATABASE_PATH", env.get("DATABASE_PATH") or env.get("SQLITE_DB_PATH")),
        ("USER_STORAGE_BASE", env.get("USER_STORAGE_BASE") or env.get("USER_DATA_DIR")),
        ("BACKUP_DIR", env.get("BACKUP_DIR")),
        ("EXPORTS_DIR", env.get("EXPORTS_DIR")),
    ]

    for p_name, p_val in path_configs:
        if not p_val or not str(p_val).strip():
            errors.append(f"{p_name} is not explicitly configured.")
            continue

        clean_path = str(p_val).strip()
        p_obj = Path(clean_path)

        is_abs = p_obj.is_absolute() or bool(re.match(r"^[a-zA-Z]:[\\/]", clean_path))
        if not is_abs:
            errors.append(f"{p_name} must be an absolute path (got '{clean_path}').")
            continue

        # Phase C.0.2: Component-aware canonical containment & forbidden location checks
        _, c_parts = canonicalize_path_components(clean_path)
        is_bad, bad_reason = is_forbidden_path(c_parts)
        if is_bad:
            errors.append(f"{p_name} ('{clean_path}') must not be located inside {bad_reason}.")

        if ".." in c_parts:
            errors.append(f"{p_name} ('{clean_path}') contains illegal relative directory traversal (..).")

        if expected_data_dir:
            if not is_path_contained_in_root(clean_path, expected_data_dir):
                errors.append(
                    f"{p_name} ('{clean_path}') is not canonically contained within expected data directory '{expected_data_dir}'."
                )

    return errors

