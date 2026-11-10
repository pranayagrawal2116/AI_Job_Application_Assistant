"""Authoritative Runtime Environment Bootstrap & Fail-Fast Validation Module.

Enforces a single, non-divergent application environment resolution policy across
FastAPI, security preflight, legacy evidence verification, and database subsystems.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Dict, Optional

from src.database.exceptions import SecurityAuthorizationError
from src.utils.logger import setup_logger

logger = setup_logger("RuntimeEnvironment")

# Authoritative normalization map for supported environments (Phase C.0.6)
SUPPORTED_ENVIRONMENTS: Dict[str, str] = {
    "development": "development",
    "dev": "development",
    "test": "test",
    "production": "production",
    "prod": "production",
    "staging": "staging",
    "qa": "qa",
}


def resolve_app_env(raw_env: Optional[str] = None) -> str:
    """Authoritatively resolves, normalizes, and validates the application execution environment.

    Contract:
    - production / prod -> 'production' (Ed25519 asymmetric only)
    - staging -> 'staging' (Ed25519 asymmetric only)
    - qa -> 'qa' (Ed25519 asymmetric only)
    - development / dev -> 'development' (Permissive policy permitted)
    - test -> 'test' (Permissive policy permitted)
    - missing / None -> raises SecurityAuthorizationError (fails closed)
    - empty / whitespace -> raises SecurityAuthorizationError (fails closed)
    - unknown / unrecognized -> raises SecurityAuthorizationError (fails closed)

    Args:
        raw_env: Optional explicit environment string. Defaults to os.environ.get("APP_ENV").

    Returns:
        The canonical normalized environment string.

    Raises:
        SecurityAuthorizationError: When APP_ENV is missing, empty, whitespace-only,
            or not present in SUPPORTED_ENVIRONMENTS.
    """
    target = raw_env if raw_env is not None else os.environ.get("APP_ENV")

    if target is None:
        raise SecurityAuthorizationError(
            "APP_ENV environment variable is missing. Application security policy fails closed."
        )

    clean_env = str(target).strip()
    if not clean_env:
        raise SecurityAuthorizationError(
            "APP_ENV environment variable is empty or whitespace. Application security policy fails closed."
        )

    normalized = clean_env.lower()
    if normalized in SUPPORTED_ENVIRONMENTS:
        return SUPPORTED_ENVIRONMENTS[normalized]

    raise SecurityAuthorizationError(
        f"Unrecognized or untrusted APP_ENV '{target}'. Application security policy fails closed."
    )


@dataclass(frozen=True)
class RuntimeEnvironment:
    """Immutable, typed snapshot of the active application runtime environment."""
    app_env: str
    raw_app_env: str
    is_production: bool
    is_development: bool
    is_test: bool
    is_staging: bool
    is_qa: bool
    env_file_loaded: Optional[str]
    is_config_ready: bool
    config_error: Optional[str] = None

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns a sanitized dictionary for telemetry or diagnostics without secrets."""
        return {
            "app_env": self.app_env,
            "is_production": self.is_production,
            "is_development": self.is_development,
            "is_test": self.is_test,
            "is_staging": self.is_staging,
            "is_qa": self.is_qa,
            "env_file_loaded": self.env_file_loaded,
            "is_config_ready": self.is_config_ready,
            "config_error": self.config_error,
        }


def bootstrap_runtime_environment(
    env_file_path: Optional[str | Path] = None,
    enforce_production: bool = True,
    override_env: bool = False,
) -> RuntimeEnvironment:
    """Discovers .env, loads variables, authoritatively resolves APP_ENV, and validates policy.

    Args:
        env_file_path: Optional explicit path to an environment file.
        enforce_production: Whether to enforce strict production secret checks if in production.
        override_env: Whether to override existing process environment variables (default False).

    Returns:
        A validated RuntimeEnvironment instance.

    Raises:
        SecurityAuthorizationError: If APP_ENV is missing, blank, or untrusted.
        ProductionConfigurationError: If APP_ENV is production and production secrets fail validation.
    """
    from src.config.env_loader import (
        load_production_env,
        validate_production_configuration,
    )

    # 1. Discover and load environment file
    loaded_path = load_production_env(env_path=env_file_path, override=override_env)
    effective_env_file = str(loaded_path) if loaded_path else None

    # 2. Authoritatively resolve APP_ENV
    raw_app_env = os.environ.get("APP_ENV", "")
    normalized_env = resolve_app_env()

    # 3. Synchronize normalized environment into process space
    os.environ["APP_ENV"] = normalized_env

    # 4. Production validation if applicable
    config_ready = True
    config_error = None
    if normalized_env == "production":
        try:
            validate_production_configuration(enforce=enforce_production)
            logger.info("Production configuration preflight validated successfully.")
        except Exception as e:
            config_ready = False
            config_error = str(e)
            if enforce_production:
                raise

    return RuntimeEnvironment(
        app_env=normalized_env,
        raw_app_env=raw_app_env,
        is_production=(normalized_env == "production"),
        is_development=(normalized_env == "development"),
        is_test=(normalized_env == "test"),
        is_staging=(normalized_env == "staging"),
        is_qa=(normalized_env == "qa"),
        env_file_loaded=effective_env_file,
        is_config_ready=config_ready,
        config_error=config_error,
    )
