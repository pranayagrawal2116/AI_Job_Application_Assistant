"""Configuration and Candidate Profile loader module."""

import json
from pathlib import Path
from typing import Any, Dict
import yaml

from src.utils.logger import setup_logger
from src.config.env_loader import load_production_env, validate_production_configuration

logger = setup_logger("ConfigLoader")

# Base project paths (two levels up from src/config/ is root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
PROFILE_DIR = DATA_DIR / "profile"


def load_yaml(file_path: Path) -> Dict[str, Any]:
    """Loads and parses a YAML configuration file."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_json(file_path: Path) -> Dict[str, Any]:
    """Loads and parses a JSON configuration file."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f) or {}


class AppConfig:
    """Provides validated access to application configs, scoring rules, and candidate profile."""

    def __init__(
        self,
        config_path: Path = CONFIG_DIR / "config.yaml",
        scoring_path: Path = CONFIG_DIR / "scoring_rules.yaml",
        search_path: Path = CONFIG_DIR / "search_criteria.json",
        profile_path: Path = PROFILE_DIR / "candidate_profile.yaml",
    ):
        self.config_path = config_path
        self.scoring_path = scoring_path
        self.search_path = search_path
        self.profile_path = profile_path

        self._app_config: Dict[str, Any] = {}
        self._scoring_rules: Dict[str, Any] = {}
        self._search_criteria: Dict[str, Any] = {}
        self._candidate_profile: Dict[str, Any] = {}

        self.reload()

    def reload(self) -> None:
        """Reloads all configuration files from disk."""
        logger.info("Loading configuration files...")
        self._app_config = load_yaml(self.config_path)
        self._scoring_rules = load_yaml(self.scoring_path)
        self._search_criteria = load_json(self.search_path)
        self._candidate_profile = load_yaml(self.profile_path)
        self._validate()

    def _validate(self) -> None:
        """Validates critical structure and safety rules."""
        safety = self._app_config.get("safety_and_compliance", {})
        if not safety.get("require_manual_submission_approval", False):
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: require_manual_submission_approval must be set to true."
            )
        if safety.get("allow_automated_submission", False):
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: allow_automated_submission must be false."
            )

        candidate = self._candidate_profile.get("candidate", {})
        if not candidate.get("education"):
            raise ValueError("Candidate profile must include educational history.")

    @property
    def app(self) -> Dict[str, Any]:
        return self._app_config.get("app", {})

    @property
    def target_preferences(self) -> Dict[str, Any]:
        return self._app_config.get("target_preferences", {})

    @property
    def platforms(self) -> Dict[str, Any]:
        return self._app_config.get("platforms", {})

    @property
    def scoring_rules(self) -> Dict[str, Any]:
        return self._scoring_rules

    @property
    def search_criteria(self) -> Dict[str, Any]:
        return self._search_criteria

    @property
    def candidate_profile(self) -> Dict[str, Any]:
        return self._candidate_profile.get("candidate", {})

    @property
    def candidate_preferences(self) -> Dict[str, Any]:
        return self._candidate_profile.get("preferences", {})


# Default singleton instance for easy import
config = AppConfig()

__all__ = [
    "BASE_DIR",
    "CONFIG_DIR",
    "DATA_DIR",
    "PROFILE_DIR",
    "AppConfig",
    "config",
    "load_yaml",
    "load_json",
    "load_production_env",
    "validate_production_configuration",
]
