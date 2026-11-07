"""Universal Targeted Query and Search Variant Generator across all industries and professions."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class QueryGenerator:
    """Generates search queries combining target career roles and candidate-specific geographical locations."""

    DEFAULT_TARGET_LOCATIONS = [
        "Remote",
        "Work from Home",
        "India",
    ]

    def __init__(self, config_path: Optional[Path] = None):
        self.roles: List[str] = []
        self.locations = list(self.DEFAULT_TARGET_LOCATIONS)
        if config_path and config_path.exists():
            self._load_from_config(config_path)

    def _load_from_config(self, config_path: Path) -> None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                custom_roles = data.get("target_roles")
                if custom_roles and isinstance(custom_roles, list):
                    self.roles = custom_roles
                custom_locs = data.get("locations")
                if custom_locs and isinstance(custom_locs, list):
                    self.locations = custom_locs
        except Exception:
            pass

    def generate_query_matrix(
        self,
        roles: Optional[List[str]] = None,
        locations: Optional[List[str]] = None,
        max_combinations: Optional[int] = None,
    ) -> List[Tuple[str, str]]:
        """Generates prioritized (role, location) search pairs without assuming tech/AI-ML defaults."""
        target_roles = roles if roles is not None else self.roles
        target_locs = locations if locations is not None else self.locations

        if not target_roles:
            return []

        matrix: List[Tuple[str, str]] = []
        # Prioritize Remote and Work from Home first, followed by explicit locations
        sorted_locs = sorted(
            target_locs,
            key=lambda l: 0 if l.lower() in ("remote", "work from home") else (2 if l.lower() == "india" else 1)
        )

        for role in target_roles:
            for loc in sorted_locs:
                matrix.append((role, loc))
                if max_combinations and len(matrix) >= max_combinations:
                    return matrix

        return matrix

    def generate_keywords_for_role(self, role: str) -> List[str]:
        """Returns secondary keyword variations across diverse domains for fine-grained searching."""
        role_lower = role.lower()
        if "tax" in role_lower:
            return ["UK Taxation", "Tax Compliance", "Tax Computations", "Corporate Tax", "SA100"]
        if "audit" in role_lower:
            return ["Internal Audit", "Audit Associate", "Financial Audit", "Internal Controls", "Stock Audit"]
        if "account" in role_lower or "payable" in role_lower:
            return ["Accounts Payable", "General Ledger", "Reconciliation", "Financial Reporting", "Invoicing"]
        if "flutter" in role_lower or "mobile" in role_lower:
            return ["Flutter Developer", "Dart", "Mobile Application", "Android", "Cross-Platform"]
        if "machine learning" in role_lower or "ml" in role_lower:
            return ["Machine Learning", "Scikit-Learn", "Model Training", "Supervised Learning"]
        if "artificial intelligence" in role_lower or "ai" in role_lower:
            return ["Artificial Intelligence", "Deep Learning", "LLM", "GenAI"]
        if "data science" in role_lower:
            return ["Data Science", "Pandas", "EDA", "Data Analysis", "Python"]
        if "python" in role_lower:
            return ["Python Developer", "Backend", "Data Preprocessing", "Automation"]
        if "financial" in role_lower or "finance" in role_lower:
            return ["Financial Analysis", "Working Capital", "Financial Modeling", "Reporting"]
        return [role]

