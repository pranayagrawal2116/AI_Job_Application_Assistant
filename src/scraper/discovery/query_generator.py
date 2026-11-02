"""Targeted Query and Search Variant Generator for AI/ML Internships."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class QueryGenerator:
    """Generates search queries combining target AI/ML roles and geographical locations."""

    DEFAULT_TARGET_ROLES = [
        "Artificial Intelligence Intern",
        "Machine Learning Intern",
        "Data Science Intern",
        "Python Developer Intern",
        "Deep Learning Intern",
        "Generative AI Intern",
        "NLP Intern",
        "Computer Vision Intern",
        "AI Research Intern",
        "Data Analyst Intern",
    ]

    DEFAULT_TARGET_LOCATIONS = [
        "Remote",
        "Work from Home",
        "Pune",
        "Bengaluru",
        "Mumbai",
        "Hyderabad",
        "Delhi NCR",
        "India",
    ]

    def __init__(self, config_path: Optional[Path] = None):
        self.roles = list(self.DEFAULT_TARGET_ROLES)
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
        """Generates prioritized (role, location) search pairs."""
        target_roles = roles or self.roles
        target_locs = locations or self.locations

        matrix: List[Tuple[str, str]] = []
        # Prioritize Remote and Pune (candidate's home university) first
        sorted_locs = sorted(
            target_locs,
            key=lambda l: 0 if l.lower() in ("remote", "work from home") else (1 if l.lower() == "pune" else 2)
        )

        for role in target_roles:
            for loc in sorted_locs:
                matrix.append((role, loc))
                if max_combinations and len(matrix) >= max_combinations:
                    return matrix

        return matrix

    def generate_keywords_for_role(self, role: str) -> List[str]:
        """Returns secondary keyword variations for fine-grained searching."""
        role_lower = role.lower()
        if "machine learning" in role_lower or "ml" in role_lower:
            return ["Machine Learning", "Scikit-Learn", "Model Training", "Supervised Learning"]
        if "artificial intelligence" in role_lower or "ai" in role_lower:
            return ["Artificial Intelligence", "Deep Learning", "LLM", "GenAI"]
        if "data science" in role_lower:
            return ["Data Science", "Pandas", "EDA", "Data Analysis", "Python"]
        if "python" in role_lower:
            return ["Python Developer", "Backend", "Data Preprocessing", "Automation"]
        return [role]

