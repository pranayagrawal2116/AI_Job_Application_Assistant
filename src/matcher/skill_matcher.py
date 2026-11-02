"""Technical Skill Matcher module with ontology and relationship awareness."""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Set, Tuple

from src.database.models import Job


# Knowledge ontology connecting confirmed skills with related concepts and libraries
SKILL_RELATIONSHIPS = {
    "python": {
        "related": [
            "python programming",
            "pandas",
            "numpy",
            "scikit-learn",
            "scipy",
            "matplotlib",
            "seaborn",
            "jupyter",
            "oop",
            "scripting",
        ],
        "category": "language",
    },
    "machine learning": {
        "related": [
            "supervised learning",
            "unsupervised learning",
            "classification",
            "regression",
            "clustering",
            "model evaluation",
            "model training",
            "cross-validation",
            "feature engineering",
            "random forest",
            "decision trees",
            "gradient boosting",
            "xgboost",
        ],
        "category": "domain",
    },
    "artificial intelligence": {
        "related": [
            "deep learning",
            "neural networks",
            "nlp",
            "natural language processing",
            "computer vision",
            "generative ai",
            "llms",
            "transformers",
            "heuristics",
        ],
        "category": "domain",
    },
    "data science": {
        "related": [
            "data preprocessing",
            "data visualization",
            "data analysis",
            "eda",
            "exploratory data analysis",
            "statistical modeling",
            "statistics",
            "data cleaning",
            "data wrangling",
        ],
        "category": "domain",
    },
    "data preprocessing": {
        "related": ["feature scaling", "missing value imputation", "encoding", "outlier detection", "pandas"],
        "category": "specialization",
    },
    "data visualization": {
        "related": ["matplotlib", "seaborn", "plotting", "charts", "dashboards"],
        "category": "specialization",
    },
    "flutter": {
        "related": ["dart", "mobile application development", "cross-platform", "flutter widgets", "state management"],
        "category": "framework",
    },
    "dart": {
        "related": ["flutter", "oop", "mobile development"],
        "category": "language",
    },
}


@dataclass
class SkillMatchResult:
    score: float
    max_points: float
    confirmed_skills: List[str] = field(default_factory=list)
    related_skills: List[str] = field(default_factory=list)
    missing_skills: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "confirmed_skills": self.confirmed_skills,
            "related_skills": self.related_skills,
            "missing_skills": self.missing_skills,
            "details": self.details,
        }


class SkillMatcher:
    """Evaluates technical skill alignment, distinguishing confirmed, related, and missing skills."""

    def __init__(self, candidate_profile: Dict[str, Any], scoring_rules: Dict[str, Any]):
        skills_cfg = scoring_rules.get("weights", {}).get("technical_skills", {})
        self.max_points = float(skills_cfg.get("max_points", 25))
        self.bonus_tools = [t.lower() for t in skills_cfg.get("bonus_tools", [])]

        # Extract verified candidate skills from profile
        self.confirmed_skills_set: Set[str] = set()
        tech_skills = candidate_profile.get("technical_skills", {})
        for cat, items in tech_skills.items():
            if isinstance(items, list):
                for item in items:
                    self.confirmed_skills_set.add(item.strip().lower())

        for interest in candidate_profile.get("technical_interests", []):
            self.confirmed_skills_set.add(interest.strip().lower())

        # Build candidate's related skills map based on confirmed knowledge
        self.related_skills_set: Set[str] = set()
        for confirmed in self.confirmed_skills_set:
            if confirmed in SKILL_RELATIONSHIPS:
                for rel in SKILL_RELATIONSHIPS[confirmed]["related"]:
                    if rel not in self.confirmed_skills_set:
                        self.related_skills_set.add(rel)

    def match(self, job: Job) -> SkillMatchResult:
        """Evaluates job skills requirements against verified candidate competencies."""
        required_demands = self._extract_job_skill_demands(job)

        confirmed_matches: List[str] = []
        related_matches: List[str] = []
        missing_demands: List[str] = []

        if not required_demands:
            # If job didn't specify distinct skills, match against core interests in description
            text = f"{job.job_title} {job.job_description or ''}".lower()
            for skill in self.confirmed_skills_set:
                if re.search(r"\b" + re.escape(skill) + r"\b", text):
                    confirmed_matches.append(skill)

            if confirmed_matches:
                score = min(self.max_points, len(confirmed_matches) * 5.0)
            else:
                score = 0.0

            return SkillMatchResult(
                score=score,
                max_points=self.max_points,
                confirmed_skills=sorted(confirmed_matches),
                related_skills=[],
                missing_skills=[],
                details={"method": "fallback_description_search"},
            )

        for demand in required_demands:
            norm_demand = demand.lower().strip()
            # 1. Direct match with confirmed skills
            if norm_demand in self.confirmed_skills_set:
                confirmed_matches.append(demand)
            elif any(norm_demand in cs or cs in norm_demand for cs in self.confirmed_skills_set):
                confirmed_matches.append(demand)
            # 2. Match with related skills
            elif norm_demand in self.related_skills_set or any(norm_demand in rs for rs in self.related_skills_set):
                related_matches.append(demand)
            else:
                missing_demands.append(demand)

        # Calculate weighted skill match score
        total_demands = len(required_demands)
        # Confirmed weight: 1.0, Related conceptual weight: 0.65, Missing: 0.0
        weighted_points = (len(confirmed_matches) * 1.0) + (len(related_matches) * 0.65)
        match_ratio = weighted_points / total_demands if total_demands > 0 else 0.0

        raw_score = match_ratio * self.max_points

        # Bonus tools addition (if mentioned in job description and confirmed/related)
        bonus_points = 0.0
        desc_text = (job.job_description or "").lower()
        for tool in self.bonus_tools:
            if re.search(r"\b" + re.escape(tool) + r"\b", desc_text):
                if tool in self.confirmed_skills_set or tool in self.related_skills_set:
                    bonus_points += 0.5

        final_score = min(self.max_points, raw_score + bonus_points)

        return SkillMatchResult(
            score=final_score,
            max_points=self.max_points,
            confirmed_skills=sorted(list(set(confirmed_matches))),
            related_skills=sorted(list(set(related_matches))),
            missing_skills=sorted(list(set(missing_demands))),
            details={
                "total_demands_evaluated": total_demands,
                "confirmed_count": len(confirmed_matches),
                "related_count": len(related_matches),
                "missing_count": len(missing_demands),
                "bonus_points": bonus_points,
            },
        )

    def _extract_job_skill_demands(self, job: Job) -> List[str]:
        """Extracts required skills from job structured fields or extracts key technical tokens."""
        demands: List[str] = []

        if isinstance(job.required_skills, list) and job.required_skills:
            demands.extend([str(s).strip() for s in job.required_skills if str(s).strip()])
        elif isinstance(job.required_skills, str) and job.required_skills.strip():
            try:
                parsed = json.loads(job.required_skills)
                if isinstance(parsed, list):
                    demands.extend([str(s).strip() for s in parsed if str(s).strip()])
                else:
                    demands.extend([s.strip() for s in job.required_skills.split(",") if s.strip()])
            except Exception:
                demands.extend([s.strip() for s in job.required_skills.split(",") if s.strip()])

        # If empty, parse common skills from job description
        if not demands and job.job_description:
            known_tokens = [
                "python", "machine learning", "deep learning", "nlp", "computer vision",
                "generative ai", "data science", "sql", "pytorch", "tensorflow",
                "pandas", "numpy", "scikit-learn", "flutter", "dart", "c++", "java",
                "react", "aws", "docker", "git", "statistics"
            ]
            desc_lower = job.job_description.lower()
            for token in known_tokens:
                if re.search(r"\b" + re.escape(token) + r"\b", desc_lower):
                    demands.append(token.title())

        return list(dict.fromkeys(demands))

