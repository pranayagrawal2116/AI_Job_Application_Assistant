"""Domain Relevance Matcher module."""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List

from src.database.models import Job


@dataclass
class DomainMatchResult:
    score: float
    max_points: float
    tier: int
    matched_keywords: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "tier": self.tier,
            "matched_keywords": self.matched_keywords,
            "details": self.details,
        }


class DomainMatcher:
    """Evaluates alignment between job content and AI/ML target domains."""

    def __init__(self, scoring_rules: Dict[str, Any]):
        domain_cfg = scoring_rules.get("weights", {}).get("domain_relevance", {})
        self.max_points = float(domain_cfg.get("max_points", 30))
        keywords_cfg = domain_cfg.get("keywords", {})
        self.tier_1 = [k.lower() for k in keywords_cfg.get("tier_1_keywords", [])]
        self.tier_2 = [k.lower() for k in keywords_cfg.get("tier_2_keywords", [])]
        self.tier_3 = [k.lower() for k in keywords_cfg.get("tier_3_keywords", [])]

    def match(self, job: Job) -> DomainMatchResult:
        """Calculates domain relevance score based on job title and description."""
        title = (job.job_title or "").lower()
        desc = (job.job_description or "").lower()
        combined_text = f"{title} {desc}"

        matched_tier_1: List[str] = []
        matched_tier_2: List[str] = []
        matched_tier_3: List[str] = []

        # Helper to search for keyword with boundary awareness
        def find_keywords(keywords_list: List[str], target_text: str) -> List[str]:
            found = []
            for kw in keywords_list:
                # Use regex word boundaries where appropriate
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, target_text):
                    found.append(kw)
            return found

        matched_tier_1 = find_keywords(self.tier_1, combined_text)
        matched_tier_2 = find_keywords(self.tier_2, combined_text)
        matched_tier_3 = find_keywords(self.tier_3, combined_text)

        # Recognize common acronyms in AI/ML (e.g. \bai\b, \bml\b)
        if re.search(r"\b(ai|ml)\b", combined_text) and not matched_tier_1:
            matched_tier_1.append("ai/ml")

        # Check title directly for strong tier assignment
        title_tier_1 = find_keywords(self.tier_1, title)
        if re.search(r"\b(ai|ml)\b", title) and not title_tier_1:
            title_tier_1.append("ai/ml")
        title_tier_2 = find_keywords(self.tier_2, title)
        title_tier_3 = find_keywords(self.tier_3, title)

        if title_tier_1 or len(matched_tier_1) >= 2:
            score = self.max_points
            tier = 1
        elif matched_tier_1:
            # Single tier 1 mention in description
            score = self.max_points * 0.90  # 27 / 30
            tier = 1
        elif title_tier_2 or len(matched_tier_2) >= 1:
            score = self.max_points * (20.0 / 30.0)  # 20 points
            tier = 2
        elif title_tier_3 or len(matched_tier_3) >= 1:
            score = self.max_points * (10.0 / 30.0)  # 10 points
            tier = 3
        else:
            score = 0.0
            tier = 0

        all_matched = sorted(list(set(matched_tier_1 + matched_tier_2 + matched_tier_3)))

        return DomainMatchResult(
            score=min(score, self.max_points),
            max_points=self.max_points,
            tier=tier,
            matched_keywords=all_matched,
            details={
                "tier_1_matches": matched_tier_1,
                "tier_2_matches": matched_tier_2,
                "tier_3_matches": matched_tier_3,
                "title_matches": title_tier_1 + title_tier_2 + title_tier_3,
            },
        )
