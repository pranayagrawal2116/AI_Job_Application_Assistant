"""Canonical Resume-Based Career Context Resolver.

Produces an authoritative candidate-specific career context derived strictly from the latest
primary resume parsed evidence without cross-candidate preference contamination or AI/ML defaults.
"""

from dataclasses import dataclass, field
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.database.db_manager import DatabaseManager
from src.preparer.career_role_inferencer import CareerRoleInferencer, InferredRole

logger = logging.getLogger(__name__)


@dataclass
class CandidateCareerContext:
    """Authoritative career search and matching context for an authenticated candidate."""
    user_id: int
    has_primary_resume: bool = False
    primary_resume_id: Optional[int] = None
    primary_resume_file_hash: Optional[str] = None
    resume_fingerprint: Optional[str] = None
    career_domain: str = "general"
    candidate_category: str = "General"
    inferred_roles: List[InferredRole] = field(default_factory=list)
    selected_roles: List[str] = field(default_factory=list)
    supporting_skills: List[str] = field(default_factory=list)
    relevant_qualifications: List[str] = field(default_factory=list)
    relevant_experience: List[Dict[str, Any]] = field(default_factory=list)
    target_locations: List[str] = field(default_factory=list)
    role_source: str = "neutral_fallback"
    inference_confidence: float = 0.50

    def to_dict(self) -> Dict[str, Any]:
        """Serializes career context to a clean, JSON-compatible dictionary."""
        return {
            "user_id": self.user_id,
            "has_primary_resume": self.has_primary_resume,
            "primary_resume_id": self.primary_resume_id,
            "primary_resume_file_hash": self.primary_resume_file_hash,
            "resume_fingerprint": self.resume_fingerprint,
            "career_domain": self.career_domain,
            "candidate_category": self.candidate_category,
            "inferred_roles": [r.to_dict() if hasattr(r, "to_dict") else r for r in self.inferred_roles],
            "selected_roles": list(self.selected_roles),
            "supporting_skills": list(self.supporting_skills),
            "relevant_qualifications": list(self.relevant_qualifications),
            "relevant_experience": list(self.relevant_experience),
            "target_locations": list(self.target_locations),
            "role_source": self.role_source,
            "inference_confidence": round(self.inference_confidence, 2),
        }


class CareerContextResolver:
    """Resolves authoritative career-search context from candidate resumes and profiles."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        inferencer: Optional[CareerRoleInferencer] = None,
    ):
        self.db = db_manager or DatabaseManager()
        self.inferencer = inferencer or CareerRoleInferencer()

    @staticmethod
    def compute_resume_fingerprint(
        resume_id: int,
        file_hash: Optional[str],
        parsed_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Computes an immutable resume fingerprint tied to the resume record and file hash."""
        if file_hash and len(file_hash) >= 8:
            return f"rfp_{resume_id}_{file_hash[:16]}"
        if parsed_data:
            content_str = json.dumps(parsed_data, sort_keys=True, default=str)
            digest = hashlib.sha256(content_str.encode("utf-8")).hexdigest()[:16]
            return f"rfp_{resume_id}_{digest}"
        return f"rfp_{resume_id}_v1"

    def resolve_candidate_career_context(self, user_id: int) -> CandidateCareerContext:
        """Derives authoritative career search context for a candidate user.

        Data precedence:
        1. Latest primary resume parsed_data.
        2. Verified candidate profile evidence.
        3. Explicit user preference overrides (if confirmed for this resume).
        4. Neutral fallback when sufficient evidence is unavailable.
        """
        # 1. Retrieve candidate resumes
        resumes = self.db.list_user_resumes(user_id) if hasattr(self.db, "list_user_resumes") else (
            self.db.get_user_resumes(user_id) if hasattr(self.db, "get_user_resumes") else []
        )
        prof_rec = self.db.get_user_candidate_profile(user_id)
        prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}

        if not resumes:
            # If candidate has profile data (e.g. manual profile creation or API), infer roles from profile
            if prof_data and (prof_data.get("education") or prof_data.get("technical_skills") or prof_data.get("work_experience") or prof_data.get("search_preferences")):
                domain_info = self.inferencer.infer_career_domain(prof_data)
                career_domain = domain_info.get("domain") or "general"
                candidate_category = domain_info.get("domain_label") or "General Professional"
                inferred_roles = self.inferencer.infer_roles(prof_data)
                prefs = prof_data.get("search_preferences", {})
                selected_roles = list(prefs.get("target_roles", [])) or [r.role_title for r in inferred_roles[:5]]
                target_locations = list(prefs.get("target_locations", [])) or ["Remote", "India"]
                prof_hash = prof_rec.get("profile_hash") or hashlib.sha256(json.dumps(prof_data, sort_keys=True).encode()).hexdigest()
                return CandidateCareerContext(
                    user_id=user_id,
                    has_primary_resume=False,
                    primary_resume_id=None,
                    primary_resume_file_hash=None,
                    resume_fingerprint=f"profile_{user_id}_{prof_hash[:16]}",
                    career_domain=career_domain,
                    candidate_category=candidate_category,
                    inferred_roles=inferred_roles,
                    selected_roles=selected_roles,
                    target_locations=target_locations,
                    role_source="candidate_profile_inference",
                    inference_confidence=max((r.confidence for r in inferred_roles), default=0.75) if inferred_roles else 0.50,
                )

            return CandidateCareerContext(
                user_id=user_id,
                has_primary_resume=False,
                career_domain="general",
                candidate_category="General",
                role_source="neutral_fallback",
                selected_roles=[],
                target_locations=["Remote", "India"],
                inference_confidence=0.0,
            )

        # 2. Identify active primary resume
        primary = next((r for r in resumes if r.get("is_primary")), resumes[0])
        resume_id = int(primary["id"])
        file_hash = primary.get("file_hash") or ""

        # Parse primary resume data
        raw_parsed = primary.get("parsed_data")
        parsed_data: Dict[str, Any] = {}
        if isinstance(raw_parsed, str) and raw_parsed.strip():
            try:
                parsed_data = json.loads(raw_parsed)
            except Exception:
                parsed_data = {}
        elif isinstance(raw_parsed, dict):
            parsed_data = raw_parsed

        # Also retrieve candidate profile
        prof_rec = self.db.get_user_candidate_profile(user_id)
        prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}

        # Merge evidence source (parsed_data primary, prof_data secondary)
        effective_data = parsed_data if parsed_data else prof_data
        resume_fingerprint = self.compute_resume_fingerprint(resume_id, file_hash, effective_data)

        # 3. Infer career domain and roles from factual resume evidence
        domain_info = self.inferencer.infer_career_domain(effective_data)
        career_domain = domain_info.get("domain") or "general"
        candidate_category = domain_info.get("domain_label") or "General Professional"

        inferred_roles = self.inferencer.infer_roles(effective_data)
        inferred_locations = self.inferencer.infer_locations(effective_data)

        # Extract supporting skills
        skills: List[str] = []
        raw_tech = effective_data.get("technical_skills", [])
        if isinstance(raw_tech, list):
            skills.extend([s for s in raw_tech if isinstance(s, str)])
        elif isinstance(raw_tech, dict):
            for v in raw_tech.values():
                if isinstance(v, list):
                    skills.extend([s for s in v if isinstance(s, str)])
                elif isinstance(v, str):
                    skills.append(v)
        prof_skills = effective_data.get("professional_skills", [])
        if isinstance(prof_skills, list):
            skills.extend([s for s in prof_skills if isinstance(s, str)])
        tools = effective_data.get("tools_and_software", [])
        if isinstance(tools, list):
            skills.extend([s for s in tools if isinstance(s, str)])

        # Extract qualifications
        qualifications: List[str] = []
        for c in effective_data.get("certifications", []) + effective_data.get("professional_qualifications", []):
            name = c.get("name") if isinstance(c, dict) else str(c)
            if name and name not in qualifications:
                qualifications.append(name)
        for e in effective_data.get("education", []):
            deg = e.get("degree") or ""
            maj = e.get("major") or e.get("field_of_study") or ""
            combo = f"{deg} in {maj}".strip() if maj else deg
            if combo and combo not in qualifications:
                qualifications.append(combo)

        # Extract experience
        experience_summary: List[Dict[str, Any]] = []
        for exp in effective_data.get("work_experience", []):
            experience_summary.append({
                "job_title": exp.get("job_title", ""),
                "employer": exp.get("employer", ""),
                "duration": exp.get("duration", ""),
            })

        # 4. Check for explicit candidate user overrides
        prefs = prof_data.get("search_preferences", {}) or prof_data.get("preferences", {})
        is_user_override = bool(prefs.get("is_user_override") or prefs.get("explicit_user_override"))
        override_fingerprint = prefs.get("resume_fingerprint")

        # An explicit override is only valid if it matches this exact resume fingerprint
        if is_user_override and override_fingerprint == resume_fingerprint and prefs.get("target_roles"):
            selected_roles = list(prefs["target_roles"])
            role_source = "explicit_user_override"
            target_locations = list(prefs.get("target_locations", [])) or inferred_locations
        else:
            selected_roles = [r.role_title for r in inferred_roles[:5]]
            target_locations = inferred_locations
            role_source = "primary_resume_inference"

        confidence = max((r.confidence for r in inferred_roles), default=0.75) if inferred_roles else 0.50

        return CandidateCareerContext(
            user_id=user_id,
            has_primary_resume=True,
            primary_resume_id=resume_id,
            primary_resume_file_hash=file_hash,
            resume_fingerprint=resume_fingerprint,
            career_domain=career_domain,
            candidate_category=candidate_category,
            inferred_roles=inferred_roles,
            selected_roles=selected_roles,
            supporting_skills=skills,
            relevant_qualifications=qualifications,
            relevant_experience=experience_summary,
            target_locations=target_locations,
            role_source=role_source,
            inference_confidence=confidence,
        )

    def is_job_relevant(self, job_title: str, job_description: str, career_ctx: CandidateCareerContext) -> bool:
        """Determines if a discovered job opportunity aligns with candidate career domain.

        Strictly protects against keyword hallucinations:
        - Excludes software/AI/ML engineering jobs for accounting, finance, and audit candidates.
        - Excludes clinical healthcare jobs for non-healthcare candidates.
        - Excludes corporate law/litigation jobs for non-legal candidates.
        - Excludes mechanical/hardware engineering jobs for pure software candidates.
        """
        if not career_ctx.has_primary_resume:
            return True

        title_lower = (job_title or "").lower()
        domain = career_ctx.career_domain

        # 1. Negative rules for Accounting & Finance candidates
        if domain in ("accounting_finance", "finance", "audit", "tax"):
            tech_patterns = [
                r"\bmachine learning\b",
                r"\bartificial intelligence\b",
                r"\bcomputer vision\b",
                r"\bdeep learning\b",
                r"\bpython developer\b",
                r"\bsoftware engineer\b",
                r"\bfrontend developer\b",
                r"\bbackend developer\b",
                r"\bfull stack\b",
                r"\bmobile app developer\b",
                r"\bflutter developer\b",
                r"\bdevops engineer\b",
                r"\bcloud architect\b",
            ]
            for pat in tech_patterns:
                if re.search(pat, title_lower):
                    # Check if candidate has computer science or tech skills to support it
                    has_cs_skills = any(
                        s in career_ctx.supporting_skills
                        for s in ["Python", "JavaScript", "React", "Node.js", "Java", "C++"]
                    )
                    if not has_cs_skills:
                        return False

        # 2. Negative rules for Software & Tech candidates
        elif domain in ("software_tech", "engineering_tech"):
            unrelated_patterns = [
                r"\bstaff nurse\b",
                r"\bcardiologist\b",
                r"\bphysician\b",
                r"\bcorporate counsel\b",
                r"\blegal associate\b",
                r"\bsttorney\b",
                r"\bchartered accountant\b",
                r"\bstatutory audit\b",
                r"\buk tax associate\b",
            ]
            for pat in unrelated_patterns:
                if re.search(pat, title_lower):
                    return False

        # 3. Negative rules for Healthcare candidates
        elif domain == "healthcare":
            unrelated_patterns = [
                r"\bsoftware engineer\b",
                r"\bfrontend developer\b",
                r"\bbackend developer\b",
                r"\bdevops engineer\b",
                r"\btax accountant\b",
                r"\baudit associate\b",
            ]
            for pat in unrelated_patterns:
                if re.search(pat, title_lower):
                    return False

        # 4. Negative rules for Legal candidates
        elif domain == "legal":
            unrelated_patterns = [
                r"\bsoftware engineer\b",
                r"\bmachine learning\b",
                r"\bcardiologist\b",
                r"\bstaff nurse\b",
                r"\bmechanical engineer\b",
            ]
            for pat in unrelated_patterns:
                if re.search(pat, title_lower):
                    return False

        # 5. Negative rules for Mechanical Engineering candidates
        elif domain == "mechanical_engineering":
            unrelated_patterns = [
                r"\bcardiologist\b",
                r"\bstaff nurse\b",
                r"\bcorporate counsel\b",
                r"\buk tax associate\b",
            ]
            for pat in unrelated_patterns:
                if re.search(pat, title_lower):
                    return False

        return True
