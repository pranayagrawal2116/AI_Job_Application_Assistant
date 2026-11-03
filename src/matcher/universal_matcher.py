"""Universal Resume-to-Job Matching Engine (Phase 5).

Provides explainable, deterministic, cross-industry resume-to-job matching across 100 points
with configurable career-stage scoring profiles, three-state eligibility analysis
(ELIGIBLE, INELIGIBLE, UNKNOWN), zero-hallucination guarantees, and immutable persistence.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    JobDescriptionNotFoundError,
    JobNotFoundError,
    ResumeNotFoundError,
)
from src.database.models import JobDescription, MatchResult, ResumeRecord
from src.matcher.scoring_profiles import (
    ScoringProfileConfig,
    get_scoring_profile,
    recommend_scoring_profile,
)
from src.matcher.terminology import (
    are_skills_strictly_distinct,
    get_degree_level_rank,
    is_statutory_license,
    match_license_names,
    normalize_skill_token,
    RELATED_SKILLS_MAP,
)
from src.preparer.job_parser import StructuredJobDescription
from src.preparer.resume_parser import ParsedResume
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash
from src.utils.logger import setup_logger

logger = setup_logger("UniversalMatcher")


# -----------------------------------------------------------------------------
# DOMAIN MODELS FOR NORMALIZED FACTS & REQUIREMENTS
# -----------------------------------------------------------------------------

@dataclass
class NormalizedSkill:
    name: str
    canonical_name: str
    provenance_field: str = "skills"
    verification_status: str = "EXTRACTED_UNVERIFIED"
    raw_text: str = ""
    is_confirmed: bool = False


@dataclass
class NormalizedEducation:
    institution: str = ""
    degree: str = ""
    major: str = ""
    degree_rank: int = 0
    cgpa: Optional[float] = None
    graduation_year: Optional[int] = None
    verification_status: str = "EXTRACTED_UNVERIFIED"


@dataclass
class NormalizedExperience:
    employer: str = ""
    job_title: str = ""
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    duration_months: Optional[int] = None
    is_internship: bool = False
    is_freelance: bool = False
    responsibilities: List[str] = field(default_factory=list)
    verification_status: str = "EXTRACTED_UNVERIFIED"


@dataclass
class NormalizedProject:
    title: str = ""
    description: str = ""
    technologies: List[str] = field(default_factory=list)


@dataclass
class NormalizedCertification:
    name: str = ""
    issuing_org: Optional[str] = None
    is_license: bool = False
    verification_status: str = "EXTRACTED_UNVERIFIED"


@dataclass
class NormalizedCandidateFacts:
    candidate_name: str = ""
    career_level: str = "entry"
    skills: Dict[str, NormalizedSkill] = field(default_factory=dict)
    education: List[NormalizedEducation] = field(default_factory=list)
    experience: List[NormalizedExperience] = field(default_factory=list)
    total_experience_months: Optional[int] = None
    confirmed_experience_months: Optional[int] = None
    experience_dates_missing: bool = False
    projects: List[NormalizedProject] = field(default_factory=list)
    certifications: List[NormalizedCertification] = field(default_factory=list)
    location: Optional[str] = None
    willing_to_relocate: bool = False
    work_authorization: Optional[str] = None
    raw_text: str = ""


@dataclass
class NormalizedJobRequirements:
    job_title: str = ""
    company_name: str = ""
    industry: str = ""
    mandatory_skills: List[str] = field(default_factory=list)
    preferred_skills: List[str] = field(default_factory=list)
    required_degree_levels: List[str] = field(default_factory=list)
    min_degree_rank: int = 0
    preferred_fields_of_study: List[str] = field(default_factory=list)
    min_gpa: Optional[float] = None
    min_years_experience: Optional[float] = None
    max_years_experience: Optional[float] = None
    mandatory_licenses: List[str] = field(default_factory=list)
    preferred_certifications: List[str] = field(default_factory=list)
    location: Optional[str] = None
    work_arrangement: str = "Unknown"
    is_remote: bool = False
    responsibilities: List[str] = field(default_factory=list)
    snapshot_hash: str = ""
    is_internship: bool = False
    raw_text: str = ""


@dataclass
class SkillAssessment:
    job_skill: str
    matched_candidate_skill: Optional[str] = None
    classification: str = "MISSING"  # EXACT_MATCH, RELATED_MATCH, PARTIAL_MATCH, MISSING, NOT_ASSESSED
    candidate_evidence: str = ""
    explanation: str = ""
    confidence: float = 0.0
    is_mandatory: bool = True


@dataclass
class DimensionBreakdown:
    dimension_key: str
    dimension_label: str
    max_points: float
    earned_points: float
    coverage_confidence: float
    evidence: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class UniversalMatchResult:
    user_id: int
    match_score: float
    match_classification: str
    eligibility_status: str  # ELIGIBLE, INELIGIBLE, UNKNOWN
    scoring_profile: str
    scoring_config_version: str
    assessment_confidence: float
    dimension_breakdown: Dict[str, DimensionBreakdown]
    skills_assessment: List[SkillAssessment]
    education_analysis: Dict[str, Any]
    experience_analysis: Dict[str, Any]
    certification_analysis: Dict[str, Any]
    eligibility_reasons: List[str]
    strong_matches: List[str]
    partial_matches: List[str]
    missing_requirements: List[str]
    eligibility_concerns: List[str]
    recommendations: List[str]
    scoring_explanations: Dict[str, str]
    resume_file_hash: Optional[str] = None
    job_snapshot_hash: Optional[str] = None
    resume_id: Optional[int] = None
    resume_version_num: int = 1
    candidate_profile_version: int = 1
    candidate_profile_hash: Optional[str] = None
    job_description_id: Optional[int] = None
    job_id: Optional[int] = None
    engine_version: str = "2.1.1"
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "match_score": self.match_score,
            "match_classification": self.match_classification,
            "eligibility_status": self.eligibility_status,
            "scoring_profile": self.scoring_profile,
            "scoring_config_version": self.scoring_config_version,
            "assessment_confidence": self.assessment_confidence,
            "dimension_breakdown": {k: asdict(v) for k, v in self.dimension_breakdown.items()},
            "skills_assessment": [asdict(sa) for sa in self.skills_assessment],
            "education_analysis": self.education_analysis,
            "experience_analysis": self.experience_analysis,
            "certification_analysis": self.certification_analysis,
            "eligibility_reasons": self.eligibility_reasons,
            "strong_matches": self.strong_matches,
            "partial_matches": self.partial_matches,
            "missing_requirements": self.missing_requirements,
            "eligibility_concerns": self.eligibility_concerns,
            "recommendations": self.recommendations,
            "scoring_explanations": self.scoring_explanations,
            "resume_file_hash": self.resume_file_hash,
            "job_snapshot_hash": self.job_snapshot_hash,
            "resume_id": self.resume_id,
            "resume_version_num": self.resume_version_num,
            "candidate_profile_version": self.candidate_profile_version,
            "candidate_profile_hash": self.candidate_profile_hash,
            "job_description_id": self.job_description_id,
            "job_id": self.job_id,
            "engine_version": self.engine_version,
            "evaluated_at": self.evaluated_at,
        }


# -----------------------------------------------------------------------------
# COMPONENT 1: CANDIDATE FACT NORMALIZER
# -----------------------------------------------------------------------------

class CandidateFactNormalizer:
    """Normalizes candidate facts from resume documents and verified candidate profiles.
    
    Zero-hallucination guarantee: Missing facts remain None or empty; provenance
    and verification statuses are strictly preserved.
    """

    @classmethod
    def normalize(
        cls,
        resume_data: Optional[Dict[str, Any] | ParsedResume | ResumeRecord | str] = None,
        profile_data: Optional[Dict[str, Any]] = None,
    ) -> NormalizedCandidateFacts:
        facts = NormalizedCandidateFacts()

        # 1. Profile Data Layer (Primary if user-confirmed)
        profile = profile_data or {}
        personal = profile.get("personal", {})
        if personal:
            facts.candidate_name = personal.get("full_name") or ""
            facts.location = personal.get("location") or ""
            facts.career_level = personal.get("career_level") or "entry"

        # 2. Resume Data Layer
        r_dict: Dict[str, Any] = {}
        if isinstance(resume_data, ResumeRecord):
            resume_data = resume_data.parsed_data
        if isinstance(resume_data, str):
            try:
                resume_data = json.loads(resume_data)
            except Exception:
                resume_data = {}
        if isinstance(resume_data, ParsedResume):
            r_dict = resume_data.to_dict()
        elif isinstance(resume_data, dict):
            r_dict = resume_data

        if not facts.candidate_name and r_dict.get("full_name"):
            facts.candidate_name = r_dict["full_name"]
        if not facts.location and r_dict.get("location"):
            facts.location = r_dict["location"]
        if not facts.career_level or facts.career_level == "entry":
            facts.career_level = r_dict.get("career_level") or "entry"

        facts.raw_text = r_dict.get("raw_text") or ""

        # 3. Skills Normalization
        cls._normalize_skills(facts, r_dict, profile)

        # 4. Education Normalization
        cls._normalize_education(facts, r_dict, profile)

        # 5. Experience Normalization & Overlap Handling
        cls._normalize_experience(facts, r_dict, profile)

        # 6. Projects Normalization
        cls._normalize_projects(facts, r_dict, profile)

        # 7. Certifications & Licenses Normalization
        cls._normalize_certifications(facts, r_dict, profile)

        return facts

    @staticmethod
    def _is_confirmed(item: Any, section_key: str, profile: Dict[str, Any], from_profile: bool = False) -> bool:
        """Determines if an item is confirmed by the candidate based on item attributes and profile provenance."""
        if isinstance(item, dict):
            status = item.get("verification_status")
            if status in ("USER_CONFIRMED", "USER_CORRECTED", "CONFIRMED"):
                return True
            if item.get("is_confirmed") is True or item.get("is_verified") is True:
                return True
            if status in ("EXTRACTED_UNVERIFIED", "UNVERIFIED", "PENDING"):
                return False
            if item.get("is_confirmed") is False:
                return False

        # Check section-level field provenance in profile
        field_prov = profile.get("field_provenance")
        if isinstance(field_prov, dict) and field_prov:
            prov = field_prov.get(section_key, {})
            if isinstance(prov, dict):
                p_status = prov.get("verification_status")
                if p_status in ("USER_CONFIRMED", "USER_CORRECTED", "CONFIRMED"):
                    return True
                if prov.get("is_confirmed") is True:
                    return True
                if p_status in ("EXTRACTED_UNVERIFIED", "UNVERIFIED", "PENDING"):
                    return False
            return False

        if profile.get("is_user_confirmed") is True or profile.get("status") == "CONFIRMED":
            return True

        if from_profile:
            return True

        return False

    @classmethod
    def _normalize_skills(cls, facts: NormalizedCandidateFacts, r_dict: Dict[str, Any], profile: Dict[str, Any]) -> None:
        """Consolidates skills with provenance and verification status."""
        profile_skills = profile.get("skills", {})
        is_skills_conf = cls._is_confirmed(profile_skills, "skills", profile, from_profile=True) or cls._is_confirmed(profile_skills, "technical_skills", profile, from_profile=True)
        if isinstance(profile_skills, dict):
            for category, skills_list in profile_skills.items():
                if isinstance(skills_list, list):
                    for s in skills_list:
                        s_str = str(s).strip()
                        if s_str:
                            norm_key = normalize_skill_token(s_str)
                            facts.skills[norm_key] = NormalizedSkill(
                                name=s_str,
                                canonical_name=norm_key,
                                provenance_field=f"profile.skills.{category}",
                                verification_status="USER_CONFIRMED" if is_skills_conf else "EXTRACTED_UNVERIFIED",
                                raw_text=s_str,
                                is_confirmed=is_skills_conf,
                            )
        elif isinstance(profile_skills, list):
            for s in profile_skills:
                s_str = str(s).strip()
                if s_str:
                    norm_key = normalize_skill_token(s_str)
                    facts.skills[norm_key] = NormalizedSkill(
                        name=s_str,
                        canonical_name=norm_key,
                        provenance_field="profile.skills",
                        verification_status="USER_CONFIRMED" if is_skills_conf else "EXTRACTED_UNVERIFIED",
                        raw_text=s_str,
                        is_confirmed=is_skills_conf,
                    )

        # B. Resume skills (extracted, fallback if not already confirmed)
        for cat in ("technical_skills", "professional_skills", "soft_skills", "tools_and_software", "languages"):
            skills_val = r_dict.get(cat, [])
            if isinstance(skills_val, list):
                for s in skills_val:
                    s_str = str(s).strip()
                    if s_str:
                        norm_key = normalize_skill_token(s_str)
                        if norm_key not in facts.skills:
                            facts.skills[norm_key] = NormalizedSkill(
                                name=s_str,
                                canonical_name=norm_key,
                                provenance_field=f"resume.{cat}",
                                verification_status="EXTRACTED_UNVERIFIED",
                                raw_text=s_str,
                                is_confirmed=False,
                            )

    @classmethod
    def _normalize_education(cls, facts: NormalizedCandidateFacts, r_dict: Dict[str, Any], profile: Dict[str, Any]) -> None:
        raw_edu = profile.get("education") or r_dict.get("education") or []
        from_profile = bool(profile.get("education"))
        for edu in raw_edu:
            if isinstance(edu, dict):
                inst = edu.get("institution", "")
                deg = edu.get("degree", "")
                major = edu.get("major", "")
                cgpa_val = None
                raw_cgpa = edu.get("current_cgpa") or edu.get("cgpa") or edu.get("gpa")
                if raw_cgpa is not None:
                    try:
                        cgpa_val = float(str(raw_cgpa).replace("/10", "").replace("/4", "").strip())
                    except ValueError:
                        pass
                grad_year = None
                raw_year = edu.get("expected_graduation_year") or edu.get("graduation_year")
                if raw_year is not None:
                    try:
                        grad_year = int(re.search(r"\d{4}", str(raw_year)).group(0))  # type: ignore[union-attr]
                    except Exception:
                        pass

                rank = get_degree_level_rank(f"{deg} {major}")
                is_conf = cls._is_confirmed(edu, "education", profile, from_profile=from_profile)
                facts.education.append(
                    NormalizedEducation(
                        institution=inst,
                        degree=deg,
                        major=major,
                        degree_rank=rank,
                        cgpa=cgpa_val,
                        graduation_year=grad_year,
                        verification_status="USER_CONFIRMED" if is_conf else "EXTRACTED_UNVERIFIED",
                    )
                )

    @classmethod
    def _normalize_experience(cls, facts: NormalizedCandidateFacts, r_dict: Dict[str, Any], profile: Dict[str, Any]) -> None:
        raw_exp = profile.get("experience") or profile.get("work_experience") or r_dict.get("experience") or r_dict.get("work_experience") or []
        from_profile = bool(profile.get("experience") or profile.get("work_experience"))
        total_months = 0
        confirmed_months = 0
        all_intervals: List[Tuple[datetime, datetime]] = []
        confirmed_intervals: List[Tuple[datetime, datetime]] = []
        has_incomplete_dates = False

        for exp in raw_exp:
            if isinstance(exp, dict):
                emp = exp.get("employer") or exp.get("company", "")
                title = exp.get("job_title") or exp.get("title", "")
                dur_str = exp.get("duration") or exp.get("dates", "")
                dur_months = exp.get("duration_months")
                resp = exp.get("responsibilities", [])
                if isinstance(resp, str):
                    resp = [resp]

                is_intern = "intern" in title.lower() or "intern" in dur_str.lower()
                is_free = "freelance" in title.lower() or "freelance" in emp.lower()
                is_conf = cls._is_confirmed(exp, "work_experience", profile, from_profile=from_profile) or cls._is_confirmed(exp, "experience", profile, from_profile=from_profile)

                # Parse duration months if not explicit
                if dur_months is None and dur_str:
                    m = re.search(r"(\d+)\s*(?:month|mo)", dur_str, re.IGNORECASE)
                    if m:
                        dur_months = int(m.group(1))
                    y = re.search(r"(\d+)\s*(?:year|yr)", dur_str, re.IGNORECASE)
                    if y:
                        dur_months = (dur_months or 0) + int(y.group(1)) * 12

                # Date parsing for interval overlap merging
                start_dt = cls._parse_month_year(exp.get("start_date") or dur_str)
                end_dt = cls._parse_month_year(exp.get("end_date") or dur_str, default_now=True)

                if start_dt and end_dt and start_dt <= end_dt:
                    all_intervals.append((start_dt, end_dt))
                    if is_conf:
                        confirmed_intervals.append((start_dt, end_dt))
                elif dur_months is not None and dur_months > 0:
                    total_months += dur_months
                    if is_conf:
                        confirmed_months += dur_months
                else:
                    has_incomplete_dates = True

                facts.experience.append(
                    NormalizedExperience(
                        employer=emp,
                        job_title=title,
                        start_date=exp.get("start_date"),
                        end_date=exp.get("end_date"),
                        duration_months=dur_months,
                        is_internship=is_intern,
                        is_freelance=is_free,
                        responsibilities=resp,
                        verification_status="USER_CONFIRMED" if is_conf else "EXTRACTED_UNVERIFIED",
                    )
                )

        # Merge overlapping date intervals for all experience
        if all_intervals:
            merged = cls._merge_intervals(all_intervals)
            int_months = sum(
                (int((end.year - start.year) * 12 + (end.month - start.month)) + 1)
                for start, end in merged
            )
            facts.total_experience_months = max(total_months, int_months)
        elif total_months > 0:
            facts.total_experience_months = total_months
        elif not raw_exp:
            facts.total_experience_months = 0
        else:
            facts.total_experience_months = None

        # Merge overlapping date intervals for confirmed experience
        if confirmed_intervals:
            merged_c = cls._merge_intervals(confirmed_intervals)
            c_int_months = sum(
                (int((end.year - start.year) * 12 + (end.month - start.month)) + 1)
                for start, end in merged_c
            )
            facts.confirmed_experience_months = max(confirmed_months, c_int_months)
        elif confirmed_months > 0:
            facts.confirmed_experience_months = confirmed_months
        elif not raw_exp:
            facts.confirmed_experience_months = 0
        else:
            facts.confirmed_experience_months = None

        facts.experience_dates_missing = has_incomplete_dates or (bool(raw_exp) and facts.total_experience_months is None)

    @staticmethod
    def _parse_month_year(s: Optional[str], default_now: bool = False) -> Optional[datetime]:
        if not s:
            return None
        clean = str(s).strip().lower()
        if "present" in clean or "current" in clean:
            return datetime.now(timezone.utc)

        # Match ISO format "YYYY-MM-DD" or "YYYY-MM"
        m_iso = re.search(r"\b(\d{4})[-/](\d{1,2})(?:[-/](\d{1,2}))?\b", clean)
        if m_iso:
            year = int(m_iso.group(1))
            month = int(m_iso.group(2))
            if 1 <= month <= 12:
                return datetime(year, month, 1, tzinfo=timezone.utc)

        # Match "Month Year" (e.g. "Jan 2020")
        m = re.search(r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s*(\d{4})", clean)
        if m:
            month_map = {
                "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
                "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
            }
            month = month_map[m.group(1)[:3]]
            year = int(m.group(2))
            return datetime(year, month, 1, tzinfo=timezone.utc)

        # Match "MM/YYYY" or "MM-YYYY"
        m2 = re.search(r"\b(\d{1,2})[-/](\d{4})\b", clean)
        if m2:
            month = int(m2.group(1))
            year = int(m2.group(2))
            if 1 <= month <= 12:
                return datetime(year, month, 1, tzinfo=timezone.utc)

        # Match standalone year "YYYY"
        m3 = re.search(r"\b(19\d{2}|20\d{2})\b", clean)
        if m3:
            return datetime(int(m3.group(1)), 1 if not default_now else 12, 1, tzinfo=timezone.utc)

        return None

    @staticmethod
    def _merge_intervals(intervals: List[Tuple[datetime, datetime]]) -> List[Tuple[datetime, datetime]]:
        """Merges overlapping date intervals to calculate true non-overlapping experience duration."""
        if not intervals:
            return []
        sorted_intervals = sorted(intervals, key=lambda x: x[0])
        merged = [sorted_intervals[0]]
        for current in sorted_intervals[1:]:
            prev_start, prev_end = merged[-1]
            if current[0] <= prev_end:
                merged[-1] = (prev_start, max(prev_end, current[1]))
            else:
                merged.append(current)
        return merged

    @classmethod
    def _normalize_projects(cls, facts: NormalizedCandidateFacts, r_dict: Dict[str, Any], profile: Dict[str, Any]) -> None:
        raw_proj = profile.get("projects") or r_dict.get("projects") or []
        for p in raw_proj:
            if isinstance(p, dict):
                t = p.get("title") or p.get("name", "")
                d = p.get("description", "")
                tech = p.get("technologies") or p.get("tech_stack", [])
                if isinstance(tech, str):
                    tech = [s.strip() for s in tech.split(",")]
                facts.projects.append(NormalizedProject(title=t, description=d, technologies=tech))

    @classmethod
    def _normalize_certifications(cls, facts: NormalizedCandidateFacts, r_dict: Dict[str, Any], profile: Dict[str, Any]) -> None:
        raw_certs = profile.get("certifications") or r_dict.get("certifications") or []
        from_profile = bool(profile.get("certifications"))
        for c in raw_certs:
            c_name = ""
            org = None
            if isinstance(c, dict):
                c_name = c.get("name") or c.get("title", "")
                org = c.get("issuing_organization") or c.get("issuer")
            elif isinstance(c, str):
                c_name = c

            if c_name:
                is_lic = is_statutory_license(c_name)
                is_conf = cls._is_confirmed(c, "certifications", profile, from_profile=from_profile)
                facts.certifications.append(
                    NormalizedCertification(
                        name=c_name,
                        issuing_org=org,
                        is_license=is_lic,
                        verification_status="USER_CONFIRMED" if is_conf else "EXTRACTED_UNVERIFIED",
                    )
                )


# -----------------------------------------------------------------------------
# COMPONENT 2: JOB REQUIREMENT NORMALIZER
# -----------------------------------------------------------------------------

class JobRequirementNormalizer:
    """Normalizes structured job requirements and validates snapshot hash."""

    @classmethod
    def normalize(
        cls,
        job_data: Dict[str, Any] | StructuredJobDescription | JobDescription | Any,
    ) -> NormalizedJobRequirements:
        reqs = NormalizedJobRequirements()

        j_dict: Dict[str, Any] = {}
        if isinstance(job_data, str):
            try:
                job_data = json.loads(job_data)
            except Exception:
                job_data = {}
        if isinstance(job_data, StructuredJobDescription):
            j_dict = job_data.to_dict()
        elif isinstance(job_data, JobDescription):
            j_dict = job_data.to_dict()
            if isinstance(j_dict.get("parsed_data"), str):
                try:
                    j_dict["parsed_data"] = json.loads(j_dict["parsed_data"])
                except Exception:
                    pass
            if isinstance(j_dict.get("parsed_data"), dict):
                j_dict.update(j_dict["parsed_data"])
        elif isinstance(job_data, dict):
            j_dict = job_data
            if isinstance(j_dict.get("parsed_data"), str):
                try:
                    j_dict["parsed_data"] = json.loads(j_dict["parsed_data"])
                except Exception:
                    pass
            if isinstance(j_dict.get("parsed_data"), dict):
                j_dict.update(j_dict["parsed_data"])
        elif hasattr(job_data, "to_dict"):
            j_dict = job_data.to_dict()

        reqs.job_title = j_dict.get("job_title", "")
        reqs.company_name = j_dict.get("company_name", "")
        reqs.industry = j_dict.get("industry") or j_dict.get("department") or ""
        reqs.location = j_dict.get("location")
        reqs.work_arrangement = j_dict.get("work_arrangement", "Unknown")
        reqs.is_remote = bool(
            reqs.work_arrangement.lower() in ("remote", "work from home")
            or (reqs.location and "remote" in reqs.location.lower())
        )
        reqs.is_internship = bool(
            "intern" in reqs.job_title.lower()
            or j_dict.get("employment_type", "").lower() == "internship"
            or j_dict.get("internship_duration")
        )
        reqs.raw_text = j_dict.get("raw_text") or j_dict.get("job_description") or ""

        # Responsibilities
        raw_resp = j_dict.get("responsibilities", [])
        if isinstance(raw_resp, str):
            raw_resp = [r.strip() for r in raw_resp.split("\n") if r.strip()]
        reqs.responsibilities = raw_resp

        # Mandatory & Preferred Skills
        m_skills = j_dict.get("mandatory_skills") or j_dict.get("required_skills") or []
        if isinstance(m_skills, str):
            m_skills = [s.strip() for s in m_skills.split(",") if s.strip()]
        reqs.mandatory_skills = m_skills

        p_skills = j_dict.get("preferred_skills") or []
        if isinstance(p_skills, str):
            p_skills = [s.strip() for s in p_skills.split(",") if s.strip()]
        reqs.preferred_skills = p_skills

        # Education requirements
        req_degrees = j_dict.get("required_degree_levels", [])
        if isinstance(req_degrees, str):
            req_degrees = [d.strip() for d in req_degrees.split(",") if d.strip()]
        reqs.required_degree_levels = req_degrees
        reqs.min_degree_rank = max(
            [get_degree_level_rank(d) for d in req_degrees] or [0]
        )

        p_majors = j_dict.get("preferred_fields_of_study", [])
        if isinstance(p_majors, str):
            p_majors = [m.strip() for m in p_majors.split(",") if m.strip()]
        reqs.preferred_fields_of_study = p_majors

        # CGPA cutoff
        raw_gpa = j_dict.get("min_gpa_or_percentage")
        if raw_gpa is None:
            raw_gpa = j_dict.get("min_gpa")
        if raw_gpa is None:
            raw_gpa = j_dict.get("min_cgpa")
        if raw_gpa is not None:
            try:
                reqs.min_gpa = float(raw_gpa)
            except ValueError:
                pass

        # Experience requirements
        if j_dict.get("min_years_experience") is not None:
            try:
                reqs.min_years_experience = float(j_dict["min_years_experience"])
            except ValueError:
                pass
        if j_dict.get("max_years_experience") is not None:
            try:
                reqs.max_years_experience = float(j_dict["max_years_experience"])
            except ValueError:
                pass

        # Certifications and Licenses
        raw_lic = j_dict.get("licenses_required") or j_dict.get("mandatory_licenses") or []
        if isinstance(raw_lic, str):
            raw_lic = [l.strip() for l in raw_lic.split(",") if l.strip()]
        reqs.mandatory_licenses = raw_lic

        raw_certs = j_dict.get("certifications_required") or j_dict.get("preferred_certifications") or []
        if isinstance(raw_certs, str):
            raw_certs = [c.strip() for c in raw_certs.split(",") if c.strip()]
        reqs.preferred_certifications = raw_certs

        # Snapshot hash verification / calculation
        snapshot_hash = j_dict.get("snapshot_hash") or j_dict.get("content_hash")
        if not snapshot_hash:
            snapshot_hash = canonical_json_hash({
                "job_title": reqs.job_title,
                "company_name": reqs.company_name,
                "mandatory_skills": reqs.mandatory_skills,
                "responsibilities": reqs.responsibilities,
            })
        reqs.snapshot_hash = snapshot_hash

        return reqs


# -----------------------------------------------------------------------------
# COMPONENT 3: SKILL MATCHING ENGINE
# -----------------------------------------------------------------------------

class UniversalSkillMatcher:
    """Compares required and preferred skills against verified candidate competencies.
    
    Classifies skills as EXACT_MATCH, RELATED_MATCH, PARTIAL_MATCH, MISSING, or NOT_ASSESSED.
    Guarantees that distinct skills (e.g. Java vs JavaScript) never match.
    """

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[List[SkillAssessment], float, float]:
        """Evaluates candidate skills against job requirements.
        
        Returns:
            (assessments_list, score_ratio_0_to_1, confidence_0_to_1)
        """
        assessments: List[SkillAssessment] = []
        all_job_skills: List[Tuple[str, bool]] = []

        for s in reqs.mandatory_skills:
            all_job_skills.append((s, True))
        for s in reqs.preferred_skills:
            all_job_skills.append((s, False))

        if not all_job_skills:
            # If no skills specified in job description, assign neutral 1.0 ratio and baseline confidence
            return [], 1.0, 0.7

        total_weight = 0.0
        earned_weight = 0.0
        total_confidence = 0.0

        for skill_text, is_mandatory in all_job_skills:
            skill_importance = 1.0 if is_mandatory else 0.5
            total_weight += skill_importance

            assessment = cls._match_single_skill(skill_text, is_mandatory, facts)
            assessments.append(assessment)

            # Scoring weight by classification
            cls_weight = 0.0
            if assessment.classification == "EXACT_MATCH":
                cls_weight = 1.0
            elif assessment.classification == "RELATED_MATCH":
                cls_weight = 0.60
            elif assessment.classification == "PARTIAL_MATCH":
                cls_weight = 0.35
            else:
                cls_weight = 0.0

            earned_weight += skill_importance * cls_weight * assessment.confidence
            total_confidence += assessment.confidence

        score_ratio = (earned_weight / total_weight) if total_weight > 0 else 0.0
        avg_confidence = (total_confidence / len(all_job_skills)) if all_job_skills else 1.0

        return assessments, min(1.0, max(0.0, score_ratio)), avg_confidence

    @classmethod
    def _match_single_skill(
        cls,
        job_skill: str,
        is_mandatory: bool,
        facts: NormalizedCandidateFacts,
    ) -> SkillAssessment:
        norm_job = normalize_skill_token(job_skill)
        if not norm_job:
            return SkillAssessment(
                job_skill=job_skill,
                classification="NOT_ASSESSED",
                explanation="Job skill specification was ambiguous or empty.",
                confidence=0.5,
                is_mandatory=is_mandatory,
            )

        # 1. Exact or Synonym Match
        for cand_norm, cand_skill in facts.skills.items():
            if are_skills_strictly_distinct(norm_job, cand_norm):
                continue
            if norm_job == cand_norm:
                conf = 1.0 if cand_skill.is_confirmed else 0.85
                is_synonym = (cand_skill.name.lower().strip() != job_skill.lower().strip())
                synonym_note = " (via recognized terminology synonym)" if is_synonym else ""
                return SkillAssessment(
                    job_skill=job_skill,
                    matched_candidate_skill=cand_skill.name,
                    classification="EXACT_MATCH",
                    candidate_evidence=f"Confirmed in candidate competencies: '{cand_skill.name}' ({cand_skill.verification_status}){synonym_note}",
                    explanation=f"Exact match on requirement '{job_skill}'.",
                    confidence=conf,
                    is_mandatory=is_mandatory,
                )

        # 2. Related Match via Domain Taxonomy
        related_set = RELATED_SKILLS_MAP.get(norm_job, set())
        for cand_norm, cand_skill in facts.skills.items():
            if are_skills_strictly_distinct(norm_job, cand_norm):
                continue
            if cand_norm in related_set or norm_job in RELATED_SKILLS_MAP.get(cand_norm, set()):
                return SkillAssessment(
                    job_skill=job_skill,
                    matched_candidate_skill=cand_skill.name,
                    classification="RELATED_MATCH",
                    candidate_evidence=f"Candidate possesses related skill: '{cand_skill.name}' ({cand_skill.verification_status})",
                    explanation=f"Related skill match: Candidate possesses '{cand_skill.name}', related to '{job_skill}'.",
                    confidence=0.75,
                    is_mandatory=is_mandatory,
                )

        # 3. Partial Match (Token overlap or project/experience context)
        for cand_norm, cand_skill in facts.skills.items():
            if are_skills_strictly_distinct(norm_job, cand_norm):
                continue
            # Substring or token overlap (e.g. "sql" in candidate and "postgresql" in job)
            if (len(norm_job) >= 3 and len(cand_norm) >= 3) and (norm_job in cand_norm or cand_norm in norm_job):
                return SkillAssessment(
                    job_skill=job_skill,
                    matched_candidate_skill=cand_skill.name,
                    classification="PARTIAL_MATCH",
                    candidate_evidence=f"Partial overlap in candidate skill: '{cand_skill.name}'",
                    explanation=f"Partial overlap between '{cand_skill.name}' and job requirement '{job_skill}'.",
                    confidence=0.60,
                    is_mandatory=is_mandatory,
                )

        # Search in project descriptions or experience duties
        for proj in facts.projects:
            if re.search(r"\b" + re.escape(norm_job) + r"\b", proj.description.lower()):
                return SkillAssessment(
                    job_skill=job_skill,
                    matched_candidate_skill=proj.title,
                    classification="PARTIAL_MATCH",
                    candidate_evidence=f"Demonstrated in practical project '{proj.title}'",
                    explanation=f"Applied practical context found in project '{proj.title}'.",
                    confidence=0.55,
                    is_mandatory=is_mandatory,
                )

        return SkillAssessment(
            job_skill=job_skill,
            classification="MISSING",
            explanation=f"No verified candidate evidence found for '{job_skill}'.",
            confidence=1.0,
            is_mandatory=is_mandatory,
        )


# -----------------------------------------------------------------------------
# COMPONENT 4: EDUCATION COMPATIBILITY EVALUATOR
# -----------------------------------------------------------------------------

class EducationCompatibilityEvaluator:
    """Evaluates degree level, field of study, and minimum CGPA criteria."""

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[Dict[str, Any], float, float]:
        """Returns (analysis_dict, score_ratio_0_to_1, confidence_0_to_1)."""
        analysis: Dict[str, Any] = {
            "status": "SATISFIED",
            "highest_candidate_degree": "None",
            "candidate_degree_rank": 0,
            "required_degree_rank": reqs.min_degree_rank,
            "major_match": "NOT_ASSESSED",
            "cgpa_status": "NOT_SPECIFIED",
            "notes": [],
        }

        if reqs.min_degree_rank == 0 and not reqs.preferred_fields_of_study and reqs.min_gpa is None:
            analysis["notes"].append("No specific formal degree, major, or CGPA cutoff required for this role.")
            return analysis, 1.0, 1.0

        if not facts.education:
            analysis["status"] = "NOT_FOUND"
            analysis["notes"].append("Candidate profile contains no documented education records.")
            return analysis, 0.0, 0.5

        # Highest degree rank
        cand_highest_rank = max([e.degree_rank for e in facts.education] or [0])
        best_edu = max(facts.education, key=lambda e: e.degree_rank)
        analysis["highest_candidate_degree"] = f"{best_edu.degree} in {best_edu.major}".strip()
        analysis["candidate_degree_rank"] = cand_highest_rank

        degree_ratio = 1.0
        if reqs.min_degree_rank > 0:
            if cand_highest_rank >= reqs.min_degree_rank:
                analysis["notes"].append(f"Degree level satisfies or exceeds requirement ({best_edu.degree}).")
                degree_ratio = 1.0
            else:
                degree_ratio = max(0.2, cand_highest_rank / reqs.min_degree_rank)
                analysis["status"] = "BELOW_REQUIRED_LEVEL"
                analysis["notes"].append(f"Candidate degree rank ({cand_highest_rank}) is below required level ({reqs.min_degree_rank}).")

        # Major match
        major_ratio = 1.0
        if reqs.preferred_fields_of_study:
            cand_majors = [e.major.lower() for e in facts.education if e.major]
            matched_major = any(
                any(p.lower() in cm or cm in p.lower() for p in reqs.preferred_fields_of_study)
                for cm in cand_majors
            )
            if matched_major:
                analysis["major_match"] = "SATISFIED"
                analysis["notes"].append(f"Field of study aligns with preferred disciplines ({', '.join(cand_majors)}).")
                major_ratio = 1.0
            else:
                analysis["major_match"] = "RELATED_OR_UNMATCHED"
                analysis["notes"].append(f"Candidate major ({', '.join(cand_majors)}) does not directly match preferred fields: {', '.join(reqs.preferred_fields_of_study)}.")
                major_ratio = 0.60

        # CGPA Cutoff
        cgpa_ratio = 1.0
        if reqs.min_gpa is not None:
            cand_cgpa = best_edu.cgpa
            if cand_cgpa is not None:
                if cand_cgpa >= reqs.min_gpa:
                    analysis["cgpa_status"] = "SATISFIED"
                    analysis["notes"].append(f"Candidate CGPA {cand_cgpa} satisfies cutoff of {reqs.min_gpa}.")
                    cgpa_ratio = 1.0
                else:
                    analysis["cgpa_status"] = "BELOW_CUTOFF"
                    analysis["status"] = "BELOW_CUTOFF"
                    analysis["notes"].append(f"Candidate CGPA {cand_cgpa} is below employer cutoff of {reqs.min_gpa}.")
                    cgpa_ratio = max(0.0, cand_cgpa / reqs.min_gpa * 0.7)
            else:
                analysis["cgpa_status"] = "UNKNOWN"
                analysis["notes"].append(f"Employer mandates CGPA cutoff of {reqs.min_gpa}, but candidate CGPA is not documented.")
                cgpa_ratio = 0.50

        total_ratio = (degree_ratio * 0.5) + (major_ratio * 0.3) + (cgpa_ratio * 0.2)
        confidence = 1.0 if best_edu.verification_status == "USER_CONFIRMED" else 0.85

        return analysis, min(1.0, max(0.0, total_ratio)), confidence


# -----------------------------------------------------------------------------
# COMPONENT 5: EXPERIENCE EVALUATOR
# -----------------------------------------------------------------------------

class ExperienceEvaluator:
    """Evaluates total duration, relevant experience, and role alignment without penalizing gaps."""

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
        scoring_profile: ScoringProfileConfig,
    ) -> Tuple[Dict[str, Any], float, float]:
        analysis: Dict[str, Any] = {
            "total_experience_months": facts.total_experience_months,
            "experience_dates_missing": facts.experience_dates_missing,
            "required_years": reqs.min_years_experience,
            "candidate_years": (facts.total_experience_months / 12.0) if facts.total_experience_months is not None else None,
            "is_internship_role": reqs.is_internship,
            "status": "SATISFIED",
            "notes": [],
        }

        # If profile excludes experience (e.g. student/intern or career changer)
        if scoring_profile.weights.get("experience", 0.0) == 0.0:
            analysis["notes"].append(scoring_profile.excluded_dimension_reasons.get("experience", "Experience weight reallocated in selected profile."))
            return analysis, 1.0, 1.0

        req_years = reqs.min_years_experience or 0.0
        if req_years == 0.0:
            analysis["notes"].append("No minimum years of experience required for this role.")
            return analysis, 1.0, 0.95

        if facts.experience_dates_missing:
            analysis["status"] = "UNKNOWN_DURATION"
            analysis["notes"].append("Candidate work experience entries lack verifiable dates; duration cannot be reliably determined.")
            return analysis, 0.40, 0.40

        if facts.total_experience_months is None or facts.total_experience_months == 0:
            analysis["status"] = "ZERO_EXPERIENCE"
            analysis["notes"].append(f"Role requires {req_years} years experience; candidate has no documented employment records.")
            return analysis, 0.0, 0.90

        cand_years = facts.total_experience_months / 12.0
        if cand_years >= req_years:
            analysis["notes"].append(f"Candidate documented experience ({cand_years:.1f} yrs) meets or exceeds requirement ({req_years:.1f} yrs).")
            return analysis, 1.0, 1.0
        else:
            ratio = cand_years / req_years
            analysis["status"] = "BELOW_REQUIREMENT"
            analysis["notes"].append(f"Candidate experience ({cand_years:.1f} yrs) is below requirement ({req_years:.1f} yrs).")
            return analysis, min(1.0, max(0.1, ratio)), 0.90


# -----------------------------------------------------------------------------
# COMPONENT 6: CERTIFICATION & LICENSING EVALUATOR
# -----------------------------------------------------------------------------

class CertificationLicensingEvaluator:
    """Evaluates statutory professional licenses and preferred certifications."""

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[Dict[str, Any], float, float]:
        analysis: Dict[str, Any] = {
            "mandatory_licenses": reqs.mandatory_licenses,
            "preferred_certifications": reqs.preferred_certifications,
            "license_status": "SATISFIED",
            "certifications_matched": [],
            "certifications_missing": [],
            "notes": [],
        }

        if not reqs.mandatory_licenses and not reqs.preferred_certifications:
            analysis["notes"].append("No mandatory licenses or professional certifications required for this role.")
            return analysis, 1.0, 1.0

        # 1. Statutory Licenses
        license_ratio = 1.0
        cand_lics = [c for c in facts.certifications if c.is_license or is_statutory_license(c.name)]
        for mand_lic in reqs.mandatory_licenses:
            matched_cert = next((c for c in cand_lics if match_license_names(mand_lic, c.name)), None)
            if matched_cert:
                if matched_cert.verification_status == "USER_CONFIRMED":
                    analysis["notes"].append(f"Verified statutory license: '{mand_lic}'.")
                else:
                    if analysis["license_status"] == "SATISFIED":
                        analysis["license_status"] = "UNVERIFIED"
                    analysis["notes"].append(
                        f"Mandatory statutory license '{mand_lic}' documented in resume but unverified; requires candidate confirmation."
                    )
                    license_ratio = min(license_ratio, 0.70)
            else:
                analysis["license_status"] = "NOT_DOCUMENTED"
                analysis["notes"].append(f"Mandatory statutory license '{mand_lic}' is not documented in candidate profile.")
                license_ratio = 0.0

        # 2. Preferred Certifications
        cert_ratio = 1.0
        if reqs.preferred_certifications:
            cand_cert_names = [c.name.lower() for c in facts.certifications]
            matched_count = 0
            for pref in reqs.preferred_certifications:
                norm_pref = pref.lower()
                if any(norm_pref in cc or cc in norm_pref for cc in cand_cert_names):
                    analysis["certifications_matched"].append(pref)
                    matched_count += 1
                else:
                    analysis["certifications_missing"].append(pref)

            cert_ratio = matched_count / len(reqs.preferred_certifications)

        combined_ratio = (license_ratio * 0.7) + (cert_ratio * 0.3)
        return analysis, min(1.0, max(0.0, combined_ratio)), 0.90


# -----------------------------------------------------------------------------
# COMPONENT 7: RESPONSIBILITY ALIGNMENT EVALUATOR
# -----------------------------------------------------------------------------

class ResponsibilityAlignmentEvaluator:
    """Analyzes alignment between job responsibilities and candidate past duties/projects."""

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[float, List[str]]:
        if not reqs.responsibilities:
            return 1.0, ["General responsibility alignment accepted (no specific duties enumerated in job description)."]

        candidate_corpus = []
        for exp in facts.experience:
            candidate_corpus.extend(exp.responsibilities)
            candidate_corpus.append(exp.job_title)
        for proj in facts.projects:
            candidate_corpus.append(proj.title)
            candidate_corpus.append(proj.description)

        full_corpus_text = " ".join(candidate_corpus).lower()
        if not full_corpus_text:
            return 0.3, ["Candidate has no documented project or duty descriptions for responsibility alignment."]

        aligned_count = 0
        notes = []
        for resp in reqs.responsibilities:
            # Extract key action terms
            keywords = [w for w in re.findall(r"\b[a-zA-Z]{4,}\b", resp.lower()) if w not in ("with", "from", "that", "this", "will", "have", "team", "work")]
            if not keywords:
                aligned_count += 1
                continue
            matched = sum(1 for kw in keywords if kw in full_corpus_text)
            if matched >= 1:
                aligned_count += 1
                notes.append(f"Demonstrated duty alignment: '{resp[:60]}...'")

        ratio = aligned_count / len(reqs.responsibilities)
        return min(1.0, max(0.2, ratio)), notes


# -----------------------------------------------------------------------------
# COMPONENT 8: LOCATION & WORK-MODE EVALUATOR
# -----------------------------------------------------------------------------

class LocationWorkModeEvaluator:
    """Evaluates location, remote compatibility, and arrangement requirements."""

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[float, float, List[str]]:
        """Returns (score_ratio, confidence, notes)."""
        notes = []
        if reqs.is_remote:
            notes.append(f"Work arrangement is Remote ({reqs.work_arrangement}); location is fully compatible.")
            return 1.0, 1.0, notes

        if not reqs.location:
            notes.append("No specific geographical location mandated in job posting.")
            return 1.0, 0.85, notes

        if not facts.location:
            notes.append("Candidate location is not documented in profile; compatibility cannot be verified.")
            return 0.50, 0.50, notes

        cand_loc = facts.location.lower()
        job_loc = reqs.location.lower()

        # Check city or country overlap
        loc_tokens = [t.strip() for t in job_loc.replace(",", " ").split() if len(t.strip()) > 2]
        if any(t in cand_loc for t in loc_tokens):
            notes.append(f"Location match: Candidate in '{facts.location}', job in '{reqs.location}'.")
            return 1.0, 1.0, notes

        if facts.willing_to_relocate:
            notes.append(f"Candidate location '{facts.location}' differs from '{reqs.location}', but candidate is willing to relocate.")
            return 0.80, 0.90, notes

        notes.append(f"Geographical mismatch: Candidate location '{facts.location}' does not match on-site job location '{reqs.location}'.")
        return 0.30, 0.90, notes


# -----------------------------------------------------------------------------
# COMPONENT 9: THREE-STATE ELIGIBILITY EVALUATOR
# -----------------------------------------------------------------------------

class UniversalEligibilityEvaluator:
    """Strict three-state eligibility engine: ELIGIBLE, INELIGIBLE, or UNKNOWN.
    
    Safety Rules:
    - Never classify UNKNOWN as ELIGIBLE.
    - Never classify missing information as INELIGIBLE unless demonstrably failed.
    - Explicit reasons returned for every decision.
    """

    @classmethod
    def evaluate(
        cls,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
        edu_analysis: Dict[str, Any],
        cert_analysis: Dict[str, Any],
        exp_analysis: Dict[str, Any],
    ) -> Tuple[str, List[str]]:
        """Returns (eligibility_status, reasons_list)."""
        ineligible_reasons = []
        unknown_reasons = []

        # 1. Mandatory Statutory Licenses
        cand_lics = [c for c in facts.certifications if c.is_license or is_statutory_license(c.name)]
        for mand_lic in reqs.mandatory_licenses:
            matched_cert = next((c for c in cand_lics if match_license_names(mand_lic, c.name)), None)
            if not matched_cert:
                unknown_reasons.append(
                    f"Mandatory statutory license '{mand_lic}' is not documented in candidate profile."
                )
            elif matched_cert.verification_status != "USER_CONFIRMED":
                unknown_reasons.append(
                    f"Mandatory statutory license '{mand_lic}' was extracted from resume but has not been confirmed by candidate."
                )

        # 2. Mandatory Degree Level
        best_edu = max(facts.education, key=lambda e: e.degree_rank) if facts.education else None
        if reqs.min_degree_rank > 0:
            if not facts.education or best_edu is None:
                unknown_reasons.append(
                    "Job requires formal degree qualification, but candidate education records are missing."
                )
            else:
                cand_rank = best_edu.degree_rank
                is_conf = (best_edu.verification_status == "USER_CONFIRMED")
                if cand_rank < reqs.min_degree_rank:
                    if is_conf:
                        ineligible_reasons.append(
                            f"Candidate's highest confirmed qualification ({best_edu.degree or 'None'}) is below mandatory required degree level."
                        )
                    else:
                        unknown_reasons.append(
                            f"Candidate extracted qualification ({best_edu.degree or 'None'}) is below required degree level, but remains unverified."
                        )
                else:
                    if not is_conf:
                        unknown_reasons.append(
                            f"Candidate qualification ({best_edu.degree}) satisfies degree requirement, but remains unverified from resume."
                        )

        # 3. Mandatory CGPA Cutoff
        if reqs.min_gpa is not None:
            if not facts.education or best_edu is None or best_edu.cgpa is None:
                unknown_reasons.append(
                    f"Employer specifies mandatory CGPA cutoff of {reqs.min_gpa}, but candidate CGPA is missing."
                )
            else:
                cand_cgpa = best_edu.cgpa
                is_conf = (best_edu.verification_status == "USER_CONFIRMED")
                if cand_cgpa < reqs.min_gpa:
                    if is_conf:
                        ineligible_reasons.append(
                            f"Candidate confirmed CGPA ({cand_cgpa}) is below employer's mandatory minimum cutoff of {reqs.min_gpa}."
                        )
                    else:
                        unknown_reasons.append(
                            f"Candidate extracted CGPA ({cand_cgpa}) is below cutoff of {reqs.min_gpa}, but remains unverified."
                        )
                else:
                    if not is_conf:
                        unknown_reasons.append(
                            f"Candidate extracted CGPA ({cand_cgpa}) satisfies cutoff of {reqs.min_gpa}, but remains unverified from resume."
                        )

        # 4. Mandatory Experience Duration (for non-internship experienced roles)
        if reqs.min_years_experience and reqs.min_years_experience > 0.0 and not reqs.is_internship:
            min_yrs = reqs.min_years_experience
            if facts.experience_dates_missing:
                unknown_reasons.append(
                    f"Job mandates {min_yrs} years experience; candidate dates cannot be verified."
                )
            elif facts.total_experience_months is None:
                unknown_reasons.append(
                    f"Job mandates {min_yrs} years experience, but candidate experience duration cannot be determined."
                )
            else:
                tot_yrs = facts.total_experience_months / 12.0
                conf_yrs = (facts.confirmed_experience_months / 12.0) if facts.confirmed_experience_months is not None else 0.0
                all_unverified = bool(facts.experience and all(e.verification_status != "USER_CONFIRMED" for e in facts.experience))

                if tot_yrs < min_yrs:
                    if not all_unverified:
                        ineligible_reasons.append(
                            f"Documented experience ({tot_yrs:.1f} yrs) is below mandatory minimum requirement of {min_yrs:.1f} yrs."
                        )
                    else:
                        unknown_reasons.append(
                            f"Extracted experience ({tot_yrs:.1f} yrs) is below mandatory requirement of {min_yrs:.1f} yrs, but remains unverified."
                        )
                else:
                    # Meets or exceeds, but check if confirmed
                    if conf_yrs < min_yrs:
                        unknown_reasons.append(
                            f"Experience meets mandatory requirement ({tot_yrs:.1f} yrs >= {min_yrs:.1f} yrs), but unverified experience requires candidate confirmation."
                        )

        # Final Status Decision
        if ineligible_reasons:
            return "INELIGIBLE", ineligible_reasons
        if unknown_reasons:
            return "UNKNOWN", unknown_reasons
        return "ELIGIBLE", ["All assessable mandatory requirements are supported by verified candidate qualifications."]


# -----------------------------------------------------------------------------
# COMPONENT 10: SCORING ENGINE
# -----------------------------------------------------------------------------

class UniversalScoringEngine:
    """Computes transparent points per dimension and total match score out of 100."""

    @classmethod
    def evaluate_projects_relevance(
        cls,
        projects: List[NormalizedProject],
        reqs: NormalizedJobRequirements,
    ) -> Tuple[float, float, str]:
        """Calculates project relevance ratio (0.0 to 1.0), confidence, and explanatory notes.
        
        Evaluates project technologies, titles, descriptions against job skills and domain duties.
        Relevant projects contribute significantly more than unrelated projects.
        """
        if not projects:
            return 0.0, 1.0, "Candidate has no documented practical project deliverables."

        job_skills = set(reqs.mandatory_skills + reqs.preferred_skills)
        job_norm_skills = {normalize_skill_token(s) for s in job_skills if s}

        # Expand skills with domain/related skills
        expanded_related_skills: Set[str] = set()
        for s in job_norm_skills:
            if s in RELATED_SKILLS_MAP:
                expanded_related_skills.update(RELATED_SKILLS_MAP[s])
            for k, vals in RELATED_SKILLS_MAP.items():
                if s in vals:
                    expanded_related_skills.add(k)

        job_duty_words = set()
        token_sources = list(reqs.responsibilities)
        if reqs.job_title:
            token_sources.append(reqs.job_title)
        if reqs.industry:
            token_sources.append(reqs.industry)
        for src in token_sources:
            for w in re.findall(r"\b[a-zA-Z0-9+#.]{2,}\b", src.lower()):
                job_duty_words.add(w)

        stop_words = {"the", "and", "for", "with", "that", "this", "from", "have", "will", "our", "are", "per", "all", "any"}
        job_duty_words -= stop_words

        total_relevance = 0.0
        relevant_project_titles: List[str] = []

        for p in projects:
            p_techs = {normalize_skill_token(t) for t in p.technologies if t}
            p_text = f"{p.title} {p.description}".lower()

            tech_matches = p_techs.intersection(job_norm_skills)
            tech_rel_matches = p_techs.intersection(expanded_related_skills)
            text_skill_matches = sum(1 for s in job_norm_skills if re.search(rf"\b{re.escape(s)}\b", p_text))
            text_rel_matches = sum(1 for s in expanded_related_skills if re.search(rf"\b{re.escape(s)}\b", p_text))

            proj_words = set(re.findall(r"\b[a-zA-Z0-9+#.]{2,}\b", p_text)) - stop_words
            duty_overlap = len(proj_words.intersection(job_duty_words))

            if len(tech_matches) >= 1 or text_skill_matches >= 1:
                p_rel = 1.0
            elif len(tech_rel_matches) >= 1 or text_rel_matches >= 1 or duty_overlap >= 3:
                p_rel = 1.0
            elif duty_overlap >= 2:
                p_rel = 0.65
            elif duty_overlap >= 1:
                p_rel = 0.30
            else:
                p_rel = 0.05

            if p_rel >= 0.5:
                relevant_project_titles.append(p.title or "Untitled Project")

            total_relevance += p_rel

        proj_ratio = min(1.0, max(0.0, total_relevance))

        if relevant_project_titles:
            notes = (
                f"{len(relevant_project_titles)} of {len(projects)} project(s) demonstrated direct skill/duty alignment "
                f"({', '.join(relevant_project_titles[:3])})."
            )
        else:
            notes = (
                f"Candidate has {len(projects)} documented project(s), but none demonstrated relevance "
                f"to the required skills or domain duties."
            )

        return proj_ratio, 0.95, notes

    @classmethod
    def calculate_score(
        cls,
        scoring_profile: ScoringProfileConfig,
        skill_ratio: float,
        skill_conf: float,
        edu_ratio: float,
        edu_conf: float,
        exp_ratio: float,
        exp_conf: float,
        cert_ratio: float,
        cert_conf: float,
        resp_ratio: float,
        loc_ratio: float,
        loc_conf: float,
        facts: NormalizedCandidateFacts,
        reqs: NormalizedJobRequirements,
    ) -> Tuple[float, float, Dict[str, DimensionBreakdown]]:
        breakdown: Dict[str, DimensionBreakdown] = {}
        total_score = 0.0
        weighted_conf_sum = 0.0
        total_profile_weight = sum(scoring_profile.weights.values())

        # 1. Skills
        w_skills = scoring_profile.weights.get("skills", 25.0)
        e_skills = round(w_skills * skill_ratio, 1)
        breakdown["skills"] = DimensionBreakdown(
            dimension_key="skills",
            dimension_label=scoring_profile.dimension_labels.get("skills", "Skills and Competencies"),
            max_points=w_skills,
            earned_points=e_skills,
            coverage_confidence=skill_conf,
            notes=f"Evaluated against mandatory ({len(reqs.mandatory_skills)}) and preferred ({len(reqs.preferred_skills)}) job requirements.",
        )
        total_score += e_skills
        weighted_conf_sum += w_skills * skill_conf

        # 2. Experience
        w_exp = scoring_profile.weights.get("experience", 25.0)
        e_exp = round(w_exp * exp_ratio, 1) if w_exp > 0 else 0.0
        breakdown["experience"] = DimensionBreakdown(
            dimension_key="experience",
            dimension_label=scoring_profile.dimension_labels.get("experience", "Work Experience and Responsibilities"),
            max_points=w_exp,
            earned_points=e_exp,
            coverage_confidence=exp_conf,
            notes=scoring_profile.excluded_dimension_reasons.get("experience", "Calculated from non-overlapping employment tenure and duties."),
        )
        total_score += e_exp
        weighted_conf_sum += w_exp * exp_conf

        # 3. Education
        w_edu = scoring_profile.weights.get("education", 15.0)
        e_edu = round(w_edu * edu_ratio, 1) if w_edu > 0 else 0.0
        breakdown["education"] = DimensionBreakdown(
            dimension_key="education",
            dimension_label=scoring_profile.dimension_labels.get("education", "Education and Qualifications"),
            max_points=w_edu,
            earned_points=e_edu,
            coverage_confidence=edu_conf,
            notes="Assessed degree level rank, major relevance, and GPA cutoffs where specified.",
        )
        total_score += e_edu
        weighted_conf_sum += w_edu * edu_conf

        # 4. Projects & Achievements
        w_proj = scoring_profile.weights.get("projects", 10.0)
        proj_ratio, proj_conf, proj_notes = cls.evaluate_projects_relevance(facts.projects, reqs)
        e_proj = round(w_proj * proj_ratio, 1) if w_proj > 0 else 0.0
        breakdown["projects"] = DimensionBreakdown(
            dimension_key="projects",
            dimension_label=scoring_profile.dimension_labels.get("projects", "Projects and Achievements"),
            max_points=w_proj,
            earned_points=e_proj,
            coverage_confidence=proj_conf,
            notes=proj_notes,
        )
        total_score += e_proj
        weighted_conf_sum += w_proj * proj_conf

        # 5. Certifications & Licenses
        w_cert = scoring_profile.weights.get("certifications", 10.0)
        e_cert = round(w_cert * cert_ratio, 1) if w_cert > 0 else 0.0
        breakdown["certifications"] = DimensionBreakdown(
            dimension_key="certifications",
            dimension_label=scoring_profile.dimension_labels.get("certifications", "Certifications and Licenses"),
            max_points=w_cert,
            earned_points=e_cert,
            coverage_confidence=cert_conf,
            notes=scoring_profile.excluded_dimension_reasons.get("certifications", "Evaluated against statutory licenses and preferred credentials."),
        )
        total_score += e_cert
        weighted_conf_sum += w_cert * cert_conf

        # 6. Domain Knowledge
        w_dom = scoring_profile.weights.get("domain_knowledge", 10.0)
        e_dom = round(w_dom * resp_ratio, 1) if w_dom > 0 else 0.0
        breakdown["domain_knowledge"] = DimensionBreakdown(
            dimension_key="domain_knowledge",
            dimension_label=scoring_profile.dimension_labels.get("domain_knowledge", "Domain Knowledge"),
            max_points=w_dom,
            earned_points=e_dom,
            coverage_confidence=0.85,
            notes="Derived from responsibility keyword alignment and industry domain terminology.",
        )
        total_score += e_dom
        weighted_conf_sum += w_dom * 0.85

        # 7. Location & Work Arrangement
        w_loc = scoring_profile.weights.get("location_arrangement", 5.0)
        e_loc = round(w_loc * loc_ratio, 1) if w_loc > 0 else 0.0
        breakdown["location_arrangement"] = DimensionBreakdown(
            dimension_key="location_arrangement",
            dimension_label=scoring_profile.dimension_labels.get("location_arrangement", "Location and Work Arrangement"),
            max_points=w_loc,
            earned_points=e_loc,
            coverage_confidence=loc_conf,
            notes="Evaluated remote arrangement, on-site location compatibility, and relocation willingness.",
        )
        total_score += e_loc
        weighted_conf_sum += w_loc * loc_conf

        overall_conf = (weighted_conf_sum / total_profile_weight) if total_profile_weight > 0 else 1.0
        overall_score = min(100.0, max(0.0, round(total_score, 1)))

        return overall_score, round(overall_conf, 2), breakdown


# -----------------------------------------------------------------------------
# COMPONENT 11: EXPLANATION GENERATOR
# -----------------------------------------------------------------------------

class UniversalExplanationGenerator:
    """Generates structured, explainable match feedback and constructive candidate recommendations."""

    @classmethod
    def generate(
        cls,
        assessments: List[SkillAssessment],
        eligibility_status: str,
        eligibility_reasons: List[str],
        edu_analysis: Dict[str, Any],
        exp_analysis: Dict[str, Any],
        cert_analysis: Dict[str, Any],
        breakdown: Dict[str, DimensionBreakdown],
    ) -> Tuple[List[str], List[str], List[str], List[str], List[str], Dict[str, str]]:
        strong: List[str] = []
        partial: List[str] = []
        missing: List[str] = []
        concerns: List[str] = []
        recs: List[str] = []
        explanations: Dict[str, str] = {}

        # 1. Skills
        for sa in assessments:
            if sa.classification == "EXACT_MATCH":
                strong.append(f"Skill: {sa.job_skill} ({sa.candidate_evidence})")
            elif sa.classification in ("RELATED_MATCH", "PARTIAL_MATCH"):
                partial.append(f"Skill: {sa.job_skill} -> {sa.explanation}")
            elif sa.classification == "MISSING":
                missing.append(f"Required/Preferred Skill: {sa.job_skill}")

        # 2. Education
        if edu_analysis.get("status") == "SATISFIED":
            strong.append(f"Education: Satisfies requirement ({edu_analysis.get('highest_candidate_degree', 'Degree')})")
        elif edu_analysis.get("status") == "BELOW_REQUIRED_LEVEL":
            concerns.append("Education: Candidate degree rank is below the specified degree requirement.")
        elif edu_analysis.get("status") == "BELOW_CUTOFF":
            concerns.append("Education: Candidate CGPA is below the employer's minimum cutoff.")

        # 3. Certifications
        if cert_analysis.get("license_status") == "NOT_DOCUMENTED":
            for lic in cert_analysis.get("mandatory_licenses", []):
                concerns.append(f"License: Mandatory license '{lic}' is not documented in candidate profile.")

        # 4. Eligibility Concerns
        if eligibility_status != "ELIGIBLE":
            concerns.extend(eligibility_reasons)

        # 5. Ethical Recommendations
        if missing:
            recs.append(f"Consider acquiring or demonstrating foundational competence in missing skills: {', '.join([m.replace('Required/Preferred Skill: ', '') for m in missing[:4]])}.")
        if exp_analysis.get("experience_dates_missing"):
            recs.append("Add verified start and end dates to your work experience entries to enable accurate tenure calculation.")
        if edu_analysis.get("cgpa_status") == "UNKNOWN":
            recs.append("Add your verified CGPA or percentage in your candidate profile to satisfy employer academic cutoff checks.")
        if not strong:
            recs.append("Review whether your primary resume highlights the key qualifications and competencies relevant to this role.")

        for k, db in breakdown.items():
            explanations[k] = f"{db.dimension_label}: Earned {db.earned_points:.1f}/{db.max_points:.1f} pts. {db.notes}"

        return strong, partial, missing, concerns, recs, explanations


# -----------------------------------------------------------------------------
# COMPONENT 12: PERSISTENCE SERVICE
# -----------------------------------------------------------------------------

class MatchResultPersistenceService:
    """Persists immutable match results to SQLite with RFC 8785 canonical hashes and composite checks."""

    @classmethod
    def persist(
        cls,
        result: UniversalMatchResult,
        db_manager: Optional[DatabaseManager] = None,
    ) -> int:
        db = db_manager or DatabaseManager()

        # Classify match score
        if result.match_score >= 85.0:
            classification = "Excellent Match"
        elif result.match_score >= 70.0:
            classification = "Good Match"
        elif result.match_score >= 50.0:
            classification = "Moderate Match"
        else:
            classification = "Low Match"

        # Canonical RFC 8785 JSON representation of evaluation details
        canonical_details = result.to_dict()
        details_json_str = canonical_json_bytes(canonical_details).decode("utf-8")

        summary_explanation = f"Match Score: {result.match_score:.1f}/100 ({classification}) | Eligibility: {result.eligibility_status} | Profile: {result.scoring_profile}"

        db_model = MatchResult(
            user_id=result.user_id,
            resume_id=result.resume_id,
            job_id=result.job_id,
            job_description_id=result.job_description_id,
            match_score=result.match_score,
            match_classification=classification,
            eligibility_status=result.eligibility_status,
            score_breakdown=json.dumps({k: asdict(v) for k, v in result.dimension_breakdown.items()}),
            explanation=summary_explanation,
            resume_version_num=result.resume_version_num,
            resume_file_hash=result.resume_file_hash,
            candidate_profile_version=result.candidate_profile_version,
            candidate_profile_hash=result.candidate_profile_hash,
            job_snapshot_hash=result.job_snapshot_hash,
            scoring_profile=result.scoring_profile,
            scoring_config_version=result.scoring_config_version,
            assessment_confidence=result.assessment_confidence,
            engine_version=result.engine_version,
            matching_skills=json.dumps([asdict(sa) for sa in result.skills_assessment if sa.classification == "EXACT_MATCH"]),
            related_skills=json.dumps([asdict(sa) for sa in result.skills_assessment if sa.classification == "RELATED_MATCH"]),
            partial_matches=json.dumps([asdict(sa) for sa in result.skills_assessment if sa.classification == "PARTIAL_MATCH"]),
            missing_skills=json.dumps([asdict(sa) for sa in result.skills_assessment if sa.classification == "MISSING"]),
            education_analysis=json.dumps(result.education_analysis),
            experience_analysis=json.dumps(result.experience_analysis),
            certification_analysis=json.dumps(result.certification_analysis),
            eligibility_reasons=json.dumps(result.eligibility_reasons),
            scoring_explanations=json.dumps(result.scoring_explanations),
            recommendations=json.dumps(result.recommendations),
            details_json=details_json_str,
            evaluated_at=result.evaluated_at,
        )

        return db.save_match_result(db_model)


# -----------------------------------------------------------------------------
# MAIN ORCHESTRATOR: UNIVERSAL MATCHER
# -----------------------------------------------------------------------------

class UniversalMatcher:
    """Universal Explainable Resume-to-Job Matching Engine."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def evaluate(
        self,
        user_id: int,
        resume_data: Optional[Dict[str, Any] | ParsedResume | ResumeRecord] = None,
        job_data: Optional[Dict[str, Any] | StructuredJobDescription | JobDescription | Any] = None,
        profile_data: Optional[Dict[str, Any]] = None,
        scoring_profile_id: Optional[str] = None,
        persist: bool = True,
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
        candidate_profile_version: Optional[int] = None,
        candidate_profile_hash: Optional[str] = None,
        job_description_id: Optional[int] = None,
        job_id: Optional[int] = None,
    ) -> UniversalMatchResult:
        """Runs universal match evaluation between a candidate profile/resume and a job opportunity.
        
        Enforces composite user-ownership checks, calculates transparent dimension breakdowns,
        three-state eligibility, zero-hallucination guarantees, and optional immutable persistence.
        """
        # 1. Composite Ownership Validation if IDs supplied
        resume_file_hash = None
        if resume_id is not None:
            res_rec = self.db.get_user_resume(resume_id, user_id=user_id)
            if not res_rec:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            resume_file_hash = res_rec.get("file_hash")
            if resume_version_num is None:
                resume_version_num = res_rec.get("active_version", 1)
            if resume_data is None:
                resume_data = res_rec.get("parsed_data")
        elif resume_version_num is None:
            resume_version_num = 1

        # Resolve candidate profile from database if not explicitly provided
        if profile_data is None:
            prof_rec = self.db.get_user_candidate_profile(user_id)
            if prof_rec:
                profile_data = prof_rec.get("profile_data")
                if candidate_profile_version is None:
                    candidate_profile_version = prof_rec.get("version", 1)
                if candidate_profile_hash is None:
                    candidate_profile_hash = prof_rec.get("profile_hash")
        elif candidate_profile_hash is None and profile_data:
            candidate_profile_hash = canonical_json_hash(profile_data)

        if candidate_profile_version is None:
            candidate_profile_version = 1

        job_snapshot_hash = None
        if job_description_id is not None:
            jd_rec = self.db.get_job_description(user_id=user_id, jd_id=job_description_id)
            if not jd_rec:
                raise JobDescriptionNotFoundError(f"Job Description #{job_description_id} not found.")
            job_snapshot_hash = jd_rec.snapshot_hash or jd_rec.content_hash
            if job_data is None:
                job_data = jd_rec.to_dict()

        if job_id is not None and job_data is None:
            job_obj = self.db.get_job_by_id(job_id)
            if not job_obj:
                raise JobNotFoundError(job_id)
            job_data = job_obj.to_dict()

        # 2. Normalize Candidate Facts and Job Requirements
        facts = CandidateFactNormalizer.normalize(resume_data=resume_data, profile_data=profile_data)
        reqs = JobRequirementNormalizer.normalize(job_data=job_data)

        if not job_snapshot_hash:
            job_snapshot_hash = reqs.snapshot_hash
        if not resume_file_hash and facts.raw_text:
            resume_file_hash = hashlib.sha256(facts.raw_text.encode("utf-8")).hexdigest()

        # 3. Determine Scoring Profile
        if not scoring_profile_id:
            scoring_profile_id, rec_reason = recommend_scoring_profile(
                candidate_level=facts.career_level,
                job_industry=reqs.industry,
                job_title=reqs.job_title,
                is_internship=reqs.is_internship,
                years_experience=(facts.total_experience_months / 12.0) if facts.total_experience_months is not None else None,
            )
        profile_config = get_scoring_profile(scoring_profile_id)

        # 4. Dimension Evaluations
        skill_assessments, skill_ratio, skill_conf = UniversalSkillMatcher.evaluate(facts, reqs)
        edu_analysis, edu_ratio, edu_conf = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        exp_analysis, exp_ratio, exp_conf = ExperienceEvaluator.evaluate(facts, reqs, profile_config)
        cert_analysis, cert_ratio, cert_conf = CertificationLicensingEvaluator.evaluate(facts, reqs)
        resp_ratio, resp_notes = ResponsibilityAlignmentEvaluator.evaluate(facts, reqs)
        loc_ratio, loc_conf, loc_notes = LocationWorkModeEvaluator.evaluate(facts, reqs)

        # 5. Three-State Eligibility Analysis
        eligibility_status, eligibility_reasons = UniversalEligibilityEvaluator.evaluate(
            facts, reqs, edu_analysis, cert_analysis, exp_analysis
        )

        # 6. 100-Point Scoring Calculation
        overall_score, overall_conf, dimension_breakdown = UniversalScoringEngine.calculate_score(
            scoring_profile=profile_config,
            skill_ratio=skill_ratio,
            skill_conf=skill_conf,
            edu_ratio=edu_ratio,
            edu_conf=edu_conf,
            exp_ratio=exp_ratio,
            exp_conf=exp_conf,
            cert_ratio=cert_ratio,
            cert_conf=cert_conf,
            resp_ratio=resp_ratio,
            loc_ratio=loc_ratio,
            loc_conf=loc_conf,
            facts=facts,
            reqs=reqs,
        )

        # 7. Generate Explanations & Recommendations
        strong, partial, missing, concerns, recs, explanations = UniversalExplanationGenerator.generate(
            assessments=skill_assessments,
            eligibility_status=eligibility_status,
            eligibility_reasons=eligibility_reasons,
            edu_analysis=edu_analysis,
            exp_analysis=exp_analysis,
            cert_analysis=cert_analysis,
            breakdown=dimension_breakdown,
        )

        # Classification label
        if overall_score >= 85.0:
            match_classification = "Excellent Match"
        elif overall_score >= 70.0:
            match_classification = "Good Match"
        elif overall_score >= 50.0:
            match_classification = "Moderate Match"
        else:
            match_classification = "Low Match"

        result = UniversalMatchResult(
            user_id=user_id,
            match_score=overall_score,
            match_classification=match_classification,
            eligibility_status=eligibility_status,
            scoring_profile=profile_config.profile_id,
            scoring_config_version=profile_config.version,
            assessment_confidence=overall_conf,
            dimension_breakdown=dimension_breakdown,
            skills_assessment=skill_assessments,
            education_analysis=edu_analysis,
            experience_analysis=exp_analysis,
            certification_analysis=cert_analysis,
            eligibility_reasons=eligibility_reasons,
            strong_matches=strong,
            partial_matches=partial,
            missing_requirements=missing,
            eligibility_concerns=concerns,
            recommendations=recs,
            scoring_explanations=explanations,
            resume_file_hash=resume_file_hash,
            job_snapshot_hash=job_snapshot_hash,
            resume_id=resume_id,
            resume_version_num=resume_version_num or 1,
            candidate_profile_version=candidate_profile_version or 1,
            candidate_profile_hash=candidate_profile_hash,
            job_description_id=job_description_id,
            job_id=job_id,
        )

        # 8. Persistence if requested
        if persist:
            match_id = MatchResultPersistenceService.persist(result, db_manager=self.db)
            logger.info("Persisted UniversalMatchResult #%d for User #%d", match_id, user_id)

        return result
