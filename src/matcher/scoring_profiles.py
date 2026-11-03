"""Scoring Profile Definitions and Profile Recommendation Engine.

Provides situation-specific 100-point weighting profiles for candidates across
different career stages and professional domains. Enforces strict mathematical
invariant that all profile dimension weights sum to exactly 100 points.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class ScoringProfileConfig:
    """Configuration definition for a 100-point scoring profile."""
    profile_id: str
    name: str
    description: str
    version: str = "1.0.0"
    weights: Dict[str, float] = field(default_factory=dict)
    dimension_labels: Dict[str, str] = field(default_factory=dict)
    excluded_dimension_reasons: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        total = sum(self.weights.values())
        if abs(total - 100.0) > 0.001:
            raise ValueError(
                f"ScoringProfile '{self.profile_id}' weights must sum to exactly 100.0 (got {total:.2f})."
            )


# Standard 100-Point Scoring Profiles across Career Stages & Industries
SCORING_PROFILES: Dict[str, ScoringProfileConfig] = {
    "general_baseline": ScoringProfileConfig(
        profile_id="general_baseline",
        name="General Baseline",
        description="Balanced universal profile applicable across general professional roles.",
        weights={
            "skills": 25.0,
            "experience": 25.0,
            "education": 15.0,
            "projects": 10.0,
            "certifications": 10.0,
            "domain_knowledge": 10.0,
            "location_arrangement": 5.0,
        },
        dimension_labels={
            "skills": "Skills and Competencies",
            "experience": "Work Experience and Responsibilities",
            "education": "Education and Qualifications",
            "projects": "Projects and Achievements",
            "certifications": "Certifications and Licenses",
            "domain_knowledge": "Domain Knowledge",
            "location_arrangement": "Location and Work Arrangement",
        },
    ),
    "student_intern": ScoringProfileConfig(
        profile_id="student_intern",
        name="Student / Intern",
        description="Tailored for current students and interns. Emphasizes academic foundations, coursework, and projects rather than full-time employment.",
        weights={
            "skills": 30.0,
            "education": 25.0,
            "projects": 20.0,
            "domain_knowledge": 15.0,
            "location_arrangement": 10.0,
            "experience": 0.0,
            "certifications": 0.0,
        },
        dimension_labels={
            "skills": "Skills and Competencies",
            "education": "Education and Academic Record",
            "projects": "Projects and Practical Coursework",
            "domain_knowledge": "Domain Knowledge",
            "location_arrangement": "Location and Work Arrangement",
            "experience": "Work Experience (Not Applicable)",
            "certifications": "Certifications (Optional/Bonus)",
        },
        excluded_dimension_reasons={
            "experience": "Student/intern roles do not penalize candidates for lack of multi-year full-time employment; points reallocated to projects and academic foundations.",
            "certifications": "Professional certifications are not typically expected for student internships; points reallocated to competencies.",
        },
    ),
    "fresh_graduate": ScoringProfileConfig(
        profile_id="fresh_graduate",
        name="Fresh Graduate",
        description="Optimized for entry-level professionals with 0-1 years of experience, emphasizing degree, skills, and internship exposure.",
        weights={
            "skills": 30.0,
            "education": 25.0,
            "projects": 15.0,
            "experience": 15.0,
            "domain_knowledge": 10.0,
            "location_arrangement": 5.0,
            "certifications": 0.0,
        },
        dimension_labels={
            "skills": "Skills and Competencies",
            "education": "Degree and Academic Performance",
            "projects": "Capstone Projects and Deliverables",
            "experience": "Internships and Early Experience",
            "domain_knowledge": "Domain Knowledge",
            "location_arrangement": "Location and Arrangement",
            "certifications": "Certifications (Optional)",
        },
        excluded_dimension_reasons={
            "certifications": "Entry-level roles prioritize core degree and coursework over industry certifications.",
        },
    ),
    "experienced_professional": ScoringProfileConfig(
        profile_id="experienced_professional",
        name="Experienced Professional",
        description="Standard profile for professionals with 2+ years of verified industry experience.",
        weights={
            "experience": 30.0,
            "skills": 25.0,
            "domain_knowledge": 15.0,
            "education": 10.0,
            "certifications": 10.0,
            "projects": 5.0,
            "location_arrangement": 5.0,
        },
        dimension_labels={
            "experience": "Work Experience and Track Record",
            "skills": "Technical and Professional Skills",
            "domain_knowledge": "Domain Knowledge and Industry Depth",
            "education": "Education and Qualifications",
            "certifications": "Certifications and Licenses",
            "projects": "Key Projects and Deliverables",
            "location_arrangement": "Location and Arrangement",
        },
    ),
    "senior_executive": ScoringProfileConfig(
        profile_id="senior_executive",
        name="Senior / Executive",
        description="Focuses on leadership, organizational impact, domain strategy, and verified executive track record.",
        weights={
            "experience": 35.0,
            "domain_knowledge": 20.0,
            "skills": 20.0,
            "education": 10.0,
            "certifications": 10.0,
            "location_arrangement": 5.0,
            "projects": 0.0,
        },
        dimension_labels={
            "experience": "Executive Experience and Leadership",
            "domain_knowledge": "Strategic and Industry Domain Mastery",
            "skills": "Core Management Competencies",
            "education": "Higher Education and Executive Credentials",
            "certifications": "Professional Affiliations and Licenses",
            "location_arrangement": "Location and Mobility",
            "projects": "Individual Projects (Not Applicable)",
        },
        excluded_dimension_reasons={
            "projects": "Senior executive roles evaluate overall career leadership and P&L responsibility rather than individual task-level projects.",
        },
    ),
    "career_changer": ScoringProfileConfig(
        profile_id="career_changer",
        name="Career Changer",
        description="Balances transferable skills, portfolio projects, and recent domain training over prior linear job titles.",
        weights={
            "skills": 30.0,
            "projects": 20.0,
            "domain_knowledge": 20.0,
            "education": 15.0,
            "certifications": 10.0,
            "location_arrangement": 5.0,
            "experience": 0.0,
        },
        dimension_labels={
            "skills": "Transferable and Core Skills",
            "projects": "Practical Portfolio Projects",
            "domain_knowledge": "Target Domain Knowledge",
            "education": "Foundational Education",
            "certifications": "Domain Certifications and Retraining",
            "location_arrangement": "Location and Arrangement",
            "experience": "Direct Role Experience (Not Applicable)",
        },
        excluded_dimension_reasons={
            "experience": "Career changers are transitioning domains; past job titles are evaluated for transferable skills and projects rather than direct domain tenure.",
        },
    ),
    "freelance_independent": ScoringProfileConfig(
        profile_id="freelance_independent",
        name="Freelance / Independent Contractor",
        description="Focuses on verified client deliverables, case studies, hands-on tool execution, and remote readiness.",
        weights={
            "skills": 35.0,
            "projects": 25.0,
            "experience": 20.0,
            "certifications": 10.0,
            "location_arrangement": 10.0,
            "education": 0.0,
            "domain_knowledge": 0.0,
        },
        dimension_labels={
            "skills": "Practical Execution Skills",
            "projects": "Client Projects and Portfolio",
            "experience": "Client and Contract Experience",
            "certifications": "Technical Certifications and Tools",
            "location_arrangement": "Remote Setup and Availability",
            "education": "Formal Education (Not Applicable)",
            "domain_knowledge": "General Domain (Integrated into Skills)",
        },
        excluded_dimension_reasons={
            "education": "Independent contracting prioritizes portfolio deliverables and skills over formal academic degrees.",
            "domain_knowledge": "Domain understanding is assessed directly via completed client projects.",
        },
    ),
    "healthcare_clinical": ScoringProfileConfig(
        profile_id="healthcare_clinical",
        name="Healthcare & Clinical",
        description="Mandatory statutory licenses, patient care competencies, and clinical bedside experience.",
        weights={
            "certifications": 25.0,
            "experience": 25.0,
            "skills": 25.0,
            "education": 15.0,
            "domain_knowledge": 5.0,
            "location_arrangement": 5.0,
            "projects": 0.0,
        },
        dimension_labels={
            "certifications": "Statutory Licenses and Clinical Credentials",
            "experience": "Clinical and Hospital Experience",
            "skills": "Patient Care and Clinical Competencies",
            "education": "Medical/Nursing Degree and Accreditation",
            "domain_knowledge": "Medical Domain Knowledge",
            "location_arrangement": "Facility Location and Shift Compatibility",
            "projects": "Non-clinical Projects (Not Applicable)",
        },
        excluded_dimension_reasons={
            "projects": "Clinical healthcare prioritizes patient-care hours and statutory licensing over standalone software/academic projects.",
        },
    ),
    "legal_counsel": ScoringProfileConfig(
        profile_id="legal_counsel",
        name="Legal & Counsel",
        description="Strict bar admission compliance, law school credentials (JD/LLM), legal research, and litigation/transactional experience.",
        weights={
            "certifications": 25.0,
            "experience": 25.0,
            "education": 20.0,
            "skills": 20.0,
            "domain_knowledge": 5.0,
            "location_arrangement": 5.0,
            "projects": 0.0,
        },
        dimension_labels={
            "certifications": "Bar Admission and Good Standing",
            "experience": "Legal Practice and Casework Experience",
            "education": "Law School Degree (JD, LLM, LLB)",
            "skills": "Legal Research and Drafting",
            "domain_knowledge": "Jurisdictional and Statutory Knowledge",
            "location_arrangement": "Jurisdiction and Office Location",
            "projects": "Extracurricular Projects (Not Applicable)",
        },
        excluded_dimension_reasons={
            "projects": "Legal practice relies on verified casework, bar standing, and accredited law degrees rather than general projects.",
        },
    ),
    "engineering_technical": ScoringProfileConfig(
        profile_id="engineering_technical",
        name="Engineering & Technical",
        description="Rigorous engineering competencies (FEA, CAD, thermodynamics, mechanics), design projects, and accredited engineering degrees.",
        weights={
            "skills": 30.0,
            "experience": 25.0,
            "education": 20.0,
            "projects": 15.0,
            "domain_knowledge": 5.0,
            "location_arrangement": 5.0,
            "certifications": 0.0,
        },
        dimension_labels={
            "skills": "Technical and Engineering Skills",
            "experience": "Engineering Practice and Field Experience",
            "education": "Accredited Engineering Degree",
            "projects": "Engineering Design and Deliverables",
            "domain_knowledge": "Engineering Domain Knowledge",
            "location_arrangement": "Site Location and Facility Compatibility",
            "certifications": "Certifications (Optional/Integrated)",
        },
        excluded_dimension_reasons={
            "certifications": "Technical engineering primarily evaluates accredited university degrees and demonstrated CAD/FEA projects.",
        },
    ),
}


def get_scoring_profile(profile_id: Optional[str] = None) -> ScoringProfileConfig:
    """Retrieves a scoring profile configuration by ID, falling back to general_baseline."""
    if not profile_id or profile_id not in SCORING_PROFILES:
        return SCORING_PROFILES["general_baseline"]
    return SCORING_PROFILES[profile_id]


def recommend_scoring_profile(
    candidate_level: Optional[str] = None,
    job_industry: Optional[str] = None,
    job_title: Optional[str] = None,
    is_internship: bool = False,
    years_experience: Optional[float] = None,
) -> Tuple[str, str]:
    """Recommends an optimal scoring profile and provides the reasoning for its selection.
    
    Returns:
        (profile_id, recommendation_reason)
    """
    clean_industry = (job_industry or "").lower()
    clean_title = (job_title or "").lower()
    clean_level = (candidate_level or "").lower()

    # 1. Specialized Professional/Regulated Domains
    if any(h in clean_industry or h in clean_title for h in ["healthcare", "nurse", "nursing", "clinical", "hospital", "medical"]):
        return "healthcare_clinical", "Role requires clinical healthcare competencies, statutory licensure, and patient care hours."

    if any(l in clean_industry or l in clean_title for l in ["legal", "law", "attorney", "counsel", "litigation", "paralegal"]):
        return "legal_counsel", "Role requires legal practice, bar admission, and accredited law school credentials."

    if any(e in clean_industry or e in clean_title for e in ["mechanical", "civil", "structural", "aerospace", "electrical engineer"]):
        return "engineering_technical", "Role requires specialized engineering principles, technical calculations, and accredited engineering degrees."

    # 2. Student / Internship Check
    if is_internship or "intern" in clean_title or clean_level in ["student", "intern"]:
        return "student_intern", "Candidate or target role is at internship/student level; prioritizes academic record, coursework, and projects."

    # 3. Career Changer
    if clean_level in ["career_changer", "career changer"]:
        return "career_changer", "Candidate is transitioning career fields; weights transferable skills, recent training, and portfolio projects."

    # 4. Freelancer
    if clean_level in ["freelance", "freelancer", "independent"]:
        return "freelance_independent", "Candidate operates as an independent contractor; weights portfolio case studies and execution."

    # 5. Senior / Executive
    if clean_level in ["senior", "executive", "lead", "director"] or any(s in clean_title for s in ["lead", "principal", "director", "vp", "head of", "executive"]):
        if years_experience is not None and years_experience >= 7.0:
            return "senior_executive", "Senior leadership role; weights verified strategic track record, leadership, and domain impact."

    # 6. Fresh Graduate (0-1 year experience)
    if (years_experience is not None and years_experience <= 1.0) or clean_level in ["entry", "entry_level", "fresh_graduate", "fresher"]:
        return "fresh_graduate", "Early-career position; weights degree, technical foundations, and early internships."

    # 7. Experienced Professional (2+ years)
    if years_experience is not None and years_experience >= 2.0:
        return "experienced_professional", "Standard professional role; weights verified employment track record, skills, and industry depth."

    return "general_baseline", "Standard general-purpose evaluation profile."
