"""Dynamic Career Role Inference Engine.

Infers suitable job categories and search roles from actual candidate resume evidence
(experience, degrees, majors, skills, projects, headline) without hardcoded AI/ML universal defaults.
"""

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional


@dataclass
class InferredRole:
    """A suggested career search role backed by empirical resume evidence."""
    role_title: str
    evidence_sources: List[str] = field(default_factory=list)
    supporting_skills: List[str] = field(default_factory=list)
    confidence: float = 0.5  # 0.0 to 1.0
    is_candidate_selected: bool = True
    is_custom: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CareerRoleInferencer:
    """Analyzes candidate resume evidence to infer personalized, multi-domain job search roles."""

    # Domain skill clusters for fine-grained role identification
    DOMAIN_TAXONOMY: Dict[str, Dict[str, Any]] = {
        # Tech: Software & Web
        "Python Developer": {
            "keywords": ["python", "django", "flask", "fastapi", "pytest"],
            "category": "Software Engineering",
            "min_matches": 2,
        },
        "Full Stack Developer": {
            "keywords": ["react", "node.js", "javascript", "typescript", "full stack", "mongodb", "postgresql"],
            "category": "Software Engineering",
            "min_matches": 3,
        },
        "Frontend Developer": {
            "keywords": ["react", "vue", "angular", "html", "css", "tailwind", "javascript", "typescript", "frontend"],
            "category": "Software Engineering",
            "min_matches": 2,
        },
        "Backend Developer": {
            "keywords": ["fastapi", "django", "node.js", "express", "spring", "golang", "backend", "rest api", "microservices"],
            "category": "Software Engineering",
            "min_matches": 2,
        },
        "Mobile App Developer": {
            "keywords": ["flutter", "dart", "react native", "android", "ios", "swift", "kotlin", "mobile app"],
            "category": "Mobile Development",
            "min_matches": 2,
        },
        "Flutter Developer": {
            "keywords": ["flutter", "dart"],
            "category": "Mobile Development",
            "min_matches": 2,
        },
        # Tech: AI, Data & ML
        "Machine Learning Engineer": {
            "keywords": ["machine learning", "scikit-learn", "tensorflow", "pytorch", "model training", "predictive modeling"],
            "category": "Data & AI",
            "min_matches": 2,
        },
        "Data Scientist": {
            "keywords": ["data science", "pandas", "numpy", "matplotlib", "seaborn", "statistics", "eda", "r"],
            "category": "Data & AI",
            "min_matches": 2,
        },
        "Data Analyst": {
            "keywords": ["data analysis", "sql", "excel", "tableau", "power bi", "dashboard", "reporting", "data analyst"],
            "category": "Data & Analytics",
            "min_matches": 2,
        },
        "AI Engineer": {
            "keywords": ["artificial intelligence", "deep learning", "nlp", "computer vision", "llm", "genai", "generative ai"],
            "category": "Data & AI",
            "min_matches": 2,
        },
        # Tech: Cloud & DevOps
        "Cloud / DevOps Engineer": {
            "keywords": ["docker", "kubernetes", "aws", "azure", "gcp", "ci/cd", "terraform", "linux"],
            "category": "Infrastructure",
            "min_matches": 2,
        },
        # Business, Finance & Accounting
        "UK Tax Associate": {
            "keywords": ["uk tax", "uk taxation", "sa100", "making tax digital", "tax computations", "tax compliance", "digita"],
            "category": "Taxation",
            "min_matches": 1,
        },
        "Tax Compliance Associate": {
            "keywords": ["tax compliance", "tax computations", "taxation", "sa100", "direct tax", "indirect tax"],
            "category": "Taxation",
            "min_matches": 1,
        },
        "Accounts Associate": {
            "keywords": ["accounts payable", "reconciliation", "supplier payment", "working capital", "xero", "approvalmax", "general ledger"],
            "category": "Accounting",
            "min_matches": 2,
        },
        "Accounts Payable Associate": {
            "keywords": ["accounts payable", "supplier payment", "vendor reconciliation", "invoice processing", "approvalmax"],
            "category": "Accounting",
            "min_matches": 1,
        },
        "Audit Associate": {
            "keywords": ["audit", "internal audit", "stock audit", "receivables audit", "internal controls", "statutory audit"],
            "category": "Audit",
            "min_matches": 1,
        },
        "Internal Audit Associate": {
            "keywords": ["internal audit", "internal controls", "receivables audit", "risk assessment", "compliance audit"],
            "category": "Audit",
            "min_matches": 1,
        },
        "Financial Reporting Associate": {
            "keywords": ["financial reporting", "working capital analysis", "financial statements", "management reporting", "balance sheet"],
            "category": "Finance",
            "min_matches": 1,
        },
        "Financial Analyst": {
            "keywords": ["financial analysis", "financial modeling", "accounting", "valuation", "balance sheet", "excel", "cfa"],
            "category": "Finance",
            "min_matches": 2,
        },
        "Accountant": {
            "keywords": ["accounting", "tally", "taxation", "auditing", "gaap", "gst", "general ledger", "accounts payable"],
            "category": "Accounting",
            "min_matches": 2,
        },
        "Business Analyst": {
            "keywords": ["business analysis", "requirements gathering", "agile", "scrum", "uml", "user stories", "stakeholder"],
            "category": "Business",
            "min_matches": 2,
        },
        # Tech: Healthcare & Specialized Software
        "Healthcare Software Developer": {
            "keywords": ["abdm", "medical chatbot", "healthcare", "patient registration", "clinical software"],
            "category": "Software Engineering",
            "min_matches": 1,
        },
        # Design
        "UI/UX Designer": {
            "keywords": ["figma", "ui/ux", "wireframing", "prototyping", "user research", "user interface", "design system"],
            "category": "Design",
            "min_matches": 2,
        },
        # Engineering (Non-Software)
        "Mechanical Engineer": {
            "keywords": ["solidworks", "autocad", "catia", "thermodynamics", "ansys", "finite element", "mechanical design"],
            "category": "Mechanical Engineering",
            "min_matches": 2,
        },
        "Electrical Engineer": {
            "keywords": ["circuit design", "matlab", "simulink", "pcb", "embedded systems", "microcontroller", "vlsi"],
            "category": "Electrical Engineering",
            "min_matches": 2,
        },
        # Healthcare
        "Clinical Healthcare Specialist": {
            "keywords": ["patient care", "nursing", "clinical assessment", "pharmacology", "triage", "healthcare", "medical"],
            "category": "Healthcare",
            "min_matches": 2,
        },
        # Legal
        "Legal Associate": {
            "keywords": ["contract drafting", "legal research", "litigation", "compliance", "regulatory", "due diligence"],
            "category": "Legal",
            "min_matches": 2,
        },
    }

    # Degree to role mapping
    DEGREE_MAJOR_MAPPING: Dict[str, List[str]] = {
        "computer science": ["Software Engineer", "Software Developer"],
        "artificial intelligence": ["AI Engineer", "Machine Learning Engineer"],
        "data science": ["Data Scientist", "Data Analyst"],
        "information technology": ["Software Engineer", "IT Specialist"],
        "computer engineering": ["Software Engineer", "Systems Engineer"],
        "mechanical": ["Mechanical Engineer", "CAD Designer"],
        "electrical": ["Electrical Engineer", "Embedded Systems Engineer"],
        "electronics": ["Electronics Engineer", "Embedded Systems Engineer"],
        "civil": ["Civil Engineer", "Structural Designer"],
        "commerce": ["Accountant", "Financial Analyst"],
        "finance": ["Financial Analyst", "Investment Associate"],
        "accounting": ["Accountant", "Audit Associate"],
        "business administration": ["Business Analyst", "Operations Associate", "Project Coordinator"],
        "management": ["Business Analyst", "Operations Associate"],
        "marketing": ["Marketing Specialist", "Digital Marketing Associate"],
        "nursing": ["Staff Nurse", "Clinical Specialist"],
        "law": ["Legal Associate", "Corporate Counsel", "Legal Analyst"],
        "design": ["UI/UX Designer", "Product Designer"],
    }

    def infer_roles(self, data: Any) -> List[InferredRole]:
        """Infers candidate-specific career roles based on factual resume signals."""
        resume_dict = self._normalize_input(data)
        inferred: Dict[str, InferredRole] = {}

        # Check if student/fresher indicator
        is_student_or_fresher = self._is_student_or_fresher(resume_dict)

        # 1. Evidence from Previous / Current Job Titles
        for exp in resume_dict.get("work_experience", []):
            title = exp.get("job_title", "").strip()
            employer = exp.get("employer", "").strip()
            if title and len(title) > 2:
                clean_title = self._clean_role_title(title)
                evidence = f"Previous experience as {title}" + (f" at {employer}" if employer else "")
                self._add_or_update_role(
                    inferred,
                    role_title=clean_title,
                    evidence=evidence,
                    confidence=0.95,
                    skills=exp.get("technologies", []),
                )
                if is_student_or_fresher and "intern" not in clean_title.lower():
                    self._add_or_update_role(
                        inferred,
                        role_title=f"{clean_title} Intern",
                        evidence=evidence,
                        confidence=0.90,
                        skills=exp.get("technologies", []),
                    )

        # 2. Evidence from Education & Specialization
        for edu in resume_dict.get("education", []):
            degree = str(edu.get("degree", "")).lower()
            major = str(edu.get("major", "") or edu.get("field_of_study", "")).lower()
            inst = edu.get("institution", "")
            combo = f"{degree} {major}"

            for key, roles in self.DEGREE_MAJOR_MAPPING.items():
                if key in combo:
                    for r in roles:
                        evidence = f"Degree in {edu.get('degree', '') or major}" + (f" from {inst}" if inst else "")
                        conf = 0.85
                        self._add_or_update_role(inferred, r, evidence, conf)
                        if is_student_or_fresher and "intern" not in r.lower():
                            self._add_or_update_role(inferred, f"{r} Intern", evidence, conf)

        # 2b. Evidence from Certifications & Professional Qualifications
        certs = resume_dict.get("certifications", []) + resume_dict.get("professional_qualifications", [])
        for cert in certs:
            c_name = str(cert.get("name", "")).lower() if isinstance(cert, dict) else str(cert).lower()
            if "acca" in c_name or "chartered" in c_name:
                self._add_or_update_role(inferred, "UK Tax Associate", "ACCA qualification / membership", 0.95)
                self._add_or_update_role(inferred, "Tax Compliance Associate", "ACCA qualification / membership", 0.95)
                self._add_or_update_role(inferred, "Accounts Associate", "ACCA qualification / membership", 0.95)
                self._add_or_update_role(inferred, "Accounts Payable Associate", "ACCA qualification / membership", 0.90)
                self._add_or_update_role(inferred, "Audit Associate", "ACCA qualification / membership", 0.95)
                self._add_or_update_role(inferred, "Internal Audit Associate", "ACCA qualification / membership", 0.90)
                self._add_or_update_role(inferred, "Financial Reporting Associate", "ACCA qualification / membership", 0.90)
            elif "cpa" in c_name:
                self._add_or_update_role(inferred, "Certified Public Accountant", "CPA credential", 0.95)
                self._add_or_update_role(inferred, "Audit Associate", "CPA credential", 0.90)
            elif "cfa" in c_name:
                self._add_or_update_role(inferred, "Financial Analyst", "CFA credential", 0.95)
                self._add_or_update_role(inferred, "Investment Associate", "CFA credential", 0.90)

        # 2c. Evidence from Supervised Experience (ACCA PER)
        for per in resume_dict.get("per_experience", []):
            p_title = per.get("job_title") or per.get("role_name") or ""
            if p_title:
                clean_title = self._clean_role_title(p_title)
                evidence = f"ACCA Practical Experience Requirement: {p_title}"
                self._add_or_update_role(inferred, clean_title, evidence, 0.90)

        # 3. Evidence from Technical & Professional Skills
        all_skills: List[str] = []
        raw_tech = resume_dict.get("technical_skills", [])
        if isinstance(raw_tech, list):
            all_skills.extend(raw_tech)
        elif isinstance(raw_tech, dict):
            for v in raw_tech.values():
                if isinstance(v, list):
                    all_skills.extend(v)
                elif isinstance(v, str):
                    all_skills.append(v)
        all_skills.extend(resume_dict.get("professional_skills", []))
        all_skills.extend(resume_dict.get("tools_and_software", []))

        normalized_skills = {s.lower().strip() for s in all_skills if isinstance(s, str)}

        for role_name, config in self.DOMAIN_TAXONOMY.items():
            matched_keywords = [
                kw for kw in config["keywords"]
                if any(kw in s or s in kw for s in normalized_skills)
            ]
            if len(matched_keywords) >= config["min_matches"]:
                evidence = f"Demonstrated skills: {', '.join(matched_keywords[:4])}"
                conf = min(0.70 + (len(matched_keywords) * 0.05), 0.90)
                self._add_or_update_role(
                    inferred,
                    role_title=role_name,
                    evidence=evidence,
                    confidence=conf,
                    skills=matched_keywords,
                )
                if is_student_or_fresher and "intern" not in role_name.lower():
                    self._add_or_update_role(
                        inferred,
                        role_title=f"{role_name} Intern",
                        evidence=evidence,
                        confidence=conf * 0.95,
                        skills=matched_keywords,
                    )

        # 4. Evidence from Projects
        for proj in resume_dict.get("projects", []):
            p_title = proj.get("title", "") or proj.get("name", "")
            p_desc = (proj.get("description", "") or "").lower()
            p_techs = [t.lower() for t in proj.get("technologies", []) if isinstance(t, str)]

            # Check if project aligns with key domains
            for role_name, config in self.DOMAIN_TAXONOMY.items():
                if any(kw in p_desc or any(kw in t for t in p_techs) for kw in config["keywords"]):
                    evidence = f"Project deliverable: {p_title}" if p_title else "Relevant project portfolio"
                    self._add_or_update_role(
                        inferred,
                        role_title=role_name,
                        evidence=evidence,
                        confidence=0.75,
                        skills=proj.get("technologies", [])[:3],
                    )

        # 5. Evidence from Professional Headline / Summary
        personal = resume_dict.get("personal", {}) or resume_dict.get("personal_info", {})
        headline = personal.get("headline", "") or resume_dict.get("professional_headline", "")
        if headline:
            # Split only on major title delimiters: pipe, bullet, forward-slash, or em/en dash with spaces
            for part in re.split(r"\||•|—|\s[–-]\s|/", headline):
                part_clean = self._clean_role_title(part.strip())
                part_lower = part_clean.lower()
                # A headline phrase is only a role if it contains a recognized job role indicator
                if (
                    3 < len(part_clean) <= 45
                    and not any(w in part_lower for w in ["aspiring", "enthusiast", "student", "seeking", "experience in", "hands-on", "specializing"])
                ):
                    has_role_kw = any(kw in part_lower for kw in [
                        "engineer", "developer", "analyst", "associate", "manager", "auditor",
                        "accountant", "specialist", "scientist", "consultant", "officer", "executive",
                        "intern", "lead", "director", "architect", "fellow",
                    ])
                    if has_role_kw:
                        evidence = f"Professional headline: {headline}"
                        self._add_or_update_role(inferred, part_clean, evidence, 0.90)

        # Fallback if no specific role identified
        if not inferred:
            major_str = ""
            for edu in resume_dict.get("education", []):
                major_str = edu.get("major") or edu.get("degree") or ""
                if major_str:
                    break
            fallback_title = f"{major_str} Graduate" if major_str else "Graduate Trainee"
            if is_student_or_fresher:
                fallback_title = f"{fallback_title} Intern"
            inferred[fallback_title] = InferredRole(
                role_title=fallback_title,
                evidence_sources=["General educational background"],
                confidence=0.50,
            )

        # Sort by confidence descending
        sorted_roles = sorted(inferred.values(), key=lambda r: r.confidence, reverse=True)
        # Cap at top 8 recommendations
        return sorted_roles[:8]

    def infer_locations(self, data: Any) -> List[str]:
        """Extracts candidate's natural location preference from resume facts."""
        resume_dict = self._normalize_input(data)
        personal = resume_dict.get("personal", {}) or resume_dict.get("personal_info", {})
        loc = personal.get("location", "") or resume_dict.get("location", "")

        locations = ["Remote"]
        if loc and loc.strip():
            clean_loc = loc.strip()
            # Split city, state, country
            parts = [p.strip() for p in clean_loc.split(",") if p.strip()]
            for p in parts:
                if p not in locations and len(p) > 1:
                    locations.append(p)

        # Default national / broad fallback if only specific city found
        if "India" not in locations:
            locations.append("India")

        return locations

    def _normalize_input(self, data: Any) -> Dict[str, Any]:
        """Converts ParsedResume or dictionary to canonical dict representation."""
        if hasattr(data, "to_dict"):
            return data.to_dict()
        if isinstance(data, dict):
            return data
        return {}

    def _is_student_or_fresher(self, resume_dict: Dict[str, Any]) -> bool:
        """Determines if candidate is currently a student or fresher based on graduation year."""
        current_year = 2026
        for edu in resume_dict.get("education", []):
            grad_yr = edu.get("expected_graduation_year") or edu.get("graduation_year")
            if grad_yr:
                try:
                    yr = int(str(grad_yr).strip())
                    if yr >= current_year - 1:
                        return True
                except Exception:
                    pass

        # Check total experience duration
        exps = resume_dict.get("work_experience", [])
        if not exps or len(exps) <= 1:
            return True

        return False

    def _clean_role_title(self, raw_title: str) -> str:
        """Cleans and standardizes raw title strings."""
        title = re.sub(r"\s+", " ", raw_title).strip()
        # Remove pipe suffixes like "Project Manager | Mobile App Dev" -> split on |
        if "|" in title:
            title = title.split("|")[0].strip()
        return title.title()

    def _add_or_update_role(
        self,
        inferred: Dict[str, InferredRole],
        role_title: str,
        evidence: str,
        confidence: float,
        skills: Optional[List[str]] = None,
    ) -> None:
        """Helper to add or merge supporting evidence into an inferred role."""
        if not role_title or len(role_title) < 2:
            return

        clean = role_title.strip()
        if clean in inferred:
            existing = inferred[clean]
            if evidence and evidence not in existing.evidence_sources:
                existing.evidence_sources.append(evidence)
            if skills:
                for s in skills:
                    if s not in existing.supporting_skills:
                        existing.supporting_skills.append(s)
            existing.confidence = max(existing.confidence, confidence)
        else:
            inferred[clean] = InferredRole(
                role_title=clean,
                evidence_sources=[evidence] if evidence else [],
                supporting_skills=list(skills) if skills else [],
                confidence=confidence,
            )
