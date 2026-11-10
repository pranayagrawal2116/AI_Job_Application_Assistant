"""Dynamic Career Role Inference Engine.

Infers suitable job categories and search roles from actual candidate resume evidence
(experience, degrees, majors, skills, projects, headline) without hardcoded AI/ML universal defaults.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
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


@dataclass
class InferredResult:
    """Consolidated inferred roles container."""
    inferred_roles: List[InferredRole] = field(default_factory=list)
    suggested_roles: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inferred_roles": [r.to_dict() for r in self.inferred_roles],
            "suggested_roles": list(self.suggested_roles),
        }


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
        "Tax Associate": {
            "keywords": ["taxation", "tax compliance", "tax computations", "sa100", "tax returns", "direct tax", "indirect tax", "uk tax"],
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
        # Healthcare & Medicine
        "Clinical Healthcare Specialist": {
            "keywords": ["patient care", "nursing", "clinical assessment", "pharmacology", "triage", "healthcare", "medical"],
            "category": "Healthcare",
            "min_matches": 2,
        },
        "Cardiologist": {
            "keywords": ["cardiology", "interventional cardiology", "echocardiography", "coronary", "catheterization", "cardiac"],
            "category": "Healthcare",
            "min_matches": 2,
        },
        "Physician / Clinical Specialist": {
            "keywords": ["internal medicine", "patient diagnosis", "clinical protocols", "emr", "attending", "medical staff"],
            "category": "Healthcare",
            "min_matches": 2,
        },
        # Legal
        "Corporate Counsel": {
            "keywords": ["corporate law", "m&a", "mergers", "cross-border", "due diligence", "contract negotiation", "securities"],
            "category": "Legal",
            "min_matches": 2,
        },
        "Legal Associate": {
            "keywords": ["contract drafting", "legal research", "litigation", "compliance", "regulatory", "due diligence"],
            "category": "Legal",
            "min_matches": 2,
        },
        # Education
        "STEM Educator": {
            "keywords": ["physics", "curriculum development", "ap physics", "stem", "classroom instruction", "pedagogy"],
            "category": "Education",
            "min_matches": 2,
        },
        # Sales & Revenue
        "Enterprise Account Executive": {
            "keywords": ["enterprise sales", "saas sales", "arr", "quota", "sales pipeline", "solution selling", "crm"],
            "category": "Sales",
            "min_matches": 2,
        },
        # Supply Chain & Operations
        "Supply Chain Director": {
            "keywords": ["supply chain", "cold-chain", "logistics", "procurement", "inventory management", "vendor management", "freight"],
            "category": "Operations",
            "min_matches": 2,
        },
        # Life Sciences & Biotech
        "Biomarker Research Scientist": {
            "keywords": ["oncology", "biomarker", "assay development", "genomics", "pcr", "flow cytometry", "translational"],
            "category": "Life Sciences",
            "min_matches": 2,
        },
        # Hospitality & Management
        "Hospitality Operations Manager": {
            "keywords": ["hospitality", "resort operations", "guest satisfaction", "hotel management", "f&b", "hotel operations"],
            "category": "Hospitality",
            "min_matches": 2,
        },
        # Behavioral Health
        "Behavior Analyst": {
            "keywords": ["behavior analysis", "bcba", "applied behavior", "special education", "iep", "intervention plan"],
            "category": "Education",
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
        "medicine": ["Physician", "Clinical Fellow"],
        "law": ["Legal Associate", "Corporate Counsel", "Legal Analyst"],
        "design": ["UI/UX Designer", "Product Designer"],
        "physics": ["STEM Educator", "Research Scientist"],
        "biology": ["Biomarker Research Scientist", "Laboratory Specialist"],
        "biotechnology": ["Biomarker Research Scientist", "Research Scientist"],
    }

    def infer_roles(self, data: Any) -> List[InferredRole]:
        """Infers candidate-specific career roles based on factual resume signals."""
        resume_dict = self._normalize_input(data)
        inferred: Dict[str, InferredRole] = {}

        # Check if student/fresher indicator
        is_student_or_fresher = self._is_student_or_fresher(resume_dict)
        senior_terms = [
            "intern", "manager", "director", "lead", "principal", "attending", "chief",
            "executive", "senior", "counsel", "cardiologist", "physician", "surgeon",
            "chair", "officer", "partner", "vp", "president", "consultant", "head",
        ]

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
                if is_student_or_fresher and not any(k in clean_title.lower() for k in senior_terms):
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
                        if is_student_or_fresher and not any(k in r.lower() for k in senior_terms):
                            self._add_or_update_role(inferred, f"{r} Intern", evidence, conf)

        # 2b. Evidence from Certifications & Professional Qualifications
        certs = resume_dict.get("certifications", []) + resume_dict.get("professional_qualifications", [])
        for cert in certs:
            c_name = str(cert.get("name", "")).lower() if isinstance(cert, dict) else str(cert).lower()
            if "acca" in c_name or "chartered" in c_name:
                self._add_or_update_role(inferred, "UK Tax Associate", "ACCA qualification / membership", 0.95)
                self._add_or_update_role(inferred, "Tax Associate", "ACCA qualification / membership", 0.95)
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
                if is_student_or_fresher and not any(k in role_name.lower() for k in senior_terms):
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

    def infer_roles_from_resume(self, data: Any) -> InferredResult:
        """Convenience method returning both InferredRole objects and plain role title strings."""
        roles = self.infer_roles(data)
        return InferredResult(
            inferred_roles=roles,
            suggested_roles=[r.role_title for r in roles],
        )

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

        # Only add India if candidate explicitly resides in India or no location was found
        if "india" in loc.lower() or (len(locations) == 1 and locations[0] == "Remote"):
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
        current_year = datetime.now(timezone.utc).year

        # 1. Professional qualifications / statutory certifications
        certs = resume_dict.get("certifications", []) + resume_dict.get("professional_qualifications", [])
        for cert in certs:
            c_str = str(cert.get("name", "") if isinstance(cert, dict) else cert).lower()
            if any(p in c_str for p in ["acca", "cpa", "cfa", "bar", "m.d.", "md", "ph.d", "phd", "pmp", "bcba", "registered nurse", "board-certified", "architect", "mbbs"]):
                return False

        # Calculate total experience months
        exps = resume_dict.get("work_experience", [])
        total_months = 0
        for exp in exps:
            dur = exp.get("duration") or ""
            m_mo = re.search(r"(\d+)\s*(?:month|mo)", dur, re.IGNORECASE)
            if m_mo:
                total_months += int(m_mo.group(1))
            m_yr = re.search(r"(\d+)\s*(?:year|yr)", dur, re.IGNORECASE)
            if m_yr:
                total_months += int(m_yr.group(1)) * 12

        # 2. Check future graduation year
        for edu in resume_dict.get("education", []):
            grad_yr = edu.get("expected_graduation_year") or edu.get("graduation_year")
            if grad_yr:
                try:
                    yr = int(str(grad_yr).strip())
                    if yr >= current_year:
                        # Currently enrolled: student unless extensive past professional experience (>= 24 mo)
                        return total_months < 24
                except Exception:
                    pass

        # 3. Check senior keywords in headline or work experience
        senior_keywords = [
            "director", "vp", "vice president", "attending",
            "chief", "partner", "chair", "executive", "senior", "counsel",
            "cardiologist", "physician", "surgeon", "fellow", "consultant", "manager", "head",
        ]
        headline = (resume_dict.get("headline") or resume_dict.get("professional_headline") or "").lower()
        if any(re.search(r"\b" + kw + r"\b", headline) for kw in senior_keywords):
            return False

        for exp in exps:
            title = (exp.get("job_title") or "").lower()
            if any(re.search(r"\b" + kw + r"\b", title) for kw in senior_keywords):
                return False

        if total_months >= 12:
            return False

        # 4. Past graduation check
        for edu in resume_dict.get("education", []):
            grad_yr = edu.get("expected_graduation_year") or edu.get("graduation_year")
            if grad_yr:
                try:
                    yr = int(str(grad_yr).strip())
                    if yr < current_year - 1:
                        return False
                except Exception:
                    pass

        if not exps and total_months == 0:
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

    def classify_candidate(self, data: Any) -> str:
        """Classifies a candidate into an empirical career category without unverified assumptions.

        Returns one of:
            - 'professionally_qualified': Holds statutory/professional credential (ACCA, CPA, CFA, Bar, MD, PhD, etc.)
            - 'student': Currently enrolled in higher education with future graduation year
            - 'fresher': Recent graduate or < 12 months experience without senior/statutory licenses
            - 'experienced_professional': >= 12 months verified experience or senior role
            - 'general_candidate': Insufficient profile data to determine category
        """
        norm = self._normalize_input(data)

        # 1. Statutory certifications or professional credentials
        certs = norm.get("certifications", []) + norm.get("professional_qualifications", [])
        for cert in certs:
            c_str = str(cert.get("name", "") if isinstance(cert, dict) else cert).lower()
            if any(p in c_str for p in ["acca", "cpa", "cfa", "bar", "m.d.", "md", "ph.d", "phd", "pmp", "bcba", "registered nurse", "board-certified", "architect", "mbbs"]):
                return "professionally_qualified"

        # Check education degrees for professional qualifications (e.g. "ACCA Member")
        for edu in norm.get("education", []):
            deg = (edu.get("degree") or "").lower()
            if any(p in deg for p in ["acca", "cpa", "cfa", "bar", "m.d.", "mbbs"]):
                return "professionally_qualified"

        # 2. Total experience months and senior keywords
        exps = norm.get("work_experience", [])
        total_months = 0
        for exp in exps:
            dur = exp.get("duration") or ""
            m_mo = re.search(r"(\d+)\s*(?:month|mo)", dur, re.IGNORECASE)
            if m_mo:
                total_months += int(m_mo.group(1))
            m_yr = re.search(r"(\d+)\s*(?:year|yr)", dur, re.IGNORECASE)
            if m_yr:
                total_months += int(m_yr.group(1)) * 12

        senior_keywords = [
            "director", "vp", "vice president", "attending",
            "chief", "partner", "chair", "executive", "senior", "counsel",
            "cardiologist", "physician", "surgeon", "fellow", "consultant", "head",
        ]
        headline = (norm.get("headline") or norm.get("professional_headline") or "").lower()
        if any(re.search(r"\b" + kw + r"\b", headline) for kw in senior_keywords):
            return "experienced_professional"
        for exp in exps:
            title = (exp.get("job_title") or "").lower()
            if any(re.search(r"\b" + kw + r"\b", title) for kw in senior_keywords):
                return "experienced_professional"

        current_year = datetime.now(timezone.utc).year

        # 3. Check enrolled student (future graduation year) vs recent graduate
        has_future_grad = False
        has_recent_grad = False
        has_any_edu = False
        for edu in norm.get("education", []):
            has_any_edu = True
            exp_grad_yr = edu.get("expected_graduation_year")
            grad_yr = edu.get("graduation_year")
            if exp_grad_yr:
                try:
                    yr = int(str(exp_grad_yr).strip())
                    if yr > current_year:
                        has_future_grad = True
                    elif yr >= current_year - 2:
                        has_recent_grad = True
                except Exception:
                    pass
            elif grad_yr:
                try:
                    yr = int(str(grad_yr).strip())
                    if yr > current_year:
                        has_future_grad = True
                    elif yr >= current_year - 2:
                        has_recent_grad = True
                except Exception:
                    pass

        if has_future_grad and total_months < 24:
            return "student"

        # 4. Experienced professional check
        if total_months >= 12:
            return "experienced_professional"

        # 5. Fresher check
        if has_recent_grad or (has_any_edu and total_months == 0) or (total_months < 12 and (norm.get("projects") or norm.get("education"))):
            return "fresher"

        if not has_any_edu and not exps and not norm.get("skills"):
            return "general_candidate"

        return "fresher" if total_months < 12 else "experienced_professional"

    def calculate_profile_completeness(self, data: Any, resumes_count: int = 0) -> Dict[str, Any]:
        """Calculates fair, non-penalizing profile completeness (0-100) based on candidate classification.

        Students and freshers are not penalized for lacking employment history if they have project/practical evidence.
        Professionally qualified candidates are credited for their professional credentials.
        """
        norm = self._normalize_input(data)
        category = self.classify_candidate(norm)

        category_labels = {
            "student": "Student",
            "fresher": "Recent Graduate / Fresher",
            "professionally_qualified": "Professionally Qualified Candidate",
            "experienced_professional": "Experienced Professional",
            "general_candidate": "Candidate",
        }

        # 1. Personal Info (20 pts)
        personal = norm.get("personal", {}) or norm.get("personal_info", {})
        has_name = bool(personal.get("full_name") or norm.get("full_name"))
        has_contact = bool(personal.get("email") or personal.get("phone") or norm.get("email") or norm.get("phone"))
        personal_pts = 20 if (has_name and has_contact) else (10 if has_name else 0)

        # 2. Education (20 pts)
        edus = norm.get("education", [])
        edu_pts = 20 if edus and len(edus) > 0 else 0

        # 3. Skills (20 pts)
        tech_skills = norm.get("technical_skills") or []
        prof_skills = norm.get("professional_skills") or []
        flat_skills = norm.get("skills") or []
        total_skills = len(tech_skills) + len(prof_skills) + len(flat_skills)
        skills_pts = 20 if total_skills > 0 else 0

        # 4. Resume availability (20 pts)
        resume_pts = 20 if resumes_count > 0 else 0

        # 5. Career / Practical Evidence (20 pts)
        exps = norm.get("work_experience", [])
        projs = norm.get("projects", [])
        certs = norm.get("certifications", []) + norm.get("professional_qualifications", [])

        has_exp = bool(exps and len(exps) > 0)
        has_projs = bool(projs and len(projs) > 0)
        has_certs = bool(certs and len(certs) > 0)

        career_pts = 0
        missing_sections = []

        if category in ("student", "fresher"):
            # Satisfied if projects OR work_experience present
            if has_projs or has_exp:
                career_pts = 20
            else:
                missing_sections.append("Projects or Practical Experience")
        elif category == "professionally_qualified":
            # Satisfied if professional_qualifications/certifications OR work_experience present
            if has_certs or has_exp:
                career_pts = 20
            else:
                missing_sections.append("Professional Qualifications or Experience")
        elif category == "experienced_professional":
            if has_exp:
                career_pts = 20
            else:
                missing_sections.append("Work Experience")
        else:
            if has_exp or has_projs or has_certs:
                career_pts = 20
            else:
                missing_sections.append("Experience or Projects")

        if personal_pts < 20:
            missing_sections.append("Contact Details")
        if edu_pts == 0:
            missing_sections.append("Education")
        if skills_pts == 0:
            missing_sections.append("Skills")
        if resume_pts == 0:
            missing_sections.append("Resume Upload")

        total_score = min(100, personal_pts + edu_pts + skills_pts + resume_pts + career_pts)

        return {
            "completeness_score": total_score,
            "candidate_category": category,
            "category_label": category_labels.get(category, "Candidate"),
            "evidence_breakdown": {
                "personal_info": personal_pts,
                "education": edu_pts,
                "skills": skills_pts,
                "resume_uploaded": resume_pts,
                "career_evidence": career_pts,
            },
            "missing_sections": missing_sections,
            "is_application_ready": total_score >= 80,
        }

    def infer_career_domain(self, data: Any) -> Dict[str, Any]:
        """Infers the candidate's professional domain based strictly on factual credentials and degrees.

        Never defaults to finance, accounting, or AI/ML without empirical evidence.
        Recognized domains:
            - accounting_finance: ACCA, CA, CPA, CMA, Tax, Audit, Accounting
            - healthcare: MBBS, MD, Physician, Nurse, Clinical, Medical, BDS, Pharmacist
            - legal: Bar, LLB, LLM, Attorney, Lawyer, Legal Counsel, Juris Doctor
            - investment_risk: CFA, FRM, Portfolio Management, Risk Manager
            - project_management: PMP, PMI, Prince2, Scrum Master, Agile Coach
            - engineering_tech: Computer Science, Software, Engineering, Data Science, AI
        """
        norm = self._normalize_input(data)

        # Check credentials, certifications, degrees, headlines, and work experience
        certs = norm.get("certifications", []) + norm.get("professional_qualifications", [])
        edus = norm.get("education", [])
        exps = norm.get("work_experience", [])
        headline = (norm.get("headline") or norm.get("professional_headline") or "").lower()

        evidence_texts: List[str] = [headline]
        for c in certs:
            evidence_texts.append(str(c.get("name", "") if isinstance(c, dict) else c).lower())
        for e in edus:
            evidence_texts.append((e.get("degree") or "").lower())
            evidence_texts.append((e.get("field_of_study") or e.get("major") or "").lower())
        for x in exps:
            evidence_texts.append((x.get("job_title") or "").lower())

        combined_text = " ".join(evidence_texts)

        domain_definitions = [
            {
                "id": "accounting_finance",
                "label": "Accounting & Finance",
                "roles_label": "accounting, audit, and tax",
                "patterns": [
                    r"\bacca\b", r"\bcpa\b", r"\bca\b", r"\bchartered accountant\b",
                    r"\bcma\b", r"\btax\b", r"\baudit\b", r"\baccounting\b",
                    r"\bcost accountant\b", r"\bfinancial reporting\b", r"\bstatutory audit\b"
                ],
            },
            {
                "id": "healthcare",
                "label": "Healthcare & Medicine",
                "roles_label": "clinical and healthcare",
                "patterns": [
                    r"\bmbbs\b", r"\bmd\b", r"\bm\.d\.\b", r"\bphysician\b",
                    r"\bnurse\b", r"\brn\b", r"\bregistered nurse\b", r"\bclinical\b",
                    r"\bmedical\b", r"\bsurgeon\b", r"\bbds\b", r"\bpharmacist\b",
                    r"\bpharmd\b", r"\bhealthcare\b"
                ],
            },
            {
                "id": "legal",
                "label": "Legal & Compliance",
                "roles_label": "legal and compliance",
                "patterns": [
                    r"\bbar\b", r"\bllb\b", r"\bllm\b", r"\battorney\b",
                    r"\blawyer\b", r"\blegal counsel\b", r"\bjuris doctor\b",
                    r"\bjd\b", r"\badvocate\b", r"\bcompliance officer\b", r"\blitigation\b"
                ],
            },
            {
                "id": "investment_risk",
                "label": "Investment & Risk",
                "roles_label": "investment and risk management",
                "patterns": [
                    r"\bcfa\b", r"\bfrm\b", r"\bchartered financial analyst\b",
                    r"\bfinancial risk manager\b", r"\bportfolio manager\b",
                    r"\bequity research\b", r"\brisk analyst\b", r"\bhedge fund\b"
                ],
            },
            {
                "id": "project_management",
                "label": "Project Management",
                "roles_label": "project and program management",
                "patterns": [
                    r"\bpmp\b", r"\bpmi\b", r"\bprince2\b", r"\bscrum master\b",
                    r"\bcsm\b", r"\bagile coach\b", r"\bprogram manager\b"
                ],
            },
            {
                "id": "mechanical_engineering",
                "label": "Mechanical & Industrial Engineering",
                "roles_label": "mechanical engineering and design",
                "patterns": [
                    r"\bmechanical engineer\b", r"\bmechanical engineering\b",
                    r"\bsolidworks\b", r"\bautocad\b", r"\bcatia\b", r"\bansys\b",
                    r"\bthermodynamics\b", r"\bfinite element\b", r"\bcad designer\b",
                    r"\bmanufacturing engineer\b"
                ],
            },
            {
                "id": "engineering_tech",
                "label": "Engineering & Technology",
                "roles_label": "software engineering and technology",
                "patterns": [
                    r"\bsoftware engineer\b", r"\bcomputer science\b",
                    r"\bsoftware developer\b", r"\bdata scientist\b",
                    r"\bmachine learning\b", r"\bb\.tech\b", r"\bm\.tech\b",
                    r"\belectrical engineering\b", r"\bcivil engineering\b"
                ],
            },
        ]

        for d in domain_definitions:
            matched_pats = [p for p in d["patterns"] if re.search(p, combined_text, re.IGNORECASE)]
            if matched_pats:
                return {
                    "domain": d["id"],
                    "domain_label": d["label"],
                    "suggested_roles_label": d["roles_label"],
                    "supporting_patterns": matched_pats,
                }

        return {
            "domain": None,
            "domain_label": None,
            "suggested_roles_label": None,
            "supporting_patterns": [],
        }
