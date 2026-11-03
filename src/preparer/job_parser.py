"""Universal Job Description Parser Module.

Cross-industry, zero-hallucination parsing engine for job postings in any field
(Software, Medicine, Law, Finance, Engineering, Management, Marketing, Design, etc.).
Extracts structured requirements, responsibilities, compensation, and qualifications
with verifiable provenance and requirement classification.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from docx import Document
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from src.database.exceptions import (
    CorruptedFileError,
    EncryptedFileError,
    InvalidFileFormatError,
)
from src.utils.logger import setup_logger

logger = setup_logger("JobParser")

CURRENT_PARSER_VERSION = "1.0.0"


# -------------------------------------------------------------------------
# REQUIREMENT CLASSIFICATION & PROVENANCE
# -------------------------------------------------------------------------

class RequirementClassification:
    MANDATORY = "MANDATORY"
    PREFERRED = "PREFERRED"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


class VerificationStatus:
    EXTRACTED_UNVERIFIED = "EXTRACTED_UNVERIFIED"
    USER_CONFIRMED = "USER_CONFIRMED"
    USER_CORRECTED = "USER_CORRECTED"
    NOT_FOUND = "NOT_FOUND"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class JobProvenanceField:
    """Detailed origin, confidence, and audit tracking for an individual extracted attribute."""
    value: Any = None
    source: str = "job_description_text"
    source_section: str = ""
    source_text: str = ""
    confidence: float = 1.0
    verification_status: str = VerificationStatus.EXTRACTED_UNVERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -------------------------------------------------------------------------
# STRUCTURED JOB DESCRIPTION DATA MODELS
# -------------------------------------------------------------------------

@dataclass
class StructuredJobDescription:
    """Universal, industry-independent structured representation of a job posting."""

    # Identity
    job_title: Optional[str] = None
    company_name: Optional[str] = None
    department: Optional[str] = None
    job_id_or_req_number: Optional[str] = None

    # Overview & Responsibilities
    summary: str = ""
    responsibilities: List[str] = field(default_factory=list)
    key_deliverables: List[str] = field(default_factory=list)

    # Skills & Requirements Classification
    mandatory_skills: List[str] = field(default_factory=list)
    preferred_skills: List[str] = field(default_factory=list)
    tools_and_technologies: List[str] = field(default_factory=list)
    soft_skills: List[str] = field(default_factory=list)

    # Education & Credentials
    required_degree_levels: List[str] = field(default_factory=list)
    preferred_fields_of_study: List[str] = field(default_factory=list)
    min_gpa_or_percentage: Optional[float] = None
    certifications_required: List[str] = field(default_factory=list)
    licenses_required: List[str] = field(default_factory=list)

    # Experience Requirements
    min_years_experience: Optional[float] = None
    max_years_experience: Optional[float] = None
    experience_level: str = "Not Specified"
    specific_domain_experience: List[str] = field(default_factory=list)

    # Employment & Schedule
    employment_type: str = "Full-time"
    internship_duration: Optional[str] = None
    shift_schedule: Optional[str] = None

    # Location & Work Arrangement
    location: Optional[str] = None
    work_arrangement: str = "Undisclosed"
    relocation_assistance: Optional[bool] = None
    visa_sponsorship: Optional[bool] = None

    # Compensation & Benefits
    compensation_disclosed: bool = False
    raw_compensation_text: Optional[str] = None
    currency: Optional[str] = None
    salary_min: Optional[float] = None
    salary_max: Optional[float] = None
    salary_period: Optional[str] = None
    benefits: List[str] = field(default_factory=list)

    # Important Dates
    application_deadline: Optional[str] = None
    start_date: Optional[str] = None
    posting_date: Optional[str] = None

    # Application Instructions
    application_url: Optional[str] = None
    application_email: Optional[str] = None
    submission_instructions: Optional[str] = None
    required_documents: List[str] = field(default_factory=list)
    screening_questions: List[str] = field(default_factory=list)

    # Metadata & Provenance
    extraction_confidence: float = 1.0
    parser_version: str = CURRENT_PARSER_VERSION
    field_provenance: Dict[str, JobProvenanceField] = field(default_factory=dict)
    raw_text: str = ""
    parsed_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["field_provenance"] = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in self.field_provenance.items()}
        return result

    def get_provenance(self, field_name: str) -> Optional[Dict[str, Any]]:
        field_obj = self.field_provenance.get(field_name)
        return field_obj.to_dict() if field_obj else None


# -------------------------------------------------------------------------
# CROSS-INDUSTRY SECTION & SKILL VOCABULARIES
# -------------------------------------------------------------------------

JOB_SECTION_PATTERNS = {
    "SUMMARY": re.compile(
        r"^(?:job\s+summary|overview|about\s+(?:the\s+)?(?:role|position|job|company|team)|who\s+we\s+are|company\s+overview|position\s+summary|role\s+purpose|introduction)\b",
        re.IGNORECASE,
    ),
    "RESPONSIBILITIES": re.compile(
        r"^(?:responsibilities|key\s+responsibilities|duties|essential\s+duties|what\s+you(?:'ll|\s+will)\s+do|day\s+to\s+day|key\s+accountabilities|scope\s+of\s+work|tasks)\b",
        re.IGNORECASE,
    ),
    "MANDATORY_REQUIREMENTS": re.compile(
        r"^(?:requirements|minimum\s+qualifications|basic\s+qualifications|required\s+skills|must\s+have|mandatory\s+requirements|what\s+you\s+need|eligibility\s+criteria|essential\s+requirements|who\s+you\s+are)\b",
        re.IGNORECASE,
    ),
    "PREFERRED_REQUIREMENTS": re.compile(
        r"^(?:preferred(?:\s+qualifications|\s+requirements|\s+skills)?|nice\s+to\s+have|desired\s+skills|good\s+to\s+have|bonus\s+points|bonus\s+qualifications|plus|preferred\s+skills|what\s+sets\s+you\s+apart)\b",
        re.IGNORECASE,
    ),
    "EDUCATION": re.compile(
        r"^(?:education|educational\s+requirements|academic\s+background|qualifications|degrees|training)\b",
        re.IGNORECASE,
    ),
    "BENEFITS": re.compile(
        r"^(?:benefits|what\s+we\s+offer|perks|compensation\s*&\s*benefits|why\s+join\s+us|rewards|perks\s*&\s*benefits)\b",
        re.IGNORECASE,
    ),
    "HOW_TO_APPLY": re.compile(
        r"^(?:how\s+to\s+apply|application\s+process|submission\s+instructions|to\s+apply|instructions)\b",
        re.IGNORECASE,
    ),
}

# Industry skills & tools catalog for targeted matching
CROSS_INDUSTRY_SKILLS = {
    # Software & IT
    "Python", "Java", "C++", "C#", "JavaScript", "TypeScript", "Go", "Rust", "PHP", "Ruby", "Swift", "Kotlin",
    "React", "Angular", "Vue", "Node.js", "Django", "FastAPI", "Flask", "Spring Boot", ".NET",
    "SQL", "PostgreSQL", "MySQL", "MongoDB", "Redis", "SQLite", "GraphQL", "REST API",
    "AWS", "Azure", "GCP", "Docker", "Kubernetes", "CI/CD", "Git", "Linux", "Terraform",
    "Machine Learning", "Deep Learning", "Data Science", "NLP", "Computer Vision", "LLM", "Generative AI",
    "Pandas", "NumPy", "Scikit-Learn", "PyTorch", "TensorFlow", "Flutter", "Dart",
    # Healthcare & Medicine
    "Patient Care", "Clinical Rotations", "Diagnosis", "Treatment Planning", "Electronic Health Records",
    "EHR", "EMR", "Epic", "Cerner", "BLS", "ACLS", "PALS", "HIPAA", "Pharmacology", "Phlebotomy",
    "Surgical Assistance", "Triage", "Telehealth", "Infection Control", "Medical Billing",
    # Finance & Accounting
    "Financial Modeling", "Budgeting", "Forecasting", "GAAP", "IFRS", "Auditing", "Tax Compliance",
    "Financial Reporting", "General Ledger", "Accounts Payable", "Accounts Receivable", "Reconciliation",
    "Excel", "QuickBooks", "SAP", "NetSuite", "Bloomberg Terminal", "Valuation",
    # Law & Legal
    "Legal Research", "Legal Writing", "Contract Drafting", "Litigation", "Due Diligence",
    "Regulatory Compliance", "Westlaw", "LexisNexis", "Intellectual Property", "Corporate Governance",
    "Brief Writing", "Depositions", "Legal Analysis",
    # Engineering (Mech / Civil / Elec)
    "AutoCAD", "SolidWorks", "Revit", "MATLAB", "FEA", "CFD", "Thermodynamics", "Circuit Design",
    "PCB Layout", "PLC", "Structural Analysis", "HVAC", "Lean Manufacturing", "Six Sigma",
    # Business, Management & HR
    "Project Management", "Agile", "Scrum", "Kanban", "JIRA", "Stakeholder Management",
    "Talent Acquisition", "Employee Relations", "Performance Management", "Strategic Planning",
    "Risk Management", "Vendor Management", "Change Management",
    # Marketing & Sales
    "SEO", "SEM", "Content Marketing", "Social Media Marketing", "Google Analytics", "Copywriting",
    "Email Marketing", "CRM", "Salesforce", "HubSpot", "Lead Generation", "B2B Sales", "Account Management",
    # Creative & Design
    "Figma", "Adobe Photoshop", "Illustrator", "InDesign", "Premiere Pro", "After Effects",
    "UI/UX Design", "Wireframing", "Prototyping", "Graphic Design", "Typography", "User Research",
    # Education
    "Curriculum Design", "Classroom Management", "Lesson Planning", "Pedagogy", "Educational Technology",
    "Assessment Design", "Student Advising",
}

DEGREE_LEVELS = [
    (re.compile(r"\b(Ph\.?D\.?|Doctorate|Doctor\s+of\s+Philosophy|MD|MBBS|JD)\b", re.IGNORECASE), "Doctorate / Professional"),
    (re.compile(r"\b(Master'?s|M\.?S\.?|M\.?Tech|M\.?Sc\.?|M\.?A\.?|MBA|LL\.?M)\b", re.IGNORECASE), "Master's Degree"),
    (re.compile(r"\b(Bachelor'?s|B\.?Tech|B\.?S\.?|B\.?Sc\.?|B\.?A\.?|B\.?E\.?|B\.?Com|LL\.?B)\b", re.IGNORECASE), "Bachelor's Degree"),
    (re.compile(r"\b(Associate(?:'?s)?\s+Degree|Diploma)\b", re.IGNORECASE), "Associate / Diploma"),
    (re.compile(r"\b(High\s+School|Secondary\s+School|12th\s+Grade)\b", re.IGNORECASE), "High School"),
]

LICENSES_AND_CERTS = [
    (re.compile(r"\b(CPA|Certified\s+Public\s+Accountant)\b", re.IGNORECASE), "CPA"),
    (re.compile(r"\b(CFA|Chartered\s+Financial\s+Analyst)\b", re.IGNORECASE), "CFA"),
    (re.compile(r"\b(PMP|Project\s+Management\s+Professional)\b", re.IGNORECASE), "PMP"),
    (re.compile(r"\b(Bar\s+Admission|Admitted\s+to\s+the\s+Bar|State\s+Bar)\b", re.IGNORECASE), "Bar Admission"),
    (re.compile(r"\b(Medical\s+License|State\s+Medical\s+Board|Board\s+Certified)\b", re.IGNORECASE), "Board Certification / Medical License"),
    (re.compile(r"\b(PE\s+License|Professional\s+Engineer)\b", re.IGNORECASE), "PE License"),
    (re.compile(r"\b(RN|Registered\s+Nurse)\b", re.IGNORECASE), "Registered Nurse (RN)"),
    (re.compile(r"\b(AWS\s+Certified|AWS\s+Certification)\b", re.IGNORECASE), "AWS Certified"),
    (re.compile(r"\b(Scrum\s+Master|CSM)\b", re.IGNORECASE), "Scrum Master (CSM)"),
    (re.compile(r"\b(Six\s+Sigma\s+(?:Green|Black)\s+Belt)\b", re.IGNORECASE), "Six Sigma"),
]


class JobParser:
    """Universal, cross-industry job description parser with zero-hallucination guarantees."""

    @staticmethod
    def compute_text_hash(text: str) -> str:
        """Computes deterministic SHA-256 hash of job text."""
        return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()

    # -------------------------------------------------------------------------
    # DOCUMENT TEXT EXTRACTION (PDF & DOCX)
    # -------------------------------------------------------------------------

    def extract_text_from_pdf(self, path_or_bytes: Union[str, Path, bytes]) -> str:
        """Safely extracts plain text from PDF document enforcing security checks."""
        if isinstance(path_or_bytes, bytes):
            pdf_bytes = path_or_bytes
        else:
            with open(path_or_bytes, "rb") as f:
                pdf_bytes = f.read()

        if not pdf_bytes.startswith(b"%PDF-"):
            raise InvalidFileFormatError("File does not start with valid PDF magic bytes.")

        stream = io.BytesIO(pdf_bytes)
        try:
            reader = PdfReader(stream)
            if reader.is_encrypted:
                try:
                    decrypted = reader.decrypt("")
                    if decrypted == 0:
                        raise EncryptedFileError("PDF document is encrypted with a password.")
                except Exception:
                    raise EncryptedFileError("PDF document is encrypted with a password.")

            pages_text = []
            for page in reader.pages:
                txt = page.extract_text() or ""
                pages_text.append(txt)

            return "\n\n".join(pages_text).strip()
        except (EncryptedFileError, InvalidFileFormatError):
            raise
        except PdfReadError as e:
            raise CorruptedFileError(f"Malformed PDF file: {e}")
        except Exception as e:
            raise CorruptedFileError(f"Error reading PDF job description: {e}")

    def extract_text_from_docx(self, path_or_bytes: Union[str, Path, bytes]) -> str:
        """Safely extracts plain text from DOCX document enforcing security checks."""
        if isinstance(path_or_bytes, bytes):
            docx_bytes = path_or_bytes
        else:
            with open(path_or_bytes, "rb") as f:
                docx_bytes = f.read()

        if not docx_bytes.startswith(b"PK\x03\x04"):
            raise InvalidFileFormatError("File does not start with valid DOCX/ZIP magic bytes.")

        stream = io.BytesIO(docx_bytes)
        try:
            doc = Document(stream)
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    row_cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if row_cells:
                        paragraphs.append(" | ".join(row_cells))
            return "\n\n".join(paragraphs).strip()
        except InvalidFileFormatError:
            raise
        except Exception as e:
            raise CorruptedFileError(f"Error reading DOCX job description: {e}")

    # -------------------------------------------------------------------------
    # MAIN PARSER ENGINE
    # -------------------------------------------------------------------------

    def parse_job_description(
        self,
        raw_text: str,
        hint_title: Optional[str] = None,
        hint_company: Optional[str] = None,
        hint_location: Optional[str] = None,
        source: str = "text_input",
    ) -> StructuredJobDescription:
        """Parses raw job description text into structured model with provenance.

        Args:
            raw_text: Plain text job description.
            hint_title: Optional title hint from document metadata or page title.
            hint_company: Optional company hint from metadata.
            hint_location: Optional location hint from metadata.
            source: Ingestion source channel identifier.

        Returns:
            StructuredJobDescription with verified fields and provenance tracking.
        """
        if not raw_text or not isinstance(raw_text, str):
            raise InvalidFileFormatError("Job description text cannot be empty.")

        # Sanitize control characters (passive untrusted data defense)
        clean_text = self._sanitize_passive_text(raw_text)

        if len(clean_text.strip()) < 20:
            raise InvalidFileFormatError("Job description content is too short (minimum 20 characters required).")

        now_iso = datetime.now(timezone.utc).isoformat()
        provenance: Dict[str, JobProvenanceField] = {}

        # 1. Segment into sections
        sections = self._segment_sections(clean_text)

        # 2. Extract Title and Company
        job_title, company_name = self._extract_identity(clean_text, sections, hint_title, hint_company)
        provenance["job_title"] = JobProvenanceField(
            value=job_title,
            source=source,
            source_section="HEADER" if not hint_title else "HINT_OR_HEADER",
            source_text=job_title or "",
            confidence=0.9 if job_title else 0.3,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED if job_title else VerificationStatus.NEEDS_REVIEW,
        )
        provenance["company_name"] = JobProvenanceField(
            value=company_name,
            source=source,
            source_section="HEADER" if not hint_company else "HINT_OR_HEADER",
            source_text=company_name or "",
            confidence=0.85 if company_name else 0.3,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED if company_name else VerificationStatus.NEEDS_REVIEW,
        )

        # 3. Extract Summary and Responsibilities
        summary_text = sections.get("SUMMARY", "")
        if not summary_text:
            # Fall back to first 2 non-empty lines
            first_lines = [l.strip() for l in clean_text.splitlines() if l.strip()][:3]
            summary_text = " ".join(first_lines)

        responsibilities = self._extract_bullet_items(sections.get("RESPONSIBILITIES", ""))
        key_deliverables = self._extract_key_deliverables(responsibilities)

        # 4. Extract Skills & Classify Mandatory vs Preferred
        mandatory_skills, preferred_skills, tools_tech, soft_skills = self._extract_and_classify_skills(sections, clean_text)

        # 5. Extract Education & Credentials
        degrees, fields_of_study, min_gpa, certs, licenses = self._extract_education_and_credentials(sections, clean_text)

        # 6. Extract Experience Requirements
        min_years, max_years, exp_level = self._extract_experience(sections, clean_text)

        # 7. Extract Employment & Schedule
        emp_type, duration, schedule = self._extract_employment_type(sections, clean_text)

        # 8. Extract Location & Work Arrangement
        location, arrangement = self._extract_location_and_arrangement(sections, clean_text, hint_location)

        # 9. Extract Compensation & Benefits (Zero-Hallucination: Undisclosed if not found)
        comp_info = self._extract_compensation(sections, clean_text)

        # 10. Extract Deadlines & Dates
        deadline, start_date, posting_date = self._extract_dates(sections, clean_text)

        # 11. Extract Application Instructions & Required Documents
        app_url, app_email, instructions, req_docs, screening_qs = self._extract_application_instructions(sections, clean_text)

        # Record Field Provenance for all core fields
        provenance["responsibilities"] = JobProvenanceField(
            value=responsibilities,
            source=source,
            source_section="RESPONSIBILITIES",
            source_text=f"{len(responsibilities)} items identified",
            confidence=0.85 if responsibilities else 0.5,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        )
        provenance["mandatory_skills"] = JobProvenanceField(
            value=mandatory_skills,
            source=source,
            source_section="MANDATORY_REQUIREMENTS",
            source_text=", ".join(mandatory_skills[:5]),
            confidence=0.9 if mandatory_skills else 0.5,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        )
        provenance["preferred_skills"] = JobProvenanceField(
            value=preferred_skills,
            source=source,
            source_section="PREFERRED_REQUIREMENTS",
            source_text=", ".join(preferred_skills[:5]),
            confidence=0.85,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        )
        provenance["min_years_experience"] = JobProvenanceField(
            value=min_years,
            source=source,
            source_section="EXPERIENCE",
            source_text=f"min: {min_years}" if min_years is not None else "undisclosed",
            confidence=0.9 if min_years is not None else 1.0,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        )
        provenance["compensation"] = JobProvenanceField(
            value=comp_info["raw_text"],
            source=source,
            source_section="BENEFITS",
            source_text=comp_info["raw_text"] or "Undisclosed",
            confidence=0.9 if comp_info["disclosed"] else 1.0,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        )
        provenance["location"] = JobProvenanceField(
            value=location,
            source=source,
            source_section="LOCATION",
            source_text=location or "Undisclosed",
            confidence=0.85 if location else 0.5,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED if location else VerificationStatus.NEEDS_REVIEW,
        )

        # Compute overall extraction confidence
        score_weights = [
            0.25 if job_title else 0.0,
            0.20 if company_name else 0.0,
            0.20 if (mandatory_skills or preferred_skills) else 0.05,
            0.15 if responsibilities else 0.05,
            0.10 if (min_years is not None or exp_level != "Not Specified") else 0.05,
            0.10 if location else 0.05,
        ]
        overall_confidence = round(sum(score_weights), 2)

        return StructuredJobDescription(
            job_title=job_title,
            company_name=company_name,
            summary=summary_text,
            responsibilities=responsibilities,
            key_deliverables=key_deliverables,
            mandatory_skills=mandatory_skills,
            preferred_skills=preferred_skills,
            tools_and_technologies=tools_tech,
            soft_skills=soft_skills,
            required_degree_levels=degrees,
            preferred_fields_of_study=fields_of_study,
            min_gpa_or_percentage=min_gpa,
            certifications_required=certs,
            licenses_required=licenses,
            min_years_experience=min_years,
            max_years_experience=max_years,
            experience_level=exp_level,
            employment_type=emp_type,
            internship_duration=duration,
            shift_schedule=schedule,
            location=location,
            work_arrangement=arrangement,
            compensation_disclosed=comp_info["disclosed"],
            raw_compensation_text=comp_info["raw_text"],
            currency=comp_info["currency"],
            salary_min=comp_info["min"],
            salary_max=comp_info["max"],
            salary_period=comp_info["period"],
            benefits=comp_info["benefits"],
            application_deadline=deadline,
            start_date=start_date,
            posting_date=posting_date,
            application_url=app_url,
            application_email=app_email,
            submission_instructions=instructions,
            required_documents=req_docs,
            screening_questions=screening_qs,
            extraction_confidence=overall_confidence,
            parser_version=CURRENT_PARSER_VERSION,
            field_provenance=provenance,
            raw_text=clean_text,
            parsed_timestamp=now_iso,
        )

    # -------------------------------------------------------------------------
    # INTERNAL HEURISTIC HELPERS
    # -------------------------------------------------------------------------

    def _sanitize_passive_text(self, text: str) -> str:
        """Sanitizes text, stripping null bytes and carriage returns."""
        # Remove null bytes and non-standard control characters
        text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
        # Keep printable and standard whitespace
        return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")

    def _segment_sections(self, text: str) -> Dict[str, str]:
        """Segments plain text into recognized semantic job sections."""
        lines = text.splitlines()
        sections: Dict[str, List[str]] = {"HEADER": []}
        current_section = "HEADER"

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            matched_sec = None
            # Check if this line is a section header (short line, ends with colon or bold-like)
            if len(trimmed) < 60:
                clean_header = trimmed.rstrip(":").strip()
                for sec_name, pattern in JOB_SECTION_PATTERNS.items():
                    if pattern.search(clean_header):
                        matched_sec = sec_name
                        break

            if matched_sec:
                current_section = matched_sec
                if current_section not in sections:
                    sections[current_section] = []
            else:
                sections[current_section].append(trimmed)

        return {k: "\n".join(v) for k, v in sections.items()}

    def _extract_identity(
        self,
        full_text: str,
        sections: Dict[str, str],
        hint_title: Optional[str],
        hint_company: Optional[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extracts job title and company name with hint priority."""
        title = hint_title.strip() if hint_title else None
        company = hint_company.strip() if hint_company else None

        # Clean hint title if it contains boilerplate like "Job Application for ..." or " - Careers"
        if title:
            title = re.sub(r"\s*[-|–]\s*(?:Careers|Jobs|LinkedIn|Indeed|Glassdoor).*", "", title, flags=re.IGNORECASE).strip()

        # Check explicit label patterns first (accounting for possible line indentation):
        # e.g. "Position: ...", "Job Title: ...", "Role: ..."
        title_match = re.search(r"^\s*(?:position|job\s+title|role|title)[:\s]+([^\n\r]+)", full_text, re.IGNORECASE | re.MULTILINE)
        if title_match and not title:
            title = title_match.group(1).strip()

        # e.g. "Company: ...", "Employer: ...", "Organization: ..."
        comp_match = re.search(r"^\s*(?:company|organization|employer)[:\s]+([^\n\r]+)", full_text, re.IGNORECASE | re.MULTILINE)
        if comp_match and not company:
            company = comp_match.group(1).strip()

        # If title contains "at Company" or "@ Company" and company is not yet determined
        if title and (" at " in title or " @ " in title) and not company:
            at_m = re.match(r"^(.+?)\s+(?:at|@)\s+(.+)$", title, re.IGNORECASE)
            if at_m:
                title = at_m.group(1).strip()
                company = at_m.group(2).strip()

        header_lines = [l.strip() for l in full_text.splitlines() if l.strip()][:5]

        # Company suffixes: Inc, LLC, LLP, Ltd, Hospital, University, Partners, Technologies, etc.
        company_suffix_pattern = re.compile(
            r"\b(LLP|LLC|Inc\.?|Ltd\.?|Corporation|Corp\.?|Hospital|University|Institute|Partners|Technologies|Solutions|Group)\b",
            re.IGNORECASE,
        )

        # 1. If line 0 is a stand-alone company name with suffix and no "is hiring" or "Position:"
        if header_lines and not company:
            line_0 = header_lines[0]
            if (
                len(line_0) < 60
                and company_suffix_pattern.search(line_0)
                and not re.search(r"\b(is\s+hiring|is\s+seeking|is\s+looking)\b", line_0, re.IGNORECASE)
                and not re.search(r"^(?:position|job\s+title|title|role)[:\s]", line_0, re.IGNORECASE)
            ):
                company = line_0
                if len(header_lines) > 1 and not title:
                    line_1 = re.sub(r"^(?:position|job\s+title|title|role)[:\s]+", "", header_lines[1], flags=re.IGNORECASE).strip()
                    title = line_1

        # 2. Check if any line in header has "X is hiring / looking for / seeking Y" or "X at Y"
        if not title or not company:
            for line in header_lines:
                hiring_match = re.match(r"^(.+?)\s+(?:is\s+hiring|is\s+seeking|is\s+looking\s+for)(?:\s+an?|\s+for)?\s+(.+)$", line, re.IGNORECASE)
                if hiring_match:
                    if not company:
                        company = hiring_match.group(1).strip()
                    if not title:
                        title = hiring_match.group(2).strip().rstrip(".")
                    break

                at_match = re.match(r"^(.+?)\s+(?:at|@)\s+(.+)$", line, re.IGNORECASE)
                if at_match:
                    if not title:
                        title = at_match.group(1).strip()
                    if not company:
                        company = at_match.group(2).strip()
                    break

        if not title and header_lines:
            line_0 = header_lines[0]
            if company and line_0 == company and len(header_lines) > 1:
                title = re.sub(r"^(?:position|job\s+title|title|role)[:\s]+", "", header_lines[1], flags=re.IGNORECASE).strip()
            else:
                title = line_0

        return title, company

    def _extract_bullet_items(self, section_text: str) -> List[str]:
        """Extracts individual bullet points or numbered responsibilities."""
        if not section_text:
            return []

        items: List[str] = []
        for line in section_text.splitlines():
            trimmed = line.strip()
            if not trimmed:
                continue
            # Strip bullet prefixes (-, *, •, –, 1., 2.)
            clean_item = re.sub(r"^(?:[-*•–—]|(?:\d+[.)]))\s*", "", trimmed).strip()
            if len(clean_item) > 5:
                items.append(clean_item)

        return items

    def _extract_key_deliverables(self, responsibilities: List[str]) -> List[str]:
        """Extracts high-impact deliverables from responsibilities."""
        action_verbs = re.compile(r"^(?:build|lead|design|develop|implement|architect|deliver|manage|spearhead|audit|publish)\b", re.IGNORECASE)
        return [r for r in responsibilities if action_verbs.search(r)]

    def _extract_and_classify_skills(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """Classifies skills into mandatory, preferred, tools/tech, and soft skills."""
        mandatory_text = sections.get("MANDATORY_REQUIREMENTS", "")
        preferred_text = sections.get("PREFERRED_REQUIREMENTS", "")

        mandatory_skills: List[str] = []
        preferred_skills: List[str] = []
        tools_tech: List[str] = []
        soft_skills: List[str] = []

        # Find all catalog skills present in text
        for skill in CROSS_INDUSTRY_SKILLS:
            pattern = r"\b" + re.escape(skill) + r"\b"
            if mandatory_text and re.search(pattern, mandatory_text, re.IGNORECASE):
                if skill not in mandatory_skills:
                    mandatory_skills.append(skill)
            elif preferred_text and re.search(pattern, preferred_text, re.IGNORECASE):
                if skill not in preferred_skills:
                    preferred_skills.append(skill)
            elif re.search(pattern, full_text, re.IGNORECASE):
                # If in general text without explicit section, default to mandatory if in requirements
                if skill not in mandatory_skills:
                    mandatory_skills.append(skill)

        # Distinguish tools vs soft skills
        common_soft_skills = {
            "Communication", "Leadership", "Teamwork", "Problem Solving", "Time Management",
            "Negotiation", "Critical Thinking", "Adaptability", "Collaboration",
        }
        for s in common_soft_skills:
            if re.search(r"\b" + re.escape(s) + r"\b", full_text, re.IGNORECASE):
                soft_skills.append(s)

        tools_tech = [s for s in mandatory_skills + preferred_skills if s not in soft_skills]

        return mandatory_skills, preferred_skills, tools_tech, soft_skills

    def _extract_education_and_credentials(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[List[str], List[str], Optional[float], List[str], List[str]]:
        """Extracts required degree levels, fields of study, min GPA, and licenses."""
        edu_text = sections.get("EDUCATION", "") + "\n" + sections.get("MANDATORY_REQUIREMENTS", "") + "\n" + full_text

        degrees: List[str] = []
        for pattern, level in DEGREE_LEVELS:
            if pattern.search(edu_text):
                if level not in degrees:
                    degrees.append(level)

        # Fields of study
        fields_of_study: List[str] = []
        study_patterns = [
            "Computer Science", "Information Technology", "Software Engineering", "Artificial Intelligence",
            "Data Science", "Medicine", "Nursing", "Law", "Finance", "Accounting", "Business Administration",
            "Mechanical Engineering", "Civil Engineering", "Electrical Engineering", "Marketing", "Design",
        ]
        for field_name in study_patterns:
            if re.search(r"\b" + re.escape(field_name) + r"\b", edu_text, re.IGNORECASE):
                fields_of_study.append(field_name)

        # Minimum GPA or percentage cutoff
        min_gpa: Optional[float] = None
        gpa_match = re.search(r"(?:minimum|min|cutoff|at\s+least)?\s*(?:cgpa|gpa)[:\s]*([0-9]+(?:\.[0-9]+)?)", edu_text, re.IGNORECASE)
        if gpa_match:
            try:
                min_gpa = float(gpa_match.group(1))
            except ValueError:
                pass

        # Certifications and Licenses
        licenses: List[str] = []
        certs: List[str] = []
        for pattern, lic_name in LICENSES_AND_CERTS:
            if pattern.search(edu_text):
                if "License" in lic_name or "Admission" in lic_name or "Nurse" in lic_name:
                    licenses.append(lic_name)
                else:
                    certs.append(lic_name)

        return degrees, fields_of_study, min_gpa, certs, licenses

    def _extract_experience(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[Optional[float], Optional[float], str]:
        """Extracts experience range (min, max) and level without guessing."""
        exp_text = sections.get("MANDATORY_REQUIREMENTS", "") + "\n" + sections.get("HEADER", "") + "\n" + full_text

        min_years: Optional[float] = None
        max_years: Optional[float] = None

        # Look for range: "3 - 5 years of experience" or "3 to 5 years"
        range_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*\+?\s*years?(?:\s+of\s+experience)?", exp_text, re.IGNORECASE)
        if range_match:
            try:
                min_years = float(range_match.group(1))
                max_years = float(range_match.group(2))
            except ValueError:
                pass

        # Look for single bound: "3+ years", "at least 2 years"
        if min_years is None:
            bound_match = re.search(r"(?:at least|minimum|min)\s*(\d+(?:\.\d+)?)\s*\+?\s*years?", exp_text, re.IGNORECASE)
            if not bound_match:
                bound_match = re.search(r"(\d+(?:\.\d+)?)\s*\+\s*years?(?:\s+of\s+experience)?", exp_text, re.IGNORECASE)

            if bound_match:
                try:
                    min_years = float(bound_match.group(1))
                except ValueError:
                    pass

        # Classify experience level
        exp_level = "Not Specified"
        if re.search(r"\b(intern|internship|trainee|apprentice)\b", exp_text, re.IGNORECASE):
            exp_level = "Internship"
        elif re.search(r"\b(fresher|entry[- ]level|graduate\s+program|0\s*-\s*1\s+years?)\b", exp_text, re.IGNORECASE):
            exp_level = "Entry-level"
        elif min_years is not None:
            if min_years >= 8:
                exp_level = "Executive / Director"
            elif min_years >= 5:
                exp_level = "Senior"
            elif min_years >= 2:
                exp_level = "Mid-level"
            elif min_years >= 0:
                exp_level = "Entry-level"

        return min_years, max_years, exp_level

    def _extract_employment_type(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[str, Optional[str], Optional[str]]:
        """Extracts employment type (full-time, part-time, internship), duration, and shift."""
        emp_type = "Full-time"
        if re.search(r"\bintern(?:ship)?\b", full_text, re.IGNORECASE):
            emp_type = "Internship"
        elif re.search(r"\bpart[- ]time\b", full_text, re.IGNORECASE):
            emp_type = "Part-time"
        elif re.search(r"\bcontract(?:or)?\b", full_text, re.IGNORECASE):
            emp_type = "Contract"
        elif re.search(r"\btemporary\b", full_text, re.IGNORECASE):
            emp_type = "Temporary"

        # Duration (for internships or contracts)
        duration: Optional[str] = None
        dur_match = re.search(r"(\d+\s*(?:months?|weeks?)|summer|winter|semester)", full_text, re.IGNORECASE)
        if dur_match:
            duration = dur_match.group(1).strip()

        # Shift
        schedule: Optional[str] = None
        if re.search(r"\bnight\s+shift\b", full_text, re.IGNORECASE):
            schedule = "Night Shift"
        elif re.search(r"\brotat(?:ing|ional)\s+shift\b", full_text, re.IGNORECASE):
            schedule = "Rotating"
        elif re.search(r"\bflexible\s+hours\b", full_text, re.IGNORECASE):
            schedule = "Flexible"

        return emp_type, duration, schedule

    def _extract_location_and_arrangement(
        self,
        sections: Dict[str, str],
        full_text: str,
        hint_location: Optional[str],
    ) -> Tuple[Optional[str], str]:
        """Extracts location string and work arrangement (Remote, Hybrid, On-site)."""
        location = hint_location.strip() if hint_location else None

        arrangement = "Undisclosed"
        if re.search(r"\b(remote|work\s+from\s+home|wfh|anywhere)\b", full_text, re.IGNORECASE):
            arrangement = "Remote"
        elif re.search(r"\b(hybrid|flexible\s+workplace)\b", full_text, re.IGNORECASE):
            arrangement = "Hybrid"
        elif re.search(r"\b(on[- ]site|in[- ]office|in[- ]person)\b", full_text, re.IGNORECASE):
            arrangement = "On-site"

        if not location:
            # Look for "Location: City, Country" pattern
            loc_match = re.search(r"(?:location|job\s+location|office)[:\s]+([^\n\r]+)", full_text, re.IGNORECASE)
            if loc_match:
                candidate_loc = loc_match.group(1).strip()
                if len(candidate_loc) < 80:
                    location = candidate_loc

        return location, arrangement

    def _extract_compensation(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Dict[str, Any]:
        """Extracts compensation details without fabricating values."""
        comp_text = sections.get("BENEFITS", "") + "\n" + full_text

        result: Dict[str, Any] = {
            "disclosed": False,
            "raw_text": None,
            "currency": None,
            "min": None,
            "max": None,
            "period": None,
            "benefits": [],
        }

        # Check currency and salary/stipend pattern
        curr_match = re.search(
            r"(₹|\$|€|£|\b(?:rs\.?|inr|usd|eur|gbp)\b)\s*([0-9]+[0-9,]*(?:\s*-\s*[0-9]+[0-9,]*)?(?:\s*(?:k|lakhs?|lpa|lac))?)",
            comp_text,
            re.IGNORECASE,
        )
        if curr_match:
            result["disclosed"] = True
            result["raw_text"] = curr_match.group(0).strip()
            curr_symbol = curr_match.group(1).upper()
            result["currency"] = "INR" if curr_symbol in ("₹", "RS", "RS.", "INR") else "USD" if curr_symbol in ("$", "USD") else curr_symbol

            period_match = re.search(r"/\s*(?:yr|year|annum|month|mo|pm|hr|hour)", comp_text, re.IGNORECASE)
            if period_match:
                p = period_match.group(0).lower()
                if "yr" in p or "year" in p or "annum" in p:
                    result["period"] = "per year"
                elif "mo" in p or "month" in p or "pm" in p:
                    result["period"] = "per month"
                elif "hr" in p or "hour" in p:
                    result["period"] = "per hour"

        # Extract benefits (health insurance, 401k, etc.)
        benefits_catalog = [
            "Health Insurance", "Dental", "Vision", "401(k)", "Provident Fund", "PF",
            "Paid Time Off", "PTO", "Parental Leave", "Stock Options", "Equity", "Gym Membership",
        ]
        for b in benefits_catalog:
            if re.search(r"\b" + re.escape(b) + r"\b", comp_text, re.IGNORECASE):
                result["benefits"].append(b)

        return result

    def _extract_dates(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extracts application deadline, start date, and posting date."""
        deadline: Optional[str] = None
        dl_match = re.search(r"(?:apply\s+by|deadline|applications\s+close)[:\s]*([0-9]{1,2}(?:st|nd|rd|th)?\s+[a-z]{3,9}(?:\s+[0-9]{2,4})?|[0-9]{4}-[0-9]{2}-[0-9]{2})", full_text, re.IGNORECASE)
        if dl_match:
            deadline = dl_match.group(1).strip()

        start_date: Optional[str] = None
        st_match = re.search(r"(?:start\s+date|starting)[:\s]*([0-9]{1,2}(?:st|nd|rd|th)?\s+[a-z]{3,9}(?:\s+[0-9]{2,4})?|[a-z]+\s+[0-9]{4})", full_text, re.IGNORECASE)
        if st_match:
            start_date = st_match.group(1).strip()

        posting_date: Optional[str] = None
        pd_match = re.search(r"(?:posted\s+on|posted|date\s+posted)[:\s]*([0-9]{1,2}(?:st|nd|rd|th)?\s+[a-z]{3,9}(?:\s+[0-9]{2,4})?|[0-9]{4}-[0-9]{2}-[0-9]{2})", full_text, re.IGNORECASE)
        if pd_match:
            posting_date = pd_match.group(1).strip()

        return deadline, start_date, posting_date

    def _extract_application_instructions(
        self,
        sections: Dict[str, str],
        full_text: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str], List[str], List[str]]:
        """Extracts application URL, email, instructions, and required documents."""
        app_text = sections.get("HOW_TO_APPLY", "") + "\n" + full_text

        # Email
        email_match = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", app_text)
        app_email = email_match.group(0) if email_match else None

        # URL
        url_match = re.search(r"https?://[^\s<>\"']+", sections.get("HOW_TO_APPLY", ""))
        app_url = url_match.group(0) if url_match else None

        # Required documents
        doc_catalog = ["Resume", "CV", "Cover Letter", "Portfolio", "Transcripts", "Writing Sample", "References"]
        req_docs: List[str] = []
        for d in doc_catalog:
            if re.search(r"\b" + re.escape(d) + r"\b", app_text, re.IGNORECASE):
                if d not in req_docs:
                    req_docs.append(d)

        instructions = sections.get("HOW_TO_APPLY", "").strip() or None

        # Screening questions (lines ending with question marks in application section)
        screening_qs: List[str] = []
        for line in app_text.splitlines():
            line_str = line.strip()
            if line_str.endswith("?") and len(line_str) > 15:
                screening_qs.append(line_str)

        return app_url, app_email, instructions, req_docs, screening_qs
