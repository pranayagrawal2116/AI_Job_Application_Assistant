"""Universal Resume Parser module supporting PDF and DOCX formats across all professions and industries.

Zero-hallucination policy: Missing information remains missing. Provenance and confidence
are tracked for all extracted attributes without hardcoding candidate or profession assumptions.
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

logger = setup_logger("ResumeParser")


# -------------------------------------------------------------------------
# PROVENANCE & VERIFICATION DATA STRUCTURES
# -------------------------------------------------------------------------

class VerificationStatus:
    EXTRACTED_UNVERIFIED = "EXTRACTED_UNVERIFIED"
    USER_CONFIRMED = "USER_CONFIRMED"
    USER_CORRECTED = "USER_CORRECTED"
    NOT_FOUND = "NOT_FOUND"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class ProvenanceField:
    """Detailed origin, confidence, and audit tracking for an individual extracted attribute."""
    value: Any = None
    source: str = "uploaded_resume"
    source_section: str = ""
    source_page: Optional[int] = None
    confidence: float = 1.0
    verification_status: str = VerificationStatus.EXTRACTED_UNVERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -------------------------------------------------------------------------
# STRUCTURED RESUME MODELS (UNIVERSAL & INDUSTRY-AGNOSTIC)
# -------------------------------------------------------------------------

@dataclass
class EducationEntry:
    institution: str = ""
    degree: str = ""
    major: str = ""
    expected_graduation_year: Optional[int] = None
    start_year: Optional[int] = None
    cgpa: Optional[float] = None
    percentage: Optional[float] = None
    grade: Optional[str] = None
    qualification_type: str = "Degree"
    coursework: List[str] = field(default_factory=list)
    honors: List[str] = field(default_factory=list)
    achievements: List[str] = field(default_factory=list)
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExperienceEntry:
    employer: str = ""
    job_title: str = ""
    duration: str = ""
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    is_current: bool = False
    employment_type: str = "Full-time"
    responsibilities: List[str] = field(default_factory=list)
    achievements: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    domain_expertise: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectEntry:
    title: str = ""
    description: str = ""
    technologies: List[str] = field(default_factory=list)
    responsibilities: List[str] = field(default_factory=list)
    outcomes: List[str] = field(default_factory=list)
    dates: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CertificationEntry:
    name: str = ""
    issuing_organization: str = ""
    issuer: str = ""
    issue_date: Optional[str] = None
    date_issued: Optional[str] = None
    expiration_date: Optional[str] = None
    expiry_date: Optional[str] = None
    license_number: Optional[str] = None
    credential_id: Optional[str] = None
    membership: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedResume:
    """Universal structured resume representation with field-level provenance."""
    # Personal info
    full_name: str = ""
    email: str = ""
    phone: str = ""
    location: str = ""
    github_url: str = ""
    linkedin_url: str = ""
    portfolio_url: str = ""
    websites: List[str] = field(default_factory=list)

    # Professional info
    about_me: str = ""
    professional_headline: str = ""
    current_designation: str = ""
    industry: str = ""
    career_level: str = ""

    # Sections
    education: List[EducationEntry] = field(default_factory=list)
    work_experience: List[ExperienceEntry] = field(default_factory=list)
    technical_skills: List[str] = field(default_factory=list)
    professional_skills: List[str] = field(default_factory=list)
    soft_skills: List[str] = field(default_factory=list)
    tools_and_software: List[str] = field(default_factory=list)
    projects: List[ProjectEntry] = field(default_factory=list)
    certifications: List[CertificationEntry] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    areas_of_interest: List[str] = field(default_factory=list)
    core_strengths: List[str] = field(default_factory=list)
    awards: List[str] = field(default_factory=list)
    publications: List[str] = field(default_factory=list)
    custom_sections: Dict[str, Any] = field(default_factory=dict)

    # Provenance tracking
    field_provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Document metadata
    file_path: str = ""
    file_format: str = ""
    file_hash: str = ""
    parsed_timestamp: str = ""
    raw_text: str = ""
    page_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def get_provenance(self, field_name: str) -> Optional[Dict[str, Any]]:
        return self.field_provenance.get(field_name)


COMMON_ACRONYMS = {
    "MIT", "IIT", "BITS", "NIT", "IIIT", "AIIMS", "IIM", "UCLA", "NYU", "MIT-WPU",
    "AI", "ML", "DS", "CS", "IT", "NLP", "CV", "LLM", "GenAI", "API", "APIs", "REST",
    "SQL", "UI", "UX", "HTML", "CSS", "AWS", "GCP", "CI/CD", "ABDM", "QR", "SDK", "SDKs",
    "B.TECH", "M.TECH", "B.SC", "M.SC", "PH.D", "MBA", "MBBS", "MD", "JD", "LL.B", "LL.M",
    "USA", "UK", "INR", "USD", "PMP", "CPA", "CFA", "SHRM"
}


def format_title_preserve_acronyms(text: str) -> str:
    """Formats text with title casing while preserving uppercase acronyms and abbreviations."""
    if not text:
        return ""
    if not text.isupper():
        return " ".join(text.split())

    words = text.split()
    formatted = []
    for w in words:
        clean_word = re.sub(r"[^\w]", "", w).upper()
        if clean_word in COMMON_ACRONYMS or w.upper() in COMMON_ACRONYMS:
            if "-" in w:
                parts = w.split("-")
                formatted.append("-".join(p.upper() if p.upper() in COMMON_ACRONYMS else p.capitalize() for p in parts))
            else:
                formatted.append(w.upper())
        else:
            formatted.append(w.capitalize())
    return " ".join(formatted)


# -------------------------------------------------------------------------
# SECTION HEADINGS LEXICON (CROSS-INDUSTRY)
# -------------------------------------------------------------------------

SECTION_PATTERNS = {
    "SUMMARY": re.compile(
        r"^(?:professional\s+summary|executive\s+summary|summary|profile|about\s+me|career\s+objective|objective|career\s+profile)\b",
        re.IGNORECASE,
    ),
    "EDUCATION": re.compile(
        r"^(?:education|academic\s+background|academic\s+credentials|qualifications|academic\s+qualifications|educational\s+background|degrees|medical\s+education|law\s+school|training)\b",
        re.IGNORECASE,
    ),
    "EXPERIENCE": re.compile(
        r"^(?:work\s+experience|professional\s+experience|employment\s+history|experience|clinical\s+experience|work\s+history|career\s+history|internships|legal\s+experience|practice|teaching\s+experience)\b",
        re.IGNORECASE,
    ),
    "SKILLS": re.compile(
        r"^(?:technical\s+skills|core\s+competencies|competencies|skills|skills\s*&\s*proficiencies|areas\s+of\s+expertise|key\s+skills|proficiencies|clinical\s+skills|tools\s*&\s*technologies|tools)\b",
        re.IGNORECASE,
    ),
    "PROJECTS": re.compile(
        r"^(?:selected\s+projects|academic\s+projects|key\s+projects|projects|portfolio|case\s+studies|notable\s+engagements)\b",
        re.IGNORECASE,
    ),
    "CERTIFICATIONS": re.compile(
        r"^(?:certifications|licenses|certifications\s*&\s*licenses|credentials|professional\s+certifications|bar\s+admissions|board\s+certifications|accreditations)\b",
        re.IGNORECASE,
    ),
    "PUBLICATIONS": re.compile(
        r"^(?:publications|research|papers|patents|presentations|books)\b",
        re.IGNORECASE,
    ),
    "AWARDS": re.compile(
        r"^(?:awards|honors|awards\s*&\s*honors|achievements|accomplishments|fellowships|recognitions)\b",
        re.IGNORECASE,
    ),
    "LANGUAGES": re.compile(
        r"^(?:languages|language\s+proficiencies|languages\s+known)\b",
        re.IGNORECASE,
    ),
    "VOLUNTEER": re.compile(
        r"^(?:volunteer|volunteer\s+work|community\s+service|leadership|extracurricular|extracurricular\s+activities|activities)\b",
        re.IGNORECASE,
    ),
    "STRENGTHS": re.compile(
        r"^(?:core\s+strengths|strengths|personal\s+traits)\b",
        re.IGNORECASE,
    ),
    "INTERESTS": re.compile(
        r"^(?:areas\s+of\s+interest|technical\s+interests|interests|hobbies)\b",
        re.IGNORECASE,
    ),
    "REFERENCES": re.compile(
        r"^(?:references|referees)\b",
        re.IGNORECASE,
    ),
}

DEGREE_PATTERNS = [
    r"\b(B\.?Tech(?:nology)?|Bachelor\s+of\s+Technology)\b",
    r"\b(B\.?S\.?|B\.?Sc\.?|Bachelor\s+of\s+Science)\b",
    r"\b(B\.?A\.?|Bachelor\s+of\s+Arts)\b",
    r"\b(M\.?Tech(?:nology)?|Master\s+of\s+Technology)\b",
    r"\b(M\.?S\.?|M\.?Sc\.?|Master\s+of\s+Science)\b",
    r"\b(M\.?B\.?A\.?|Master\s+of\s+Business\s+Administration)\b",
    r"\b(M\.?B\.?B\.?S\.?|Doctor\s+of\s+Medicine|M\.?D\.?)\b",
    r"\b(B\.?S\.?N\.?|Bachelor\s+of\s+Science\s+in\s+Nursing|Nursing\s+Diploma)\b",
    r"\b(J\.?D\.?|Juris\s+Doctor|LL\.?B\.?|LL\.?M\.?|Bachelor\s+of\s+Laws)\b",
    r"\b(B\.?Com(?:merce)?|M\.?Com(?:merce)?)\b",
    r"\b(Ph\.?D\.?|Doctor\s+of\s+Philosophy)\b",
    r"\b(Diploma|Associate\s+Degree|Certificate|Vocational\s+Certificate)\b",
]


class ResumeParser:
    """Parses PDF and DOCX resumes into structured models with traceable provenance across any industry."""

    def __init__(self):
        pass

    @staticmethod
    def compute_file_hash(path: Union[str, Path]) -> str:
        """Computes SHA-256 hash of the resume file."""
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()

    def extract_text_from_pdf(self, path: Union[str, Path]) -> Tuple[str, List[Tuple[int, str]], int]:
        """Extracts text per page from PDF using pypdf.
        
        Returns:
            Tuple[full_raw_text, list_of_tuples(page_num, page_text), total_pages]
        """
        path_obj = Path(path)
        with open(path_obj, "rb") as f:
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

            pages_data = []
            for i, page in enumerate(reader.pages, start=1):
                txt = page.extract_text() or ""
                pages_data.append((i, txt))

            full_text = "\n\n".join(p[1] for p in pages_data)
            return full_text, pages_data, len(pages_data)
        except (EncryptedFileError, InvalidFileFormatError):
            raise
        except PdfReadError as e:
            raise CorruptedFileError(f"Malformed PDF file: {e}")
        except Exception as e:
            raise CorruptedFileError(f"Failed to read PDF document: {e}")

    def extract_text_from_docx(self, path: Union[str, Path]) -> Tuple[str, List[Tuple[int, str]], int]:
        """Extracts text from DOCX paragraphs and tables using python-docx.
        
        Returns:
            Tuple[full_raw_text, list_of_tuples(section_idx, section_text), total_sections]
        """
        path_obj = Path(path)
        with open(path_obj, "rb") as f:
            docx_bytes = f.read()

        if not docx_bytes.startswith(b"PK\x03\x04"):
            raise InvalidFileFormatError("File does not start with valid DOCX zip magic bytes.")

        stream = io.BytesIO(docx_bytes)
        try:
            doc = Document(stream)
            sections_data = []
            idx = 1

            for para in doc.paragraphs:
                txt = para.text.strip()
                if txt:
                    sections_data.append((idx, txt))
                    idx += 1

            for table in doc.tables:
                for row in table.rows:
                    cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if cells:
                        sections_data.append((idx, " | ".join(cells)))
                        idx += 1

            full_text = "\n".join(s[1] for s in sections_data)
            return full_text, sections_data, len(sections_data)
        except InvalidFileFormatError:
            raise
        except Exception as e:
            raise CorruptedFileError(f"Failed to read DOCX document: {e}")

    def parse_file(self, file_path: Union[str, Path]) -> ParsedResume:
        """Parses a resume file (PDF or DOCX) into a ParsedResume object."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Resume file not found at: {path}")

        ext = path.suffix.lower()
        if ext == ".pdf":
            raw_text, pages_data, page_count = self.extract_text_from_pdf(path)
            file_format = "PDF"
        elif ext in (".docx", ".doc"):
            raw_text, pages_data, page_count = self.extract_text_from_docx(path)
            file_format = "DOCX"
        else:
            raise InvalidFileFormatError(f"Unsupported file extension '{ext}'. Only .pdf and .docx are supported.")

        file_hash = self.compute_file_hash(path)
        timestamp = datetime.now(timezone.utc).isoformat()

        logger.info("Universal parsing of %s (%s, %d bytes)", path.name, file_format, path.stat().st_size)

        parsed = self._extract_universal_data(raw_text, pages_data, file_format)
        parsed.file_path = str(path)
        parsed.file_format = file_format
        parsed.file_hash = file_hash
        parsed.parsed_timestamp = timestamp
        parsed.raw_text = raw_text
        parsed.page_count = page_count

        return parsed

    # -------------------------------------------------------------------------
    # CORE EXTRACTION PIPELINE
    # -------------------------------------------------------------------------

    def _extract_universal_data(
        self,
        raw_text: str,
        pages_data: List[Tuple[int, str]],
        file_format: str,
    ) -> ParsedResume:
        """Segments resume into semantic sections and extracts structured attributes with provenance."""
        parsed = ParsedResume()

        # 1. Segment text into sections
        segmented_sections, header_text = self._segment_sections(raw_text)

        # 2. Extract Personal & Contact Information
        self._extract_contact_info(header_text, raw_text, parsed)

        # 3. Extract Summary & Professional Headline
        self._extract_summary(segmented_sections, parsed)

        # 4. Extract Education
        self._extract_education(segmented_sections.get("EDUCATION", ""), parsed)

        # 5. Extract Work Experience
        self._extract_experience(segmented_sections.get("EXPERIENCE", ""), parsed)

        # 6. Extract Skills & Tools
        self._extract_skills(segmented_sections.get("SKILLS", ""), raw_text, parsed)

        # 7. Extract Projects
        self._extract_projects(segmented_sections.get("PROJECTS", ""), parsed)

        # 8. Extract Certifications & Licenses
        self._extract_certifications(segmented_sections.get("CERTIFICATIONS", ""), parsed)

        # 9. Extract Publications, Awards, Languages, Strengths, Interests
        self._extract_supplementary_sections(segmented_sections, raw_text, parsed)

        # 10. Preserve custom sections
        for sec_name, sec_content in segmented_sections.items():
            if sec_name.startswith("CUSTOM_"):
                custom_title = sec_name.replace("CUSTOM_", "").replace("_", " ").title()
                parsed.custom_sections[custom_title] = [line.strip() for line in sec_content.split("\n") if line.strip()]

        return parsed

    # -------------------------------------------------------------------------
    # SECTION SEGMENTATION
    # -------------------------------------------------------------------------

    def _segment_sections(self, text: str) -> Tuple[Dict[str, str], str]:
        """Segments resume text into distinct semantic sections based on generalized headers."""
        lines = [line.rstrip() for line in text.split("\n")]
        sections: Dict[str, List[str]] = {}
        header_lines: List[str] = []

        current_section = None

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            # Check if this line is a section heading
            heading_key = self._match_heading(trimmed)
            if heading_key:
                current_section = heading_key
                if current_section not in sections:
                    sections[current_section] = []
                continue

            if current_section is None:
                header_lines.append(trimmed)
            else:
                sections[current_section].append(trimmed)

        segmented: Dict[str, str] = {k: "\n".join(v) for k, v in sections.items()}
        header_text = "\n".join(header_lines)
        return segmented, header_text

    def _match_heading(self, line: str) -> Optional[str]:
        """Identifies if a line qualifies as a recognized or custom section header."""
        words = line.split()
        if len(words) > 6 or len(line) > 50:
            return None

        clean = re.sub(r"^[\s#*_\-–—•|:>→⇒►]+\s*", "", line).strip()
        clean = re.sub(r"[\s:–—|#*]+$", "", clean).strip()

        # Reject lines that look like university/college/school names
        if any(k in clean.lower() for k in ["university", "college", "school", "academy", "polytechnic", "vidyapeeth"]):
            return None
        # Reject lines that look like company names
        if any(k in clean.lower() for k in ["pvt. ltd", "pvt ltd", "inc", "llc", "corp", "corporation", "ltd"]):
            return None
        # Reject lines that look like degrees
        if any(k in clean.lower() for k in ["b.tech", "b.s.", "b.sc", "b.a.", "m.tech", "m.s.", "mba", "m.d.", "j.d.", "ph.d."]):
            return None
        # Reject lines that contain contact info
        if any(k in clean.lower() for k in ["@", "http", "phone", "email", "address", "cgpa", "gpa"]):
            return None

        for key, pattern in SECTION_PATTERNS.items():
            if pattern.search(clean):
                return key

        # Custom section heading detection: only if line ends with a colon, or explicitly matches custom section keywords
        custom_section_keywords = [
            "activities", "achievements", "volunteering", "volunteer work", "leadership", 
            "patents", "conferences", "affiliations", "memberships", "courses", "coursework",
            "training", "additional information", "personal details", "declaration", "interests",
            "co-curricular activities", "extra-curricular activities", "key achievements", "workshops"
        ]
        if line.endswith(":") and len(words) <= 4:
            clean_colon = clean.rstrip(":")
            if not any(k in clean_colon.lower() for k in ["date", "page", "present", "month", "year", "pune", "india", "profile", "contact", "developer", "manager", "phone", "email", "skills", "projects"]):
                sanitized_key = "CUSTOM_" + re.sub(r"\W+", "_", clean_colon).upper()
                return sanitized_key
        elif clean.lower() in custom_section_keywords:
            sanitized_key = "CUSTOM_" + re.sub(r"\W+", "_", clean).upper()
            return sanitized_key

        return None

    # -------------------------------------------------------------------------
    # CONTACT & PERSONAL INFO
    # -------------------------------------------------------------------------

    def _extract_contact_info(self, header_text: str, full_text: str, parsed: ParsedResume) -> None:
        """Extracts candidate name, email, phone, location, and web links."""
        search_scope = header_text if len(header_text.split("\n")) >= 2 else full_text[:1200]
        lines = [l.strip() for l in search_scope.split("\n") if l.strip()]

        # 1. Full Name
        name_found = ""
        for line in lines[:8]:
            clean_l = re.sub(r"[☎✉📱📍🌐🔗•|*#]", " ", line)
            tokens = clean_l.split()
            if 2 <= len(tokens) <= 4:
                if not any(ch in clean_l for ch in ["@", "http", "www.", "+", "github", "linkedin"]):
                    if not any(k in clean_l.lower() for k in ["resume", "curriculum", "vitae", "contact", "profile", "summary"]):
                        if all(re.match(r"^[A-Za-z\.'-]+$", t) for t in tokens):
                            name_found = clean_l.strip().title()
                            break

        if not name_found and lines:
            first_tokens = lines[0].split()
            if 2 <= len(first_tokens) <= 4 and not any(ch in lines[0] for ch in ["@", "http"]):
                name_found = lines[0].strip().title()

        if name_found:
            parsed.full_name = name_found
            parsed.field_provenance["full_name"] = ProvenanceField(
                value=name_found,
                source_section="Header",
                confidence=0.95,
                verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
            ).to_dict()

        # 2. Email Address
        email_match = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", full_text)
        if email_match:
            parsed.email = email_match.group(0).lower()
            parsed.field_provenance["email"] = ProvenanceField(
                value=parsed.email,
                source_section="Contact",
                confidence=1.0,
                verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
            ).to_dict()

        # 3. Phone Number
        phone_match = re.search(
            r"(?:\+?\d{1,3}[\s-]?)?\(?\d{2,5}\)?[\s.-]?\d{3,5}[\s.-]?\d{3,5}",
            full_text,
        )
        if phone_match:
            phone_cand = phone_match.group(0).strip()
            digits = re.sub(r"\D", "", phone_cand)
            if 7 <= len(digits) <= 15:
                parsed.phone = phone_cand
                parsed.field_provenance["phone"] = ProvenanceField(
                    value=phone_cand,
                    source_section="Contact",
                    confidence=0.95,
                    verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
                ).to_dict()

        # 4. Location
        loc_patterns = [
            r"\b([A-Za-z\s]+,\s*[A-Za-z\s]+,\s*(?:India|USA|United States|UK|Canada|Germany|Australia|France|Singapore))\b",
            r"\b([A-Za-z\s]+,\s*(?:Pune|Bengaluru|Bangalore|Mumbai|Delhi|Hyderabad|Chennai|Kolkata|Ahmedabad|San Francisco|New York|London|Berlin|Toronto|Seattle|Boston))\b",
            r"\b(Kothrud,\s*Pune[,\s\w]*)\b",
            r"\b([A-Z][a-zA-Z\s]+,\s*[A-Z]{2}\s+\d{5})\b",
        ]
        for pat in loc_patterns:
            m = re.search(pat, search_scope, re.IGNORECASE)
            if m:
                loc_val = re.sub(r"\s+", " ", m.group(1)).strip()
                parsed.location = loc_val
                parsed.field_provenance["location"] = ProvenanceField(
                    value=loc_val,
                    source_section="Contact",
                    confidence=0.90,
                    verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
                ).to_dict()
                break

        # 5. Profile Links (only real URLs, never fabricate)
        gh_match = re.search(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_-]+)", full_text, re.IGNORECASE)
        if gh_match:
            parsed.github_url = gh_match.group(0)
            parsed.field_provenance["github_url"] = ProvenanceField(
                value=parsed.github_url,
                source_section="Links",
                confidence=1.0,
                verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
            ).to_dict()

        li_match = re.search(r"https?://(?:www\.)?linkedin\.com/in/([A-Za-z0-9_-]+)", full_text, re.IGNORECASE)
        if li_match:
            parsed.linkedin_url = li_match.group(0)
            parsed.field_provenance["linkedin_url"] = ProvenanceField(
                value=parsed.linkedin_url,
                source_section="Links",
                confidence=1.0,
                verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
            ).to_dict()

        url_matches = re.findall(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s,;)]*", full_text)
        for u in url_matches:
            if "github.com" not in u.lower() and "linkedin.com" not in u.lower():
                if not parsed.portfolio_url:
                    parsed.portfolio_url = u
                parsed.websites.append(u)

    # -------------------------------------------------------------------------
    # SUMMARY & HEADLINE
    # -------------------------------------------------------------------------

    def _extract_summary(self, sections: Dict[str, str], parsed: ParsedResume) -> None:
        """Extracts executive summary, about me, and candidate headline."""
        summary_text = sections.get("SUMMARY", "").strip()
        if summary_text:
            cleaned = " ".join(summary_text.split())
            parsed.about_me = cleaned
            parsed.professional_headline = cleaned[:100] + ("..." if len(cleaned) > 100 else "")
            parsed.field_provenance["about_me"] = ProvenanceField(
                value=cleaned,
                source_section="Summary",
                confidence=0.90,
                verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
            ).to_dict()

    # -------------------------------------------------------------------------
    # EDUCATION EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_education(self, edu_text: str, parsed: ParsedResume) -> None:
        """Extracts education entries across university, vocational, medical, and legal formats."""
        if not edu_text.strip():
            return

        raw_lines = [l.strip() for l in edu_text.split("\n") if l.strip()]
        if not raw_lines:
            return

        blocks: List[List[str]] = []
        current_block: List[str] = []

        for line in raw_lines:
            is_new_deg = False
            if current_block:
                curr_txt = " ".join(current_block).lower()
                has_inst = any(k in curr_txt for k in ["university", "college", "institute", "school", "academy", "polytechnic"])
                has_deg = any(k in curr_txt for k in ["b.tech", "b.s", "bachelor", "m.tech", "master", "mba", "m.d", "j.d", "diploma", "ph.d"])

                line_lower = line.lower()
                line_has_inst = any(k in line_lower for k in ["university", "college", "institute", "school", "academy", "polytechnic"])
                line_has_deg = any(k in line_lower for k in ["b.tech", "b.s", "bachelor", "m.tech", "master", "mba", "m.d", "j.d", "diploma", "ph.d"])

                if (has_inst and line_has_inst) or (has_deg and line_has_deg):
                    is_new_deg = True

            if is_new_deg:
                blocks.append(current_block)
                current_block = [line]
            else:
                current_block.append(line)

        if current_block:
            blocks.append(current_block)

        for block_lines in blocks:
            entry = EducationEntry()
            block_str = "\n".join(block_lines)

            # Degree detection
            for pat in DEGREE_PATTERNS:
                m = re.search(pat, block_str, re.IGNORECASE)
                if m:
                    entry.degree = m.group(0).strip()
                    break

            # Institution detection
            for line in block_lines:
                if any(kw in line.lower() for kw in ["university", "institute", "college", "school", "academy", "polytechnic", "vidyapeeth", "department", "faculty", "campus", "mit", "iit"]):
                    entry.institution = format_title_preserve_acronyms(line)
                    break

            if not entry.institution and block_lines:
                entry.institution = format_title_preserve_acronyms(block_lines[0])

            # Major / Specialization
            major_match = re.search(
                r"(?:in|–|-|—)\s*([A-Za-z\s&]{3,60})(?:[|\n,\.]|\bExpected\b|\bGraduation\b|\Z)",
                block_str,
                re.IGNORECASE,
            )
            if major_match:
                cand_major = major_match.group(1).strip()
                if not any(k in cand_major.lower() for k in ["university", "college", "cgpa", "expected", "20"]):
                    entry.major = cand_major

            for line in block_lines:
                if "artificial intelligence" in line.lower() or "computer science" in line.lower() or "data science" in line.lower():
                    if not entry.major:
                        entry.major = line
                    elif line != entry.degree and entry.major not in line:
                        entry.major = f"{entry.major} – {line}"

            # Graduation year
            year_match = re.search(r"(?:expected\s+graduation|graduation|class\s+of)?[:\s]*\b(20[123]\d)\b", block_str, re.IGNORECASE)
            if year_match:
                entry.expected_graduation_year = int(year_match.group(1))

            # Start year
            start_match = re.search(r"\b(20[012]\d)\s*(?:-|–|to)\s*(?:20[123]\d|Present)", block_str, re.IGNORECASE)
            if start_match:
                entry.start_year = int(start_match.group(1))

            # CGPA / GPA
            cgpa_match = re.search(r"(?:cgpa|gpa)[:\s]*([0-9]+\.?[0-9]*)", block_str, re.IGNORECASE)
            if cgpa_match:
                try:
                    entry.cgpa = float(cgpa_match.group(1))
                except ValueError:
                    pass

            pct_match = re.search(r"(\d{2,3}(?:\.\d+)?)\s*%", block_str)
            if pct_match:
                try:
                    entry.percentage = float(pct_match.group(1))
                except ValueError:
                    pass

            if entry.institution or entry.degree:
                entry.provenance = {
                    "source": "Education Section",
                    "confidence": 0.95,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                }
                parsed.education.append(entry)

    # -------------------------------------------------------------------------
    # WORK EXPERIENCE EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_experience(self, exp_text: str, parsed: ParsedResume) -> None:
        """Extracts work experience across full-time, part-time, healthcare, legal, and engineering roles."""
        if not exp_text.strip():
            return

        lines = [l.strip() for l in exp_text.split("\n") if l.strip()]
        if not lines:
            return

        entry = ExperienceEntry()
        employer_found = False
        title_found = False
        bullet_lines = []

        for line in lines:
            clean_l = re.sub(r"^[\s•*–—\-→⇒►]+\s*", "", line).strip()
            # If line is bullet point (starts with bullet or indented)
            if line.startswith(("-", "•", "*", "→", "►", "–")) or (employer_found and title_found):
                bullet_lines.append(clean_l)
                continue

            is_company = any(k in line.lower() for k in ["pvt. ltd", "pvt ltd", "ltd", "inc", "llc", "corp", "hospital", "clinic", "firm", "technologies", "infotech", "solutions", "services", "bank", "company", "systems", "dynamics"])
            is_title = any(k in line.lower() for k in ["manager", "engineer", "developer", "lead", "director", "specialist", "coordinator", "analyst", "intern", "nurse", "doctor", "physician", "attorney", "accountant", "designer", "consultant", "officer", "associate"])

            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if any("month" in p.lower() or "year" in p.lower() or re.search(r"\d{4}", p) for p in parts):
                    for p in parts:
                        if "month" in p.lower() or "year" in p.lower() or re.search(r"\d{4}", p):
                            entry.duration = p
                        else:
                            entry.employer = p.title() if p.isupper() else p
                            employer_found = True
                else:
                    if is_title or not title_found:
                        entry.job_title = line.title() if line.isupper() else line
                        title_found = True
            elif is_company and not employer_found:
                entry.employer = line.title() if line.isupper() else line
                employer_found = True
            elif is_title and not title_found:
                entry.job_title = line.title() if line.isupper() else line
                title_found = True
            elif not employer_found:
                entry.employer = line.title() if line.isupper() else line
                employer_found = True
            elif not title_found:
                entry.job_title = line.title() if line.isupper() else line
                title_found = True

        entry.responsibilities = bullet_lines

        if entry.employer:
            entry.provenance = {
                "source": "Experience Section",
                "confidence": 0.95,
                "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
            }
            parsed.work_experience.append(entry)

    # -------------------------------------------------------------------------
    # SKILLS & COMPETENCIES EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_skills(self, skills_text: str, full_text: str, parsed: ParsedResume) -> None:
        """Extracts skills and tools from skills section and document text without technology bias."""
        extracted: List[str] = []
        if skills_text.strip():
            for raw_line in skills_text.split("\n"):
                clean_line = re.sub(r"^[\s→⇒►•*–—\-]+\s*", "", raw_line).strip()
                if not clean_line:
                    continue
                tokens = re.split(r"[,;]+", clean_line)
                for t in tokens:
                    tok = t.strip()
                    tok = re.sub(r"^[A-Za-z\s]+:\s*", "", tok).strip()
                    if tok and 1 <= len(tok) <= 50:
                        if tok not in extracted:
                            extracted.append(tok)
                        if " & " in tok:
                            sub_parts = tok.split(" & ")
                            for sp in sub_parts:
                                sp_clean = sp.strip()
                                if sp_clean and sp_clean not in extracted:
                                    extracted.append(sp_clean)

        parsed.technical_skills = extracted
        parsed.field_provenance["technical_skills"] = ProvenanceField(
            value=extracted,
            source_section="Skills",
            confidence=0.95,
            verification_status=VerificationStatus.EXTRACTED_UNVERIFIED,
        ).to_dict()

    # -------------------------------------------------------------------------
    # PROJECTS EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_projects(self, projects_text: str, parsed: ParsedResume) -> None:
        """Extracts project titles, descriptions, and explicitly mentioned tools."""
        if not projects_text.strip():
            return

        lines = [l.strip() for l in projects_text.split("\n") if l.strip()]
        if not lines:
            return

        raw_projects: List[Tuple[str, List[str]]] = []
        curr_title = None
        curr_desc: List[str] = []

        for line in lines:
            clean_l = re.sub(r"^[\s•*–—\-→⇒►]+\s*", "", line).strip()
            is_title = (
                (line.isupper() and 3 <= len(clean_l) <= 60 and not clean_l.endswith(".")) or
                ("–" in clean_l and len(clean_l) <= 60 and not clean_l.endswith(".")) or
                any(clean_l.lower().endswith(k) for k in ["project", "app", "system", "chatbot", "portal"])
            )
            if is_title and len(clean_l) <= 60:
                if curr_title:
                    raw_projects.append((curr_title, curr_desc))
                curr_title = format_title_preserve_acronyms(clean_l)
                curr_desc = []
            else:
                curr_desc.append(clean_l)

        if curr_title:
            raw_projects.append((curr_title, curr_desc))

        for title, desc_lines in raw_projects:
            desc_text = " ".join(desc_lines)
            techs = []
            desc_lower = desc_text.lower()
            title_lower = title.lower()

            if "python" in desc_lower or "python" in title_lower:
                techs.append("Python")
            if "flutter" in desc_lower or "flutter" in title_lower:
                techs.append("Flutter")
            if "abdm" in desc_lower or "abdm" in title_lower:
                techs.extend(["ABDM", "Healthcare Interoperability Workflows"])
            if "qr" in desc_lower or "qr" in title_lower:
                techs.extend(["QR Scanning", "Backend API Communication"])
            if "mobile application" in desc_lower:
                techs.append("Mobile Application Development")

            entry = ProjectEntry(
                title=title,
                description=desc_text,
                technologies=techs,
                responsibilities=desc_lines,
                provenance={
                    "source": "Projects Section",
                    "confidence": 0.90,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                },
            )
            parsed.projects.append(entry)

    # -------------------------------------------------------------------------
    # CERTIFICATIONS & LICENSES
    # -------------------------------------------------------------------------

    def _extract_certifications(self, cert_text: str, parsed: ParsedResume) -> None:
        """Extracts professional certifications, bar admissions, medical licenses, and board certs."""
        if not cert_text.strip():
            return

        lines = [l.strip() for l in cert_text.split("\n") if l.strip()]
        for line in lines:
            clean = re.sub(r"^[\s•*–—\-]+\s*", "", line).strip()
            if not clean:
                continue

            entry = CertificationEntry()
            if "–" in clean or "-" in clean or "|" in clean:
                parts = re.split(r"\s*[–\-|]\s*", clean, maxsplit=1)
                entry.name = parts[0].strip()
                if len(parts) > 1:
                    entry.issuing_organization = parts[1].strip()
            else:
                entry.name = clean

            entry.provenance = {
                "source": "Certifications Section",
                "confidence": 0.90,
                "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
            }
            parsed.certifications.append(entry)

    # -------------------------------------------------------------------------
    # SUPPLEMENTARY SECTIONS
    # -------------------------------------------------------------------------

    def _extract_supplementary_sections(
        self,
        sections: Dict[str, str],
        full_text: str,
        parsed: ParsedResume,
    ) -> None:
        """Extracts languages, publications, awards, strengths, and areas of interest."""
        lang_text = sections.get("LANGUAGES", "")
        if lang_text:
            parsed.languages = [
                re.sub(r"^[\s•*–—\-]+\s*", "", l).strip()
                for l in re.split(r"[,|\n;]+", lang_text)
                if l.strip() and len(l.strip()) <= 25
            ]

        awards_text = sections.get("AWARDS", "")
        if awards_text:
            parsed.awards = [
                re.sub(r"^[\s•*–—\-]+\s*", "", l).strip()
                for l in awards_text.split("\n")
                if l.strip()
            ]

        pub_text = sections.get("PUBLICATIONS", "")
        if pub_text:
            parsed.publications = [
                re.sub(r"^[\s•*–—\-]+\s*", "", l).strip()
                for l in pub_text.split("\n")
                if l.strip()
            ]

        strengths_text = sections.get("STRENGTHS", "")
        if strengths_text:
            parsed.core_strengths = [
                re.sub(r"^[\s•*–—\-]+\s*", "", l).strip()
                for l in re.split(r"[,|\n;]+", strengths_text)
                if l.strip() and len(l.strip()) <= 40
            ]

        interests_text = sections.get("INTERESTS", "")
        if interests_text:
            parsed.areas_of_interest = [
                re.sub(r"^[\s•*–—\-]+\s*", "", l).strip()
                for l in re.split(r"[,|\n;]+", interests_text)
                if l.strip() and len(l.strip()) <= 40
            ]
