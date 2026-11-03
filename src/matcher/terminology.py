"""Controlled Terminology Dictionaries, Synonyms, and Domain Ontologies.

Provides cross-industry synonym resolution, related skill taxonomies, anti-aliasing
guards (e.g. Java != JavaScript), degree level hierarchies, and professional license classifications.
"""

import re
from typing import Dict, Optional, Set, Tuple

# Degree Level Ranking Hierarchy
DEGREE_LEVEL_HIERARCHY: Dict[str, int] = {
    "none": 0,
    "high school": 1,
    "secondary": 1,
    "ged": 1,
    "diploma": 2,
    "associate": 2,
    "vocational": 2,
    "bachelor": 3,
    "bachelors": 3,
    "undergraduate": 3,
    "b.tech": 3,
    "btech": 3,
    "b.e.": 3,
    "be": 3,
    "b.s.": 3,
    "bs": 3,
    "b.sc": 3,
    "bsc": 3,
    "b.a.": 3,
    "ba": 3,
    "b.com": 3,
    "bcom": 3,
    "bba": 3,
    "llb": 3,
    "mbbs": 3,
    "master": 4,
    "masters": 4,
    "graduate": 4,
    "m.tech": 4,
    "mtech": 4,
    "m.s.": 4,
    "ms": 4,
    "m.sc": 4,
    "msc": 4,
    "mba": 4,
    "m.a.": 4,
    "ma": 4,
    "llm": 4,
    "doctorate": 5,
    "doctoral": 5,
    "ph.d.": 5,
    "phd": 5,
    "md": 5,
    "m.d.": 5,
    "jd": 5,
    "j.d.": 5,
    "postgraduate": 5,
}

# Statutory/Regulated Professional Licenses (distinct from voluntary certificates)
STATUTORY_LICENSES: Set[str] = {
    "registered nurse",
    "rn",
    "rn license",
    "licensed practical nurse",
    "lpn",
    "nurse practitioner",
    "medical license",
    "medical registration",
    "physician license",
    "mbbs",
    "state medical board license",
    "bar admission",
    "admitted to the bar",
    "state bar",
    "licensed attorney",
    "law practice license",
    "cpa license",
    "certified public accountant license",
    "professional engineer",
    "pe license",
    "pe registration",
    "licensed professional engineer",
    "chartered accountant",
    "teaching license",
    "state teaching credential",
    "commercial driver license",
    "cdl",
}

# Strict Non-Equivalent Pairs that MUST NEVER match as exact or synonym
STRICT_NON_EQUIVALENT_PAIRS: Set[Tuple[str, str]] = {
    ("java", "javascript"),
    ("javascript", "java"),
    ("c", "c++"),
    ("c++", "c"),
    ("c", "c#"),
    ("c#", "c"),
    ("c++", "c#"),
    ("c#", "c++"),
    ("python", "cython"),
    ("cython", "python"),
    ("r", "rust"),
    ("rust", "r"),
}

# Controlled Synonym Mappings across Tech, Healthcare, Finance, Legal, Engineering, Management
SKILL_SYNONYMS: Dict[str, str] = {
    # Tech & Software
    "financial modelling": "financial modeling",
    "financial modeling": "financial modeling",
    "machine learning": "machine learning",
    "ml": "machine learning",
    "deep learning": "deep learning",
    "dl": "deep learning",
    "natural language processing": "natural language processing",
    "nlp": "natural language processing",
    "computer vision": "computer vision",
    "cv": "computer vision",
    "artificial intelligence": "artificial intelligence",
    "genai": "generative ai",
    "generative ai": "generative ai",
    "k8s": "kubernetes",
    "kubernetes": "kubernetes",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "typescript": "typescript",
    "py": "python",
    "python": "python",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "postgres sql": "postgresql",
    "react": "react",
    "reactjs": "react",
    "react.js": "react",
    "vue": "vue",
    "vuejs": "vue",
    "vue.js": "vue",
    "angular": "angular",
    "angularjs": "angular",
    "node": "nodejs",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "ci/cd": "ci/cd",
    "cicd": "ci/cd",
    "continuous integration": "ci/cd",
    "continuous deployment": "ci/cd",
    "rest api": "rest apis",
    "rest apis": "rest apis",
    "restful apis": "rest apis",
    "restful api": "rest apis",
    "docker": "docker",
    "git": "git",
    "github": "git",

    # Healthcare & Clinical
    "registered nurse": "registered nurse",
    "rn": "registered nurse",
    "patient care": "patient care",
    "clinical patient care": "patient care",
    "phlebotomy": "phlebotomy",
    "venipuncture": "phlebotomy",
    "blood draw": "phlebotomy",
    "triage": "triage",
    "patient triage": "triage",
    "electronic health records": "electronic health records",
    "ehr": "electronic health records",
    "emr": "electronic health records",
    "electronic medical records": "electronic health records",
    "basic life support": "bls",
    "bls": "bls",
    "advanced cardiac life support": "acls",
    "acls": "acls",
    "clinical assessment": "clinical assessment",
    "patient assessment": "clinical assessment",
    "vital signs monitoring": "vital signs",
    "vital signs": "vital signs",

    # Finance & Accounting
    "gaap": "gaap",
    "generally accepted accounting principles": "gaap",
    "ifrs": "ifrs",
    "international financial reporting standards": "ifrs",
    "general ledger": "general ledger",
    "gl": "general ledger",
    "account reconciliation": "account reconciliation",
    "bank reconciliation": "account reconciliation",
    "auditing": "auditing",
    "financial auditing": "auditing",
    "internal audit": "auditing",
    "external audit": "auditing",
    "tax compliance": "tax compliance",
    "tax preparation": "tax compliance",
    "corporate taxation": "tax compliance",
    "financial statement analysis": "financial reporting",
    "financial reporting": "financial reporting",
    "dcf modeling": "financial modeling",
    "valuation": "valuation",
    "equity research": "equity research",
    "cpa": "cpa",
    "cfa": "cfa",

    # Legal
    "legal research": "legal research",
    "case law research": "legal research",
    "contract drafting": "contract drafting",
    "contract negotiation": "contract drafting",
    "contract review": "contract drafting",
    "litigation support": "litigation",
    "litigation": "litigation",
    "civil litigation": "litigation",
    "commercial litigation": "litigation",
    "westlaw": "westlaw",
    "lexisnexis": "lexisnexis",
    "regulatory compliance": "regulatory compliance",
    "compliance": "regulatory compliance",
    "statutory interpretation": "legal research",

    # Engineering & CAD
    "autocad": "autocad",
    "cad": "autocad",
    "computer-aided design": "autocad",
    "solidworks": "solidworks",
    "catia": "catia",
    "matlab": "matlab",
    "finite element analysis": "fea",
    "fea": "fea",
    "structural analysis": "structural analysis",
    "structural design": "structural analysis",
    "thermodynamics": "thermodynamics",
    "plc programming": "plc programming",
    "plc": "plc programming",

    # Management & Business
    "agile": "agile",
    "agile methodology": "agile",
    "scrum": "scrum",
    "project management": "project management",
    "project planning": "project management",
    "stakeholder management": "stakeholder management",
    "cross-functional leadership": "team leadership",
    "team leadership": "team leadership",
    "budget management": "budget management",
    "budgeting": "budget management",
    "pmp": "pmp",

    # Marketing & Sales
    "search engine optimization": "seo",
    "seo": "seo",
    "search engine marketing": "sem",
    "sem": "sem",
    "google analytics": "google analytics",
    "content strategy": "content marketing",
    "content marketing": "content marketing",
    "crm": "crm",
    "customer relationship management": "crm",
    "lead generation": "lead generation",
    "b2b sales": "b2b sales",
    "sales pipeline management": "pipeline management",
    "pipeline management": "pipeline management",

    # Design & Creative
    "figma": "figma",
    "adobe photoshop": "photoshop",
    "photoshop": "photoshop",
    "adobe illustrator": "illustrator",
    "illustrator": "illustrator",
    "ui/ux design": "ui/ux design",
    "ui ux": "ui/ux design",
    "user experience design": "ui/ux design",
    "user interface design": "ui/ux design",
    "wireframing": "wireframing",
    "user research": "user research",
}

# Related Skills Taxonomies (for Related Matches)
RELATED_SKILLS_MAP: Dict[str, Set[str]] = {
    # Tech
    "ai": {"machine learning", "deep learning", "data science", "nlp", "computer vision", "artificial intelligence"},
    "artificial intelligence": {"machine learning", "deep learning", "ai", "data science"},
    "machine learning": {"deep learning", "data science", "statistics", "python", "pytorch", "tensorflow", "computer vision", "neural networks"},
    "pytorch": {"tensorflow", "keras", "deep learning", "machine learning"},
    "tensorflow": {"pytorch", "keras", "deep learning", "machine learning"},
    "deep learning": {"machine learning", "pytorch", "tensorflow", "neural networks", "computer vision"},
    "computer vision": {"image processing", "deep learning", "machine learning", "pytorch", "opencv"},
    "nlp": {"natural language processing", "deep learning", "machine learning", "llm", "transformers"},
    "natural language processing": {"nlp", "deep learning", "machine learning", "llm"},
    "react": {"vue", "angular", "frontend development", "javascript", "typescript"},
    "vue": {"react", "angular", "frontend development", "javascript"},
    "angular": {"react", "vue", "frontend development", "typescript"},
    "postgresql": {"mysql", "sqlite", "sql", "relational database"},
    "mysql": {"postgresql", "sqlite", "sql", "relational database"},
    "sql": {"postgresql", "mysql", "sqlite", "database queries"},
    "aws": {"azure", "gcp", "cloud computing"},
    "azure": {"aws", "gcp", "cloud computing"},
    "gcp": {"aws", "azure", "cloud computing"},
    "docker": {"kubernetes", "containerization", "devops"},
    "kubernetes": {"docker", "container orchestration", "devops"},

    # Healthcare
    "patient care": {"clinical assessment", "vital signs", "patient triage"},
    "clinical assessment": {"patient care", "vital signs", "triage"},
    "phlebotomy": {"clinical skills", "venipuncture", "laboratory procedures"},
    "electronic health records": {"epic systems", "cerner", "clinical documentation"},
    "bls": {"acls", "cpr", "emergency response"},
    "acls": {"bls", "cardiac life support", "emergency response"},

    # Finance
    "financial modeling": {"financial forecasting", "valuation", "excel modeling", "dcf modeling"},
    "financial reporting": {"financial statement analysis", "gaap", "ifrs", "accounting"},
    "gaap": {"ifrs", "accounting standards", "financial reporting"},
    "ifrs": {"gaap", "accounting standards", "financial reporting"},
    "general ledger": {"account reconciliation", "bookkeeping", "journal entries"},
    "auditing": {"internal audit", "compliance", "financial controls"},

    # Legal
    "litigation": {"trial advocacy", "dispute resolution", "arbitration", "motion practice"},
    "legal research": {"case law analysis", "statutory interpretation", "brief writing"},
    "contract drafting": {"contract review", "commercial contracts", "negotiation"},

    # Engineering
    "autocad": {"solidworks", "catia", "computer aided design"},
    "solidworks": {"autocad", "catia", "3d modeling"},
    "structural analysis": {"fea", "civil engineering", "mechanics of materials"},
}


def normalize_skill_token(skill: str) -> str:
    """Normalizes skill token while preserving meaningful punctuation (e.g., C++, .NET, C#)."""
    if not skill:
        return ""
    s = skill.strip().lower()
    # Normalize common spacing around punctuation
    s = re.sub(r"\s+", " ", s)
    # Check if exact synonym exists directly
    if s in SKILL_SYNONYMS:
        return SKILL_SYNONYMS[s]
    # Strip leading/trailing non-alphanumeric except '+', '#', '.'
    s = re.sub(r"^[^\w+#.]+|[^\w+#.]+$", "", s)
    return SKILL_SYNONYMS.get(s, s)


def are_skills_strictly_distinct(skill_a: str, skill_b: str) -> bool:
    """Returns True if two skills are strictly distinct and MUST NEVER match (e.g. Java vs JavaScript)."""
    norm_a = normalize_skill_token(skill_a)
    norm_b = normalize_skill_token(skill_b)
    if (norm_a, norm_b) in STRICT_NON_EQUIVALENT_PAIRS or (norm_b, norm_a) in STRICT_NON_EQUIVALENT_PAIRS:
        return True
    return False


def get_degree_level_rank(degree_text: str) -> int:
    """Determines numeric education hierarchy rank (0-5) from degree string."""
    if not degree_text:
        return 0
    # Strip dots so 'B.S.' -> 'bs', 'B.E.' -> 'be', 'Ph.D.' -> 'phd'
    clean = re.sub(r"\.", "", degree_text.lower()).strip()

    # Keyword scanning with boundaries
    max_rank = 0
    for keyword, rank in DEGREE_LEVEL_HIERARCHY.items():
        if keyword == "none":
            continue
        clean_kw = re.sub(r"\.", "", keyword.lower()).strip()
        pattern = r"(?<!\w)" + re.escape(clean_kw) + r"(?!\w)"
        if re.search(pattern, clean):
            if rank > max_rank:
                max_rank = rank

    return max_rank


LICENSE_CANONICAL_MAP: Dict[str, str] = {
    "rn": "registered nurse",
    "rn license": "registered nurse",
    "registered nurse": "registered nurse",
    "registered nurse license": "registered nurse",
    "lpn": "licensed practical nurse",
    "lpn license": "licensed practical nurse",
    "licensed practical nurse": "licensed practical nurse",
    "nurse practitioner": "nurse practitioner",
    "nurse practitioner license": "nurse practitioner",
    "np license": "nurse practitioner",
    "cpa": "certified public accountant",
    "cpa license": "certified public accountant",
    "certified public accountant": "certified public accountant",
    "certified public accountant license": "certified public accountant",
    "pe": "professional engineer",
    "pe license": "professional engineer",
    "pe registration": "professional engineer",
    "professional engineer": "professional engineer",
    "licensed professional engineer": "professional engineer",
    "bar admission": "state bar admission",
    "admitted to the bar": "state bar admission",
    "admitted to the state bar": "state bar admission",
    "state bar": "state bar admission",
    "state bar admission": "state bar admission",
    "licensed attorney": "state bar admission",
    "law practice license": "state bar admission",
    "medical license": "medical license",
    "physician license": "medical license",
    "medical registration": "medical license",
    "state medical board license": "medical license",
    "mbbs": "medical license",
    "chartered accountant": "chartered accountant",
    "cdl": "commercial driver license",
    "commercial driver license": "commercial driver license",
    "cdl license": "commercial driver license",
    "commercial driver's license": "commercial driver license",
    "teaching license": "teaching license",
    "teaching credential": "teaching license",
    "state teaching credential": "teaching license",
    "state teaching license": "teaching license",
}


def canonicalize_license_name(name: str) -> str:
    """Normalizes license name to canonical title."""
    if not name:
        return ""
    clean = re.sub(r"\.", "", name.lower()).strip()
    clean = re.sub(r"\s+", " ", clean)
    return LICENSE_CANONICAL_MAP.get(clean, clean)


def match_license_names(mand_lic: str, cand_lic: str) -> bool:
    """Matches mandatory license requirements against candidate credentials using controlled terminology.
    
    Prevents arbitrary substring false positives (e.g. 'rn' inside 'intern' or 'internal auditor').
    """
    if not mand_lic or not cand_lic:
        return False
    
    c_mand = canonicalize_license_name(mand_lic)
    c_cand = canonicalize_license_name(cand_lic)
    
    if c_mand == c_cand:
        return True
        
    pattern_mand = rf"(?<!\w){re.escape(c_mand)}(?!\w)"
    if re.search(pattern_mand, c_cand):
        return True
    pattern_cand = rf"(?<!\w){re.escape(c_cand)}(?!\w)"
    if re.search(pattern_cand, c_mand):
        return True
        
    return False


def is_statutory_license(license_name: str) -> bool:
    """Returns True if the given credential is a legally regulated/statutory professional license."""
    if not license_name:
        return False
    clean = re.sub(r"\.", "", license_name.lower()).strip()
    clean = re.sub(r"\s+", " ", clean)
    if clean in LICENSE_CANONICAL_MAP or clean in STATUTORY_LICENSES:
        return True
    for lic in STATUTORY_LICENSES:
        pattern = rf"(?<!\w){re.escape(lic)}(?!\w)"
        if re.search(pattern, clean):
            return True
    return False


def split_date_range(s: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Splits a date range string (e.g. 'Jan 2020 - Dec 2023', '2020-01 to 2024-01') into start and end parts.

    Returns (start_str, end_str) or (None, None) if not a recognizable date range.
    Never returns a complete range in either start or end.
    """
    if not s:
        return None, None
    clean = str(s).strip()
    m = re.split(r"\s+(?:to|–|—|-|->)\s+|\s*(?:–|—)\s*|\s*-\s*(?=[A-Za-z]|\d{4})", clean, maxsplit=1)
    if len(m) == 2:
        start_part = m[0].strip()
        end_part = m[1].strip()
        if start_part and end_part:
            return start_part, end_part
    return None, None
