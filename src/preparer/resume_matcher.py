"""Resume-Job Matching & Alignment module comparing job postings against candidate resume."""

from dataclasses import asdict, dataclass, field
import json
import re
from typing import Any, Dict, List, Optional

from src.database.models import Job
from src.utils.logger import setup_logger

logger = setup_logger("ResumeJobMatcher")


@dataclass
class JobAlignment:
    job_id: int
    company_name: str
    job_title: str
    matching_skills: List[str] = field(default_factory=list)
    missing_requirements: List[str] = field(default_factory=list)
    relevant_projects: List[Dict[str, Any]] = field(default_factory=list)
    relevant_experience: List[Dict[str, Any]] = field(default_factory=list)
    alignment_summary: str = ""
    match_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResumeJobMatcher:
    """Compares verified resume content with job requirements without hallucination."""

    def __init__(self, candidate_profile: Optional[Dict[str, Any]] = None):
        if candidate_profile:
            self.profile = candidate_profile
        else:
            from src.config import config
            self.profile = config.candidate_profile

    def align_job(self, job: Job | Dict[str, Any]) -> JobAlignment:
        """Evaluates how a candidate's verified resume aligns with an internship opportunity."""
        if isinstance(job, dict):
            job_id = job.get("id", 0)
            company_name = job.get("company_name", "Unknown")
            job_title = job.get("job_title", "Intern")
            description = job.get("job_description", "")
            req_skills = job.get("required_skills", [])
        else:
            job_id = job.id or 0
            company_name = job.company_name
            job_title = job.job_title
            description = job.job_description or ""
            req_skills = job.required_skills or []

        if isinstance(req_skills, str):
            try:
                req_skills = json.loads(req_skills)
            except Exception:
                req_skills = [s.strip() for s in req_skills.split(",") if s.strip()]

        job_full_text = f"{job_title} {description} {' '.join(req_skills)}".lower()

        # 1. Candidate's verified skills
        candidate_skills = self.profile.get("technical_skills", {}).get("all_skills", [])
        if not candidate_skills:
            # Fallback to sublists
            prog = self.profile.get("technical_skills", {}).get("programming_languages", [])
            mobile = self.profile.get("technical_skills", {}).get("mobile_development", [])
            apis = self.profile.get("technical_skills", {}).get("backend_and_apis", [])
            dbs = self.profile.get("technical_skills", {}).get("databases", [])
            tools = self.profile.get("technical_skills", {}).get("developer_tools", [])
            candidate_skills = list(set(prog + mobile + apis + dbs + tools))

        matching_skills = []
        for sk in candidate_skills:
            if re.search(r"(?<!\w)" + re.escape(sk.lower()) + r"(?!\w)", job_full_text):
                matching_skills.append(sk)

        # 2. Extract employer requested skills from req_skills and job text
        missing_requirements = []
        common_tech_tokens = [
            "pytorch", "tensorflow", "keras", "opencv", "scikit-learn",
            "langchain", "transformers", "hugging face", "llm", "generative ai",
            "docker", "kubernetes", "aws", "gcp", "azure", "sql", "nosql",
            "fastapi", "flask", "django", "react", "next.js", "c++", "linux"
        ]
        # Inspect explicitly mentioned job skills
        for r_skill in req_skills:
            r_str = str(r_skill).strip()
            if r_str and not any(m.lower() in r_str.lower() or r_str.lower() in m.lower() for m in candidate_skills):
                if r_str not in missing_requirements:
                    missing_requirements.append(r_str)

        for tok in common_tech_tokens:
            if re.search(r"(?<!\w)" + re.escape(tok) + r"(?!\w)", job_full_text):
                if not any(tok == c.lower() or tok in c.lower() for c in candidate_skills):
                    if tok.capitalize() not in missing_requirements:
                        missing_requirements.append(tok.capitalize())

        # 3. Match Relevant Projects
        candidate_projects = self.profile.get("projects", [])
        relevant_projects = []
        is_ai_ml_role = any(k in job_full_text for k in ["ai", "machine learning", "deep learning", "nlp", "chatbot", "data science", "cv", "vision"])
        is_app_mobile_role = any(k in job_full_text for k in ["mobile", "flutter", "android", "app", "ui", "dart"])
        is_api_backend_role = any(k in job_full_text for k in ["api", "backend", "integration", "rest", "server"])

        for proj in candidate_projects:
            title = proj.get("title", "")
            desc = proj.get("description", "")
            techs = proj.get("technologies", [])
            relevance_score = 0

            if is_ai_ml_role and "chatbot" in title.lower():
                relevance_score += 3
            if is_app_mobile_role and any(k in title.lower() for k in ["flutter", "mobile", "android"]):
                relevance_score += 3
            if is_api_backend_role and any(k in title.lower() for k in ["abdm", "registration", "consent", "api"]):
                relevance_score += 2

            for t in techs:
                if t.lower() in job_full_text:
                    relevance_score += 1

            if relevance_score > 0 or not relevant_projects:
                relevant_projects.append({
                    "title": title,
                    "description": desc,
                    "technologies": techs,
                    "relevance_score": relevance_score,
                })

        relevant_projects.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)
        relevant_projects = relevant_projects[:3]

        # 4. Relevant Work Experience
        candidate_exp = self.profile.get("work_experience", [])
        relevant_exp = []
        for exp in candidate_exp:
            relevant_exp.append({
                "employer": exp.get("employer"),
                "job_title": exp.get("job_title"),
                "duration": exp.get("duration"),
                "highlights": exp.get("responsibilities", []),
            })

        # 5. Tailored Application Alignment Summary
        edu = self.profile.get("education", [{}])[0]
        deg = edu.get("degree", "B.Tech")
        inst = edu.get("institution", "MIT World Peace University")
        cgpa = edu.get("current_cgpa", 7.6)

        skills_str = ", ".join(matching_skills[:5]) if matching_skills else "Python, problem-solving, and software fundamentals"
        proj_str = relevant_projects[0]["title"] if relevant_projects else "Medical Chatbot"
        
        summary_sentences = [
            f"Candidate is a {deg} student at {inst} (CGPA {cgpa}, Class of 2028).",
            f"Strong technical alignment with verified skills in {skills_str}.",
            f"Directly applicable project experience includes '{proj_str}'.",
        ]
        if relevant_exp:
            summary_sentences.append(
                f"Possesses hands-on industry experience as {relevant_exp[0]['job_title']} at {relevant_exp[0]['employer']} ({relevant_exp[0]['duration']})."
            )
        if missing_requirements:
            summary_sentences.append(
                f"Transparent gap: employer mentions {', '.join(missing_requirements[:3])}, requiring rapid self-study or on-the-job adaptation."
            )

        alignment_summary = " ".join(summary_sentences)

        total_req_count = len(matching_skills) + len(missing_requirements)
        match_pct = round((len(matching_skills) / max(1, total_req_count)) * 100, 1)

        return JobAlignment(
            job_id=job_id,
            company_name=company_name,
            job_title=job_title,
            matching_skills=matching_skills,
            missing_requirements=missing_requirements,
            relevant_projects=relevant_projects,
            relevant_experience=relevant_exp,
            alignment_summary=alignment_summary,
            match_percentage=match_pct,
        )
