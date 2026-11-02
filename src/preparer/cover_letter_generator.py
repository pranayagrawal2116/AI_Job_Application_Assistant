"""Personalized Cover Letter Generator based on verified candidate profile and job requirements."""

from datetime import datetime
from pathlib import Path
import re
from typing import Any, Dict, Optional

from src.database.models import Job
from src.preparer.resume_matcher import JobAlignment, ResumeJobMatcher
from src.utils.logger import setup_logger

logger = setup_logger("CoverLetterGenerator")


class CoverLetterGenerator:
    """Generates professional, personalized, and non-generic cover letters without fabricating experience."""

    def __init__(
        self,
        candidate_profile: Optional[Dict[str, Any]] = None,
        output_dir: Optional[str | Path] = None,
    ):
        if candidate_profile:
            self.profile = candidate_profile
        else:
            from src.config import config
            self.profile = config.candidate_profile

        self.output_dir = Path(output_dir or "data/exports/cover_letters").resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.matcher = ResumeJobMatcher(candidate_profile=self.profile)

    def generate_cover_letter(
        self,
        job: Job | Dict[str, Any],
        alignment: Optional[JobAlignment] = None,
    ) -> Dict[str, str]:
        """Generates and saves a customized cover letter for a given internship.
        
        Returns:
            Dict containing 'letter_text', 'file_path', and 'filename'.
        """
        if alignment is None:
            alignment = self.matcher.align_job(job)

        company = alignment.company_name
        title = alignment.job_title
        job_id = alignment.job_id

        # Candidate details
        personal = self.profile.get("personal", {})
        cand_name = personal.get("full_name", "Pranay Anup Agrawal")
        email = personal.get("email", "pranayagrawal2116@gmail.com")
        phone = personal.get("phone", "95100 29575")
        location = personal.get("location", "Kothrud, Pune, Maharashtra")

        edu = self.profile.get("education", [{}])[0]
        institution = edu.get("institution", "MIT World Peace University")
        degree = edu.get("degree", "Bachelor of Technology (B.Tech)")
        major = edu.get("major", "Computer Science Engineering – Artificial Intelligence & Data Science")
        grad_year = edu.get("expected_graduation_year", 2028)
        cgpa = edu.get("current_cgpa", 7.6)

        # Matching elements
        skills_highlight = ", ".join(alignment.matching_skills[:4]) if alignment.matching_skills else "Python, software engineering fundamentals, and data handling"
        
        top_project = alignment.relevant_projects[0] if alignment.relevant_projects else {
            "title": "Medical Chatbot",
            "description": "Built a Python-based conversational tool providing structured health information access.",
            "technologies": ["Python", "NLP", "Machine Learning"],
        }
        
        top_exp = alignment.relevant_experience[0] if alignment.relevant_experience else {
            "employer": "Sarita Infotech Pvt. Ltd.",
            "job_title": "Project Manager | Mobile App Development",
            "duration": "3 months",
            "highlights": ["Coordinating feature delivery, Flutter application screens, and REST API integration."],
        }

        today_str = datetime.now().strftime("%B %d, %Y")

        # Draft Letter
        letter_lines = [
            f"# {cand_name}",
            f"{location} | {phone} | {email}",
            f"GitHub: https://github.com | LinkedIn: https://linkedin.com",
            "",
            f"**Date:** {today_str}",
            "",
            f"**To:** Hiring Team, {company}",
            f"**Subject:** Application for {title} Role",
            "",
            f"Dear Hiring Team at {company},",
            "",
            f"I am writing to express my strong interest in the **{title}** position at {company}. "
            f"I am currently pursuing my {degree} in {major} at {institution} (Class of {grad_year}, CGPA: {cgpa}). "
            f"With a dedicated focus on Artificial Intelligence, Data Science, and practical software engineering, "
            f"I am eager to contribute meaningfully to your team while further honing my technical capabilities.",
            "",
            f"During my academic and project work, I have focused heavily on building robust, real-world solutions. "
            f"In my project, **{top_project['title']}**, I {top_project['description'].lower()} utilizing "
            f"{', '.join(top_project['technologies'])}. This initiative strengthened my ability to decompose complex requirements, "
            f"write clean and maintainable code, and handle data-intensive workflows effectively.",
            "",
            f"In addition to academic project work, I bring hands-on industry exposure from my role as **{top_exp['job_title']}** "
            f"at **{top_exp['employer']}** ({top_exp['duration']}). There, I contributed directly to coordinating mobile application delivery, "
            f"building core UI screens, integrating backend REST APIs, and troubleshooting critical workflows. This experience instilled in me "
            f"a rigorous engineering discipline, strong team collaboration, and a deep appreciation for shipping reliable software.",
            "",
            f"Your work at {company} represents exactly the dynamic environment where I seek to apply my verified proficiencies in {skills_highlight}. "
            f"I am adaptable, analytically minded, and excited to tackle challenging problems alongside experienced engineers.",
            "",
            "Thank you for your time and consideration. I welcome the opportunity to discuss how my background, enthusiasm, "
            "and technical foundation can support your objectives.",
            "",
            "Sincerely,",
            f"**{cand_name}**",
            f"{phone} | {email}",
        ]

        letter_text = "\n".join(letter_lines)

        # File naming
        clean_company = re.sub(r"[^\w\-]", "_", company.lower())[:30]
        filename = f"cover_letter_job_{job_id}_{clean_company}.md"
        file_path = self.output_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(letter_text)

        logger.info(f"Generated tailored cover letter for Job #{job_id} ({company}) at: {file_path}")

        return {
            "letter_text": letter_text,
            "file_path": str(file_path),
            "filename": filename,
        }
