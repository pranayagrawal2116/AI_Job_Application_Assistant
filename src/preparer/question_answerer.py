"""Application Screening Question Answer Generator based strictly on verified resume information."""

from pathlib import Path
from typing import Any, Dict, Optional

from src.database.models import Job
from src.preparer.resume_matcher import JobAlignment, ResumeJobMatcher
from src.utils.logger import setup_logger

logger = setup_logger("QuestionAnswerer")


class QuestionAnswerer:
    """Generates truthful, non-hallucinatory screening question responses for job applications."""

    def __init__(
        self,
        candidate_profile: Optional[Dict[str, Any]] = None,
    ):
        if candidate_profile:
            self.profile = candidate_profile
        else:
            json_path = Path("data/profile/candidate_profile.json")
            if json_path.exists():
                try:
                    import json
                    with open(json_path, "r", encoding="utf-8") as pf:
                        self.profile = json.load(pf)
                except Exception:
                    from src.config import config
                    self.profile = config.candidate_profile
            else:
                from src.config import config
                self.profile = config.candidate_profile
        self.matcher = ResumeJobMatcher(candidate_profile=self.profile)

    def generate_standard_answers(
        self,
        job: Job | Dict[str, Any],
        alignment: Optional[JobAlignment] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Prepares comprehensive, tailored answers for standard candidate screening questions."""
        if alignment is None:
            alignment = self.matcher.align_job(job)

        company = alignment.company_name
        title = alignment.job_title

        personal = self.profile.get("personal", {})
        cand_name = personal.get("full_name", "Pranay Anup Agrawal")

        edu = self.profile.get("education", [{}])[0]
        inst = edu.get("institution", "MIT World Peace University")
        degree = edu.get("degree", "Bachelor of Technology (B.Tech)")
        major = edu.get("major", "Computer Science Engineering – Artificial Intelligence & Data Science")
        grad_year = edu.get("expected_graduation_year", 2028)
        cgpa = edu.get("current_cgpa", 7.6)

        top_project = alignment.relevant_projects[0] if alignment.relevant_projects else {
            "title": "Medical Chatbot",
            "description": "Built a Python-based medical chatbot project focused on conversational access to health-related information.",
            "technologies": ["Python"],
        }
        proj_title = top_project.get("title", "Medical Chatbot")
        raw_desc = top_project.get("description", "Built a Python-based medical chatbot project focused on conversational access to health-related information.")
        proj_desc = " ".join(raw_desc) if isinstance(raw_desc, (list, tuple)) else str(raw_desc)

        top_exp = alignment.relevant_experience[0] if alignment.relevant_experience else {
            "employer": "Sarita Infotech Pvt. Ltd.",
            "job_title": "Project Manager | Mobile App Development",
            "duration": "3 months",
            "highlights": ["Coordinating feature delivery, Flutter application screens, and REST API integration."],
        }

        # Check candidate inputs for availability and working hours
        cand_inputs = self.profile.get("candidate_inputs", {})
        avail = cand_inputs.get("internship_availability")
        hours = cand_inputs.get("weekly_working_hours")

        if avail and hours:
            avail_ans = (
                f"As a current undergraduate student at {inst} (Class of {grad_year}, CGPA: {cgpa}), "
                f"my confirmed availability is {avail} committing {hours} per week."
            )
            avail_status = "READY"
        elif avail:
            avail_ans = (
                f"As a current undergraduate student at {inst} (Class of {grad_year}, CGPA: {cgpa}), "
                f"my confirmed availability is {avail}. Weekly working hours pending candidate input."
            )
            avail_status = "READY"
        else:
            avail_ans = (
                "[NEEDS CANDIDATE INPUT: Please confirm your exact internship availability (e.g., Remote / Flexible / Part-time) "
                "and weekly working hours before submitting.]"
            )
            avail_status = "NEEDS_CANDIDATE_INPUT"

        answers = {
            "tell_about_yourself": {
                "question": "Tell us about yourself.",
                "answer": (
                    f"My name is {cand_name}. I am a {degree} student majoring in {major} at {inst} "
                    f"(Class of {grad_year}, CGPA: {cgpa}). I have coursework in Artificial Intelligence, "
                    f"Data Science, and practical software development. Over the past 3 months, I served as {top_exp['job_title']} "
                    f"at {top_exp['employer']}, coordinating mobile feature delivery, building Flutter screens, and integrating "
                    f"backend REST APIs. I enjoy building practical, user-focused applications and am eager to contribute to {company}."
                ),
                "status": "READY",
            },
            "why_this_internship": {
                "question": "Why do you want this internship?",
                "answer": (
                    f"I am applying for the {title} position at {company} because it aligns with my academic studies in "
                    f"Computer Science & Engineering (AI & Data Science) and my practical programming interests. "
                    f"I look forward to applying my verified skills in {', '.join(alignment.matching_skills[:3]) or 'software development'} "
                    f"to real-world engineering tasks while learning from experienced professionals at {company}."
                ),
                "status": "READY",
            },
            "describe_relevant_experience": {
                "question": "Describe your relevant work experience.",
                "answer": (
                    f"I completed a 3-month tenure at {top_exp['employer']} as {top_exp['job_title']}. In this role, I coordinated "
                    f"mobile application implementation and feature delivery, developed Flutter-based user screens, integrated backend REST APIs, "
                    f"and supported debugging, testing, and team communication across the development process."
                ),
                "status": "READY",
            },
            "explain_project": {
                "question": "Explain a project you have worked on.",
                "answer": (
                    f"In my project, '{proj_title}', I {proj_desc.lower().rstrip('.')}. "
                    f"This project provided practical experience translating functional requirements into working code."
                ),
                "status": "READY",
            },
            "technical_skills": {
                "question": "What technical skills do you possess?",
                "answer": (
                    "My verified programming languages include Python, Dart, JavaScript, and C/C++. On the application side, "
                    "I have hands-on experience with Flutter, Android development, REST API integration, Node.js fundamentals, "
                    "SQLite, and MySQL. My tooling stack includes Git/GitHub, VS Code, Android Studio, and Postman."
                ),
                "status": "READY",
            },
            "why_should_we_select_you": {
                "question": "Why should we select you?",
                "answer": (
                    f"You should select me because I combine academic training in AI & Data Science (CGPA {cgpa}) with "
                    f"practical engineering experience from my 3-month role at {top_exp['employer']}. I have experience delivering "
                    f"application screens, integrating APIs, and collaborating in a structured development cycle."
                ),
                "status": "READY",
            },
            "availability": {
                "question": "What is your availability for this internship?",
                "answer": avail_ans,
                "status": avail_status,
            },
        }
        return answers

    def answer_custom_question(self, question_text: str) -> Dict[str, Any]:
        """Answers arbitrary questions or flags as NEEDS CANDIDATE INPUT if data is unverified."""
        q_lower = question_text.lower()
        cand_inputs = self.profile.get("candidate_inputs", {})

        # 1. Expected Stipend / Salary
        if any(k in q_lower for k in ["stipend", "salary", "compensation", "expected ctc", "remuneration"]):
            val = cand_inputs.get("expected_stipend")
            if val:
                return {"question": question_text, "answer": f"Expected stipend: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Expected stipend not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 2. Availability / Weekly Hours
        if any(k in q_lower for k in ["hours per week", "weekly hours", "hours can you commit", "how many hours"]):
            val = cand_inputs.get("weekly_working_hours")
            if val:
                return {"question": question_text, "answer": f"Available for {val} per week.", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Weekly working hours not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 3. Internship Duration Preference
        if any(k in q_lower for k in ["duration", "how many months", "months can you intern", "period of internship"]):
            val = cand_inputs.get("internship_duration_preference")
            if val:
                return {"question": question_text, "answer": f"Preferred internship duration: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Internship duration preference not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 4. Joining Date / Earliest Start Date
        if any(k in q_lower for k in ["joining date", "start date", "when can you start", "when can you join", "can you join", "earliest date", "earliest start"]):
            val = cand_inputs.get("joining_date")
            if val:
                return {"question": question_text, "answer": f"Earliest available joining date: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Earliest joining date not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 5. Relocation Willingness
        if any(k in q_lower for k in ["relocat", "willing to move", "open to relocate"]):
            val = cand_inputs.get("relocation_willingness")
            if val:
                return {"question": question_text, "answer": f"Relocation status: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Relocation willingness not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 6. Work Mode (On-site / Hybrid / Remote)
        if any(k in q_lower for k in ["work mode", "on-site", "hybrid", "in-office", "work from office"]):
            val = cand_inputs.get("work_mode_preference")
            if val:
                return {"question": question_text, "answer": f"Work mode preference: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: On-site/hybrid/remote preference not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 7. Notice Period
        if any(k in q_lower for k in ["notice period", "current notice", "serving notice"]):
            val = cand_inputs.get("notice_period")
            if val:
                return {"question": question_text, "answer": f"Notice period: {val}", "status": "READY"}
            return {
                "question": question_text,
                "answer": "[NEEDS CANDIDATE INPUT: Notice period not specified in candidate profile.]",
                "status": "NEEDS_CANDIDATE_INPUT",
            }

        # 8. Unverified certifications / external queries
        unverified_triggers = [
            "visa", "passport", "driver's license", "commercial experience",
            "aws certification", "azure certification", "gcp certification"
        ]
        for trig in unverified_triggers:
            if trig in q_lower:
                return {
                    "question": question_text,
                    "answer": "[NEEDS CANDIDATE INPUT: Information not present in verified resume. Please provide your input before submission.]",
                    "status": "NEEDS_CANDIDATE_INPUT",
                }

        # Check standard category mappings
        if any(k in q_lower for k in ["about you", "introduce yourself", "tell me about yourself", "who are you"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["tell_about_yourself"]

        if any(k in q_lower for k in ["skills", "technologies", "tech stack", "languages you know"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["technical_skills"]

        if any(k in q_lower for k in ["project", "portfolio", "built"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["explain_project"]

        if any(k in q_lower for k in ["experience", "prior work", "internship experience", "past job"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["describe_relevant_experience"]

        if any(k in q_lower for k in ["availability", "when are you available"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["availability"]

        # Default fallback
        return {
            "question": question_text,
            "answer": "[NEEDS CANDIDATE INPUT: Candidate customization recommended for this specific question.]",
            "status": "NEEDS_CANDIDATE_INPUT",
        }

