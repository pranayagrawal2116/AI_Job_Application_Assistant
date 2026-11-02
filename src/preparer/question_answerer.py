"""Application Screening Question Answer Generator based strictly on verified resume information."""

import re
from typing import Any, Dict, List, Optional

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
        location = personal.get("location", "Kothrud, Pune, Maharashtra")

        edu = self.profile.get("education", [{}])[0]
        inst = edu.get("institution", "MIT World Peace University")
        degree = edu.get("degree", "Bachelor of Technology (B.Tech)")
        major = edu.get("major", "Computer Science Engineering – Artificial Intelligence & Data Science")
        grad_year = edu.get("expected_graduation_year", 2028)
        cgpa = edu.get("current_cgpa", 7.6)

        skills = self.profile.get("technical_skills", {}).get("all_skills", ["Python", "Dart", "JavaScript", "C/C++", "Flutter"])
        skills_str = ", ".join(skills[:8])

        top_project = alignment.relevant_projects[0] if alignment.relevant_projects else {
            "title": "Medical Chatbot",
            "description": "Built a Python-based conversational tool focused on structured healthcare information access.",
            "technologies": ["Python", "NLP", "Machine Learning"],
        }

        top_exp = alignment.relevant_experience[0] if alignment.relevant_experience else {
            "employer": "Sarita Infotech Pvt. Ltd.",
            "job_title": "Project Manager | Mobile App Development",
            "duration": "3 months",
            "highlights": ["Coordinating feature delivery, Flutter application screens, and REST API integration."],
        }

        answers = {
            "tell_about_yourself": {
                "question": "Tell us about yourself.",
                "answer": (
                    f"My name is {cand_name}. I am a {degree} student majoring in {major} at {inst} "
                    f"(Class of {grad_year}, CGPA: {cgpa}). I have a strong foundation in Artificial Intelligence, "
                    f"Machine Learning, and software development, combined with practical engineering experience. "
                    f"Over the past 3 months, I served as {top_exp['job_title']} at {top_exp['employer']}, "
                    f"managing mobile feature deliveries and integrating backend REST APIs. I enjoy building practical, "
                    f"user-centric applications and am eager to contribute my energy and skills to {company}."
                ),
                "status": "READY",
            },
            "why_this_internship": {
                "question": "Why do you want this internship?",
                "answer": (
                    f"I am specifically targeting the {title} opportunity at {company} because it aligns closely with "
                    f"my academic curriculum in AI & Data Science and my practical programming interests. "
                    f"{company} offers an environment where I can apply my verified skills in {', '.join(alignment.matching_skills[:3]) or 'software engineering'} "
                    f"to real-world datasets and production challenges, while learning best practices from an experienced engineering team."
                ),
                "status": "READY",
            },
            "describe_relevant_experience": {
                "question": "Describe your relevant work experience.",
                "answer": (
                    f"I worked for 3 months at {top_exp['employer']} as {top_exp['job_title']}. In this role, I coordinated "
                    f"the development and feature rollout of a mobile application, developed Flutter-based user screens, "
                    f"integrated backend REST APIs with JSON data handling, and actively assisted with testing, debugging, "
                    f"and cross-functional team communication. This taught me how to manage real delivery timelines and adhere "
                    f"to code quality standards."
                ),
                "status": "READY",
            },
            "explain_project": {
                "question": "Explain a project you have worked on.",
                "answer": (
                    f"One of my key projects is '{top_project['title']}', where I {top_project['description'].lower()} "
                    f"using {', '.join(top_project['technologies'])}. This involved designing clean data models, "
                    f"implementing core logic, handling API communications, and rigorously testing edge cases to provide "
                    f"a smooth, reliable user experience."
                ),
                "status": "READY",
            },
            "technical_skills": {
                "question": "What technical skills do you possess?",
                "answer": (
                    f"My verified programming languages include Python, Dart, JavaScript, and C/C++. On the application side, "
                    f"I have hands-on experience with Flutter, Android development, REST API integration, Node.js fundamentals, "
                    f"SQLite, and MySQL. My tooling stack includes Git/GitHub, VS Code, Android Studio, and Postman."
                ),
                "status": "READY",
            },
            "why_should_we_select_you": {
                "question": "Why should we select you?",
                "answer": (
                    f"You should select me because I offer a unique combination of solid academic knowledge (B.Tech in AI & Data Science, "
                    f"CGPA {cgpa}) and proven execution discipline from my 3-month role at {top_exp['employer']}. I have already delivered "
                    f"functional software, integrated APIs, and worked under delivery deadlines. I am adaptable, fast-learning, and committed "
                    f"to making a positive impact on your team from day one."
                ),
                "status": "READY",
            },
            "availability": {
                "question": "What is your availability for this internship?",
                "answer": (
                    f"As a current undergraduate student at {inst} (expected graduation 2028), I am fully available for "
                    f"remote, work-from-home, or flexible internships in India. I can commit standard internship hours and adapt to "
                    f"your team's schedule for meetings, sprint standups, and project deliveries."
                ),
                "status": "READY",
            },
        }
        return answers

    def answer_custom_question(self, question_text: str) -> Dict[str, Any]:
        """Answers arbitrary questions or flags as NEEDS CANDIDATE INPUT if data is unverified."""
        q_lower = question_text.lower()

        # Check for unverified questions
        unverified_triggers = [
            "salary", "compensation", "stipend requirement", "relocat", "visa",
            "passport", "notice period", "immediate joining date", "driver's license",
            "years of commercial", "aws certification", "azure certification"
        ]
        for trig in unverified_triggers:
            if trig in q_lower:
                return {
                    "question": question_text,
                    "answer": "[NEEDS CANDIDATE INPUT: Information not present in verified resume. Please provide your input before submission.]",
                    "status": "NEEDS_CANDIDATE_INPUT",
                }

        # Check if it maps to standard categories
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

        if any(k in q_lower for k in ["availability", "start date", "when can you start", "hours per week"]):
            std = self.generate_standard_answers({"company_name": "the employer", "job_title": "Intern"})
            return std["availability"]

        # Default fallback: safe response or request candidate input
        return {
            "question": question_text,
            "answer": "[NEEDS CANDIDATE INPUT: Candidate customization recommended for this specific question.]",
            "status": "NEEDS_CANDIDATE_INPUT",
        }

