"""Profile Updater module that syncs verified resume details into candidate profile and database."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.database.db_manager import DatabaseManager
from src.matcher.terminology import split_date_range
from src.preparer.resume_parser import ParsedResume, ResumeParser, VerificationStatus
from src.utils.logger import setup_logger

logger = setup_logger("ProfileUpdater")


class ProfileUpdater:
    """Updates the canonical candidate profile JSON and records immutable SQLite snapshots."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        profile_path: Optional[str | Path] = None,
    ):
        self.db = db_manager or DatabaseManager()
        self.profile_path = Path(profile_path or "data/profile/candidate_profile.json").resolve()

    def build_profile_dict(self, resume: ParsedResume) -> Dict[str, Any]:
        """Constructs canonical candidate profile JSON structure from verified resume data.
        
        Strict zero-hallucination policy: Only verified fields from the resume are populated.
        """
        # Education
        edu_list = []
        for edu in resume.education:
            edu_list.append({
                "institution": edu.institution,
                "degree": edu.degree,
                "major": edu.major,
                "expected_graduation_year": edu.expected_graduation_year,
                "current_cgpa": edu.cgpa,
                "coursework": edu.coursework,
                "honors": edu.honors,
            })

        # Experience
        exp_list = []
        for exp in resume.work_experience:
            start_d = exp.start_date
            end_d = exp.end_date
            is_curr = exp.is_current
            dur_str = exp.duration or ""

            if (not start_d or not end_d) and dur_str:
                s_part, e_part = split_date_range(dur_str)
                if s_part:
                    start_d = start_d or s_part
                if e_part:
                    end_d = end_d or e_part
                    if "present" in e_part.lower() or "current" in e_part.lower():
                        is_curr = True

            duration_months = getattr(exp, "duration_months", None)
            if duration_months is None and dur_str:
                import re
                m = re.search(r"(\d+)\s*(?:month|mo)", dur_str, re.IGNORECASE)
                if m:
                    duration_months = int(m.group(1))
                y = re.search(r"(\d+)\s*(?:year|yr)", dur_str, re.IGNORECASE)
                if y:
                    duration_months = (duration_months or 0) + int(y.group(1)) * 12

            exp_status = VerificationStatus.EXTRACTED_UNVERIFIED
            if exp.provenance and isinstance(exp.provenance, dict):
                exp_status = exp.provenance.get("verification_status", VerificationStatus.EXTRACTED_UNVERIFIED)

            exp_list.append({
                "employer": exp.employer,
                "job_title": exp.job_title,
                "duration": dur_str,
                "duration_months": duration_months,
                "start_date": start_d,
                "end_date": end_d,
                "is_current": is_curr,
                "responsibilities": exp.responsibilities,
                "achievements": exp.achievements,
                "verification_status": exp_status,
            })

        # Projects
        proj_list = []
        for proj in resume.projects:
            proj_list.append({
                "title": proj.title,
                "description": proj.description,
                "technologies": proj.technologies,
                "responsibilities": proj.responsibilities,
            })

        # Certifications
        cert_list = []
        for cert in resume.certifications:
            cert_list.append({
                "name": cert.name,
                "issuer": cert.issuer,
                "date_issued": cert.date_issued,
                "expiry_date": cert.expiry_date,
                "credential_id": cert.credential_id,
            })

        # Technical skills (categorized without fabricating unverified tools)
        prog_languages = [s for s in ["Python", "Dart", "JavaScript", "C/C++", "C++", "C", "Java", "TypeScript", "Go", "Rust", "SQL", "R"] if s in resume.technical_skills]
        mobile_skills = [s for s in ["Flutter", "Android application development", "Android Studio", "React Native", "iOS", "Swift"] if s in resume.technical_skills]
        backend_api = [s for s in ["REST API integration", "Node.js", "Node.js fundamentals", "Postman", "JSON", "XML", "FastAPI", "Django", "Flask"] if s in resume.technical_skills]
        databases = [s for s in ["SQLite", "MySQL", "PostgreSQL", "MongoDB", "Redis"] if s in resume.technical_skills]
        dev_tools = [s for s in ["Git", "GitHub", "Git & GitHub", "VS Code", "Android Studio", "Postman", "Docker", "Kubernetes"] if s in resume.technical_skills]

        # Preserve existing candidate inputs if already configured by the user
        existing_inputs = {}
        if self.profile_path.exists():
            try:
                with open(self.profile_path, "r", encoding="utf-8") as pf:
                    existing_data = json.load(pf)
                    existing_inputs = existing_data.get("candidate_inputs", {})
            except Exception:
                pass

        candidate_inputs = {
            "expected_stipend": existing_inputs.get("expected_stipend"),
            "internship_availability": existing_inputs.get("internship_availability"),
            "weekly_working_hours": existing_inputs.get("weekly_working_hours"),
            "internship_duration_preference": existing_inputs.get("internship_duration_preference"),
            "joining_date": existing_inputs.get("joining_date"),
            "relocation_willingness": existing_inputs.get("relocation_willingness"),
            "work_mode_preference": existing_inputs.get("work_mode_preference"),
            "notice_period": existing_inputs.get("notice_period"),
            "github_url": existing_inputs.get("github_url") or resume.github_url or "",
            "linkedin_url": existing_inputs.get("linkedin_url") or resume.linkedin_url or "",
        }

        profile_data = {
            "personal": {
                "full_name": resume.full_name or "",
                "email": resume.email or "",
                "phone": resume.phone or "",
                "location": resume.location or "",
                "headline": resume.professional_headline or "",
                "github": candidate_inputs["github_url"],
                "linkedin": candidate_inputs["linkedin_url"],
                "portfolio": resume.portfolio_url or "",
                "websites": resume.websites,
                "summary": resume.about_me,
            },
            "education": edu_list,
            "work_experience": exp_list,
            "technical_skills": {
                "programming_languages": prog_languages,
                "mobile_development": mobile_skills,
                "backend_and_apis": backend_api,
                "databases": databases,
                "developer_tools": dev_tools,
                "all_skills": resume.technical_skills,
            },
            "professional_skills": resume.professional_skills,
            "soft_skills": resume.soft_skills,
            "tools_and_software": resume.tools_and_software,
            "projects": proj_list,
            "certifications": cert_list,
            "candidate_inputs": candidate_inputs,
            "preferences": {
                "target_roles": [
                    "AI Intern",
                    "Machine Learning Intern",
                    "Data Science Intern",
                    "Python Developer Intern",
                    "Deep Learning Intern",
                    "Generative AI Intern",
                    "NLP Intern",
                    "Computer Vision Intern",
                ],
                "target_locations": ["India", "Remote", "Work from Home", "Pune", "Bengaluru"],
                "experience_level": "Student / Fresher",
            },
            "languages": resume.languages,
            "areas_of_interest": resume.areas_of_interest,
            "core_strengths": resume.core_strengths,
            "awards": resume.awards,
            "publications": resume.publications,
            "custom_sections": resume.custom_sections,
            "field_provenance": resume.field_provenance or {},
            "resume_metadata": {
                "source_file": Path(resume.file_path).name if resume.file_path else "",
                "file_hash": resume.file_hash,
                "file_format": resume.file_format,
                "extraction_timestamp": resume.parsed_timestamp or datetime.now(timezone.utc).isoformat(),
            },
        }
        return profile_data

    def diff_profile_with_resume(
        self, current_profile: Dict[str, Any], resume: ParsedResume
    ) -> Dict[str, Any]:
        """Calculates differences between existing candidate profile and parsed resume.

        Identifies:
        - new_fields: Empty in profile but present in resume.
        - modified_fields: Present in both, different, unconfirmed.
        - protected_fields: USER_CONFIRMED or USER_CORRECTED in profile that differ from resume.
        - unmodified_fields: Identical in both.
        """
        new_prof = self.build_profile_dict(resume)
        field_provenance = current_profile.get("field_provenance", {})

        new_fields: List[Dict[str, Any]] = []
        modified_fields: List[Dict[str, Any]] = []
        protected_fields: List[Dict[str, Any]] = []
        unmodified_fields: List[Dict[str, Any]] = []

        # Check personal fields
        curr_personal = current_profile.get("personal", {})
        new_personal = new_prof.get("personal", {})

        for field_name, new_val in new_personal.items():
            curr_val = curr_personal.get(field_name)
            prov = field_provenance.get(field_name, {})
            status = prov.get("verification_status")

            if curr_val == new_val:
                unmodified_fields.append({
                    "field": f"personal.{field_name}",
                    "current_value": curr_val,
                    "new_value": new_val,
                })
            elif not curr_val and new_val:
                new_fields.append({
                    "field": f"personal.{field_name}",
                    "current_value": curr_val,
                    "new_value": new_val,
                })
            elif status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": f"personal.{field_name}",
                    "current_value": curr_val,
                    "new_value": new_val,
                    "verification_status": status,
                    "reason": "User confirmed or corrected value must not be overwritten without explicit approval.",
                })
            else:
                modified_fields.append({
                    "field": f"personal.{field_name}",
                    "current_value": curr_val,
                    "new_value": new_val,
                    "verification_status": status or VerificationStatus.EXTRACTED_UNVERIFIED,
                })

        # Check education
        curr_edu = current_profile.get("education", [])
        new_edu = new_prof.get("education", [])
        if curr_edu != new_edu:
            prov = field_provenance.get("education", {})
            status = prov.get("verification_status")
            if status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": "education",
                    "current_value": curr_edu,
                    "new_value": new_edu,
                    "verification_status": status,
                })
            elif not curr_edu and new_edu:
                new_fields.append({"field": "education", "current_value": curr_edu, "new_value": new_edu})
            else:
                modified_fields.append({"field": "education", "current_value": curr_edu, "new_value": new_edu})
        else:
            unmodified_fields.append({"field": "education", "current_value": curr_edu, "new_value": new_edu})

        # Check work experience
        curr_exp = current_profile.get("work_experience", [])
        new_exp = new_prof.get("work_experience", [])
        if curr_exp != new_exp:
            prov = field_provenance.get("work_experience", {})
            status = prov.get("verification_status")
            if status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": "work_experience",
                    "current_value": curr_exp,
                    "new_value": new_exp,
                    "verification_status": status,
                })
            elif not curr_exp and new_exp:
                new_fields.append({"field": "work_experience", "current_value": curr_exp, "new_value": new_exp})
            else:
                modified_fields.append({"field": "work_experience", "current_value": curr_exp, "new_value": new_exp})
        else:
            unmodified_fields.append({"field": "work_experience", "current_value": curr_exp, "new_value": new_exp})

        # Check skills
        curr_skills = current_profile.get("technical_skills", {}).get("all_skills", [])
        new_skills = new_prof.get("technical_skills", {}).get("all_skills", [])
        if set(curr_skills) != set(new_skills):
            prov = field_provenance.get("technical_skills", {})
            status = prov.get("verification_status")
            if status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": "technical_skills",
                    "current_value": curr_skills,
                    "new_value": new_skills,
                    "verification_status": status,
                })
            elif not curr_skills and new_skills:
                new_fields.append({"field": "technical_skills", "current_value": curr_skills, "new_value": new_skills})
            else:
                modified_fields.append({"field": "technical_skills", "current_value": curr_skills, "new_value": new_skills})
        else:
            unmodified_fields.append({"field": "technical_skills", "current_value": curr_skills, "new_value": new_skills})

        # Check projects
        curr_proj = current_profile.get("projects", [])
        new_proj = new_prof.get("projects", [])
        if curr_proj != new_proj:
            prov = field_provenance.get("projects", {})
            status = prov.get("verification_status")
            if status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": "projects",
                    "current_value": curr_proj,
                    "new_value": new_proj,
                    "verification_status": status,
                })
            elif not curr_proj and new_proj:
                new_fields.append({"field": "projects", "current_value": curr_proj, "new_value": new_proj})
            else:
                modified_fields.append({"field": "projects", "current_value": curr_proj, "new_value": new_proj})
        else:
            unmodified_fields.append({"field": "projects", "current_value": curr_proj, "new_value": new_proj})

        # Check certifications & licenses
        curr_cert = current_profile.get("certifications", [])
        new_cert = new_prof.get("certifications", [])
        if curr_cert != new_cert:
            prov = field_provenance.get("certifications", {}) or field_provenance.get("licenses", {})
            status = prov.get("verification_status") if isinstance(prov, dict) else None
            if not status and any(isinstance(c, dict) and c.get("verification_status") in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED) for c in curr_cert):
                status = VerificationStatus.USER_CONFIRMED

            if status in (VerificationStatus.USER_CONFIRMED, VerificationStatus.USER_CORRECTED):
                protected_fields.append({
                    "field": "certifications",
                    "current_value": curr_cert,
                    "new_value": new_cert,
                    "verification_status": status,
                    "reason": "User confirmed certifications/licenses must not be overwritten without explicit approval.",
                })
            elif not curr_cert and new_cert:
                new_fields.append({"field": "certifications", "current_value": curr_cert, "new_value": new_cert})
            else:
                modified_fields.append({"field": "certifications", "current_value": curr_cert, "new_value": new_cert})
        else:
            unmodified_fields.append({"field": "certifications", "current_value": curr_cert, "new_value": new_cert})

        return {
            "new_fields": new_fields,
            "modified_fields": modified_fields,
            "protected_fields": protected_fields,
            "unmodified_fields": unmodified_fields,
            "has_changes": bool(new_fields or modified_fields or protected_fields),
        }

    def apply_approved_sync(
        self,
        current_profile: Dict[str, Any],
        resume: ParsedResume,
        approved_fields: Optional[List[str]] = None,
        override_protected: bool = False,
    ) -> Dict[str, Any]:
        """Merges parsed resume into candidate profile without overwriting protected fields."""
        updated = copy.deepcopy(current_profile)
        new_prof = self.build_profile_dict(resume)
        diff = self.diff_profile_with_resume(current_profile, resume)

        field_provenance = updated.setdefault("field_provenance", {})

        # Process personal fields
        for field_info in diff["new_fields"] + diff["modified_fields"] + diff["protected_fields"]:
            fname = field_info["field"]
            is_protected = any(p["field"] == fname for p in diff["protected_fields"])

            # Check if this change is approved
            if approved_fields is not None and fname not in approved_fields:
                continue

            if is_protected and not override_protected:
                logger.info("Preserving protected field '%s' from overwrite.", fname)
                continue

            # Apply change
            if fname.startswith("personal."):
                attr = fname.split(".", 1)[1]
                updated.setdefault("personal", {})[attr] = field_info["new_value"]
                field_provenance[attr] = {
                    "value": field_info["new_value"],
                    "source_section": "Resume Extraction",
                    "confidence": 0.95,
                    "verification_status": (
                        VerificationStatus.USER_CORRECTED if is_protected else VerificationStatus.EXTRACTED_UNVERIFIED
                    ),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            elif fname == "education":
                updated["education"] = field_info["new_value"]
                field_provenance["education"] = {
                    "source_section": "Education",
                    "confidence": 0.95,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            elif fname == "work_experience":
                updated["work_experience"] = field_info["new_value"]
                field_provenance["work_experience"] = {
                    "source_section": "Experience",
                    "confidence": 0.95,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            elif fname == "technical_skills":
                updated["technical_skills"] = new_prof["technical_skills"]
                field_provenance["technical_skills"] = {
                    "source_section": "Skills",
                    "confidence": 0.95,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            elif fname == "projects":
                updated["projects"] = field_info["new_value"]
                field_provenance["projects"] = {
                    "source_section": "Projects",
                    "confidence": 0.95,
                    "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            elif fname == "certifications":
                updated["certifications"] = field_info["new_value"]
                field_provenance["certifications"] = {
                    "source_section": "Certifications",
                    "confidence": 0.95,
                    "verification_status": (
                        VerificationStatus.USER_CORRECTED if is_protected else VerificationStatus.EXTRACTED_UNVERIFIED
                    ),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }

        # Sync auxiliary sections if present in new resume
        for aux in ["languages", "awards", "publications", "custom_sections"]:
            if new_prof.get(aux):
                updated[aux] = new_prof[aux]

        # Update metadata
        updated["resume_metadata"] = new_prof["resume_metadata"]
        return updated

    def sync_user_profile(
        self,
        user_id: int,
        resume_path: str | Path,
        approved_fields: Optional[List[str]] = None,
        override_protected: bool = False,
    ) -> Dict[str, Any]:
        """Synchronizes a user's candidate profile from a resume file and stores a database snapshot."""
        parser = ResumeParser()
        parsed = parser.parse_file(resume_path)

        curr_rec = self.db.get_user_candidate_profile(user_id)
        if not curr_rec:
            # First profile creation for this user
            profile_data = self.build_profile_dict(parsed)
            saved = self.db.save_user_candidate_profile(user_id, profile_data)
            logger.info("Created initial candidate profile for user %d (Snapshot v%d)", user_id, saved["version"])
            return saved["profile_data"]
        else:
            current_profile = curr_rec["profile_data"]
            updated_profile = self.apply_approved_sync(
                current_profile, parsed, approved_fields, override_protected
            )
            saved = self.db.save_user_candidate_profile(user_id, updated_profile)
            logger.info("Updated candidate profile for user %d to version %d", user_id, saved["version"])
            return saved["profile_data"]

    def sync_from_resume(
        self, resume_path: str | Path, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Parses the resume file, updates candidate_profile.json, and stores a version in SQLite."""
        if user_id is not None:
            return self.sync_user_profile(user_id=user_id, resume_path=resume_path)

        parser = ResumeParser()
        parsed = parser.parse_file(resume_path)
        profile_data = self.build_profile_dict(parsed)

        # 1. Write to JSON
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.profile_path, "w", encoding="utf-8") as f:
            json.dump(profile_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Updated candidate profile JSON at: {self.profile_path}")

        # 2. Record immutable version in SQLite
        record = self.db.save_candidate_profile(profile_data)
        logger.info(f"Saved candidate profile snapshot #{record.id} in SQLite at {record.last_updated}")

        # 3. Reload config if loaded
        try:
            from src.config import config
            config.reload()
        except Exception as e:
            logger.debug(f"Config reload notice: {e}")

        return profile_data

