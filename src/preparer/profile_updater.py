"""Profile Updater module that syncs verified resume details into candidate profile and database."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

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

    def build_profile_dict(
        self,
        resume: Union[ParsedResume, Dict[str, Any]],
        existing_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Constructs canonical candidate profile JSON structure from verified resume data.
        
        Strict zero-hallucination policy: Only verified fields from the resume are populated.
        Supports both ParsedResume instances and parsed dictionary payloads.
        """
        def _get_val(obj: Any, attr: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(attr, default)
            return getattr(obj, attr, default)

        # Education
        edu_list = []
        raw_edu = _get_val(resume, "education", [])
        for edu in raw_edu:
            inst = _get_val(edu, "institution", "")
            deg = _get_val(edu, "degree", "")
            maj = _get_val(edu, "major", "")
            grad_yr = _get_val(edu, "expected_graduation_year") or _get_val(edu, "graduation_year")
            cgpa_val = _get_val(edu, "cgpa") or _get_val(edu, "current_cgpa")
            c_work = _get_val(edu, "coursework", [])
            hnrs = _get_val(edu, "honors", [])
            edu_list.append({
                "institution": inst,
                "degree": deg,
                "major": maj,
                "expected_graduation_year": grad_yr,
                "current_cgpa": cgpa_val,
                "coursework": c_work,
                "honors": hnrs,
            })

        # Experience
        exp_list = []
        raw_exp = _get_val(resume, "work_experience", [])
        for exp in raw_exp:
            start_d = _get_val(exp, "start_date")
            end_d = _get_val(exp, "end_date")
            is_curr = bool(_get_val(exp, "is_current", False))
            dur_str = _get_val(exp, "duration", "") or ""

            if (not start_d or not end_d) and dur_str:
                s_part, e_part = split_date_range(dur_str)
                if s_part:
                    start_d = start_d or s_part
                if e_part:
                    end_d = end_d or e_part
                    if "present" in e_part.lower() or "current" in e_part.lower():
                        is_curr = True

            duration_months = _get_val(exp, "duration_months")
            if duration_months is None and dur_str:
                import re
                m = re.search(r"(\d+)\s*(?:month|mo)", dur_str, re.IGNORECASE)
                if m:
                    duration_months = int(m.group(1))
                y = re.search(r"(\d+)\s*(?:year|yr)", dur_str, re.IGNORECASE)
                if y:
                    duration_months = (duration_months or 0) + int(y.group(1)) * 12

            exp_status = VerificationStatus.EXTRACTED_UNVERIFIED
            exp_prov = _get_val(exp, "provenance")
            if exp_prov and isinstance(exp_prov, dict):
                exp_status = exp_prov.get("verification_status", VerificationStatus.EXTRACTED_UNVERIFIED)

            exp_list.append({
                "employer": _get_val(exp, "employer", ""),
                "job_title": _get_val(exp, "job_title", ""),
                "duration": dur_str,
                "duration_months": duration_months,
                "start_date": start_d,
                "end_date": end_d,
                "is_current": is_curr,
                "responsibilities": _get_val(exp, "responsibilities", []),
                "achievements": _get_val(exp, "achievements", []),
                "verification_status": exp_status,
            })

        # Projects
        proj_list = []
        raw_proj = _get_val(resume, "projects", [])
        for proj in raw_proj:
            proj_list.append({
                "title": _get_val(proj, "title", ""),
                "description": _get_val(proj, "description", ""),
                "technologies": _get_val(proj, "technologies", []),
                "responsibilities": _get_val(proj, "responsibilities", []),
            })

        # ACCA PER / Supervised Professional Experience
        per_list = []
        raw_per = _get_val(resume, "per_experience", [])
        for per in raw_per:
            start_d = _get_val(per, "start_date")
            end_d = _get_val(per, "end_date")
            is_curr = bool(_get_val(per, "is_current", False))
            dur_str = _get_val(per, "duration", "") or ""

            if (not start_d or not end_d) and dur_str:
                s_part, e_part = split_date_range(dur_str)
                if s_part:
                    start_d = start_d or s_part
                if e_part:
                    end_d = end_d or e_part
                    if "present" in e_part.lower() or "current" in e_part.lower():
                        is_curr = True

            per_list.append({
                "employer": _get_val(per, "employer", ""),
                "job_title": _get_val(per, "job_title", ""),
                "role_name": _get_val(per, "job_title", ""),
                "duration": dur_str,
                "start_date": start_d,
                "end_date": end_d,
                "is_current": is_curr,
                "responsibilities": _get_val(per, "responsibilities", []),
                "supervisory_context": _get_val(per, "domain_expertise") or "ACCA Practical Experience Requirement (PER)",
                "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
            })

        # Certifications
        cert_list = []
        raw_cert = _get_val(resume, "certifications", [])
        for cert in raw_cert:
            c_name = _get_val(cert, "name", "")
            c_issuer = _get_val(cert, "issuer") or _get_val(cert, "issuing_organization", "")
            cert_list.append({
                "name": c_name,
                "issuer": c_issuer,
                "date_issued": _get_val(cert, "date_issued"),
                "expiry_date": _get_val(cert, "expiry_date"),
                "credential_id": _get_val(cert, "credential_id"),
            })

        # Professional Qualifications & Memberships
        prof_qual_list = []
        raw_pq = _get_val(resume, "professional_qualifications", [])
        for pq in raw_pq:
            pq_name = _get_val(pq, "name", "")
            pq_issuer = _get_val(pq, "issuer") or _get_val(pq, "issuing_organization", "")
            pq_mem = _get_val(pq, "membership") or pq_name
            prof_qual_list.append({
                "name": pq_name,
                "issuer": pq_issuer,
                "membership": pq_mem,
                "verification_status": VerificationStatus.EXTRACTED_UNVERIFIED,
            })

        # Technical skills (categorized without fabricating unverified tools)
        raw_tech = _get_val(resume, "technical_skills") or _get_val(resume, "skills", [])
        prog_languages = [s for s in ["Python", "Dart", "JavaScript", "C/C++", "C++", "C", "Java", "TypeScript", "Go", "Rust", "SQL", "R"] if s in raw_tech]
        mobile_skills = [s for s in ["Flutter", "Android application development", "Android Studio", "React Native", "iOS", "Swift"] if s in raw_tech]
        backend_api = [s for s in ["REST API integration", "Node.js", "Node.js fundamentals", "Postman", "JSON", "XML", "FastAPI", "Django", "Flask"] if s in raw_tech]
        databases = [s for s in ["SQLite", "MySQL", "PostgreSQL", "MongoDB", "Redis"] if s in raw_tech]
        dev_tools = [s for s in ["Git", "GitHub", "Git & GitHub", "VS Code", "Android Studio", "Postman", "Docker", "Kubernetes"] if s in raw_tech]

        # Preserve existing candidate inputs if already configured by the user
        existing_inputs = {}
        if existing_profile is not None:
            existing_inputs = existing_profile.get("candidate_inputs", {})
        elif self.db is None and self.profile_path.exists():
            try:
                with open(self.profile_path, "r", encoding="utf-8") as pf:
                    existing_data = json.load(pf)
                    existing_inputs = existing_data.get("candidate_inputs", {})
            except Exception:
                pass

        c_github = existing_inputs.get("github_url") or _get_val(resume, "github_url") or ""
        c_linkedin = existing_inputs.get("linkedin_url") or _get_val(resume, "linkedin_url") or ""

        candidate_inputs = {
            "expected_stipend": existing_inputs.get("expected_stipend"),
            "internship_availability": existing_inputs.get("internship_availability"),
            "weekly_working_hours": existing_inputs.get("weekly_working_hours"),
            "internship_duration_preference": existing_inputs.get("internship_duration_preference"),
            "joining_date": existing_inputs.get("joining_date"),
            "relocation_willingness": existing_inputs.get("relocation_willingness"),
            "work_mode_preference": existing_inputs.get("work_mode_preference"),
            "notice_period": existing_inputs.get("notice_period"),
            "github_url": c_github,
            "linkedin_url": c_linkedin,
        }

        # Personal info
        r_name = _get_val(resume, "full_name") or _get_val(resume, "name") or ""
        r_email = _get_val(resume, "email") or ""
        r_phone = _get_val(resume, "phone") or ""
        r_loc = _get_val(resume, "location") or ""
        r_head = _get_val(resume, "professional_headline") or _get_val(resume, "headline") or ""
        r_port = _get_val(resume, "portfolio_url") or ""
        r_web = _get_val(resume, "websites", [])
        r_sum = _get_val(resume, "about_me") or _get_val(resume, "summary") or ""

        personal_dict = {
            "full_name": r_name,
            "email": (existing_profile.get("personal", {}).get("email") if existing_profile else None) or r_email,
            "phone": r_phone,
            "location": r_loc,
            "headline": r_head,
            "github": candidate_inputs["github_url"],
            "linkedin": candidate_inputs["linkedin_url"],
            "portfolio": r_port,
            "websites": r_web,
            "summary": r_sum,
        }

        # Dynamic Career Role & Search Preference Inference (Zero Hardcoded Universal Roles)
        from src.preparer.career_role_inferencer import CareerRoleInferencer
        inferencer = CareerRoleInferencer()
        if isinstance(resume, dict):
            inferred_roles_res = inferencer.infer_roles_from_resume(resume)
            inferred_roles = inferred_roles_res.inferred_roles
            inferred_locations = inferencer.infer_locations(resume)
            res_dict = resume
        else:
            inferred_roles = inferencer.infer_roles(resume)
            inferred_locations = inferencer.infer_locations(resume)
            res_dict = resume.to_dict() if hasattr(resume, "to_dict") else {}

        # Preserve existing user-configured search preferences if present
        existing_prefs = {}
        if existing_profile is not None:
            existing_prefs = existing_profile.get("search_preferences", {}) or existing_profile.get("preferences", {})
        elif self.db is None and self.profile_path.exists():
            # Legacy single-user file mode only
            try:
                with open(self.profile_path, "r", encoding="utf-8") as pf:
                    existing_data = json.load(pf)
                    existing_prefs = existing_data.get("search_preferences", {}) or existing_data.get("preferences", {})
            except Exception:
                pass

        saved_roles = existing_prefs.get("target_roles")
        saved_locs = existing_prefs.get("target_locations")
        auto_disc = existing_prefs.get("auto_discover_enabled", True)

        target_roles = (
            saved_roles
            if saved_roles and isinstance(saved_roles, list) and len(saved_roles) > 0
            else [r.role_title if hasattr(r, "role_title") else str(r) for r in inferred_roles[:5]]
        )
        target_locations = saved_locs if saved_locs and isinstance(saved_locs, list) and len(saved_locs) > 0 else inferred_locations

        search_preferences = {
            "target_roles": target_roles,
            "suggested_roles": [r.to_dict() if hasattr(r, "to_dict") else {"role_title": str(r)} for r in inferred_roles],
            "target_locations": target_locations,
            "auto_discover_enabled": bool(auto_disc),
            "experience_level": existing_prefs.get("experience_level") or ("Student / Fresher" if inferencer._is_student_or_fresher(res_dict) else "Professional"),
        }

        profile_data = {
            "personal": personal_dict,
            "personal_info": copy.deepcopy(personal_dict),  # Compatibility mapping for frontend
            "education": edu_list,
            "work_experience": exp_list,
            "per_experience": per_list,
            "technical_skills": {
                "programming_languages": prog_languages,
                "mobile_development": mobile_skills,
                "backend_and_apis": backend_api,
                "databases": databases,
                "developer_tools": dev_tools,
                "all_skills": _get_val(resume, "technical_skills") or raw_tech,
            },
            "professional_skills": _get_val(resume, "professional_skills", []),
            "soft_skills": _get_val(resume, "soft_skills", []),
            "tools_and_software": _get_val(resume, "tools_and_software", []),
            "projects": proj_list,
            "certifications": cert_list,
            "professional_qualifications": prof_qual_list,
            "candidate_inputs": candidate_inputs,
            "preferences": search_preferences,
            "search_preferences": search_preferences,
            "languages": _get_val(resume, "languages", []),
            "areas_of_interest": _get_val(resume, "areas_of_interest", []),
            "core_strengths": _get_val(resume, "core_strengths", []),
            "awards": _get_val(resume, "awards", []),
            "publications": _get_val(resume, "publications", []),
            "custom_sections": _get_val(resume, "custom_sections", {}),
            "field_provenance": _get_val(resume, "field_provenance") or {},
            "resume_metadata": {
                "source_file": Path(_get_val(resume, "file_path", "")).name if _get_val(resume, "file_path") else "",
                "file_hash": _get_val(resume, "file_hash", ""),
                "file_format": _get_val(resume, "file_format", "pdf"),
                "extraction_timestamp": _get_val(resume, "parsed_timestamp") or datetime.now(timezone.utc).isoformat(),
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
        raw_curr_skills = current_profile.get("technical_skills", {})
        curr_skills = raw_curr_skills.get("all_skills", []) if isinstance(raw_curr_skills, dict) else (raw_curr_skills if isinstance(raw_curr_skills, list) else [])
        raw_new_skills = new_prof.get("technical_skills", {})
        new_skills = raw_new_skills.get("all_skills", []) if isinstance(raw_new_skills, dict) else (raw_new_skills if isinstance(raw_new_skills, list) else [])
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
        new_prof = self.build_profile_dict(resume, existing_profile=current_profile)
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
        for aux in ["languages", "awards", "publications", "custom_sections", "per_experience", "professional_qualifications", "tools_and_software", "professional_skills"]:
            if new_prof.get(aux):
                updated[aux] = new_prof[aux]

        # Always maintain personal_info synchronization for frontend
        if "personal" in updated:
            updated["personal_info"] = copy.deepcopy(updated["personal"])
        if "preferences" not in updated or not updated["preferences"]:
            updated["preferences"] = new_prof.get("preferences", {})
        if "search_preferences" not in updated or not updated["search_preferences"]:
            updated["search_preferences"] = new_prof.get("search_preferences", {})

        # Update metadata
        updated["resume_metadata"] = new_prof["resume_metadata"]
        return updated

    def sync_user_profile(
        self,
        user_id: int,
        resume_path: Optional[str | Path] = None,
        approved_fields: Optional[List[str]] = None,
        override_protected: bool = False,
        resume_id: Optional[int] = None,
        version_num: Optional[int] = None,
        user_base_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Synchronizes a user's candidate profile from a resume file or verified resume ID and stores a database snapshot."""
        from src.database.exceptions import ValidationError

        if resume_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator
            f_val = FileSecurityValidator(base_storage_dir=user_base_dir) if user_base_dir else None
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=f_val)
            verified_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=resume_id,
                version_num=version_num,
                user_base_dir=user_base_dir,
                fresh_parse=True,
            )
            parsed = verified_res.parsed_resume
        elif resume_path is not None:
            rp_str = str(resume_path).strip()
            if "\x00" in rp_str:
                from src.database.exceptions import FileSecurityError
                raise FileSecurityError(f"Null byte detected in resume_path: '{resume_path}'")
            if ".." in rp_str or ".." in Path(rp_str).parts:
                from src.database.exceptions import FileSecurityError
                raise FileSecurityError(f"Path traversal detected in resume_path: '{resume_path}'")

            from src.security.file_security import FileSecurityValidator
            f_val = FileSecurityValidator(base_storage_dir=user_base_dir) if user_base_dir else FileSecurityValidator()
            rp = Path(rp_str)
            if not rp.is_absolute():
                target_path = f_val.get_user_resumes_dir(user_id) / rp.name
            else:
                target_path = rp

            resolved_path, file_bytes, actual_hash, actual_size = f_val.resolve_and_verify_candidate_file(
                user_id=user_id,
                file_path=target_path,
                is_mandatory=True,
                resource_desc=f"Resume file for user #{user_id}",
            )
            fmt = resolved_path.suffix.lstrip(".").lower()
            parser = ResumeParser()
            parsed = parser.parse_bytes(file_bytes=file_bytes, file_format=fmt, file_path=str(resolved_path))
        else:
            raise ValidationError("Either resume_path or resume_id must be provided to sync user profile.")

        curr_rec = self.db.get_user_candidate_profile(user_id)
        if not curr_rec:
            # First profile creation for this user
            profile_data = self.build_profile_dict(parsed, existing_profile=None)
            user_rec = self.db.get_user_by_id(user_id)
            if user_rec and user_rec.get("email"):
                profile_data.setdefault("personal", {})["email"] = user_rec["email"]
                if "personal_info" in profile_data:
                    profile_data["personal_info"]["email"] = user_rec["email"]
            saved = self.db.save_user_candidate_profile(user_id, profile_data)
            logger.info("Created initial candidate profile for user %d (Snapshot v%d)", user_id, saved["version"])
            return saved["profile_data"]
        else:
            current_profile = curr_rec["profile_data"]
            updated_profile = self.apply_approved_sync(
                current_profile, parsed, approved_fields, override_protected
            )
            user_rec = self.db.get_user_by_id(user_id)
            if user_rec and user_rec.get("email"):
                updated_profile.setdefault("personal", {})["email"] = user_rec["email"]
                if "personal_info" in updated_profile:
                    updated_profile["personal_info"]["email"] = user_rec["email"]
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

