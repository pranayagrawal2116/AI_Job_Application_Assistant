"""Universal Tailored Resume Generator (Architecture v2.1.1 - Phase 6).

Generates role-specific, ATS-optimized tailored resumes across all professions
(Tech, Healthcare, Law, Finance, Engineering, Education, Sales, Trades, etc.)
with strict zero-hallucination guarantees and claim-level provenance metadata.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import difflib
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class ClaimProvenance:
    """Provenance tracking for an individual factual claim or bullet point."""
    claim_id: str
    generated_text: str
    source_type: str  # "candidate_profile", "uploaded_resume", "user_edit", "synthesized_summary"
    source_record_id: Optional[str] = None
    source_field: str = ""
    source_version: Optional[int] = 1
    evidence_status: str = "VERIFIED"  # "VERIFIED", "USER_CONFIRMED", "EXTRACTED_UNVERIFIED"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TailoredBullet:
    """A bullet point in an experience or project entry with claim provenance."""
    bullet_text: str
    claim_id: str
    provenance: ClaimProvenance
    matched_keywords: List[str] = field(default_factory=list)
    relevance_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bullet_text": self.bullet_text,
            "claim_id": self.claim_id,
            "provenance": self.provenance.to_dict(),
            "matched_keywords": self.matched_keywords,
            "relevance_score": self.relevance_score,
        }


@dataclass
class TailoredExperience:
    """Tailored work experience entry preserving verified facts."""
    employer: str
    job_title: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    duration: Optional[str] = None
    is_current: bool = False
    bullets: List[TailoredBullet] = field(default_factory=list)
    evidence_status: str = "VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "employer": self.employer,
            "job_title": self.job_title,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "duration": self.duration,
            "is_current": self.is_current,
            "bullets": [b.to_dict() for b in self.bullets],
            "evidence_status": self.evidence_status,
        }


@dataclass
class TailoredEducation:
    """Education entry preserving verified credentials."""
    institution: str
    degree: str
    major: Optional[str] = None
    graduation_year: Optional[int] = None
    cgpa: Optional[float] = None
    evidence_status: str = "VERIFIED"
    claim_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TailoredProject:
    """Project entry highlighted for job alignment."""
    title: str
    description: str
    technologies: List[str] = field(default_factory=list)
    bullets: List[TailoredBullet] = field(default_factory=list)
    relevance_score: float = 0.0
    claim_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "technologies": self.technologies,
            "bullets": [b.to_dict() for b in self.bullets],
            "relevance_score": self.relevance_score,
            "claim_id": self.claim_id,
        }


@dataclass
class TailoredResume:
    """Complete structured tailored resume with full claim-level auditability."""
    user_id: int
    target_role: str
    target_company: str
    source_resume_id: Optional[int] = None
    job_description_id: Optional[int] = None
    personal_info: Dict[str, Any] = field(default_factory=dict)
    professional_summary: str = ""
    summary_provenance: Optional[ClaimProvenance] = None
    matching_skills: List[str] = field(default_factory=list)
    additional_skills: List[str] = field(default_factory=list)
    skills_by_category: Dict[str, List[str]] = field(default_factory=dict)
    experience_entries: List[TailoredExperience] = field(default_factory=list)
    education_entries: List[TailoredEducation] = field(default_factory=list)
    certifications: List[Dict[str, Any]] = field(default_factory=list)
    licenses: List[Dict[str, Any]] = field(default_factory=list)
    projects: List[TailoredProject] = field(default_factory=list)
    custom_sections: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    provenance_map: Dict[str, ClaimProvenance] = field(default_factory=dict)
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "target_role": self.target_role,
            "target_company": self.target_company,
            "source_resume_id": self.source_resume_id,
            "job_description_id": self.job_description_id,
            "personal_info": self.personal_info,
            "professional_summary": self.professional_summary,
            "summary_provenance": self.summary_provenance.to_dict() if self.summary_provenance else None,
            "matching_skills": self.matching_skills,
            "additional_skills": self.additional_skills,
            "skills_by_category": self.skills_by_category,
            "experience_entries": [e.to_dict() for e in self.experience_entries],
            "education_entries": [e.to_dict() for e in self.education_entries],
            "certifications": self.certifications,
            "licenses": self.licenses,
            "projects": [p.to_dict() for p in self.projects],
            "custom_sections": self.custom_sections,
            "provenance_map": {k: v.to_dict() for k, v in self.provenance_map.items()},
            "version": self.version,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TailoredResume:
        prov_map: Dict[str, ClaimProvenance] = {}
        for cid, p_dict in data.get("provenance_map", {}).items():
            if isinstance(p_dict, dict):
                prov_map[cid] = ClaimProvenance(**p_dict)
            elif isinstance(p_dict, ClaimProvenance):
                prov_map[cid] = p_dict

        sum_prov = None
        if data.get("summary_provenance"):
            sum_prov = (
                ClaimProvenance(**data["summary_provenance"])
                if isinstance(data["summary_provenance"], dict)
                else data["summary_provenance"]
            )

        experiences: List[TailoredExperience] = []
        for exp in data.get("experience_entries", []):
            bullets = []
            for b in exp.get("bullets", []):
                bp = (
                    ClaimProvenance(**b["provenance"])
                    if isinstance(b.get("provenance"), dict)
                    else b.get("provenance")
                )
                bullets.append(
                    TailoredBullet(
                        bullet_text=b.get("bullet_text", ""),
                        claim_id=b.get("claim_id", ""),
                        provenance=bp,
                        matched_keywords=b.get("matched_keywords", []),
                        relevance_score=b.get("relevance_score", 0.0),
                    )
                )
            experiences.append(
                TailoredExperience(
                    employer=exp.get("employer", ""),
                    job_title=exp.get("job_title", ""),
                    start_date=exp.get("start_date"),
                    end_date=exp.get("end_date"),
                    duration=exp.get("duration"),
                    is_current=exp.get("is_current", False),
                    bullets=bullets,
                    evidence_status=exp.get("evidence_status", "VERIFIED"),
                )
            )

        educations = [TailoredEducation(**ed) for ed in data.get("education_entries", [])]

        projects = []
        for prj in data.get("projects", []):
            p_bullets = []
            for pb in prj.get("bullets", []):
                pbp = (
                    ClaimProvenance(**pb["provenance"])
                    if isinstance(pb.get("provenance"), dict)
                    else pb.get("provenance")
                )
                p_bullets.append(
                    TailoredBullet(
                        bullet_text=pb.get("bullet_text", ""),
                        claim_id=pb.get("claim_id", ""),
                        provenance=pbp,
                        matched_keywords=pb.get("matched_keywords", []),
                        relevance_score=pb.get("relevance_score", 0.0),
                    )
                )
            projects.append(
                TailoredProject(
                    title=prj.get("title", ""),
                    description=prj.get("description", ""),
                    technologies=prj.get("technologies", []),
                    bullets=p_bullets,
                    relevance_score=prj.get("relevance_score", 0.0),
                    claim_id=prj.get("claim_id"),
                )
            )

        return cls(
            user_id=data.get("user_id", 0),
            target_role=data.get("target_role", "Target Role"),
            target_company=data.get("target_company", "Target Organization"),
            source_resume_id=data.get("source_resume_id"),
            job_description_id=data.get("job_description_id"),
            personal_info=data.get("personal_info", {}),
            professional_summary=data.get("professional_summary", ""),
            summary_provenance=sum_prov,
            matching_skills=data.get("matching_skills", []),
            additional_skills=data.get("additional_skills", []),
            skills_by_category=data.get("skills_by_category", {}),
            experience_entries=experiences,
            education_entries=educations,
            certifications=data.get("certifications", []),
            licenses=data.get("licenses", []),
            projects=projects,
            custom_sections=data.get("custom_sections", {}),
            provenance_map=prov_map,
            version=data.get("version", 1),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )

    def to_markdown(self) -> str:
        """Renders the tailored resume into a clean Markdown representation."""
        lines = []
        p = self.personal_info
        name = p.get("full_name") or "Candidate"
        lines.append(f"# {name}")

        contact_parts = []
        if p.get("email"):
            contact_parts.append(p["email"])
        if p.get("phone"):
            contact_parts.append(p["phone"])
        if p.get("location"):
            contact_parts.append(p["location"])
        if p.get("linkedin"):
            contact_parts.append(f"[LinkedIn]({p['linkedin']})")
        if p.get("github"):
            contact_parts.append(f"[GitHub]({p['github']})")
        if p.get("portfolio"):
            contact_parts.append(f"[Portfolio]({p['portfolio']})")

        if contact_parts:
            lines.append(" | ".join(contact_parts))
        lines.append("")

        if self.professional_summary:
            lines.append("## Professional Summary")
            lines.append(self.professional_summary)
            lines.append("")

        if self.matching_skills or self.additional_skills or self.skills_by_category:
            lines.append("## Skills & Competencies")
            if self.matching_skills:
                lines.append(f"**Target Role Focus:** {', '.join(self.matching_skills)}")
            for cat, skl_list in self.skills_by_category.items():
                if skl_list:
                    lines.append(f"**{cat}:** {', '.join(skl_list)}")
            if self.additional_skills and not self.skills_by_category:
                lines.append(f"**Additional Skills:** {', '.join(self.additional_skills)}")
            lines.append("")

        if self.experience_entries:
            lines.append("## Professional Experience")
            for exp in self.experience_entries:
                dur = f" ({exp.duration})" if exp.duration else ""
                lines.append(f"### {exp.job_title} | {exp.employer}{dur}")
                for b in exp.bullets:
                    lines.append(f"- {b.bullet_text}")
                lines.append("")

        if self.projects:
            lines.append("## Key Projects & Deliverables")
            for prj in self.projects:
                tech_str = f" *({', '.join(prj.technologies)})*" if prj.technologies else ""
                lines.append(f"### {prj.title}{tech_str}")
                if prj.description:
                    lines.append(prj.description)
                for b in prj.bullets:
                    lines.append(f"- {b.bullet_text}")
                lines.append("")

        if self.education_entries:
            lines.append("## Education")
            for edu in self.education_entries:
                parts = [edu.degree]
                if edu.major:
                    parts.append(edu.major)
                deg_str = " in ".join(parts) if len(parts) > 1 else parts[0]
                yr_str = f" ({edu.graduation_year})" if edu.graduation_year else ""
                gpa_str = f" | CGPA: {edu.cgpa}" if edu.cgpa else ""
                lines.append(f"- **{deg_str}** — {edu.institution}{yr_str}{gpa_str}")
            lines.append("")

        if self.licenses or self.certifications:
            lines.append("## Certifications & Licenses")
            for lic in self.licenses:
                l_name = lic.get("name") if isinstance(lic, dict) else str(lic)
                lines.append(f"- **Statutory License:** {l_name}")
            for cert in self.certifications:
                c_name = cert.get("name") if isinstance(cert, dict) else str(cert)
                lines.append(f"- **Certification:** {c_name}")
            lines.append("")

        return "\n".join(lines)

    def to_plain_text(self) -> str:
        """Renders plain text suitable for ATS text parsing."""
        return re.sub(r"[#*_\[\]\(\)]", "", self.to_markdown())

    def update_bullet(
        self,
        exp_index: int,
        bullet_index: int,
        new_text: str,
        user_name: str = "Candidate",
    ) -> bool:
        """Allows explicit candidate correction of a bullet while updating provenance."""
        if 0 <= exp_index < len(self.experience_entries):
            exp = self.experience_entries[exp_index]
            if 0 <= bullet_index < len(exp.bullets):
                bullet = exp.bullets[bullet_index]
                bullet.bullet_text = new_text.strip()
                new_prov = ClaimProvenance(
                    claim_id=bullet.claim_id,
                    generated_text=new_text.strip(),
                    source_type="user_edit",
                    source_record_id=f"exp_{exp_index}_b_{bullet_index}",
                    source_field=f"experience_entries[{exp_index}].bullets[{bullet_index}]",
                    source_version=self.version + 1,
                    evidence_status="USER_CONFIRMED",
                    confidence=1.0,
                )
                bullet.provenance = new_prov
                self.provenance_map[bullet.claim_id] = new_prov
                self.version += 1
                return True
        return False

    def diff_with_original(self, original_bullets: List[str]) -> List[str]:
        """Calculates line diff between tailored bullets and original bullets."""
        tailored_lines = []
        for exp in self.experience_entries:
            for b in exp.bullets:
                tailored_lines.append(b.bullet_text)
        return list(
            difflib.unified_diff(
                original_bullets,
                tailored_lines,
                fromfile="Original Resume Bullets",
                tofile="Tailored Resume Bullets",
                lineterm="",
            )
        )


class UniversalTailoredResumeGenerator:
    """Deterministic, zero-hallucination resume tailoring engine across all industries."""

    def __init__(self):
        pass

    def generate(
        self,
        user_id: int,
        candidate_profile: Dict[str, Any],
        resume_data: Optional[Dict[str, Any]] = None,
        job_description: Optional[Dict[str, Any]] = None,
        match_result: Optional[Dict[str, Any]] = None,
        custom_instructions: Optional[str] = None,
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
        db_manager: Optional[Any] = None,
        user_base_dir: Optional[Path] = None,
    ) -> TailoredResume:
        """Generates a tailored resume rooted strictly in verified evidence."""
        target_res_id = resume_id
        if target_res_id is None and isinstance(resume_data, dict):
            target_res_id = resume_data.get("id") or resume_data.get("resume_id")

        if target_res_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator
            f_val = FileSecurityValidator(base_storage_dir=user_base_dir) if user_base_dir else None
            verifier = ResumeIntegrityVerifier(db_manager=db_manager, file_validator=f_val)
            verified_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                user_base_dir=user_base_dir,
                fresh_parse=True,
            )
            resume_dict = verified_res.parsed_resume.to_dict()
        else:
            resume_dict = resume_data or {}
        jd_dict = job_description or {}
        prof_dict = candidate_profile or {}

        # 1. Target Role & Company
        target_role = (
            jd_dict.get("role_title")
            or jd_dict.get("job_title")
            or prof_dict.get("personal", {}).get("headline")
            or "Target Role"
        )
        target_company = jd_dict.get("company_name") or "Target Organization"

        # 2. Extract Personal Info strictly from profile / resume
        personal = self._extract_personal_info(prof_dict, resume_dict)

        # 3. Extract Keywords from JD
        jd_keywords = self._extract_jd_keywords(jd_dict, match_result)

        # 4. Filter and Prioritize Skills
        matching_skills, additional_skills, skills_by_cat = self._prioritize_skills(
            prof_dict, resume_dict, jd_keywords
        )

        # 5. Build Experience with Bullet Provenance and Relevance Scoring
        experiences, exp_claims = self._build_tailored_experience(
            prof_dict, resume_dict, jd_keywords
        )

        # 6. Education
        educations, edu_claims = self._build_tailored_education(prof_dict, resume_dict)

        # 7. Projects
        projects, proj_claims = self._build_tailored_projects(
            prof_dict, resume_dict, jd_keywords
        )

        # 8. Certifications & Licenses
        certs = self._extract_certifications(prof_dict, resume_dict)
        lics = self._extract_licenses(prof_dict, resume_dict)

        # 9. Professional Summary grounded strictly in facts
        summary, summary_prov = self._synthesize_factual_summary(
            personal=personal,
            experiences=experiences,
            educations=educations,
            skills=matching_skills or additional_skills,
            target_role=target_role,
            target_company=target_company,
            custom_instructions=custom_instructions,
        )

        # 10. Assemble Provenance Map
        prov_map: Dict[str, ClaimProvenance] = {}
        if summary_prov:
            prov_map[summary_prov.claim_id] = summary_prov
        prov_map.update(exp_claims)
        prov_map.update(edu_claims)
        prov_map.update(proj_claims)

        return TailoredResume(
            user_id=user_id,
            target_role=target_role,
            target_company=target_company,
            source_resume_id=resume_dict.get("id"),
            job_description_id=jd_dict.get("id"),
            personal_info=personal,
            professional_summary=summary,
            summary_provenance=summary_prov,
            matching_skills=matching_skills,
            additional_skills=additional_skills,
            skills_by_category=skills_by_cat,
            experience_entries=experiences,
            education_entries=educations,
            certifications=certs,
            licenses=lics,
            projects=projects,
            provenance_map=prov_map,
            version=1,
        )

    def _extract_personal_info(
        self, profile: Dict[str, Any], resume: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extracts personal contact information strictly from verified profile or resume."""
        p_prof = profile.get("personal", {})
        p_res = resume.get("personal", {})

        return {
            "full_name": p_prof.get("full_name") or p_res.get("full_name") or profile.get("full_name") or "",
            "email": p_prof.get("email") or p_res.get("email") or profile.get("email") or "",
            "phone": p_prof.get("phone") or p_res.get("phone") or profile.get("phone") or "",
            "location": p_prof.get("location") or p_res.get("location") or profile.get("location") or "",
            "headline": p_prof.get("headline") or p_res.get("headline") or profile.get("headline") or "",
            "github": p_prof.get("github") or p_res.get("github") or profile.get("github") or "",
            "linkedin": p_prof.get("linkedin") or p_res.get("linkedin") or profile.get("linkedin") or "",
            "portfolio": p_prof.get("portfolio") or p_res.get("portfolio") or profile.get("portfolio") or "",
        }

    def _extract_jd_keywords(
        self, jd: Dict[str, Any], match_result: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Collects relevant target keywords from JD and Phase 5 match result."""
        keywords: List[str] = []

        if match_result:
            for s in match_result.get("matched_skills", []):
                s_name = s.get("name") if isinstance(s, dict) else str(s)
                if s_name and s_name.lower() not in [k.lower() for k in keywords]:
                    keywords.append(s_name)

        # JD Required Skills
        for sk in jd.get("required_skills", []) + jd.get("preferred_skills", []):
            sk_name = sk.get("name") if isinstance(sk, dict) else str(sk)
            if sk_name and sk_name.lower() not in [k.lower() for k in keywords]:
                keywords.append(sk_name)

        # JD Role Title terms
        role = jd.get("role_title") or jd.get("job_title") or ""
        for word in re.findall(r"[A-Za-z0-9+#]+", role):
            if len(word) > 2 and word.lower() not in ["and", "the", "for", "with"]:
                if word.lower() not in [k.lower() for k in keywords]:
                    keywords.append(word)

        return keywords

    def _prioritize_skills(
        self, profile: Dict[str, Any], resume: Dict[str, Any], jd_keywords: List[str]
    ) -> tuple[List[str], List[str], Dict[str, List[str]]]:
        """Partitions candidate's skills into matching (promoted) and additional skills."""
        all_skills: List[str] = []

        def add_s(s_val: Any):
            if not s_val:
                return
            if isinstance(s_val, list):
                for item in s_val:
                    add_s(item)
            elif isinstance(s_val, dict):
                for v in s_val.values():
                    add_s(v)
            elif isinstance(s_val, str):
                s_clean = s_val.strip()
                if s_clean and s_clean.lower() not in [x.lower() for x in all_skills]:
                    all_skills.append(s_clean)

        add_s(profile.get("skills"))
        add_s(profile.get("technical_skills"))
        add_s(profile.get("professional_skills"))
        add_s(profile.get("soft_skills"))
        add_s(resume.get("skills"))
        add_s(resume.get("technical_skills"))

        jd_lower = [k.lower() for k in jd_keywords]
        matching: List[str] = []
        additional: List[str] = []

        for skill in all_skills:
            s_low = skill.lower()
            if any(k in s_low or s_low in k for k in jd_lower):
                matching.append(skill)
            else:
                additional.append(skill)

        # Re-categorize technical vs professional
        by_cat: Dict[str, List[str]] = {}
        raw_tech = profile.get("technical_skills")
        if isinstance(raw_tech, dict):
            for k, val_list in raw_tech.items():
                if isinstance(val_list, list) and val_list and k != "all_skills":
                    cat_name = k.replace("_", " ").title()
                    by_cat[cat_name] = [v for v in val_list if isinstance(v, str)]

        return matching, additional, by_cat

    def _build_tailored_experience(
        self,
        profile: Dict[str, Any],
        resume: Dict[str, Any],
        jd_keywords: List[str],
    ) -> tuple[List[TailoredExperience], Dict[str, ClaimProvenance]]:
        """Tailors work experience, ranking and ordering bullets by alignment."""
        raw_exps = (
            profile.get("work_experience")
            or profile.get("experience")
            or resume.get("work_experience")
            or resume.get("experience")
            or []
        )

        experiences: List[TailoredExperience] = []
        claims: Dict[str, ClaimProvenance] = {}

        for e_idx, exp in enumerate(raw_exps):
            if not isinstance(exp, dict):
                continue

            raw_resps = exp.get("responsibilities", [])
            if isinstance(raw_resps, str):
                raw_resps = [r.strip() for r in raw_resps.split("\n") if r.strip()]

            scored_bullets: List[TailoredBullet] = []
            for b_idx, resp in enumerate(raw_resps):
                text = str(resp).strip()
                if not text:
                    continue

                # Match keywords in responsibility
                t_low = text.lower()
                matched = [kw for kw in jd_keywords if kw.lower() in t_low]
                rel_score = len(matched) * 1.5

                claim_id = f"claim_exp_{e_idx}_{b_idx}_{uuid.uuid4().hex[:6]}"
                exp_ev_status = exp.get("verification_status") or exp.get("evidence_status") or "EXTRACTED_UNVERIFIED"
                prov = ClaimProvenance(
                    claim_id=claim_id,
                    generated_text=text,
                    source_type="candidate_profile" if profile.get("work_experience") else "uploaded_resume",
                    source_record_id=f"work_experience[{e_idx}]",
                    source_field=f"responsibilities[{b_idx}]",
                    source_version=1,
                    evidence_status=exp_ev_status,
                    confidence=1.0,
                )
                claims[claim_id] = prov
                scored_bullets.append(
                    TailoredBullet(
                        bullet_text=text,
                        claim_id=claim_id,
                        provenance=prov,
                        matched_keywords=matched,
                        relevance_score=rel_score,
                    )
                )

            # Prioritize matching bullets first, then remaining
            scored_bullets.sort(key=lambda b: b.relevance_score, reverse=True)

            experiences.append(
                TailoredExperience(
                    employer=exp.get("employer") or exp.get("company") or "Organization",
                    job_title=exp.get("job_title") or exp.get("role") or "Role",
                    start_date=exp.get("start_date"),
                    end_date=exp.get("end_date"),
                    duration=exp.get("duration"),
                    is_current=bool(exp.get("is_current", False)),
                    bullets=scored_bullets,
                    evidence_status=exp.get("verification_status") or exp.get("evidence_status") or "EXTRACTED_UNVERIFIED",
                )
            )

        return experiences, claims

    def _build_tailored_education(
        self, profile: Dict[str, Any], resume: Dict[str, Any]
    ) -> tuple[List[TailoredEducation], Dict[str, ClaimProvenance]]:
        """Extracts education entries strictly from verified facts."""
        raw_edus = profile.get("education") or resume.get("education") or []
        edus: List[TailoredEducation] = []
        claims: Dict[str, ClaimProvenance] = {}

        for idx, ed in enumerate(raw_edus):
            if not isinstance(ed, dict):
                continue
            inst = ed.get("institution") or ed.get("university") or ""
            deg = ed.get("degree") or ""
            if not inst and not deg:
                continue

            claim_id = f"claim_edu_{idx}_{uuid.uuid4().hex[:6]}"
            edu_ev_status = ed.get("verification_status") or ed.get("evidence_status") or "EXTRACTED_UNVERIFIED"
            prov = ClaimProvenance(
                claim_id=claim_id,
                generated_text=f"{deg} at {inst}",
                source_type="candidate_profile" if profile.get("education") else "uploaded_resume",
                source_record_id=f"education[{idx}]",
                source_field="degree/institution",
                evidence_status=edu_ev_status,
                confidence=1.0,
            )
            claims[claim_id] = prov

            yr = ed.get("expected_graduation_year") or ed.get("graduation_year")
            cg = ed.get("current_cgpa") or ed.get("cgpa")
            edus.append(
                TailoredEducation(
                    institution=inst,
                    degree=deg,
                    major=ed.get("major"),
                    graduation_year=int(yr) if yr else None,
                    cgpa=float(cg) if cg else None,
                    evidence_status=edu_ev_status,
                    claim_id=claim_id,
                )
            )

        return edus, claims

    def _build_tailored_projects(
        self,
        profile: Dict[str, Any],
        resume: Dict[str, Any],
        jd_keywords: List[str],
    ) -> tuple[List[TailoredProject], Dict[str, ClaimProvenance]]:
        """Extracts and scores candidate's projects against target JD keywords."""
        raw_projs = profile.get("projects") or resume.get("projects") or []
        projs: List[TailoredProject] = []
        claims: Dict[str, ClaimProvenance] = {}

        for p_idx, p in enumerate(raw_projs):
            if not isinstance(p, dict):
                continue
            title = p.get("title") or p.get("name") or ""
            if not title:
                continue

            desc = p.get("description") or ""
            techs = p.get("technologies") or []
            if isinstance(techs, str):
                techs = [t.strip() for t in techs.split(",") if t.strip()]

            # Score project relevance
            combined_txt = f"{title} {desc} {' '.join(techs)}".lower()
            matched = [kw for kw in jd_keywords if kw.lower() in combined_txt]
            rel = float(len(matched))

            claim_id = f"claim_proj_{p_idx}_{uuid.uuid4().hex[:6]}"
            proj_ev_status = p.get("verification_status") or p.get("evidence_status") or "EXTRACTED_UNVERIFIED"
            prov = ClaimProvenance(
                claim_id=claim_id,
                generated_text=f"{title}: {desc[:80]}",
                source_type="candidate_profile" if profile.get("projects") else "uploaded_resume",
                source_record_id=f"projects[{p_idx}]",
                source_field="title/description",
                evidence_status=proj_ev_status,
                confidence=1.0,
            )
            claims[claim_id] = prov

            projs.append(
                TailoredProject(
                    title=title,
                    description=desc,
                    technologies=techs,
                    relevance_score=rel,
                    claim_id=claim_id,
                )
            )

        # Sort projects by relevance
        projs.sort(key=lambda p: p.relevance_score, reverse=True)
        return projs, claims

    def _extract_certifications(
        self, profile: Dict[str, Any], resume: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        raw = profile.get("certifications") or resume.get("certifications") or []
        out = []
        for c in raw:
            if isinstance(c, dict):
                ev = c.get("verification_status") or c.get("evidence_status") or "EXTRACTED_UNVERIFIED"
                entry = dict(c)
                entry["verification_status"] = ev
                out.append(entry)
            elif isinstance(c, str) and c.strip():
                out.append({"name": c.strip(), "verification_status": "EXTRACTED_UNVERIFIED"})
        return out

    def _extract_licenses(
        self, profile: Dict[str, Any], resume: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        raw = profile.get("licenses") or profile.get("statutory_licenses") or resume.get("licenses") or []
        out = []
        for l in raw:
            if isinstance(l, dict):
                ev = l.get("verification_status") or l.get("evidence_status") or "EXTRACTED_UNVERIFIED"
                entry = dict(l)
                entry["verification_status"] = ev
                entry["is_license"] = True
                out.append(entry)
            elif isinstance(l, str) and l.strip():
                out.append({"name": l.strip(), "is_license": True, "verification_status": "EXTRACTED_UNVERIFIED"})
        return out

    def _synthesize_factual_summary(
        self,
        personal: Dict[str, Any],
        experiences: List[TailoredExperience],
        educations: List[TailoredEducation],
        skills: List[str],
        target_role: str,
        target_company: str,
        custom_instructions: Optional[str] = None,
    ) -> tuple[str, ClaimProvenance]:
        """Synthesizes a professional summary grounded strictly in verifiable facts."""
        headline = personal.get("headline") or target_role

        # Build evidence grounding
        highest_edu = educations[0] if educations else None
        recent_exp = experiences[0] if experiences else None

        parts = []
        if highest_edu and highest_edu.degree:
            edu_str = highest_edu.degree
            if highest_edu.major:
                edu_str += f" in {highest_edu.major}"
            parts.append(f"Qualified with a {edu_str} from {highest_edu.institution}")

        if recent_exp and recent_exp.job_title:
            dur_str = f" ({recent_exp.duration})" if recent_exp.duration else ""
            parts.append(f"experience as {recent_exp.job_title} at {recent_exp.employer}{dur_str}")

        top_skills = skills[:4]
        skills_phrase = f"skilled in {', '.join(top_skills)}" if top_skills else ""

        body = ""
        if parts:
            body = f"{headline} with " + " and ".join(parts)
            if skills_phrase:
                body += f", {skills_phrase}."
            else:
                body += "."
        elif skills_phrase:
            body = f"Dedicated {headline} {skills_phrase}."
        else:
            body = f"Motivated {headline} focused on delivering professional excellence."

        closing = f" Prepared to contribute effectively to {target_company} as {target_role}."
        summary_text = body + closing

        # Determine evidence status
        has_unverified = False
        if highest_edu and highest_edu.evidence_status == "EXTRACTED_UNVERIFIED":
            has_unverified = True
        if recent_exp and recent_exp.evidence_status == "EXTRACTED_UNVERIFIED":
            has_unverified = True

        claim_id = f"claim_summary_{uuid.uuid4().hex[:8]}"
        prov = ClaimProvenance(
            claim_id=claim_id,
            generated_text=summary_text,
            source_type="synthesized_summary",
            source_field="profile_synthesis",
            evidence_status="EXTRACTED_UNVERIFIED" if has_unverified else "USER_CONFIRMED",
            confidence=0.95,
        )

        return summary_text, prov
