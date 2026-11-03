"""Universal Document Generation and Export Engine (Architecture v2.1.1 - Phase 6).

Generates high-fidelity, ATS-friendly PDF and DOCX application documents:
- Tailored Resumes
- Customized Cover Letters
- Screening Question & Answer Sheets
- Consolidated Application Packets (combining all materials + audit summary)

Provides template styling (Modern, Minimal, Traditional, Executive, Technical, Healthcare, Academic)
and verifies PDF and DOCX structural integrity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import html
from pathlib import Path
from typing import Any, Dict
import uuid
import zipfile

from docx import Document
from docx.shared import Inches, Pt
import pypdf
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer

from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
from src.utils.logger import setup_logger

logger = setup_logger("DocumentGenerator")


class DocumentTemplate(str, Enum):
    """Layout and typography styles for generated application documents."""
    MODERN = "Modern (Clean, Slate Accent)"
    MINIMAL = "Minimal (Black & White, High ATS)"
    TRADITIONAL = "Traditional (Serif, Classic Layout)"
    EXECUTIVE = "Executive (Navy & Gold Accent)"
    TECHNICAL = "Technical (Monospace Skills, Dense)"
    HEALTHCARE = "Healthcare (Clinical, Structured)"
    ACADEMIC = "Academic (Curriculum Vitae Style)"


@dataclass
class GeneratedDocument:
    """Metadata record for a generated document."""
    document_type: str  # "resume", "cover_letter", "screening_qa", "application_packet"
    file_format: str  # "pdf", "docx"
    file_path: str
    filename: str
    file_hash: str
    file_size_bytes: int
    template: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UniversalDocumentGenerator:
    """Enterprise-grade document generator producing validated PDF and DOCX materials."""

    def __init__(self):
        pass

    # -------------------------------------------------------------------------
    # 1. TAILORED RESUME GENERATORS (PDF & DOCX)
    # -------------------------------------------------------------------------

    def generate_resume_pdf(
        self,
        resume: TailoredResume,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates ATS-optimized PDF resume."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"resume_{uuid.uuid4().hex[:10]}.pdf"
        fpath = output_dir / fname

        doc = SimpleDocTemplate(
            str(fpath),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        accent_color = self._get_template_color(template)

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=accent_color,
            spaceAfter=4,
        )
        contact_style = ParagraphStyle(
            "ContactInfo",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=8,
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=accent_color,
            spaceBefore=8,
            spaceAfter=3,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            spaceAfter=4,
        )
        bullet_style = ParagraphStyle(
            "Bullet",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            leftIndent=12,
            spaceAfter=2,
        )

        story = []

        # Header: Name and Contact
        name = resume.personal_info.get("full_name") or "Candidate Name"
        story.append(Paragraph(html.escape(name), title_style))

        contact_bits = []
        p = resume.personal_info
        if p.get("location"):
            contact_bits.append(p["location"])
        if p.get("phone"):
            contact_bits.append(p["phone"])
        if p.get("email"):
            contact_bits.append(p["email"])
        if p.get("linkedin"):
            contact_bits.append(p["linkedin"])
        if p.get("github"):
            contact_bits.append(p["github"])

        if contact_bits:
            story.append(Paragraph(html.escape(" | ".join(contact_bits)), contact_style))

        story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=6))

        # Professional Summary
        if resume.professional_summary:
            story.append(Paragraph("PROFESSIONAL SUMMARY", section_style))
            story.append(Paragraph(html.escape(resume.professional_summary), body_style))
            story.append(Spacer(1, 4))

        # Skills
        if resume.matching_skills or resume.additional_skills or resume.skills_by_category:
            story.append(Paragraph("SKILLS & COMPETENCIES", section_style))
            if resume.matching_skills:
                story.append(
                    Paragraph(
                        f"<b>Core Capabilities:</b> {html.escape(', '.join(resume.matching_skills))}",
                        body_style,
                    )
                )
            for cat, sk_list in resume.skills_by_category.items():
                if sk_list:
                    story.append(
                        Paragraph(
                            f"<b>{html.escape(cat)}:</b> {html.escape(', '.join(sk_list))}",
                            body_style,
                        )
                    )
            if resume.additional_skills and not resume.skills_by_category:
                story.append(
                    Paragraph(
                        f"<b>Additional Skills:</b> {html.escape(', '.join(resume.additional_skills))}",
                        body_style,
                    )
                )
            story.append(Spacer(1, 4))

        # Work Experience
        if resume.experience_entries:
            story.append(Paragraph("PROFESSIONAL EXPERIENCE", section_style))
            for exp in resume.experience_entries:
                dur_str = f" ({exp.duration})" if exp.duration else ""
                story.append(
                    Paragraph(
                        f"<b>{html.escape(exp.job_title)}</b> — <i>{html.escape(exp.employer)}</i>{html.escape(dur_str)}",
                        body_style,
                    )
                )
                for b in exp.bullets:
                    story.append(Paragraph(f"• {html.escape(b.bullet_text)}", bullet_style))
                story.append(Spacer(1, 3))

        # Projects
        if resume.projects:
            story.append(Paragraph("KEY PROJECTS & DELIVERABLES", section_style))
            for prj in resume.projects:
                tech_str = f" <i>({', '.join(prj.technologies)})</i>" if prj.technologies else ""
                story.append(
                    Paragraph(
                        f"<b>{html.escape(prj.title)}</b>{tech_str}",
                        body_style,
                    )
                )
                if prj.description:
                    story.append(Paragraph(html.escape(prj.description), body_style))
                for b in prj.bullets:
                    story.append(Paragraph(f"• {html.escape(b.bullet_text)}", bullet_style))
                story.append(Spacer(1, 3))

        # Education
        if resume.education_entries:
            story.append(Paragraph("EDUCATION & CREDENTIALS", section_style))
            for edu in resume.education_entries:
                parts = [edu.degree]
                if edu.major:
                    parts.append(edu.major)
                deg_str = " in ".join(parts) if len(parts) > 1 else parts[0]
                yr_str = f" ({edu.graduation_year})" if edu.graduation_year else ""
                gpa_str = f" | CGPA: {edu.cgpa}" if edu.cgpa else ""
                story.append(
                    Paragraph(
                        f"<b>{html.escape(deg_str)}</b> — {html.escape(edu.institution)}{yr_str}{gpa_str}",
                        body_style,
                    )
                )
            story.append(Spacer(1, 4))

        # Certifications and Licenses
        if resume.licenses or resume.certifications:
            story.append(Paragraph("CERTIFICATIONS & LICENSES", section_style))
            for lic in resume.licenses:
                l_name = lic.get("name") if isinstance(lic, dict) else str(lic)
                story.append(Paragraph(f"• <b>Statutory License:</b> {html.escape(l_name)}", bullet_style))
            for cert in resume.certifications:
                c_name = cert.get("name") if isinstance(cert, dict) else str(cert)
                story.append(Paragraph(f"• <b>Certification:</b> {html.escape(c_name)}", bullet_style))

        doc.build(story)
        self.validate_pdf_document(fpath)

        file_bytes = fpath.read_bytes()
        fhash = hashlib.sha256(file_bytes).hexdigest()
        return GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(fpath),
            filename=fname,
            file_hash=fhash,
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    def generate_resume_docx(
        self,
        resume: TailoredResume,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates ATS-optimized Word DOCX resume."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"resume_{uuid.uuid4().hex[:10]}.docx"
        fpath = output_dir / fname

        doc = Document()
        for sec in doc.sections:
            sec.top_margin = Inches(0.5)
            sec.bottom_margin = Inches(0.5)
            sec.left_margin = Inches(0.5)
            sec.right_margin = Inches(0.5)

        # Header
        name = resume.personal_info.get("full_name") or "Candidate Name"
        h = doc.add_heading(name, level=0)
        h.paragraph_format.space_after = Pt(2)

        # Contact Info
        contact_bits = []
        p = resume.personal_info
        for k in ["location", "phone", "email", "linkedin", "github"]:
            if p.get(k):
                contact_bits.append(p[k])
        if contact_bits:
            cp = doc.add_paragraph(" | ".join(contact_bits))
            cp.paragraph_format.space_after = Pt(6)

        # Professional Summary
        if resume.professional_summary:
            doc.add_heading("PROFESSIONAL SUMMARY", level=1)
            doc.add_paragraph(resume.professional_summary)

        # Skills
        if resume.matching_skills or resume.additional_skills or resume.skills_by_category:
            doc.add_heading("SKILLS & COMPETENCIES", level=1)
            if resume.matching_skills:
                sp = doc.add_paragraph()
                sp.add_run("Core Capabilities: ").bold = True
                sp.add_run(", ".join(resume.matching_skills))
            for cat, sk_list in resume.skills_by_category.items():
                if sk_list:
                    cp = doc.add_paragraph()
                    cp.add_run(f"{cat}: ").bold = True
                    cp.add_run(", ".join(sk_list))
            if resume.additional_skills and not resume.skills_by_category:
                ap = doc.add_paragraph()
                ap.add_run("Additional Skills: ").bold = True
                ap.add_run(", ".join(resume.additional_skills))

        # Experience
        if resume.experience_entries:
            doc.add_heading("PROFESSIONAL EXPERIENCE", level=1)
            for exp in resume.experience_entries:
                dur_str = f" ({exp.duration})" if exp.duration else ""
                ep = doc.add_paragraph()
                ep.add_run(f"{exp.job_title} — {exp.employer}{dur_str}").bold = True
                for b in exp.bullets:
                    doc.add_paragraph(b.bullet_text, style="List Bullet")

        # Projects
        if resume.projects:
            doc.add_heading("KEY PROJECTS & DELIVERABLES", level=1)
            for prj in resume.projects:
                tech_str = f" ({', '.join(prj.technologies)})" if prj.technologies else ""
                pp = doc.add_paragraph()
                pp.add_run(f"{prj.title}{tech_str}").bold = True
                if prj.description:
                    doc.add_paragraph(prj.description)
                for b in prj.bullets:
                    doc.add_paragraph(b.bullet_text, style="List Bullet")

        # Education
        if resume.education_entries:
            doc.add_heading("EDUCATION", level=1)
            for edu in resume.education_entries:
                parts = [edu.degree]
                if edu.major:
                    parts.append(edu.major)
                deg_str = " in ".join(parts) if len(parts) > 1 else parts[0]
                yr_str = f" ({edu.graduation_year})" if edu.graduation_year else ""
                gpa_str = f" | CGPA: {edu.cgpa}" if edu.cgpa else ""
                doc.add_paragraph(f"{deg_str} — {edu.institution}{yr_str}{gpa_str}", style="List Bullet")

        # Certifications and Licenses
        if resume.licenses or resume.certifications:
            doc.add_heading("CERTIFICATIONS & LICENSES", level=1)
            for lic in resume.licenses:
                l_name = lic.get("name") if isinstance(lic, dict) else str(lic)
                doc.add_paragraph(f"Statutory License: {l_name}", style="List Bullet")
            for cert in resume.certifications:
                c_name = cert.get("name") if isinstance(cert, dict) else str(cert)
                doc.add_paragraph(f"Certification: {c_name}", style="List Bullet")

        doc.save(str(fpath))
        self.validate_docx_document(fpath)

        file_bytes = fpath.read_bytes()
        fhash = hashlib.sha256(file_bytes).hexdigest()
        return GeneratedDocument(
            document_type="resume",
            file_format="docx",
            file_path=str(fpath),
            filename=fname,
            file_hash=fhash,
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    # -------------------------------------------------------------------------
    # 2. COVER LETTER GENERATORS (PDF & DOCX)
    # -------------------------------------------------------------------------

    def generate_cover_letter_pdf(
        self,
        cover_letter: CoverLetter,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates professional PDF cover letter."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"cover_letter_{uuid.uuid4().hex[:10]}.pdf"
        fpath = output_dir / fname

        doc = SimpleDocTemplate(
            str(fpath),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()
        accent_color = self._get_template_color(template)

        title_style = ParagraphStyle(
            "CLTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=accent_color,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "CLBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            spaceAfter=10,
        )

        story = []
        # Render markdown paragraphs into flowables
        lines = cover_letter.letter_text.split("\n")
        for line in lines:
            line_str = line.strip()
            if not line_str:
                story.append(Spacer(1, 4))
                continue
            if line_str.startswith("# "):
                story.append(Paragraph(html.escape(line_str[2:]), title_style))
                story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
            elif line_str.startswith("**") and line_str.endswith("**"):
                story.append(Paragraph(f"<b>{html.escape(line_str[2:-2])}</b>", body_style))
            else:
                story.append(Paragraph(html.escape(line_str), body_style))

        doc.build(story)
        self.validate_pdf_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    def generate_cover_letter_docx(
        self,
        cover_letter: CoverLetter,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates professional DOCX cover letter."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"cover_letter_{uuid.uuid4().hex[:10]}.docx"
        fpath = output_dir / fname

        doc = Document()
        for sec in doc.sections:
            sec.top_margin = Inches(0.75)
            sec.bottom_margin = Inches(0.75)
            sec.left_margin = Inches(0.75)
            sec.right_margin = Inches(0.75)

        for line in cover_letter.letter_text.split("\n"):
            line_s = line.strip()
            if not line_s:
                continue
            if line_s.startswith("# "):
                doc.add_heading(line_s[2:], level=0)
            elif line_s.startswith("**") and line_s.endswith("**"):
                p = doc.add_paragraph()
                p.add_run(line_s[2:-2]).bold = True
            else:
                doc.add_paragraph(line_s)

        doc.save(str(fpath))
        self.validate_docx_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="cover_letter",
            file_format="docx",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    # -------------------------------------------------------------------------
    # 3. SCREENING Q&A GENERATORS (PDF & DOCX)
    # -------------------------------------------------------------------------

    def generate_screening_qa_pdf(
        self,
        qa_packet: ScreeningQAPacket,
        output_dir: Path,
    ) -> GeneratedDocument:
        """Generates screening questions & answers document in PDF format."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"screening_qa_{uuid.uuid4().hex[:10]}.pdf"
        fpath = output_dir / fname

        doc = SimpleDocTemplate(
            str(fpath),
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        accent = colors.HexColor("#2B6CB0")

        title_style = ParagraphStyle("QATitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=accent, spaceAfter=8)
        q_style = ParagraphStyle("QText", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=14, textColor=colors.HexColor("#1A202C"), spaceBefore=6, spaceAfter=2)
        cat_style = ParagraphStyle("QCat", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=10, textColor=colors.HexColor("#718096"), spaceAfter=2)
        ans_style = ParagraphStyle("QAns", parent=styles["Normal"], fontName="Helvetica", fontSize=9, leading=13, leftIndent=10, spaceAfter=6)

        story = [
            Paragraph("SCREENING QUESTIONS & RESPONSES", title_style),
            HRFlowable(width="100%", thickness=1, color=accent, spaceAfter=8),
        ]

        for idx, q in enumerate(qa_packet.questions, start=1):
            story.append(Paragraph(f"<b>Question {idx}:</b> {html.escape(q.question_text)}", q_style))
            story.append(Paragraph(f"Category: <i>{html.escape(q.category)}</i> | Status: <b>{html.escape(q.state)}</b>", cat_style))
            story.append(Paragraph(f"<b>Response:</b> {html.escape(q.answer_text)}", ans_style))
            story.append(Spacer(1, 4))

        doc.build(story)
        self.validate_pdf_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="screening_qa",
            file_format="pdf",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=DocumentTemplate.MODERN.value,
        )

    def generate_screening_qa_docx(
        self,
        qa_packet: ScreeningQAPacket,
        output_dir: Path,
    ) -> GeneratedDocument:
        """Generates screening questions & answers document in Word DOCX format."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"screening_qa_{uuid.uuid4().hex[:10]}.docx"
        fpath = output_dir / fname

        doc = Document()
        doc.add_heading("SCREENING QUESTIONS & RESPONSES", level=0)

        for idx, q in enumerate(qa_packet.questions, start=1):
            qp = doc.add_paragraph()
            qp.add_run(f"Question {idx}: {q.question_text}").bold = True
            doc.add_paragraph(f"Category: {q.category} | Review State: {q.state}")
            ap = doc.add_paragraph()
            ap.add_run("Response: ").bold = True
            ap.add_run(q.answer_text)

        doc.save(str(fpath))
        self.validate_docx_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="screening_qa",
            file_format="docx",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=DocumentTemplate.MODERN.value,
        )

    # -------------------------------------------------------------------------
    # 4. CONSOLIDATED APPLICATION PACKET GENERATORS (PDF & DOCX)
    # -------------------------------------------------------------------------

    def generate_application_packet_pdf(
        self,
        resume: TailoredResume,
        cover_letter: CoverLetter,
        qa_packet: ScreeningQAPacket,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates consolidated PDF combining Resume, Cover Letter, QA, and Audit Summary."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"packet_{uuid.uuid4().hex[:10]}.pdf"
        fpath = output_dir / fname

        doc = SimpleDocTemplate(
            str(fpath),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        accent = self._get_template_color(template)

        title_style = ParagraphStyle("PktTitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=accent, spaceAfter=4)
        sec_style = ParagraphStyle("PktSec", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=accent, spaceBefore=12, spaceAfter=4)
        body_style = ParagraphStyle("PktBody", parent=styles["Normal"], fontName="Helvetica", fontSize=9, leading=13, spaceAfter=4)

        story = [
            Paragraph("APPLICATION PACKET", title_style),
            Paragraph(f"Candidate: <b>{html.escape(resume.personal_info.get('full_name', ''))}</b> | Target: <b>{html.escape(resume.target_role)}</b> at <b>{html.escape(resume.target_company)}</b>", body_style),
            HRFlowable(width="100%", thickness=1.5, color=accent, spaceAfter=10),
            Paragraph("SECTION 1: COVER LETTER", sec_style),
        ]

        # Add cover letter paragraphs
        for p in cover_letter.paragraphs:
            story.append(Paragraph(html.escape(p), body_style))
            story.append(Spacer(1, 4))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray, spaceBefore=8, spaceAfter=8))
        story.append(Paragraph("SECTION 2: TAILORED RESUME SUMMARY", sec_style))
        if resume.professional_summary:
            story.append(Paragraph(f"<b>Summary:</b> {html.escape(resume.professional_summary)}", body_style))
        if resume.matching_skills:
            story.append(Paragraph(f"<b>Key Competencies:</b> {html.escape(', '.join(resume.matching_skills))}", body_style))

        for exp in resume.experience_entries:
            dur = f" ({exp.duration})" if exp.duration else ""
            story.append(Paragraph(f"<b>{html.escape(exp.job_title)}</b> at {html.escape(exp.employer)}{dur}", body_style))
            for b in exp.bullets:
                story.append(Paragraph(f"• {html.escape(b.bullet_text)}", body_style))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray, spaceBefore=8, spaceAfter=8))
        story.append(Paragraph("SECTION 3: SCREENING QUESTIONS & ANSWERS", sec_style))
        for q in qa_packet.questions:
            story.append(Paragraph(f"<b>Q: {html.escape(q.question_text)}</b>", body_style))
            story.append(Paragraph(f"A: {html.escape(q.answer_text)}", body_style))

        doc.build(story)
        self.validate_pdf_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="application_packet",
            file_format="pdf",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    def generate_application_packet_docx(
        self,
        resume: TailoredResume,
        cover_letter: CoverLetter,
        qa_packet: ScreeningQAPacket,
        output_dir: Path,
        template: DocumentTemplate = DocumentTemplate.MODERN,
    ) -> GeneratedDocument:
        """Generates consolidated Word DOCX packet."""
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"packet_{uuid.uuid4().hex[:10]}.docx"
        fpath = output_dir / fname

        doc = Document()
        doc.add_heading("APPLICATION PACKET", level=0)
        doc.add_paragraph(f"Candidate: {resume.personal_info.get('full_name', '')} | Role: {resume.target_role} | Company: {resume.target_company}")

        doc.add_heading("SECTION 1: COVER LETTER", level=1)
        for p in cover_letter.paragraphs:
            doc.add_paragraph(p)

        doc.add_heading("SECTION 2: TAILORED RESUME", level=1)
        if resume.professional_summary:
            doc.add_paragraph(f"Summary: {resume.professional_summary}")
        for exp in resume.experience_entries:
            dur = f" ({exp.duration})" if exp.duration else ""
            ep = doc.add_paragraph()
            ep.add_run(f"{exp.job_title} at {exp.employer}{dur}").bold = True
            for b in exp.bullets:
                doc.add_paragraph(b.bullet_text, style="List Bullet")

        doc.add_heading("SECTION 3: SCREENING QUESTIONS & ANSWERS", level=1)
        for q in qa_packet.questions:
            qp = doc.add_paragraph()
            qp.add_run(f"Q: {q.question_text}").bold = True
            doc.add_paragraph(f"A: {q.answer_text}")

        doc.save(str(fpath))
        self.validate_docx_document(fpath)

        file_bytes = fpath.read_bytes()
        return GeneratedDocument(
            document_type="application_packet",
            file_format="docx",
            file_path=str(fpath),
            filename=fname,
            file_hash=hashlib.sha256(file_bytes).hexdigest(),
            file_size_bytes=len(file_bytes),
            template=template.value,
        )

    # -------------------------------------------------------------------------
    # 5. VALIDATION UTILITIES
    # -------------------------------------------------------------------------

    @staticmethod
    def validate_pdf_document(file_path: Path) -> bool:
        """Validates that a generated PDF is non-empty, contains standard headers, and is extractable."""
        if not file_path.exists():
            raise FileNotFoundError(f"PDF file does not exist: {file_path}")
        if file_path.stat().st_size < 100:
            raise ValueError(f"PDF file is suspiciously small ({file_path.stat().st_size} bytes).")

        header = file_path.read_bytes()[:5]
        if header != b"%PDF-":
            raise ValueError(f"Invalid PDF header: {header}")

        # Verify extractability using pypdf
        reader = pypdf.PdfReader(str(file_path))
        if len(reader.pages) < 1:
            raise ValueError("PDF contains 0 pages.")
        text = "".join(page.extract_text() or "" for page in reader.pages)
        if not text.strip():
            raise ValueError(f"PDF contains no extractable text: {file_path}")
        return True

    @staticmethod
    def validate_docx_document(file_path: Path) -> bool:
        """Validates that a generated DOCX is a valid ZIP archive containing word/document.xml."""
        if not file_path.exists():
            raise FileNotFoundError(f"DOCX file does not exist: {file_path}")
        if not zipfile.is_zipfile(str(file_path)):
            raise ValueError(f"DOCX file is not a valid ZIP package: {file_path}")

        with zipfile.ZipFile(str(file_path)) as z:
            names = z.namelist()
            if "word/document.xml" not in names:
                raise ValueError("DOCX package missing word/document.xml")

        # Verify Document parser can load it
        Document(str(file_path))
        return True

    @staticmethod
    def _get_template_color(template: DocumentTemplate) -> colors.HexColor:
        """Returns primary accent color for template."""
        if template == DocumentTemplate.EXECUTIVE:
            return colors.HexColor("#1A365D")  # Deep Navy
        elif template == DocumentTemplate.HEALTHCARE:
            return colors.HexColor("#2C7A7B")  # Teal
        elif template == DocumentTemplate.TRADITIONAL:
            return colors.HexColor("#2D3748")  # Charcoal
        elif template == DocumentTemplate.TECHNICAL:
            return colors.HexColor("#2B6CB0")  # Blue
        elif template == DocumentTemplate.ACADEMIC:
            return colors.HexColor("#742A2A")  # Maroon
        elif template == DocumentTemplate.MINIMAL:
            return colors.HexColor("#1A202C")  # Dark Slate
        return colors.HexColor("#3182CE")  # Modern Royal Blue
