"""Preparer package: Universal Resume parsing, job alignment, tailored resumes,
cover letters, screening questions, document generation, and human approval.
"""

from src.preparer.approval_gate import ApplicationReviewPacket, HumanApprovalGate
from src.preparer.cover_letter_generator import (
    CareerLevel,
    CoverLetter,
    CoverLetterGenerator,
    LetterTone,
)
from src.preparer.document_generator import (
    DocumentTemplate,
    GeneratedDocument,
    UniversalDocumentGenerator,
)
from src.preparer.form_prefiller import FormFieldMapping, FormFillPlan, FormPrefiller
from src.preparer.job_parser import (
    JobParser,
    JobProvenanceField,
    RequirementClassification,
    StructuredJobDescription,
)
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.question_answerer import (
    AnswerState,
    QuestionAnswerer,
    QuestionCategory,
    ScreeningQAPacket,
    ScreeningQuestion,
)
from src.preparer.resume_matcher import JobAlignment, ResumeJobMatcher
from src.preparer.resume_parser import (
    EducationEntry,
    ExperienceEntry,
    ParsedResume,
    ProjectEntry,
    ResumeParser,
)
from src.preparer.tailored_resume_generator import (
    ClaimProvenance,
    TailoredBullet,
    TailoredEducation,
    TailoredExperience,
    TailoredProject,
    TailoredResume,
    UniversalTailoredResumeGenerator,
)

__all__ = [
    "ResumeParser",
    "ParsedResume",
    "EducationEntry",
    "ExperienceEntry",
    "ProjectEntry",
    "ProfileUpdater",
    "ResumeJobMatcher",
    "JobAlignment",
    "CoverLetterGenerator",
    "CoverLetter",
    "LetterTone",
    "CareerLevel",
    "QuestionAnswerer",
    "ScreeningQuestion",
    "ScreeningQAPacket",
    "QuestionCategory",
    "AnswerState",
    "FormPrefiller",
    "FormFieldMapping",
    "FormFillPlan",
    "HumanApprovalGate",
    "ApplicationReviewPacket",
    "JobParser",
    "StructuredJobDescription",
    "JobProvenanceField",
    "RequirementClassification",
    "TailoredResume",
    "UniversalTailoredResumeGenerator",
    "ClaimProvenance",
    "TailoredBullet",
    "TailoredExperience",
    "TailoredEducation",
    "TailoredProject",
    "UniversalDocumentGenerator",
    "DocumentTemplate",
    "GeneratedDocument",
]
