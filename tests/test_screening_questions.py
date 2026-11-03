"""Unit tests for Universal Screening Question Assistant (Architecture v2.1.1 - Phase 6).
Verifies 19-category classification, 5 review states, NEEDS_CANDIDATE_INPUT enforcement, and character limits.
"""

import unittest

from src.preparer.question_answerer import (
    AnswerState,
    QuestionAnswerer,
    QuestionCategory,
)


class TestUniversalScreeningQuestionAssistant(unittest.TestCase):
    """Test suite for Universal Screening Question Assistant."""

    def setUp(self):
        self.assistant = QuestionAnswerer()

        # Verified Candidate Profile
        self.candidate_profile = {
            "personal": {
                "full_name": "Priya Sharma",
                "email": "priya.sharma@example.com",
                "location": "San Francisco, CA",
            },
            "education": [
                {
                    "institution": "Stanford University",
                    "degree": "MS Computer Science",
                    "expected_graduation_year": 2025,
                    "current_cgpa": 3.9,
                }
            ],
            "work_experience": [
                {
                    "employer": "Stripe",
                    "job_title": "Software Engineering Intern",
                    "duration": "6 months",
                    "responsibilities": ["Built idempotency keys for payment processing APIs."],
                }
            ],
            "skills": ["Python", "Go", "Distributed Systems", "SQL"],
            "candidate_inputs": {
                "expected_stipend": "$60 / hour",
                "internship_availability": "June 2025",
                "weekly_working_hours": "40 hours",
                "work_authorization": "US Citizen",
                "requires_sponsorship": False,
                "willing_to_relocate": True,
            },
        }

    def test_nineteen_category_classification(self):
        """Verifies accurate classification across all 19 standardized categories."""
        test_cases = [
            ("What is your expected salary or hourly rate?", QuestionCategory.SALARY_EXPECTATIONS),
            ("Are you legally authorized to work in the US without sponsorship?", QuestionCategory.WORK_AUTHORIZATION),
            ("What is your earliest available start date?", QuestionCategory.AVAILABILITY_START_DATE),
            ("Are you willing to relocate to Seattle for this role?", QuestionCategory.LOCATION_REMOTE),
            ("Do you possess an active Professional Engineer (PE) license?", QuestionCategory.LICENSING_CERTIFICATION),
            ("What degree did you obtain from your university?", QuestionCategory.EDUCATION_DEGREE),
            ("How many years of experience do you have with Go?", QuestionCategory.EXPERIENCE_YEARS),
            ("List your programming languages and technical tools.", QuestionCategory.TECHNICAL_SKILL),
            ("Are you fluent in Spanish or Mandarin?", QuestionCategory.LANGUAGE_PROFICIENCY),
            ("What is the largest team size you have directly managed?", QuestionCategory.MANAGEMENT_LEADERSHIP),
            ("Tell me about a time you handled a difficult conflict with a coworker.", QuestionCategory.BEHAVIORAL_SITUATIONAL),
            ("Please provide a link to your GitHub or design portfolio.", QuestionCategory.PROJECT_PORTFOLIO),
            ("Do you have prior experience working in the healthcare domain?", QuestionCategory.INDUSTRY_DOMAIN),
            ("What percentage of domestic travel are you willing to accept?", QuestionCategory.WILLINGNESS_TRAVEL),
            ("Are you willing to undergo a standard background check and drug screen?", QuestionCategory.BACKGROUND_CHECK),
            ("Can you work night shifts and alternate weekend rotations?", QuestionCategory.SCHEDULE_AVAILABILITY),
            ("Do you have a dedicated home office with high-speed internet?", QuestionCategory.EQUIPMENT_HOME_OFFICE),
            ("Why do you want to work at our company?", QuestionCategory.COMPANY_MOTIVATION),
            ("Do you have any other comments for the hiring team?", QuestionCategory.GENERAL_OTHER),
        ]

        for query, expected_cat in test_cases:
            cat = self.assistant.classify_question(query)
            self.assertEqual(cat, expected_cat, f"Failed classifying '{query}': got {cat.value}")

    def test_missing_data_enforces_needs_candidate_input(self):
        """Verifies that questions with unverified or missing profile data return NEEDS_CANDIDATE_INPUT."""
        empty_profile = {"personal": {}, "candidate_inputs": {}}

        # 1. Salary missing -> NEEDS_CANDIDATE_INPUT
        sq_sal = self.assistant.answer_universal_question(
            "What is your target salary?",
            user_id=1,
            candidate_profile=empty_profile,
        )
        self.assertEqual(sq_sal.state, AnswerState.NEEDS_CANDIDATE_INPUT.value)
        self.assertIn("NEEDS CANDIDATE INPUT", sq_sal.answer_text)

        # 2. Availability missing -> NEEDS_CANDIDATE_INPUT
        sq_avail = self.assistant.answer_universal_question(
            "When can you start?",
            user_id=1,
            candidate_profile=empty_profile,
        )
        self.assertEqual(sq_avail.state, AnswerState.NEEDS_CANDIDATE_INPUT.value)

        # 3. Behavioral STAR narrative missing -> NEEDS_CANDIDATE_INPUT
        sq_star = self.assistant.answer_universal_question(
            "Tell me about a time you failed.",
            user_id=1,
            candidate_profile=empty_profile,
        )
        self.assertEqual(sq_star.state, AnswerState.NEEDS_CANDIDATE_INPUT.value)

    def test_verified_data_generates_draft_with_evidence(self):
        """Verifies that questions backed by verified profile facts generate GENERATED_DRAFT with citations."""
        sq_deg = self.assistant.answer_universal_question(
            "What degree do you hold?",
            user_id=1,
            candidate_profile=self.candidate_profile,
        )
        self.assertEqual(sq_deg.state, AnswerState.GENERATED_DRAFT.value)
        self.assertIn("Stanford University", sq_deg.answer_text)
        self.assertIn("MS Computer Science", sq_deg.answer_text)
        self.assertTrue(len(sq_deg.evidence_sources) > 0)

        sq_work = self.assistant.answer_universal_question(
            "What is your work authorization status?",
            user_id=1,
            candidate_profile=self.candidate_profile,
        )
        self.assertEqual(sq_work.state, AnswerState.GENERATED_DRAFT.value)
        self.assertIn("US Citizen", sq_work.answer_text)

    def test_character_limit_detection(self):
        """Verifies that answers exceeding character limits are flagged."""
        sq = self.assistant.answer_universal_question(
            "Why do you want to work at our company?",
            user_id=1,
            candidate_profile=self.candidate_profile,
            job_description={"company_name": "Google", "role_title": "Software Engineer"},
            character_limit=50,  # Deliberately short limit
        )
        self.assertTrue(sq.exceeds_limit)

    def test_batch_answering_and_state_transitions(self):
        """Verifies batch question answering and user edit/approval transitions."""
        questions = [
            "What is your expected compensation?",
            "What technical skills do you have?",
        ]
        results = self.assistant.batch_answer_questions(
            questions=questions,
            user_id=1,
            candidate_profile=self.candidate_profile,
        )
        self.assertEqual(len(results), 2)

        q1 = results[0]
        # Candidate edits the answer
        updated_q1 = self.assistant.update_question_answer(
            question=q1,
            new_answer="My target rate is $65 / hour, negotiable for the right role.",
            new_state=AnswerState.USER_APPROVED,
        )
        self.assertEqual(updated_q1.state, AnswerState.USER_APPROVED.value)
        self.assertEqual(updated_q1.provenance.source_type, "user_edit")
        self.assertEqual(updated_q1.provenance.evidence_status, "USER_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
