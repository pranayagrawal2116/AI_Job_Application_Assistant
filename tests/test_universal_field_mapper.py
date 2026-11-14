"""Unit tests for UniversalFieldMapper (Phase C.1: Trusted External ATS Form Auto-Population).

Verifies:
- Accurate extraction and mapping of candidate profile facts.
- Strict zero-hallucination policy (gender, DOB, salary, notice period are NEVER inferred).
- Name, phone, education, and work experience duration splitting.
- Semantic field mapping resolution against ATS input elements.
"""

from src.preparer.universal_field_mapper import (
    UniversalFieldMapper,
    ProvenanceStatus,
    FormFieldTarget,
)


class TestUniversalFieldMapper:
    """Test suite for UniversalFieldMapper and candidate fact mapping."""

    def test_extract_candidate_facts_full_profile(self):
        """Verify candidate facts extracted from full profile with proper provenance."""
        profile = {
            "full_name": "Pranay Anup Agrawal",
            "email": "pranay@example.com",
            "phone": "+91 9510029575",
            "location": "Pune, Maharashtra, India",
            "education": [
                {
                    "institution": "MIT World Peace University",
                    "degree": "B.Tech in Computer Science and Engineering",
                    "major": "Computer Science with AI & Data Science",
                    "current_cgpa": "7.6",
                    "expected_graduation_year": "2028",
                }
            ],
            "work_experience": [
                {
                    "company": "Sarita Infotech Pvt. Ltd.",
                    "title": "Project Manager",
                    "duration_months": 3,
                }
            ],
            "technical_skills": ["Python", "Machine Learning", "FastAPI", "React"],
            "personal": {
                "linkedin_url": "https://linkedin.com/in/pranayagrawal",
                "github_url": "https://github.com/pranayagrawal2116",
            },
        }

        mapper = UniversalFieldMapper(profile)
        facts = mapper.facts

        assert facts["first_name"].value == "Pranay"
        assert facts["middle_name"].value == "Anup"
        assert facts["last_name"].value == "Agrawal"
        assert facts["full_name"].value == "Pranay Anup Agrawal"
        assert facts["email"].value == "pranay@example.com"
        assert facts["phone"].value == "9510029575"
        assert facts["country_code"].value == "+91"
        assert facts["current_location"].value == "Pune, Maharashtra, India"
        assert facts["college_name"].value == "MIT World Peace University"
        assert facts["branch"].value == "Computer Science with AI & Data Science"
        assert facts["cgpa"].value == "7.6"
        assert facts["graduation_year"].value == "2028"
        assert facts["experience_years"].value == "0"
        assert facts["experience_months"].value == "3"

    def test_zero_hallucination_guarantee_for_missing_sensitive_facts(self):
        """Verify that gender, DOB, salary, and notice period are NEVER inferred or fabricated."""
        profile = {
            "full_name": "Alex Smith",
            "email": "alex@example.com",
        }

        mapper = UniversalFieldMapper(profile)
        facts = mapper.facts

        assert facts["gender"].provenance == ProvenanceStatus.NEEDS_CANDIDATE_INPUT
        assert facts["gender"].value is None

        assert facts["date_of_birth"].provenance == ProvenanceStatus.NEEDS_CANDIDATE_INPUT
        assert facts["date_of_birth"].value is None

        assert facts["current_salary"].provenance == ProvenanceStatus.NEEDS_CANDIDATE_INPUT
        assert facts["current_salary"].value is None

        assert facts["expected_salary"].provenance == ProvenanceStatus.NEEDS_CANDIDATE_INPUT
        assert facts["expected_salary"].value is None

        assert facts["availability_days"].provenance == ProvenanceStatus.NEEDS_CANDIDATE_INPUT
        assert facts["availability_days"].value is None

    def test_name_splitting_two_tokens(self):
        """Verify standard First + Last name splitting."""
        first, middle, last = UniversalFieldMapper.split_name("Jane Doe")
        assert first == "Jane"
        assert middle == ""
        assert last == "Doe"

    def test_name_splitting_single_token(self):
        """Verify single token name handling."""
        first, middle, last = UniversalFieldMapper.split_name("Cher")
        assert first == "Cher"
        assert middle == ""
        assert last == ""

    def test_phone_number_dial_code_splitting(self):
        """Verify extraction of dial codes like +1, +44, +91."""
        code_in, num_in = UniversalFieldMapper.split_phone("+91 9876543210")
        assert code_in == "+91"
        assert num_in == "9876543210"

        code_us, num_us = UniversalFieldMapper.split_phone("+1 (555) 123-4567")
        assert code_us == "+1"
        assert "5551234567" in num_us

    def test_keka_form_targets_resolution(self):
        """Verify matching against known Keka ATS form field selectors and IDs."""
        profile = {
            "full_name": "Pranay Anup Agrawal",
            "email": "pranay@example.com",
            "phone": "+91 9510029575",
            "location": "Pune",
            "work_experience": [{"duration_months": 15}],
        }

        mapper = UniversalFieldMapper(profile)

        # Simulate Keka ATS form elements
        keka_elements = [
            FormFieldTarget(element_id="firstName", name_attr="firstName", accessible_label="First Name"),
            FormFieldTarget(element_id="middleName", name_attr="middleName", accessible_label="Middle Name"),
            FormFieldTarget(element_id="lastName", name_attr="lastName", accessible_label="Last Name"),
            FormFieldTarget(element_id="email", name_attr="email", accessible_label="Email"),
            FormFieldTarget(element_id="mobilePhone.number", name_attr="mobilePhone.number", accessible_label="Mobile Number"),
            FormFieldTarget(element_id="workExperience", name_attr="workExperience", accessible_label="Total Experience (Years)"),
            FormFieldTarget(
                element_id="workExperience.months",
                name_attr="workExperience.months",
                accessible_label="Months",
                field_type="select",
                options=[("0", "0"), ("1", "1"), ("2", "2"), ("3", "3"), ("4", "4")],
            ),
            FormFieldTarget(element_id="currentLocation", name_attr="currentLocation", accessible_label="Current Location"),
        ]

        decisions = [mapper.match_field(elem) for elem in keka_elements]
        decision_map = {d.field_target.element_id: d for d in decisions}

        assert decision_map["firstName"].action == "FILL"
        assert decision_map["firstName"].intended_value == "Pranay"

        assert decision_map["middleName"].action == "FILL"
        assert decision_map["middleName"].intended_value == "Anup"

        assert decision_map["lastName"].action == "FILL"
        assert decision_map["lastName"].intended_value == "Agrawal"

        assert decision_map["email"].action == "FILL"
        assert decision_map["email"].intended_value == "pranay@example.com"

        assert decision_map["mobilePhone.number"].action == "FILL"
        assert decision_map["mobilePhone.number"].intended_value == "9510029575"

        assert decision_map["workExperience"].action == "FILL"
        assert decision_map["workExperience"].intended_value == "1"

        assert decision_map["workExperience.months"].action == "FILL"
        assert decision_map["workExperience.months"].intended_value == "3"

    def test_never_overwrite_existing_field_values(self):
        """Verify that fields with existing values (e.g. populated by ATS or candidate) are preserved."""
        profile = {"full_name": "Jane Doe", "email": "jane@example.com"}
        mapper = UniversalFieldMapper(profile)

        element_with_val = FormFieldTarget(
            element_id="firstName",
            name_attr="firstName",
            accessible_label="First Name",
            current_value="Janet",  # Already present on page
        )

        decision = mapper.match_field(element_with_val)
        assert decision.action == "PRESERVE_EXISTING"
        assert decision.intended_value == "Janet"
