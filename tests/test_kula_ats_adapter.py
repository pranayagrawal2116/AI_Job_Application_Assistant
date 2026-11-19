"""Unit & Integration Tests for Kula ATS Adapter and Universal Matching Updates."""

import pytest
from src.preparer.ats_adapter_registry import ATSAdapterRegistry, KulaATSAdapter
from src.preparer.universal_field_mapper import (
    FormFieldTarget,
    ProvenanceStatus,
    UniversalFieldMapper,
)


def test_kula_ats_adapter_matches_urls():
    adapter = KulaATSAdapter()
    assert adapter.provider_name == "KULA"

    # Matches kula.ai URLs
    assert adapter.matches("https://careers.kula.ai/avoma/13624-senior-ml-engineer/apply?source=linkedin")
    assert adapter.matches("https://kula.ai/jobs/12345/apply")

    # Matches DOM markers
    assert adapter.matches("https://jobs.example.com/apply", html_snippet="<input name='info.first_name'>")
    assert adapter.matches("https://jobs.example.com/apply", html_snippet="<div class='chakra-tabs'>Apply for this position</div>")

    # Does not match unrelated ATS
    assert not adapter.matches("https://jobs.lever.co/company/apply")
    assert not adapter.matches("https://boards.greenhouse.io/company/jobs/123")


def test_kula_ats_adapter_registry_resolution():
    adapter = ATSAdapterRegistry.resolve("https://careers.kula.ai/avoma/13624-senior-ml-engineer/apply?source=linkedin")
    assert adapter.provider_name == "KULA"
    assert "button:has-text('Apply for this position')" in adapter.get_submit_selectors()


def test_kula_form_field_mapping_and_essay_protection():
    profile = {
        "personal": {
            "name": "Pranay Agrawal",
            "email": "candidate@example.com",
            "phone": "+91 98765 43210",
        },
        "work_experience": [
            {
                "employer": "Sarita Infotech",
                "duration_months": 3,
                "job_title": "Project Manager",
            }
        ],
    }

    mapper = UniversalFieldMapper(profile)

    # 1. First name and last name resolved from single name field
    target_first = FormFieldTarget(name_attr="info.first_name", accessible_label="First name*")
    dec_first = mapper.match_field(target_first)
    assert dec_first.action == "FILL"
    assert dec_first.intended_value == "Pranay"

    target_last = FormFieldTarget(name_attr="info.last_name", accessible_label="Last name*")
    dec_last = mapper.match_field(target_last)
    assert dec_last.action == "FILL"
    assert dec_last.intended_value == "Agrawal"

    # 2. Email & Phone
    target_email = FormFieldTarget(name_attr="info.email", accessible_label="Email*")
    dec_email = mapper.match_field(target_email)
    assert dec_email.action == "FILL"
    assert dec_email.intended_value == "candidate@example.com"

    target_phone = FormFieldTarget(element_id="phone", field_type="tel", accessible_label="Phone*")
    dec_phone = mapper.match_field(target_phone)
    assert dec_phone.action == "FILL"
    assert dec_phone.intended_value == "9876543210"

    # 3. Experience years
    target_exp = FormFieldTarget(
        name_attr="additional_info._26835",
        accessible_label="How many years of relevant experience do you have?*",
    )
    dec_exp = mapper.match_field(target_exp)
    assert dec_exp.action == "FILL"
    assert dec_exp.intended_value == "0"

    # 4. Notice period -> NEEDS_INPUT
    target_notice = FormFieldTarget(
        name_attr="additional_info._26834",
        accessible_label="What is your notice period?*",
    )
    dec_notice = mapper.match_field(target_notice)
    assert dec_notice.action == "NEEDS_INPUT"

    # 5. Open-ended question MUST NOT match current_company
    target_essay = FormFieldTarget(
        name_attr="additional_info._26837",
        accessible_label="Why do you think Avoma will be a good choice as your next organization to work at?*",
    )
    dec_essay = mapper.match_field(target_essay)
    assert dec_essay.action in ("AMBIGUOUS", "NEEDS_INPUT")
    assert dec_essay.intended_value is None
