"""Score Breakdown & Multi-Factor Matching Analysis UI Component."""

from typing import Any, Dict, List, Optional
import streamlit as st

from src.matcher.job_matcher import EvaluationResult


def render_score_breakdown(evaluation: Optional[EvaluationResult], job_score: float, tier: str, is_eligible: bool):
    """Renders visual multi-factor score breakdown, skill matches, and recommendations."""
    tier_colors = {
        "Excellent": "#10B981",
        "Good": "#3B82F6",
        "Moderate": "#F59E0B",
        "Low": "#EF4444",
    }
    color = tier_colors.get(tier, "#64748B")

    # Score Banner
    st.markdown(
        f"""
        <div style="background-color: #F8FAFC; border-left: 5px solid {color}; padding: 14px 18px; border-radius: 6px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="font-size: 1.6rem; font-weight: 700; color: #0F172A;">{job_score:.1f} / 100</span>
                    <span style="background-color: {color}; color: white; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; margin-left: 10px;">
                        {tier} Match
                    </span>
                </div>
                <div>
                    <span style="background-color: {'#DCFCE7' if is_eligible else '#FEE2E2'}; color: {'#166534' if is_eligible else '#991B1B'}; padding: 6px 14px; border-radius: 14px; font-weight: 700; font-size: 0.85rem;">
                        {'✓ ELIGIBLE' if is_eligible else '✗ INELIGIBLE'}
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not evaluation:
        st.info("Detailed sub-dimension evaluation was not pre-calculated for this listing.")
        return

    exp = evaluation.explanation
    scores = evaluation.score_breakdown.get("scores", {})

    st.markdown("#### 📊 Evaluation Breakdown by Category")

    c1, c2 = st.columns(2)
    with c1:
        _render_progress("Domain Relevance", scores.get("domain", 0), 30)
        _render_progress("Technical Skills", scores.get("skills", 0), 25)
        _render_progress("Education Eligibility", scores.get("education", 0), 20)
    with c2:
        _render_progress("Experience Compatibility", scores.get("experience", 0), 10)
        _render_progress("Location Preference", scores.get("location", 0), 10)
        _render_progress("Duration Compatibility", scores.get("duration", 0), 5)

    st.divider()

    # Skill Analysis Chips
    st.markdown("#### 🧩 Skill Analysis")
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Matching & Related Skills:**")
        if exp.matching_skills:
            chips = "".join([
                f"<span style='background:#E0F2FE; color:#0369A1; padding:4px 8px; border-radius:4px; margin:2px 4px; display:inline-block; font-size:0.85rem;'>✓ {s}</span>"
                for s in exp.matching_skills
            ])
            st.markdown(chips, unsafe_allow_html=True)
        else:
            st.caption("No direct matching skills detected.")

    with col_b:
        st.markdown("**Missing / Desired Skills:**")
        if exp.missing_skills:
            chips = "".join([
                f"<span style='background:#FEF3C7; color:#92400E; padding:4px 8px; border-radius:4px; margin:2px 4px; display:inline-block; font-size:0.85rem;'>△ {s}</span>"
                for s in exp.missing_skills
            ])
            st.markdown(chips, unsafe_allow_html=True)
        else:
            st.caption("No significant missing requirements.")

    # Disqualification / Recommendations
    if not is_eligible and exp.disqualification_reasons:
        st.warning(f"**Disqualification Reason:** {', '.join(exp.disqualification_reasons)}")

    if exp.recommendations:
        st.info(f"💡 **Recommendation:** {exp.recommendations[0]}")


def _render_progress(label: str, score: float, max_score: float):
    pct = min(1.0, max(0.0, score / max_score if max_score > 0 else 0))
    st.write(f"**{label}**: {score:.1f} / {max_score:.0f} pts")
    st.progress(pct)
