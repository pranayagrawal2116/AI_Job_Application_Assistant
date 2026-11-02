"""Reusable Search and Filter Component for Job Catalog."""

from typing import Dict, List, Tuple
import pandas as pd
import streamlit as st


def render_job_filters(df: pd.DataFrame) -> pd.DataFrame:
    """Renders comprehensive filter controls and returns the filtered DataFrame."""
    if df.empty:
        return df

    with st.expander("🔍 Filter & Search Opportunities", expanded=True):
        c1, c2, c3 = st.columns([3, 2, 2])

        with c1:
            search_text = st.text_input(
                "Search Keywords",
                placeholder="Role, skill (e.g. PyTorch, NLP), or keyword...",
            )

        with c2:
            all_platforms = sorted(df["platform"].dropna().unique().tolist())
            selected_platforms = st.multiselect(
                "Source Platform",
                options=all_platforms,
                default=[],
            )

        with c3:
            eligibility_choice = st.radio(
                "Eligibility",
                options=["All Opportunities", "Eligible Only (Strict)", "Ineligible Only"],
                horizontal=True,
            )

        col_a, col_b, col_c, col_d = st.columns(4)

        with col_a:
            all_locations = sorted([loc for loc in df["location"].dropna().unique() if loc])
            selected_locations = st.multiselect(
                "Location",
                options=all_locations,
                default=[],
            )

        with col_b:
            work_types = sorted(df["work_arrangement"].dropna().unique().tolist())
            selected_work = st.multiselect(
                "Work Mode",
                options=work_types,
                default=[],
            )

        with col_c:
            min_score = st.slider(
                "Minimum Match Score",
                min_value=0,
                max_value=100,
                value=0,
                step=5,
            )

        with col_d:
            stipend_filter = st.selectbox(
                "Stipend",
                options=["All", "Paid Internships Only", "Unpaid"],
            )

    # Apply filters
    filtered_df = df.copy()

    # 1. Search Query
    if search_text and search_text.strip():
        q = search_text.lower().strip()
        mask = (
            filtered_df["job_title"].str.lower().str.contains(q, na=False)
            | filtered_df["company_name"].str.lower().str.contains(q, na=False)
            | filtered_df["location"].str.lower().str.contains(q, na=False)
            | filtered_df["job_description"].str.lower().str.contains(q, na=False)
        )
        filtered_df = filtered_df[mask]

    # 2. Platform
    if selected_platforms:
        filtered_df = filtered_df[filtered_df["platform"].isin(selected_platforms)]

    # 3. Eligibility
    if eligibility_choice == "Eligible Only (Strict)":
        filtered_df = filtered_df[filtered_df["is_eligible"] == True]
    elif eligibility_choice == "Ineligible Only":
        filtered_df = filtered_df[filtered_df["is_eligible"] == False]

    # 4. Location
    if selected_locations:
        filtered_df = filtered_df[filtered_df["location"].isin(selected_locations)]

    # 5. Work arrangement
    if selected_work:
        filtered_df = filtered_df[filtered_df["work_arrangement"].isin(selected_work)]

    # 6. Score
    if min_score > 0:
        filtered_df = filtered_df[filtered_df["match_score"] >= float(min_score)]

    # 7. Stipend
    if stipend_filter == "Paid Internships Only":
        filtered_df = filtered_df[
            ~filtered_df["stipend"].str.lower().str.contains("unpaid", na=False)
            & ~filtered_df["stipend"].str.lower().str.contains("not disclosed", na=False)
        ]
    elif stipend_filter == "Unpaid":
        filtered_df = filtered_df[filtered_df["stipend"].str.lower().str.contains("unpaid", na=False)]

    return filtered_df

