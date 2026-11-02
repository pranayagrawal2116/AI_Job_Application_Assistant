"""Overview Page: Executive summary, live KPI metrics, and summary charts."""

import streamlit as st

from dashboard.components.metric_card import render_metric_card
from dashboard.services.analytics_service import AnalyticsService
from dashboard.services.dashboard_service import DashboardService


def render_overview():
    """Renders the executive summary overview page."""
    st.markdown("## 📊 Executive Overview")
    st.caption("Real-time metrics, opportunity scoring, and pipeline tracking from local SQLite database.")

    service = DashboardService.get_instance()
    analytics = AnalyticsService(service.db)

    metrics = service.get_metrics()
    df = service.get_all_jobs_df()

    # 1. Primary Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card(
            title="Total Discovered",
            value=metrics["total_discovered"],
            subtitle="Verified SQLite Records",
            border_color="#3B82F6",
        )
    with c2:
        render_metric_card(
            title="Eligible Opportunities",
            value=metrics["eligible_count"],
            subtitle="Strict Eligibility Passed",
            delta=f"{(metrics['eligible_count']/metrics['total_discovered']*100 if metrics['total_discovered']>0 else 0):.0f}% of total",
            border_color="#10B981",
        )
    with c3:
        render_metric_card(
            title="High Match Quality",
            value=metrics["excellent_matches"] + metrics["good_matches"],
            subtitle="Excellent & Good Matches",
            border_color="#6366F1",
        )
    with c4:
        render_metric_card(
            title="Shortlisted",
            value=metrics["shortlisted_count"],
            subtitle="Active Candidate Shortlist",
            border_color="#F59E0B",
        )

    # 2. Secondary Metrics Row (Score Tiers & Pipeline)
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🌟 Excellent (85-100)", metrics["excellent_matches"])
    with col2:
        st.metric("👍 Good (70-84)", metrics["good_matches"])
    with col3:
        st.metric("⚖️ Moderate (50-69)", metrics["moderate_matches"])
    with col4:
        st.metric("🔻 Low (<50)", metrics["low_matches"])
    with col5:
        st.metric("🚫 Ineligible", metrics["ineligible_count"])

    col_p1, col_p2, col_p3 = st.columns(3)
    with col_p1:
        st.metric("📝 Prepared Applications", metrics["prepared_count"])
    with col_p2:
        st.metric("⏳ Awaiting Approval", metrics["awaiting_approval_count"])
    with col_p3:
        st.metric("📬 Applied (Confirmed)", metrics["applied_count"])

    st.divider()

    # 3. Visual Charts Grid
    if not df.empty:
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            fig_score = analytics.get_score_distribution_chart(df)
            st.plotly_chart(fig_score, use_container_width=True)

        with chart_col2:
            fig_elig = analytics.get_eligibility_pie_chart(df)
            st.plotly_chart(fig_elig, use_container_width=True)

        chart_col3, chart_col4 = st.columns(2)
        with chart_col3:
            fig_loc = analytics.get_location_distribution_chart(df)
            st.plotly_chart(fig_loc, use_container_width=True)

        with chart_col4:
            fig_plat = analytics.get_platform_distribution_chart(df)
            st.plotly_chart(fig_plat, use_container_width=True)

        st.plotly_chart(analytics.get_application_funnel_chart(metrics), use_container_width=True)
    else:
        st.info("No job opportunities discovered yet. Head over to Discovery Management to initiate a scan.")
