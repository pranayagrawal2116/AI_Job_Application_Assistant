"""Reusable Metric Card component with professional styling."""

import streamlit as st


def render_metric_card(
    title: str,
    value: str | int | float,
    subtitle: str = "",
    delta: str = "",
    delta_color: str = "normal",
    border_color: str = "#E2E8F0",
):
    """Renders a stylized KPI card with border accent and responsive layout."""
    st.markdown(
        f"""
        <div style="
            background-color: var(--card-bg, #ffffff);
            border: 1px solid {border_color};
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        ">
            <div style="font-size: 0.85rem; color: #64748B; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">
                {title}
            </div>
            <div style="font-size: 1.85rem; font-weight: 700; color: #0F172A; margin: 4px 0;">
                {value}
            </div>
            <div style="font-size: 0.8rem; color: #94A3B8;">
                {subtitle} {f"<span style='color:#10B981;'>{delta}</span>" if delta else ""}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
