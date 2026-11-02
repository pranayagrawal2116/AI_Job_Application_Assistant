"""Analytics Service: Generates charts, metric aggregates, and skill gap insights."""

from collections import Counter
import re
from typing import Any, Dict, List, Tuple
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.database.db_manager import DatabaseManager


class AnalyticsService:
    """Computes advanced aggregations, visualizations, and skill gap insights."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_score_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Creates match score distribution histogram with score tier color markers."""
        if df.empty or "match_score" not in df.columns:
            return go.Figure()

        fig = px.histogram(
            df,
            x="match_score",
            nbins=20,
            title="Match Score Distribution (0 – 100 Points)",
            labels={"match_score": "Match Score", "count": "Number of Opportunities"},
            color="match_classification",
            color_discrete_map={
                "Excellent": "#10B981",  # Green
                "Good": "#3B82F6",       # Blue
                "Moderate": "#F59E0B",   # Amber
                "Low": "#EF4444",        # Red
            },
        )
        fig.update_layout(
            bargap=0.08,
            xaxis_title="Match Score",
            yaxis_title="Count of Jobs",
            legend_title="Tier",
            margin=dict(l=20, r=20, t=40, b=20),
        )
        return fig

    def get_eligibility_pie_chart(self, df: pd.DataFrame) -> go.Figure:
        """Donut chart for eligibility status."""
        if df.empty or "is_eligible" not in df.columns:
            return go.Figure()

        counts = df["is_eligible"].value_counts()
        labels = ["Eligible" if k else "Ineligible" for k in counts.index]
        values = counts.values

        fig = go.Figure(
            data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.55,
                    marker=dict(colors=["#10B981", "#EF4444"]),
                )
            ]
        )
        fig.update_layout(
            title="Candidate Eligibility Breakdown",
            margin=dict(l=20, r=20, t=40, b=20),
            showlegend=True,
        )
        return fig

    def get_platform_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Bar chart showing opportunities by source platform."""
        if df.empty or "platform" not in df.columns:
            return go.Figure()

        plat_counts = df["platform"].value_counts().reset_index()
        plat_counts.columns = ["Platform", "Count"]

        fig = px.bar(
            plat_counts,
            x="Platform",
            y="Count",
            title="Jobs by Source Platform",
            color="Platform",
            color_discrete_sequence=px.colors.qualitative.Prism,
        )
        fig.update_layout(showlegend=False, margin=dict(l=20, r=20, t=40, b=20))
        return fig

    def get_location_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Bar chart of top locations."""
        if df.empty or "location" not in df.columns:
            return go.Figure()

        # Simplify location strings
        def simplify_loc(loc_str: str) -> str:
            loc_l = str(loc_str).lower()
            if "home" in loc_l or "remote" in loc_l:
                return "Remote / WFH"
            if "pune" in loc_l:
                return "Pune"
            if "mumbai" in loc_l:
                return "Mumbai"
            if "bengaluru" in loc_l or "bangalore" in loc_l:
                return "Bengaluru"
            if "delhi" in loc_l or "noida" in loc_l or "gurgaon" in loc_l:
                return "Delhi NCR"
            if "hyderabad" in loc_l:
                return "Hyderabad"
            if "france" in loc_l:
                return "France (Overseas)"
            if "canada" in loc_l:
                return "Canada (Overseas)"
            return loc_str[:25]

        loc_series = df["location"].apply(simplify_loc)
        counts = loc_series.value_counts().head(8).reset_index()
        counts.columns = ["Location", "Count"]

        fig = px.bar(
            counts,
            x="Count",
            y="Location",
            orientation="h",
            title="Opportunities by Geographic Location",
            color="Location",
            color_discrete_sequence=px.colors.qualitative.Safe,
        )
        fig.update_layout(yaxis=dict(autorange="reversed"), showlegend=False, margin=dict(l=20, r=20, t=40, b=20))
        return fig

    def get_skills_demand_analysis(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Extracts confirmed matching skills and prioritized missing skills from job descriptions and breakdowns."""
        all_skills: List[str] = []
        missing_skills: List[str] = []

        SKILL_LEXICON = [
            "Python", "Machine Learning", "Deep Learning", "Generative AI", "LLM", "NLP",
            "Computer Vision", "PyTorch", "TensorFlow", "Scikit-Learn", "Pandas", "NumPy",
            "Data Science", "SQL", "Docker", "Flutter", "FastAPI", "Flask", "OpenCV",
            "Keras", "Hugging Face", "LangChain", "RAG", "AWS", "Git", "C++", "Java",
        ]

        for _, row in df.iterrows():
            desc = str(row.get("job_description", "")).lower()
            title = str(row.get("job_title", "")).lower()
            content = f"{title} {desc}"

            # Check lexicon keywords
            for skill in SKILL_LEXICON:
                pattern = rf"\b{re.escape(skill.lower())}\b"
                if re.search(pattern, content):
                    all_skills.append(skill)
                    # Candidate profile knows: Python, ML, AI, Data Science, Pandas, NumPy, Scikit-learn, Flutter
                    candidate_has = skill in [
                        "Python", "Machine Learning", "Artificial Intelligence", "Data Science",
                        "Data preprocessing", "Data visualization", "Flutter", "Pandas", "NumPy", "Scikit-Learn"
                    ]
                    if not candidate_has:
                        missing_skills.append(skill)

        demand_counts = Counter(all_skills)
        missing_counts = Counter(missing_skills)

        df_demand = pd.DataFrame(demand_counts.most_common(12), columns=["Skill", "Demand Frequency"])
        df_missing = pd.DataFrame(missing_counts.most_common(8), columns=["Missing Skill", "Opportunities Requesting"])

        return df_demand, df_missing

    def get_missing_skills_chart(self, df_missing: pd.DataFrame) -> go.Figure:
        """Creates prioritized learning recommendation bar chart."""
        if df_missing.empty:
            return go.Figure()

        fig = px.bar(
            df_missing,
            x="Opportunities Requesting",
            y="Missing Skill",
            orientation="h",
            title="High-Priority Skills to Learn (Employer Demand Gap)",
            color="Opportunities Requesting",
            color_continuous_scale="Oranges",
        )
        fig.update_layout(
            yaxis=dict(autorange="reversed"),
            coloraxis_showscale=False,
            margin=dict(l=20, r=20, t=40, b=20),
        )
        return fig

    def get_application_funnel_chart(self, metrics: Dict[str, Any]) -> go.Figure:
        """Funnel/pipeline chart of application state machine."""
        stages = [
            "Discovered",
            "Under Review",
            "Shortlisted",
            "Application Prepared",
            "Awaiting Approval",
            "Applied",
            "Interview",
        ]
        values = [
            metrics.get("total_discovered", 0),
            metrics.get("total_discovered", 0) - metrics.get("shortlisted_count", 0),
            metrics.get("shortlisted_count", 0),
            metrics.get("prepared_count", 0),
            metrics.get("awaiting_approval_count", 0),
            metrics.get("applied_count", 0),
            metrics.get("interview_count", 0),
        ]

        fig = go.Figure(go.Funnel(
            y=stages,
            x=values,
            textinfo="value+percent initial",
            marker=dict(color=["#6366F1", "#8B5CF6", "#EC4899", "#F59E0B", "#10B981", "#059669", "#047857"]),
        ))
        fig.update_layout(
            title="Application State Machine Pipeline",
            margin=dict(l=20, r=20, t=40, b=20),
        )
        return fig
