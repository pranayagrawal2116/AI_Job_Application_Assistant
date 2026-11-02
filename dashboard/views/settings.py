"""Settings Page: Database operations, online backups, CSV exports, and engine configurations."""

from datetime import datetime
from pathlib import Path
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.config import config


def render_settings():
    """Renders system settings, database backups, restore tools, and scoring weights."""
    st.markdown("## ⚙️ Assistant Settings & Operations")
    st.caption("Manage persistent storage, create database backups, export CSV archives, and inspect scoring rules.")

    service = DashboardService.get_instance()
    db_path = service.db.db_path

    tab_db, tab_export, tab_scoring = st.tabs([
        "💾 Database & Backups",
        "📥 Data Export",
        "📐 Active Scoring Rules",
    ])

    with tab_db:
        st.markdown("### 🗄️ SQLite Database Status")
        c1, c2 = st.columns([3, 1])
        path_obj = Path(db_path)
        with c1:
            st.write(f"**Database Location:** `{path_obj.resolve()}`")
            st.write(f"**File Size:** {path_obj.stat().st_size / 1024:.1f} KB" if path_obj.exists() else "File not created")
            st.write(f"**Total Registered Jobs:** {len(service.db.list_jobs())}")
            st.write(f"**Total Registered Applications:** {len(service.db.list_applications())}")
        with c2:
            st.success("🟢 Connected")

        st.divider()

        st.markdown("### 🛡️ Online Database Backup")
        st.caption("Perform an atomic SQLite online backup while the application remains live.")

        col_b1, col_b2 = st.columns(2)
        with col_b1:
            if st.button("📦 Create Instant Database Backup", type="primary"):
                try:
                    backup_file = service.backup_database()
                    st.success(f"Backup created successfully: `{backup_file.name}`")
                except Exception as e:
                    st.error(f"Backup failed: {e}")

        st.divider()

        st.markdown("### 🔄 Restore Database from Backup")
        st.warning("Restoring will replace current database tables with the backup snapshot.")

        backup_dir = Path("data/storage/backups")
        available_backups = []
        if backup_dir.exists():
            available_backups = sorted(list(backup_dir.glob("*.db")), reverse=True)

        if available_backups:
            selected_backup = st.selectbox("Select Available Backup", options=[b.name for b in available_backups])
            if st.button("⚠️ Restore Selected Backup"):
                full_backup_path = backup_dir / selected_backup
                try:
                    service.restore_database(str(full_backup_path))
                    st.success("Database restored successfully.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Restore failed: {e}")
        else:
            st.info("No prior backups found in data/storage/backups/.")

    with tab_export:
        st.markdown("### 📥 Full CSV Archive Export")
        st.caption("Export all currently discovered job opportunities and application statuses to CSV.")

        if st.button("Generate Fresh CSV Export"):
            try:
                exp_path = service.export_jobs_to_csv()
                st.success(f"Export created at `{exp_path}`")
            except Exception as e:
                st.error(f"Export failed: {e}")

        # Download directly
        df = service.get_all_jobs_df()
        if not df.empty:
            csv_bytes = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Download CSV Directly",
                data=csv_bytes,
                file_name=f"all_jobs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )

    with tab_scoring:
        st.markdown("### 📐 Active Multi-Factor Scoring Rules (Phase 3 Spec)")
        st.caption("Sourced directly from config/scoring_rules.yaml:")
        st.json(config.scoring_rules)
