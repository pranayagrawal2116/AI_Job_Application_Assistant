"""Candidate Authentication, Registration, and Session Management View."""

from typing import Any, Optional
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import (
    AccountLockedError,
    AuthenticationFailedError,
    DuplicateUserError,
    ValidationError,
)


def _apply_auth_session(user: Any, session: Any) -> None:
    """Sets active candidate session keys in Streamlit session_state."""
    st.session_state["authenticated_user_id"] = user.id
    st.session_state["user_id"] = user.id
    st.session_state["authenticated_session_id"] = session.session_id
    st.session_state["session_id"] = session.session_id
    st.session_state["candidate_name"] = user.full_name
    st.session_state["user_email"] = user.email


def _clear_auth_session(service: DashboardService) -> None:
    """Revokes active server-side session and clears Streamlit session_state."""
    session_id = st.session_state.get("authenticated_session_id") or st.session_state.get("session_id")
    if session_id:
        try:
            service.logout_candidate(str(session_id))
        except Exception:
            pass
    for key in [
        "authenticated_user_id",
        "user_id",
        "authenticated_session_id",
        "session_id",
        "candidate_name",
        "user_email",
    ]:
        st.session_state.pop(key, None)


def render_inline_auth(st_module: Optional[Any] = None) -> None:
    """Renders a compact, interactive sign-in and registration card inline inside views."""
    _st = st_module or st
    service = DashboardService.get_instance()

    with _st.container():
        _st.markdown("---")
        _st.markdown("### 🔐 Candidate Sign In / Register")
        _st.caption("Sign in with your candidate credentials to access your private documents and data.")

        tab_in, tab_reg = _st.tabs(["🔑 Sign In", "✨ Register New Account"])

        with tab_in:
            with _st.form("inline_login_form"):
                email = _st.text_input("Email Address", placeholder="candidate@example.com", key="inline_login_email")
                pwd = _st.text_input("Password", type="password", key="inline_login_pwd")
                submit = _st.form_submit_button("🚀 Sign In", type="primary")

                if submit:
                    if not email or not pwd:
                        _st.error("Please enter both email and password.")
                    else:
                        try:
                            user, sess = service.login_candidate(email.strip(), pwd)
                            _apply_auth_session(user, sess)
                            _st.success(f"Welcome back, {user.full_name}!")
                            _st.rerun()
                        except AuthenticationFailedError:
                            _st.error("Invalid email or password. Please try again.")
                        except AccountLockedError as exc:
                            _st.error(f"Account temporarily locked due to multiple failed attempts: {exc}")
                        except ValidationError as exc:
                            _st.error(str(exc))
                        except Exception as exc:
                            _st.error(f"Sign in failed: {exc}")

        with tab_reg:
            with _st.form("inline_register_form"):
                full_name = _st.text_input("Full Name", placeholder="e.g. Jane Doe", key="inline_reg_name")
                email = _st.text_input("Email Address", placeholder="candidate@example.com", key="inline_reg_email")
                pwd = _st.text_input(
                    "Password",
                    type="password",
                    help="Min 8 characters with uppercase, lowercase, digit, and special symbol.",
                    key="inline_reg_pwd",
                )
                pwd_confirm = _st.text_input("Confirm Password", type="password", key="inline_reg_pwd_confirm")
                industry = _st.selectbox(
                    "Target Field / Industry",
                    options=[
                        "Artificial Intelligence & Machine Learning",
                        "Software & Systems Engineering",
                        "Data Science & Analytics",
                        "Healthcare & Medicine",
                        "Finance, Accounting & Banking",
                        "Law & Legal Services",
                        "General Engineering",
                        "Education & Academia",
                        "Management & Operations",
                        "Creative & Media",
                    ],
                    key="inline_reg_industry",
                )
                career_level = _st.selectbox(
                    "Career Level",
                    options=[
                        "Student / Intern",
                        "Entry-Level / Fresher (0-2 years)",
                        "Mid-Career (3-5 years)",
                        "Senior / Lead (5+ years)",
                        "Executive / Director",
                        "Career Changer",
                    ],
                    key="inline_reg_career",
                )
                reg_submit = _st.form_submit_button("✨ Create Account & Sign In", type="primary")

                if reg_submit:
                    if not full_name or not email or not pwd:
                        _st.error("Please fill in all required fields.")
                    elif pwd != pwd_confirm:
                        _st.error("Passwords do not match.")
                    else:
                        try:
                            user = service.register_candidate(
                                email=email.strip(),
                                password=pwd,
                                full_name=full_name.strip(),
                                profession_industry=industry,
                                career_level=career_level,
                            )
                            user, sess = service.login_candidate(email.strip(), pwd)
                            _apply_auth_session(user, sess)
                            _st.success("Account created successfully! Session established.")
                            _st.rerun()
                        except DuplicateUserError:
                            _st.error("An account with this email address already exists. Please sign in.")
                        except ValidationError as exc:
                            _st.error(str(exc))
                        except Exception as exc:
                            _st.error(f"Registration failed: {exc}")


def render_auth() -> None:
    """Renders the dedicated Sign In / Register / Account Management view."""
    st.markdown("## 🔐 Candidate Authentication & Account Management")
    st.caption("Secure, isolated multi-user account access powered by Argon2id password hashing.")

    service = DashboardService.get_instance()
    auth_uid = st.session_state.get("authenticated_user_id") or st.session_state.get("user_id")
    auth_session = st.session_state.get("authenticated_session_id") or st.session_state.get("session_id")

    # If already authenticated, show account details and logout option
    if auth_uid and auth_session:
        try:
            user_id, _ = service.resolve_authenticated_candidate(
                session_id=str(auth_session),
                client_user_id=int(auth_uid),
            )
            user_row = service.db.get_user_by_id(user_id)
        except Exception:
            user_id = None
            user_row = None

        if user_id and user_row:
            st.success(f"✅ Signed in as **{user_row.get('full_name')}** (`{user_row.get('email')}`)")

            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Candidate User ID", f"#{user_id}")
            with c2:
                st.metric("Industry", user_row.get("profession_industry") or "General")
            with c3:
                st.metric("Career Level", user_row.get("career_level") or "Candidate")

            st.markdown("---")
            col_act1, col_act2 = st.columns([2, 5])
            with col_act1:
                if st.button("🚪 Sign Out of Account", type="primary", key="btn_auth_page_signout"):
                    _clear_auth_session(service)
                    st.success("You have been signed out.")
                    st.rerun()
            return

    # Not authenticated: Show Tabbed Sign In / Register
    tab_sign_in, tab_register = st.tabs(["🔑 Sign In", "✨ Register New Account"])

    with tab_sign_in:
        st.markdown("### 🔑 Sign In to Your Candidate Account")
        st.caption("Enter your email and password to access your uploaded resumes, evaluations, and prepared packets.")

        with st.form("main_sign_in_form"):
            email_in = st.text_input("Email Address", placeholder="candidate@example.com", key="auth_login_email")
            pwd_in = st.text_input("Password", type="password", key="auth_login_pwd")
            submit_btn = st.form_submit_button("🚀 Sign In", type="primary")

            if submit_btn:
                if not email_in or not pwd_in:
                    st.error("Please provide both email address and password.")
                else:
                    try:
                        user, sess = service.login_candidate(email_in.strip(), pwd_in)
                        _apply_auth_session(user, sess)
                        st.success(f"Welcome back, {user.full_name}!")
                        st.rerun()
                    except AuthenticationFailedError:
                        st.error("Invalid email address or password. Please verify and try again.")
                    except AccountLockedError as exc:
                        st.error(f"Account temporarily locked due to multiple failed attempts: {exc}")
                    except ValidationError as exc:
                        st.error(str(exc))
                    except Exception as exc:
                        st.error(f"Sign in failed: {exc}")

    with tab_register:
        st.markdown("### ✨ Register a New Candidate Account")
        st.caption("Create a secure, private candidate workspace. Your data is isolated and protected.")

        with st.form("main_register_form"):
            col_r1, col_r2 = st.columns(2)
            with col_r1:
                name_in = st.text_input("Full Name", placeholder="e.g. Jane Doe", key="auth_reg_name")
                email_reg = st.text_input("Email Address", placeholder="candidate@example.com", key="auth_reg_email")
            with col_r2:
                pwd_reg = st.text_input(
                    "Password",
                    type="password",
                    help="Min 8 characters: uppercase, lowercase, digit, and special symbol.",
                    key="auth_reg_pwd",
                )
                pwd_reg_conf = st.text_input("Confirm Password", type="password", key="auth_reg_pwd_conf")

            col_p1, col_p2 = st.columns(2)
            with col_p1:
                ind_in = st.selectbox(
                    "Primary Profession / Industry",
                    options=[
                        "Artificial Intelligence & Machine Learning",
                        "Software & Systems Engineering",
                        "Data Science & Analytics",
                        "Healthcare & Medicine",
                        "Finance, Accounting & Banking",
                        "Law & Legal Services",
                        "General Engineering",
                        "Education & Academia",
                        "Management & Operations",
                        "Creative & Media",
                    ],
                    key="auth_reg_ind",
                )
            with col_p2:
                lvl_in = st.selectbox(
                    "Career Level",
                    options=[
                        "Student / Intern",
                        "Entry-Level / Fresher (0-2 years)",
                        "Mid-Career (3-5 years)",
                        "Senior / Lead (5+ years)",
                        "Executive / Director",
                        "Career Changer",
                    ],
                    key="auth_reg_lvl",
                )

            st.caption("🔒 Passwords are cryptographically hashed using Argon2id with unique salts.")
            reg_btn = st.form_submit_button("✨ Create Candidate Account", type="primary")

            if reg_btn:
                if not name_in or not email_reg or not pwd_reg:
                    st.error("Please fill in all mandatory fields.")
                elif pwd_reg != pwd_reg_conf:
                    st.error("Passwords do not match.")
                else:
                    try:
                        user = service.register_candidate(
                            email=email_reg.strip(),
                            password=pwd_reg,
                            full_name=name_in.strip(),
                            profession_industry=ind_in,
                            career_level=lvl_in,
                        )
                        user, sess = service.login_candidate(email_reg.strip(), pwd_reg)
                        _apply_auth_session(user, sess)
                        st.success("Account registered and session established! Redirecting...")
                        st.rerun()
                    except DuplicateUserError:
                        st.error("An account with this email address already exists. Please sign in instead.")
                    except ValidationError as exc:
                        st.error(str(exc))
                    except Exception as exc:
                        st.error(f"Registration failed: {exc}")
