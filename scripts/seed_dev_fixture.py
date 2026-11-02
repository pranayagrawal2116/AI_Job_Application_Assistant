#!/usr/bin/env python3
"""Development Fixture Seeding Script.

Safely migrates local development candidate profiles into the multi-user SQLite database.
Enforces explicit password setup; NEVER creates public default accounts or shared passwords.
"""

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.database.db_manager import DatabaseManager
from src.database.exceptions import DuplicateUserError, ValidationError
from src.security.auth import AuthenticationEngine
from src.utils.logger import setup_logger

logger = setup_logger("SeedDevFixture")

DEFAULT_FIXTURE_EXAMPLE = REPO_ROOT / "tests" / "fixtures" / "candidate_profile_fixture.example.json"
DEFAULT_FIXTURE_LOCAL = REPO_ROOT / "tests" / "fixtures" / "candidate_profile_fixture.json"


def seed_dev_fixture(
    email: str,
    password: str,
    full_name: str,
    fixture_path: Path,
    db_path: Path = None,
) -> int:
    """Seeds a local development user and associated candidate profile."""
    if not password or len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")

    if not fixture_path.is_file():
        raise FileNotFoundError(f"Fixture file not found at: {fixture_path}")

    with open(fixture_path, "r", encoding="utf-8") as f:
        profile_data = json.load(f)

    db_manager = DatabaseManager(db_path=db_path) if db_path else DatabaseManager()
    auth_engine = AuthenticationEngine(db_manager=db_manager)

    # 1. Register or retrieve user
    try:
        user = auth_engine.register_user(
            email=email,
            password=password,
            full_name=full_name,
            profession_industry="Artificial Intelligence / Data Science",
            career_level="Undergraduate / Fresher",
        )
        logger.info("Successfully registered local dev user '%s' (User ID: %d)", email, user.id)
    except DuplicateUserError:
        logger.warning("User '%s' already exists. Updating existing user's candidate profile.", email)
        user = auth_engine.get_user_by_email(email)
        if not user:
            raise RuntimeError(f"Could not load existing user for email '{email}'")

    # 2. Store profile in candidate_profiles table
    with db_manager.transaction() as conn:
        cursor = conn.cursor()
        # Deactivate existing active profiles
        cursor.execute(
            "UPDATE candidate_profiles SET is_active = 0 WHERE user_id = ?",
            (user.id,),
        )
        cursor.execute(
            """
            INSERT INTO candidate_profiles (user_id, profile_data, version, is_active, last_updated)
            VALUES (?, ?, 1, 1, CURRENT_TIMESTAMP)
            """,
            (user.id, json.dumps(profile_data)),
        )
        profile_id = cursor.lastrowid
        logger.info("Associated candidate profile fixture (Profile ID: %d) with User #%d", profile_id, user.id)

    print(f"✓ Development fixture successfully seeded for User #{user.id} ({user.email}).")
    return user.id


def main():
    parser = argparse.ArgumentParser(
        description="Seed local development user and candidate profile with explicit password setup."
    )
    parser.add_argument(
        "--email",
        type=str,
        default="developer.dev@example.local",
        help="Email address for the local development account.",
    )
    parser.add_argument(
        "--full-name",
        type=str,
        default="Developer Dev",
        help="Full name of the development candidate.",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Explicit password for account setup. If omitted, prompts interactively.",
    )
    parser.add_argument(
        "--fixture",
        type=str,
        default=None,
        help="Path to candidate profile JSON fixture. Defaults to local or example fixture.",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to SQLite database file. Defaults to data/storage/job_assistant.db.",
    )

    args = parser.parse_args()

    # Determine fixture path
    if args.fixture:
        fixture_path = Path(args.fixture)
    elif DEFAULT_FIXTURE_LOCAL.is_file():
        fixture_path = DEFAULT_FIXTURE_LOCAL
    else:
        fixture_path = DEFAULT_FIXTURE_EXAMPLE

    # Require explicit password setup
    password = args.password
    if not password:
        if sys.stdin.isatty():
            print("Explicit password setup required (Zero-shared-credential policy).")
            password = getpass.getpass("Enter password for dev account (min 8 chars): ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: Passwords do not match.", file=sys.stderr)
                sys.exit(1)
        else:
            print(
                "Error: Explicit password setup is mandatory. Passwords cannot be empty or default. "
                "Provide --password in automated scripts or run interactively in a TTY.",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        db_path = Path(args.db_path) if args.db_path else None
        seed_dev_fixture(
            email=args.email,
            password=password,
            full_name=args.full_name,
            fixture_path=fixture_path,
            db_path=db_path,
        )
    except Exception as e:
        print(f"Error seeding fixture: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
