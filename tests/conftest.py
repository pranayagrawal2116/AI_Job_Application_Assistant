"""Pytest root configuration for Universal AI Job Application Assistant test suites.

Enforces Phase 9.1.2.9 Section 5.3:
- Explicitly declares intended testing environment ('test') when pytest runs.
- Prevents tests from silently inheriting an unset or arbitrary developer APP_ENV.
"""

import os

# Explicitly default APP_ENV to "test" for pytest runs
os.environ.setdefault("APP_ENV", "test")
