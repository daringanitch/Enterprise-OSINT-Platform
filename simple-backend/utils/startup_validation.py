#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Startup security validation for environment variables.

Validates that critical secrets are not using insecure default values.
In demo mode: logs warnings but allows startup.
In live/production mode: raises SecurityStartupError and refuses to start.
"""

import os
import logging

logger = logging.getLogger(__name__)

# Map of env var name → known insecure default value
INSECURE_DEFAULTS: dict[str, str] = {
    'JWT_SECRET_KEY': 'dev-secret-key-change-in-production',
    'POSTGRES_PASSWORD': 'password123',
}


class SecurityStartupError(RuntimeError):
    """Raised when a critical security requirement is not met at startup.

    This error causes the application to refuse to start, preventing
    deployment with insecure default credentials.
    """
    pass


def validate_secrets(is_demo: bool) -> None:
    """Validate that critical secrets are not using insecure default values.

    Args:
        is_demo: If True, log warnings but allow startup (demo mode).
                 If False, raise SecurityStartupError on any insecure default.

    Raises:
        SecurityStartupError: If is_demo is False and any insecure default is detected.
    """
    failures = []

    for env_var, bad_default in INSECURE_DEFAULTS.items():
        actual_value = os.environ.get(env_var, bad_default)
        if actual_value == bad_default:
            msg = (
                f"SECURITY WARNING: {env_var} is using the insecure default value "
                f"'{bad_default}'. This is only acceptable in demo mode."
            )
            if is_demo:
                logger.warning(msg)
            else:
                logger.critical(
                    f"SECURITY FAILURE: {env_var} is using an insecure default. "
                    f"Set {env_var} to a secure value before starting in live mode."
                )
                failures.append(env_var)

    if failures:
        raise SecurityStartupError(
            f"Cannot start in live mode with insecure defaults for: {', '.join(failures)}. "
            f"Set these environment variables to secure values. "
            f"To run in demo mode, set PLATFORM_MODE=demo."
        )
