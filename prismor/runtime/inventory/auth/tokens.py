"""Bearer helpers for collectors that take a token from the environment."""
from __future__ import annotations

import os


def bearer_from_env(var: str) -> str:
    """Return the token stored in ``var``. Empty string if the variable is unset.

    The value is not logged. Callers put it on an Authorization header only.
    """
    if not var:
        return ""
    return os.environ.get(var, "").strip()
