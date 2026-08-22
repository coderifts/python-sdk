"""CodeRifts Python SDK — API governance for AI agents.

v3 exposes the three canonical tools (Decision Spec v2 preflight requires
top-level ``preflight_mode``):

* ``preflight_change_set`` / ``analyze_change_set`` / ``authorize_change_set``
  → ``POST /api/v1/preflight``
* ``verify_receipt`` → ``POST /api/v1/verify-receipt``
* ``get_decision_details`` → ``POST /api/v1/decisions/lookup``
"""

from .client import CodeRifts, PreflightChangeSetContext
from .exceptions import ApiError, AuthError, CodeRiftsError, RateLimitError

__version__ = "3.1.0"
__all__ = [
    "CodeRifts",
    "PreflightChangeSetContext",
    "CodeRiftsError",
    "ApiError",
    "AuthError",
    "RateLimitError",
]
