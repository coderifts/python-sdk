"""CodeRifts Python SDK — API governance for AI agents.

v2 exposes only the three canonical tools:

* ``preflight_change_set`` → ``POST /api/v1/preflight``
* ``verify_receipt`` → ``POST /api/v1/verify-receipt``
* ``get_decision_details`` → ``POST /api/v1/decisions/lookup``
"""

from .client import CodeRifts
from .exceptions import ApiError, AuthError, CodeRiftsError, RateLimitError

__version__ = "2.0.0"
__all__ = [
    "CodeRifts",
    "CodeRiftsError",
    "ApiError",
    "AuthError",
    "RateLimitError",
]
