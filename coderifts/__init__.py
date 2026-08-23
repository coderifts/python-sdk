"""CodeRifts Python SDK — API governance for AI agents.

Canonical Decision Spec v2 tools:

* ``preflight_change_set`` / ``analyze_change_set`` / ``authorize_change_set``
  → ``POST /api/v1/preflight``
* ``verify_receipt`` → ``POST /api/v1/verify-receipt``
* ``get_decision_details`` → ``POST /api/v1/decisions/lookup``

Additional REST methods match ``@coderifts/sdk`` 3.3.0 (``diff``,
``preflight_check``, ``score_mcp``, ``get_ledger``, ``simulate_policy``).
Offline Ed25519 verification is intentionally not included (no crypto dep).
"""

from .client import (
    CLOCK_SKEW_LEEWAY_MS,
    CodeRifts,
    PreflightChangeSetContext,
    declares_destructive_production,
    expiry_leeway_ms,
    is_issued_in_future,
    is_receipt_expired,
)
from .exceptions import ApiError, AuthError, CodeRiftsError, RateLimitError
from .execution_grant import (
    GRANT_VERSION,
    after_payload_canonical,
    compute_scope_hash,
    receipt_digest,
)
from .types import (
    AnalysisOutcome,
    AuthorizeChangeSetResponse,
    AuthorizeReceiptKind,
    BlastRadius,
    Decision,
    ExecutionAction,
    PreflightMode,
)

__version__ = "3.2.0"
__all__ = [
    "CLOCK_SKEW_LEEWAY_MS",
    "CodeRifts",
    "PreflightChangeSetContext",
    "PreflightMode",
    "ExecutionAction",
    "Decision",
    "AuthorizeReceiptKind",
    "AnalysisOutcome",
    "AuthorizeChangeSetResponse",
    "BlastRadius",
    "CodeRiftsError",
    "ApiError",
    "AuthError",
    "RateLimitError",
    "declares_destructive_production",
    "expiry_leeway_ms",
    "is_issued_in_future",
    "is_receipt_expired",
    "GRANT_VERSION",
    "after_payload_canonical",
    "compute_scope_hash",
    "receipt_digest",
]
