"""CodeRifts Python SDK — API governance for AI agents.

Canonical Decision Spec v2 tools:

* ``preflight_change_set`` / ``analyze_change_set`` / ``authorize_change_set``
  → ``POST /api/v1/preflight``
* ``verify_receipt`` → ``POST /api/v1/verify-receipt``
* ``get_decision_details`` → ``POST /api/v1/decisions/lookup``

Additional REST methods match ``@coderifts/sdk`` 3.3.0 (``diff``,
``preflight_check``, ``score_mcp``, ``get_ledger``, ``simulate_policy``).
``read_decision`` is the one correct entry point for reading a decision: it is
fail-closed on ``execution_action`` and never lets ``decision`` drive control
flow. It does not verify a receipt — offline Ed25519 verification is
intentionally not included (no crypto dep).
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
from .decision import (
    EXECUTION_ACTIONS,
    UNREADABLE_DECISION,
    DecisionRead,
    read_decision,
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

# ── THE VERSION IS DERIVED, NEVER TYPED ─────────────────────────────────────────────────────
#
# MEASURED: this was `__version__ = "3.5.0"` while pyproject.toml and PyPI both said 3.8.0. The
# installed wheel therefore reported a version three releases stale — and nothing failed, because
# a hand-maintained constant agrees with itself. Every release since 3.5.0 shipped a package that
# misidentified itself to anyone who asked it politely.
#
# `importlib.metadata` reads the version out of the INSTALLED DISTRIBUTION's metadata, which is
# built from pyproject.toml. There is one source now, and it is the one the packaging tools use.
#
# The fallback is for a source checkout that was never installed (running from the repo root):
# there is no distribution metadata to read, and reporting a stale number would be the original
# defect. `0.0.0+unknown` is not a version anyone will mistake for a release.
try:  # pragma: no cover - the installed path is the one that matters
    from importlib.metadata import PackageNotFoundError, version as _dist_version

    __version__ = _dist_version("coderifts-sdk")
except Exception:  # noqa: BLE001 - PackageNotFoundError on a bare checkout; anything else too
    __version__ = "0.0.0+unknown"
__all__ = [
    "verify_receipt",
    "keyring_from_document",
    "verify_available",
    "cross_check_receipt",
    "CLOCK_SKEW_LEEWAY_MS",
    "CodeRifts",
    "read_decision",
    "DecisionRead",
    "EXECUTION_ACTIONS",
    "UNREADABLE_DECISION",
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

# ── THE OFFLINE PROOF, and the thing that is not one ────────────────────────────────────────
#
# `verify_receipt` is FULL Ed25519, local, no network — and needs the extra:
#     pip install 'coderifts-sdk[verify]'
# Calling it without the extra raises ImportError naming the extra. It does NOT fall back to the
# digest cross-check: a partial check reported as a verification is worse than none, because it
# is counted as one.
#
# `cross_check_receipt` is the requests-only byte-consistency check. It reads no signature and
# says so.
from .receipt_verify import (  # noqa: E402
    verify_receipt,
    keyring_from_document,
    verify_available,
)
from .verify import cross_check_receipt  # noqa: E402
