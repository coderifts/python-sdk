"""Wire-aligned TypedDicts for the Python SDK (ID75).

Field names match the REST/JSON contract (and the TypeScript SDK) exactly —
not snake-cased away from the wire. Request parameter *names* on the client
use Python idiom (``from_`` → query ``from``); documented at the method.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

# ── closed enums (Decision Spec / control surface) ─────────────────────────

Decision = Literal["ALLOW", "WARN", "REQUIRE_APPROVAL", "BLOCK"]
ExecutionAction = Literal[
    "CONTINUE",
    "CONTINUE_WITH_MONITORING",
    "REQUEST_APPROVAL",
    "STOP",
]
PreflightMode = Literal["analyze", "authorize"]
AnalysisOutcome = Literal["NO_BREAK_DETECTED", "BREAKS_DETECTED", "ANALYSIS_FAILED"]
AuthorizeReceiptKind = Literal["operation_authorization", "NONE"]
GraphSource = Literal["none", "declared", "observed", "declared+observed"]


class BlastRadius(TypedDict, total=False):
    """ID27 additive COUNTS (not a score). Wire field ``blast_radius``."""

    endpoints: int
    fields: int
    params: int
    consumers_declared: int
    consumers_observed: int
    graph_source: GraphSource


class Artifact(TypedDict):
    id: str
    type: str
    before: str
    after: str


class PreflightChangeSetContext(TypedDict, total=False):
    """Documented preflight ``context`` contract (all fields optional).

    ``operation`` is required by the server on ``authorize``. ``base`` / ``head``
    are PR/commit SHAs when the preflight is source-bound.
    """

    operation: str
    environment: str
    repository: str
    branch: str
    pull_request: Union[str, int]
    policy_profile: str
    base: str
    head: str
    target_id: str
    fingerprint: str
    audience: str


class AnalyzeChangeSetResponse(TypedDict, total=False):
    """``preflight_mode: analyze`` — informational. Not permission.

    ``receipt_kind`` is the literal ``NONE``. Analyze structurally omits
    ``decision`` / ``execution_action`` / ``execution_grant``.
    """

    preflight_mode: Literal["analyze"]
    analysis_outcome: AnalysisOutcome
    authorization_effect: Literal["NONE"]
    may_execute: Literal[False]
    receipt_kind: Literal["NONE"]
    decision_spec_version: str
    risk_score: int
    breaking_changes: int
    blast_radius: BlastRadius
    verdict_fingerprint: str
    bundle_fingerprint: str


class AuthorizeChangeSetResponse(TypedDict, total=False):
    """``preflight_mode: authorize`` — operation-bound may-proceed.

    Branch on ``execution_action`` (closed set; unrecognised → treat as STOP).
    ``receipt_kind`` is ``operation_authorization`` when a chain receipt was
    issued, else ``NONE``. ``execution_grant`` is present only when opted in.
    """

    preflight_mode: Literal["authorize"]
    decision: Decision
    execution_action: ExecutionAction
    safe_for_agent: bool
    receipt_kind: AuthorizeReceiptKind
    chain_receipt: str
    execution_grant: str
    blast_radius: BlastRadius
    decision_spec_version: str
    risk_score: int
    breaking_changes: int
    decision_result: Dict[str, Any]
    control_envelope: Dict[str, Any]


# ── legacy / additional REST surfaces (TS SDK parity) ──────────────────────


class PreflightCheckRequest(TypedDict):
    tool_name: str
    old_spec: str
    new_spec: str


class PreflightCheckResponse(TypedDict, total=False):
    decision: str
    omega_api: float
    safe: bool
    reflex_triggers: List[Dict[str, Any]]
    affected_tools: List[Dict[str, Any]]
    confidence_score: float
    reflex_override: bool
    omega_components: Dict[str, Any]
    breaking_changes: Any
    stats: Dict[str, Any]
    mitigation_available: bool


class DiffRequest(TypedDict, total=False):
    before: str
    after: str
    branch_name: str
    config: Dict[str, Any]


class BreakingChange(TypedDict, total=False):
    type: str
    path: str
    method: str
    field: str
    severity: str
    description: str


class DiffResponse(TypedDict, total=False):
    risk_score: int
    risk_level: str
    semver_suggestion: str
    breaking_changes: List[BreakingChange]
    should_block: bool
    decision: str
    execution_action: ExecutionAction
    receipt_kind: str


class ExplainDecisionRequest(TypedDict, total=False):
    omega_api: float
    decision: str
    reflex_triggers: List[Dict[str, Any]]
    omega_components: Dict[str, Any]


class ExplainComponent(TypedDict):
    name: str
    value: float
    description: str


class ExplainDecisionResponse(TypedDict):
    summary: str
    components: List[ExplainComponent]


class HowToUnblockRequest(TypedDict, total=False):
    decision: str
    breaking_changes: List[BreakingChange]
    detected_patterns: List[Any]
    reflex_triggers: List[Dict[str, Any]]


class UnblockAction(TypedDict, total=False):
    step: int
    description: str
    code_example: str


class HowToUnblockResponse(TypedDict):
    actions: List[UnblockAction]


class ScoreMcpRequest(TypedDict):
    manifest: Dict[str, Any]


class ScoreMcpResponse(TypedDict, total=False):
    overall_score: float
    band: str
    label: str
    signals: List[Any]
    tool_count: int


class GetLedgerRequest(TypedDict, total=False):
    repo: str
    decision: str
    # Wire name is ``from``; the Python method parameter is ``from_``.
    from_: str
    to: str
    limit: int


class LedgerEntry(TypedDict, total=False):
    id: int
    repo: Optional[str]
    pr_number: Optional[int]
    decision: str
    risk_score: Optional[int]
    breaking_changes: int
    created_at: str


class GetLedgerResponse(TypedDict, total=False):
    repo: Optional[str]
    total: int
    entries: List[LedgerEntry]


class SimulatePolicyRequest(TypedDict):
    policy_yaml: str
    old_spec: str
    new_spec: str


class SimulatePolicyResponse(TypedDict, total=False):
    effective_action: str
    matched_rules: List[Dict[str, Any]]


class DecisionLookupRequest(TypedDict, total=False):
    decision_id: str
    fingerprint: str


class VerifyReceiptResponse(TypedDict, total=False):
    valid: bool
    reason: Optional[str]
    status: str
    payload: Dict[str, Any]
    currently_authorized: Optional[bool]
    authz_note: str
    correlation_id: str
    authz_status: str
    authz_reason: str
    authz_state: str
    binding_level: str
