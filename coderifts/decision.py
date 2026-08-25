"""Fail-closed decision reading for the CodeRifts Python SDK.

Mirrors the SEMANTICS and status vocabulary of ``@coderifts/sdk`` 3.7.0
``readDecision`` (measured against the shipped package, not reimplemented from
memory). The status vocabulary is the closed ``ExecutionAction`` set and the
single reason name ``UNREADABLE_DECISION`` — deliberately not a parallel
Python-only vocabulary.

The rule this module exists to enforce: ``execution_action`` is the control
input. ``decision`` is the governance *explanation* label — it may appear in
prose, it must never drive a branch (the agent-host rule
``not_for_control_flow_use_execution_action``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

__all__ = [
    "EXECUTION_ACTIONS",
    "UNREADABLE_DECISION",
    "DecisionRead",
    "read_decision",
]

#: The closed set of execution actions (identical to ``types.ExecutionAction``
#: and to the TypeScript ``isExecutionAction`` allowlist).
EXECUTION_ACTIONS = frozenset(
    {"CONTINUE", "CONTINUE_WITH_MONITORING", "REQUEST_APPROVAL", "STOP"}
)

#: The single fail-closed reason name. Matches the TypeScript SDK exactly.
UNREADABLE_DECISION = "UNREADABLE_DECISION"

_STOP = "STOP"


@dataclass(frozen=True)
class DecisionRead:
    """The result of :func:`read_decision`. Immutable.

    Attributes:
        execution_action: The action to take. Fail-closed to ``STOP`` when the
            payload is unreadable. This is the only field that may drive
            control flow.
        decision: The governance label if present, else ``None``. For prose,
            logging and human-facing copy only — never branch on it.
        envelope: The ``decision_result`` envelope when the payload carried one.
        receipt: The chain receipt block when the envelope carried one.
        reason: ``UNREADABLE_DECISION`` when this result fell closed, else
            ``None``.
    """

    execution_action: str
    decision: Optional[str] = None
    envelope: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None

    @property
    def unreadable(self) -> bool:
        """True when the payload could not be read and this fell closed to STOP."""
        return self.reason is not None


def _as_dict(payload: Any) -> Optional[Dict[str, Any]]:
    """Best-effort dict view of a payload. Never raises."""
    if isinstance(payload, dict):
        return payload
    to_dict = getattr(payload, "to_dict", None)
    if callable(to_dict):
        try:
            data = to_dict()
        except Exception:
            return None
        if isinstance(data, dict):
            return data
    return None


def _is_execution_action(value: Any) -> bool:
    return isinstance(value, str) and value in EXECUTION_ACTIONS


def _decision_of(source: Dict[str, Any]) -> Optional[str]:
    value = source.get("decision")
    return value if isinstance(value, str) else None


def read_decision(payload: Any) -> DecisionRead:
    """Read a governance decision from ANY CodeRifts response, fail-closed.

    Accepts a raw dict, a :class:`~coderifts.client._Response` wrapper, an error
    body, or arbitrary garbage. Resolution order:

    1. envelope-first — ``payload['decision_result']['execution_action']``
       (plus ``receipt`` when the envelope carries one);
    2. top-level ``payload['execution_action']`` (the REST endpoints emit it
       directly — measured live on ``/agent/preflight``, ``/diff`` and
       ``/preflight`` authorize);
    3. otherwise fail closed:
       ``DecisionRead(execution_action='STOP', reason='UNREADABLE_DECISION')``.

    Unlike the TypeScript ``readDecision``, there is intentionally **no legacy
    arm** mapping a top-level ``decision`` to an action: that arm lets the
    forbidden field drive control flow through the guard helper itself. No live
    surface needs it — every decision-bearing endpoint this SDK calls emits
    ``execution_action``. An analyze response carries neither field and
    therefore reads as ``STOP``/``UNREADABLE_DECISION``, which is correct:
    analyze is informational, not permission.

    Never raises — a guard may call this on any value.

    What this does NOT do: it does **not** verify a receipt. A returned
    ``receipt`` is transported, not validated; nothing here checks a signature,
    a chain link, or an expiry. Offline Ed25519 verification is not available in
    the Python SDK (no crypto dependency) — use the app or the TypeScript
    kernel.

    Args:
        payload: Any response value.

    Returns:
        An immutable :class:`DecisionRead`.
    """
    data = _as_dict(payload)
    if data is None:
        return DecisionRead(execution_action=_STOP, reason=UNREADABLE_DECISION)

    envelope = data.get("decision_result")
    if isinstance(envelope, dict) and _is_execution_action(
        envelope.get("execution_action")
    ):
        receipt = envelope.get("receipt")
        return DecisionRead(
            execution_action=envelope["execution_action"],
            decision=_decision_of(envelope),
            envelope=envelope,
            receipt=receipt if isinstance(receipt, dict) else None,
        )

    if _is_execution_action(data.get("execution_action")):
        return DecisionRead(
            execution_action=data["execution_action"],
            decision=_decision_of(data),
        )

    return DecisionRead(
        execution_action=_STOP,
        decision=_decision_of(data),
        reason=UNREADABLE_DECISION,
    )
