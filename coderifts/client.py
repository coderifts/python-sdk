"""CodeRifts HTTP client — REST parity with the TypeScript SDK (ID75).

Canonical Decision Spec v2 tools remain ``preflight_change_set`` /
``verify_receipt`` / ``get_decision_details``. Additional methods map 1:1 to
the TypeScript ``CodeRifts`` class REST (and two client-side helpers).
Offline Ed25519 verification is intentionally not in this package.
"""

import math
from typing import Any, Dict, List, Mapping, Optional, Union

import requests

from .exceptions import ApiError, AuthError, CodeRiftsError, RateLimitError
from .types import PreflightChangeSetContext, PreflightMode

DEFAULT_BASE_URL = "https://app.coderifts.com/api/v1"
DEFAULT_TIMEOUT = 30
SDK_VERSION = "3.2.0"

# ID104 — verification expiry leeway (ms). Server applies this; the SDK is an HTTP client.
# `exp + leeway < now` → VERIFIED_EXPIRED. 0s when intended context declares destructive
# AND environment production. IntentContext has `environment` but no `destructive` /
# `operation_class` — never guess from operation labels.
CLOCK_SKEW_LEEWAY_MS = 30_000

_PREFLIGHT_MODES = frozenset({"analyze", "authorize"})

# Re-export: existing imports of PreflightChangeSetContext from this module stay valid.
__all__ = ["CodeRifts", "PreflightChangeSetContext", "PreflightMode", "_Response"]


class _Response:
    """Dot-access wrapper around a dict response.

    Nested dicts are also wrapped. Lists and scalars are returned as-is.
    Use ``to_dict()`` for the raw payload, or ``in`` / ``[]`` for key access.
    """

    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, name: str):
        try:
            value = self._data[name]
        except KeyError:
            raise AttributeError("Response has no attribute {!r}".format(name))
        if isinstance(value, dict):
            return _Response(value)
        return value

    def __repr__(self) -> str:
        return "Response({})".format(self._data)

    def __contains__(self, key):
        return key in self._data

    def __getitem__(self, key):
        return self._data[key]

    def to_dict(self) -> dict:
        """Return the raw response dict."""
        return self._data


def _assert_request_mode(artifacts, derivation, context):
    """Fail fast on the two mutually exclusive /v1/preflight request modes.

    Python cannot express this as a type-level union the way the TypeScript SDK does
    (``CallerArtifactsRequest | ServerDerivedRequest``), so the same rule is enforced at
    runtime here and mirrored in the TypedDicts and docstrings.

    The SERVER remains the authority: this guard exists to fail fast with a readable message
    naming the rule, not to duplicate policy. Every condition below is one the API already
    rejects; the messages quote the server's own reason so the two never diverge in meaning.

      mode A  artifacts=[...]                      derivation absent
      mode B  derivation="server"                  artifacts absent, context needs
                                                   repository + base + head

    :raises ValueError: naming which rule was broken.
    """
    if derivation is not None and derivation != "server":
        raise ValueError(
            'derivation must be "server" when set (got {!r}); omit it to supply '
            "artifacts[] yourself".format(derivation)
        )
    if derivation is None:
        if not artifacts:
            raise ValueError(
                "artifacts[] is required when derivation is not set — supply the complete "
                'base->head change set, or pass derivation="server" to have the server list it'
            )
        return
    # derivation == "server"
    if artifacts:
        raise ValueError(
            'derivation="server" forbids caller-supplied artifacts[] — one source of truth '
            "per request (the server lists the change-set via the GitHub App installation)"
        )
    ctx = context or {}
    missing = [k for k in ("repository", "base", "head") if not str(ctx.get(k) or "").strip()]
    if missing:
        raise ValueError(
            'derivation="server" requires context.{} — the server returns 400 '
            "derivation_requires_base_head without base AND head, and 400 INVALID_INPUT "
            "without a parseable owner/repo".format(", context.".join(missing))
        )


class CodeRifts:
    """CodeRifts API client (REST parity with ``@coderifts/sdk`` 3.3.0).

    Args:
        api_key: Your CodeRifts API key (starts with ``cr_live_`` or ``cr_test_``).
        base_url: Override the default API base URL
            (``https://app.coderifts.com/api/v1``).
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        if not api_key:
            raise AuthError("API key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": "Bearer {}".format(api_key),
                "Content-Type": "application/json",
                "User-Agent": "coderifts-python-sdk/{}".format(SDK_VERSION),
            }
        )

    # ── internal ──────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = "{}{}".format(self._base_url, path)
        try:
            resp = self._session.request(
                method, url, timeout=self._timeout, **kwargs
            )
        except requests.exceptions.Timeout:
            raise CodeRiftsError("Request timed out", "timeout_error")
        except requests.exceptions.ConnectionError:
            raise CodeRiftsError("Connection failed", "connection_error")

        if resp.status_code == 401:
            raise AuthError()
        if resp.status_code == 429:
            raise RateLimitError()
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("error", body.get("message", resp.text))
            except Exception:
                msg = resp.text
            raise ApiError(str(msg), status_code=resp.status_code)

        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text}

    def _post(self, path: str, body: dict) -> _Response:
        data = self._request("POST", path, json=body)
        return _Response(data)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> _Response:
        data = self._request("GET", path, params=params or None)
        return _Response(data)

    # ── public methods ────────────────────────────────────────

    def preflight_change_set(
        self,
        artifacts: Optional[List[Dict[str, Any]]] = None,
        *,
        preflight_mode: PreflightMode,
        derivation: Optional[str] = None,
        context: Optional[PreflightChangeSetContext] = None,
        include_execution_grant: Optional[bool] = None,
        state_nonce: Optional[str] = None,
        previous_receipt: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> _Response:
        """Preflight a complete base→head change set of contract artifacts.

        Maps to ``POST /api/v1/preflight``.

        **Required** top-level ``preflight_mode`` (Decision Spec v2): ``'analyze'``
        or ``'authorize'``. The server returns HTTP 400 if it is omitted. Prefer
        :meth:`analyze_change_set` / :meth:`authorize_change_set` so the two
        meanings cannot be mixed via a silent default.

        **What to branch on**

        * ``execution_action`` — the proceed signal (e.g. ``CONTINUE``). Use this
          for automated go / no-go control flow (authorize responses).
        * ``decision`` — the governance explanation label (e.g. ``ALLOW``,
          ``WARN``, ``REQUIRE_APPROVAL``, ``BLOCK``). Use this for logging and
          human-facing copy, not as the sole gate.
        * On analyze responses, branch on ``analysis_outcome`` / risk fields —
          analyze is informational, not permission.

        Unrecognised ``execution_action`` values are not permission — treat as
        STOP (fail closed).

        Observed v2 fields (authorize) include ``execution_action``,
        ``receipt_kind`` (``operation_authorization`` | ``NONE``),
        ``chain_receipt``, optional ``execution_grant`` (when opted in),
        ``blast_radius`` (ID27 counts), ``decision_result``, ``control_envelope``.
        Analyze responses carry ``analysis_outcome``, ``receipt_kind: NONE``,
        ``may_execute: false`` — not permission. Nested objects wrap.

        Args:
            artifacts: Non-empty list of artifact dicts. Each entry must include
                at least ``id``, ``type``, ``before``, and ``after`` (spec
                strings or equivalent payload fields accepted by the API).
            preflight_mode: Required keyword-only. ``'analyze'`` (risk-only) or
                ``'authorize'`` (operation-bound; may mint a receipt). Top-level
                on the request body — not nested under ``context``.
            context: Optional :class:`PreflightChangeSetContext`. Documented
                fields: ``operation``, ``environment``, ``repository``,
                ``branch``, ``pull_request``, ``policy_profile``, ``base``,
                ``head`` (PR/commit SHAs). Extra keys the API accepts are still
                forwarded. For ``authorize``, the server requires a non-empty
                ``context.operation``.
            include_execution_grant: Opt-in ``cr.exec.v1`` grant on authorize.
                Default omitted. The Python client does not verify grants
                offline (no Ed25519 dependency); use the app/SDK-TS kernel.
            previous_receipt: Optional prior chain receipt to link (TS
                ``previous_receipt``).
            idempotency_key: Optional client idempotency key (TS
                ``idempotency_key``).

        Returns:
            Response wrapper over the full JSON body.
        """
        if preflight_mode not in _PREFLIGHT_MODES:
            raise ValueError(
                "preflight_mode must be 'analyze' or 'authorize' "
                "(got {!r}); prefer analyze_change_set / authorize_change_set".format(
                    preflight_mode
                )
            )
        _assert_request_mode(artifacts, derivation, context)
        body: Dict[str, Any] = {"preflight_mode": preflight_mode}
        if derivation is not None:
            body["derivation"] = derivation
        else:
            body["artifacts"] = artifacts
        if context is not None:
            body["context"] = context
        if include_execution_grant is not None:
            body["include_execution_grant"] = include_execution_grant
        if state_nonce is not None:
            body["state_nonce"] = state_nonce
        if previous_receipt is not None:
            body["previous_receipt"] = previous_receipt
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return self._post("/preflight", body)

    def analyze_change_set(
        self,
        artifacts: Optional[List[Dict[str, Any]]] = None,
        *,
        derivation: Optional[str] = None,
        state_nonce: Optional[str] = None,
        context: Optional[PreflightChangeSetContext] = None,
        previous_receipt: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> _Response:
        """Risk-only preflight (``preflight_mode='analyze'``).

        Informational — not permission; does not mint an operation-bound receipt.
        Delegates to :meth:`preflight_change_set`.
        """
        return self.preflight_change_set(
            artifacts,
            preflight_mode="analyze",
            derivation=derivation,
            state_nonce=state_nonce,
            context=context,
            previous_receipt=previous_receipt,
            idempotency_key=idempotency_key,
        )

    def authorize_change_set(
        self,
        artifacts: Optional[List[Dict[str, Any]]] = None,
        *,
        derivation: Optional[str] = None,
        state_nonce: Optional[str] = None,
        context: Optional[PreflightChangeSetContext] = None,
        include_execution_grant: Optional[bool] = None,
        previous_receipt: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> _Response:
        """Operation-bound authorize preflight (``preflight_mode='authorize'``).

        Requires a non-empty ``context.operation`` (e.g. ``merge``, ``deploy``,
        ``tool_call``) — the server returns HTTP 400 otherwise. May mint a
        signed receipt. Delegates to :meth:`preflight_change_set`.

        Branch on ``execution_action`` (``CONTINUE`` | ``CONTINUE_WITH_MONITORING``
        | ``REQUEST_APPROVAL`` | ``STOP``). Unrecognised → STOP.
        """
        return self.preflight_change_set(
            artifacts,
            preflight_mode="authorize",
            derivation=derivation,
            state_nonce=state_nonce,
            context=context,
            include_execution_grant=include_execution_grant,
            previous_receipt=previous_receipt,
            idempotency_key=idempotency_key,
        )

    def verify_receipt(
        self,
        token: str,
        operation: Optional[str] = None,
        environment: Optional[str] = None,
        target_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        audience: Optional[str] = None,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        pull_request: Optional[Union[str, int]] = None,
        base: Optional[str] = None,
        head: Optional[str] = None,
        indices: Optional[Dict[str, Any]] = None,
        decision_result: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        """Verify a signed chain-receipt and optionally evaluate authorization.

        Maps to ``POST /api/v1/verify-receipt``.

        **A valid signature is not authorization.** ``valid`` / ``status`` speak
        to cryptographic authenticity (and lifecycle flags reflected in
        ``status``). Expiry uses 30s clock-skew leeway
        (``CLOCK_SKEW_LEEWAY_MS``); 0s for destructive operations in production
        when the intended context declares them. The SDK does not compare expiry
        locally — the server does. Whether the receipt currently authorizes a
        stated intent is a separate question.

        **What to branch on**

        * ``valid`` — whether the token is a well-formed, verifiable receipt.
        * ``currently_authorized`` — **boolean or null**. ``True`` means
          authorized for the supplied intent; ``False`` means not authorized;
          ``null`` means authorization could not be evaluated (for example when
          only a token was sent). Treat null as neither authorized nor
          unauthorized — that distinction is why this endpoint exists.
        * When intent context is supplied, ``authz_status`` / ``authz_reason``
          (and when a full evaluation succeeds, ``authz_state``) refine the
          authorization outcome.

        With only ``token``, observed fields include ``valid``, ``reason``,
        ``status``, ``payload``, ``currently_authorized``, ``authz_note``, and
        ``correlation_id``. Adding intent context can add ``authz_status`` and
        ``authz_reason``.

        Args:
            token: The chain-receipt token string (e.g. from
                ``preflight_change_set`` → ``chain_receipt`` or
                ``decision_result.receipt.token``).
            operation: Optional intent field (e.g. ``merge``).
            environment: Optional intent field (e.g. ``staging``).
            target_id: Optional target binding (e.g. artifact digest).
            fingerprint: Optional change / verdict fingerprint.
            audience: Optional audience claim.
            repository: Optional repository scope for authorization binding.
            branch: Optional branch scope for authorization binding.
            pull_request: Optional pull-request identifier (``str`` or ``int``)
                for authorization binding.
            base: Optional intended base commit/ref SHA (signed-wins vs the
                envelope).
            head: Optional intended head commit/ref SHA (signed-wins vs the
                envelope).
            indices: Optional dict of lifecycle indices used in authorization
                evaluation (server requires an object).
            decision_result: Optional body-hash-bound decision envelope from a
                prior preflight or lookup; required for full scope evaluation.

        Returns:
            Response wrapper over the full JSON body.
        """
        body: Dict[str, Any] = {"token": token}
        if operation is not None:
            body["operation"] = operation
        if environment is not None:
            body["environment"] = environment
        if target_id is not None:
            body["target_id"] = target_id
        if fingerprint is not None:
            body["fingerprint"] = fingerprint
        if audience is not None:
            body["audience"] = audience
        if repository is not None:
            body["repository"] = repository
        if branch is not None:
            body["branch"] = branch
        if pull_request is not None:
            body["pull_request"] = pull_request
        if base is not None:
            body["base"] = base
        if head is not None:
            body["head"] = head
        if indices is not None:
            body["indices"] = indices
        if decision_result is not None:
            body["decision_result"] = decision_result
        return self._post("/verify-receipt", body)

    def get_decision_details(
        self,
        decision_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> _Response:
        """Look up a previously stored governance decision.

        Maps to ``POST /api/v1/decisions/lookup``.

        Provide **either** ``decision_id`` **or** ``fingerprint`` (or both). An
        empty body is rejected by the API with ``INVALID_INPUT``.

        **What to branch on**

        * ``execution_action`` — the proceed signal from the stored decision.
        * ``decision`` — the explanation label for that decision.

        Observed fields on a successful lookup include ``decision``,
        ``execution_action``, ``risk_score``, ``safe_for_agent``,
        ``breaking_changes`` (integer), ``patterns``, ``decision_result``,
        ``control_envelope``, ``verdict_fingerprint``, ``required_action_core``,
        ``meta``, and ``correlation_id``.

        Args:
            decision_id: Stored decision id (e.g. ``dec_...`` from
                ``decision_result.decision_id``).
            fingerprint: Verdict / change fingerprint (e.g. ``sha256:...``).

        Returns:
            Response wrapper over the full JSON body.
        """
        body: Dict[str, Any] = {}
        if decision_id is not None:
            body["decision_id"] = decision_id
        if fingerprint is not None:
            body["fingerprint"] = fingerprint
        return self._post("/decisions/lookup", body)

    # ── additional REST (TS CodeRifts class parity) ───────────

    def preflight_check(
        self,
        tool_name: str,
        old_spec: str,
        new_spec: str,
    ) -> _Response:
        """Single-tool agent preflight (TS ``preflightCheck``).

        Maps to ``POST /api/v1/agent/preflight``. Legacy single-spec surface —
        prefer :meth:`preflight_change_set` for Decision Spec v2.

        Branch on ``decision``. The wrapper also sets ``safe`` (ALLOW/WARN)
        matching the TypeScript client. Unrecognised decision → not safe.
        """
        raw = self._request(
            "POST",
            "/agent/preflight",
            json={
                "tool_name": tool_name,
                "old_spec": old_spec,
                "new_spec": new_spec,
            },
        )
        decision = raw.get("decision") or "ALLOW"
        body = dict(raw)
        body["decision"] = decision
        body["omega_api"] = raw.get("omega_api", 0)
        body["safe"] = decision in ("ALLOW", "WARN")
        body.setdefault("reflex_triggers", raw.get("reflex_triggers") or [])
        body.setdefault("affected_tools", raw.get("affected_tools") or [])
        return _Response(body)

    def diff(
        self,
        before: str,
        after: str,
        branch_name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        """Full OpenAPI spec diff (TS ``diff``).

        Maps to ``POST /api/v1/diff``.

        Branch on ``execution_action`` when present (authorize-shaped bodies);
        otherwise ``should_block`` / ``decision``. Unrecognised
        ``execution_action`` → STOP.
        """
        body: Dict[str, Any] = {"before": before, "after": after}
        if branch_name is not None:
            body["branch_name"] = branch_name
        if config is not None:
            body["config"] = config
        return self._post("/diff", body)

    def score_mcp(self, manifest: Dict[str, Any]) -> _Response:
        """Score an MCP manifest for agent safety (TS ``scoreMcp``).

        Maps to ``POST /api/v1/agent-readiness-score`` with ``spec_type='mcp'``
        (same body the TypeScript client sends).
        """
        return self._post(
            "/agent-readiness-score",
            {"spec": manifest, "spec_type": "mcp"},
        )

    def get_ledger(
        self,
        repo: Optional[str] = None,
        decision: Optional[str] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> _Response:
        """Query compliance ledger entries (TS ``getLedger``).

        Maps to ``GET /api/v1/ledger``. Python parameter ``from_`` is sent as
        the query string key ``from`` (``from`` is a reserved word).
        """
        params: Dict[str, Any] = {}
        if repo is not None:
            params["repo"] = repo
        if decision is not None:
            params["decision"] = decision
        if from_ is not None:
            params["from"] = from_
        if to is not None:
            params["to"] = to
        if limit is not None:
            params["limit"] = limit
        return self._get("/ledger", params=params or None)

    def simulate_policy(
        self,
        policy_yaml: str,
        old_spec: str,
        new_spec: str,
    ) -> _Response:
        """Test a YAML policy against two OpenAPI specs (TS ``simulatePolicy``).

        Maps to ``POST /api/v1/policy-simulator``.

        Branch on ``effective_action``. Unrecognised values are not permission
        — treat as STOP.
        """
        return self._post(
            "/policy-simulator",
            {
                "policy_yaml": policy_yaml,
                "old_spec": old_spec,
                "new_spec": new_spec,
            },
        )

    def explain_decision(
        self,
        omega_api: float,
        decision: str,
        reflex_triggers: Optional[List[Dict[str, Any]]] = None,
        omega_components: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        """Human-readable explanation of a decision (TS ``explainDecision``).

        Computed client-side — no HTTP call, no invented endpoint.
        """
        components = []
        if omega_components:
            for name, value in omega_components.items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    components.append(
                        {
                            "name": name,
                            "value": value,
                            "description": _describe_component(name, float(value)),
                        }
                    )
        triggers = reflex_triggers or []
        summary = "Decision: {} (Ω_API = {}).".format(decision, omega_api)
        if triggers:
            summary += " {} reflex rule(s) triggered.".format(len(triggers))
        if decision == "BLOCK":
            summary += " This change is blocked due to high risk."
        elif decision == "REQUIRE_APPROVAL":
            summary += " This change requires manual approval before merging."
        elif decision == "WARN":
            summary += " This change has warnings but can proceed."
        else:
            summary += " This change is safe to proceed."
        return _Response({"summary": summary, "components": components})

    def how_to_unblock(
        self,
        decision: str,
        breaking_changes: Optional[List[Dict[str, Any]]] = None,
        detected_patterns: Optional[List[Any]] = None,
        reflex_triggers: Optional[List[Dict[str, Any]]] = None,
    ) -> _Response:
        """Actionable steps to resolve a BLOCK (TS ``howToUnblock``).

        Computed client-side — no HTTP call, no invented endpoint.
        ``detected_patterns`` is accepted for signature parity with TypeScript
        (the TS client currently does not render it).
        """
        del detected_patterns  # signature parity; unused in the TS client too
        actions: List[Dict[str, Any]] = []
        step = 1
        if decision != "BLOCK":
            actions.append(
                {
                    "step": step,
                    "description": 'Current decision is "{}" — no unblock needed.'.format(
                        decision
                    ),
                }
            )
            return _Response({"actions": actions})
        bcs = breaking_changes or []
        if bcs:
            example = "\n".join(
                "# {} at {}: {}".format(
                    bc.get("type", ""), bc.get("path", ""), bc.get("description", "")
                )
                for bc in bcs[:3]
            )
            actions.append(
                {
                    "step": step,
                    "description": "Fix {} breaking change(s) in your spec.".format(
                        len(bcs)
                    ),
                    "code_example": example,
                }
            )
            step += 1
        for trigger in reflex_triggers or []:
            actions.append(
                {
                    "step": step,
                    "description": "Resolve reflex rule: {}".format(
                        trigger.get("rule", "")
                    ),
                }
            )
            step += 1
        actions.append(
            {
                "step": step,
                "description": (
                    "Request a manual override via POST /api/v1/ledger/:id/override "
                    "if this is an emergency."
                ),
            }
        )
        return _Response({"actions": actions})


def _describe_component(name: str, value: float) -> str:
    descriptions = {
        "S_contract": "Contract severity score — measures how severe the breaking changes are",
        "P_break": "Break probability — likelihood that downstream consumers will break",
        "S_blast_eff": "Blast radius — how many consumers are affected",
        "S_agent": "Agent safety score — risk to AI agent tool invocations",
        "S_runtime": "Runtime impact — risk of runtime failures",
        "ECI": "Ecosystem coupling index — how tightly coupled the API is",
        "M_eff": "Migration effort — estimated effort to migrate consumers",
        "D_contract": "Contract distance — semantic distance between old and new contracts",
        "confidence_score": "Confidence in the analysis result",
    }
    return descriptions.get(name, "{} = {}".format(name, value))


def _is_finite_number(value: object) -> bool:
    """Match JS ``Number.isFinite``: real int/float only, not bool, not coerced strings."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def expiry_leeway_ms(context: Optional[Mapping[str, Any]] = None) -> int:
    """Return verification expiry leeway in milliseconds.

    0 only when intended context declares destructive AND production. Measured
    IntentContext has ``environment`` but no ``destructive`` / ``operation_class``.
    """
    if declares_destructive_production(context):
        return 0
    return CLOCK_SKEW_LEEWAY_MS


def declares_destructive_production(context: Optional[Mapping[str, Any]] = None) -> bool:
    """True only when intended context DECLARES destructive AND production.

    No such destructive field exists on IntentContext — always False.
    """
    if not isinstance(context, Mapping):
        return False
    if context.get("environment") != "production":
        return False
    return False


def is_receipt_expired(
    expires_at_ms: object,
    now_ms: object,
    context: Optional[Mapping[str, Any]] = None,
) -> bool:
    """``exp + leeway < now`` → expired (verification verdict only).

    Non-finite timestamps cannot be judged (same as JS ``Number.isFinite`` miss).
    """
    if not _is_finite_number(expires_at_ms) or not _is_finite_number(now_ms):
        return False
    return (float(expires_at_ms) + expiry_leeway_ms(context)) < float(now_ms)


def is_issued_in_future(
    issued_at_ms: object,
    now_ms: object,
    context: Optional[Mapping[str, Any]] = None,
) -> bool:
    """Future-dated iat (`ts`): same 30s leeway on the other side. No nbf."""
    if not _is_finite_number(issued_at_ms) or not _is_finite_number(now_ms):
        return False
    return float(issued_at_ms) > (float(now_ms) + expiry_leeway_ms(context))

