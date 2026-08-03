"""CodeRifts HTTP client — three canonical tools only."""

from typing import Any, Dict, List, Optional

import requests

from .exceptions import ApiError, AuthError, CodeRiftsError, RateLimitError

DEFAULT_BASE_URL = "https://app.coderifts.com/api/v1"
DEFAULT_TIMEOUT = 30
SDK_VERSION = "2.0.0"


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


class CodeRifts:
    """CodeRifts API client for the three canonical governance tools.

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

    # ── public methods (canonical surface only) ───────────────

    def preflight_change_set(
        self,
        artifacts: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        """Preflight a complete base→head change set of contract artifacts.

        Maps to ``POST /api/v1/preflight``.

        **What to branch on**

        * ``execution_action`` — the proceed signal (e.g. ``CONTINUE``). Use this
          for automated go / no-go control flow.
        * ``decision`` — the governance explanation label (e.g. ``ALLOW``,
          ``WARN``, ``REQUIRE_APPROVAL``, ``BLOCK``). Use this for logging and
          human-facing copy, not as the sole gate.

        Observed response fields on a successful call include ``decision``,
        ``execution_action``, ``risk_score``, ``safe_for_agent``,
        ``breaking_changes`` (an integer count, not a list), ``patterns``,
        ``requires_migration``, ``evidence_quality``, ``coderifts_version``,
        ``timestamp``, ``decision_result``, ``control_envelope``,
        ``chain_receipt``, and related analysis/meta fields. Nested objects are
        available via attribute access on the returned wrapper.

        Args:
            artifacts: Non-empty list of artifact dicts. Each entry must include
                at least ``id``, ``type``, ``before``, and ``after`` (spec
                strings or equivalent payload fields accepted by the API).
            context: Optional dict. Observed fields include ``operation`` and
                ``environment`` (and further keys the API accepts).

        Returns:
            Response wrapper over the full JSON body.
        """
        body: Dict[str, Any] = {"artifacts": artifacts}
        if context is not None:
            body["context"] = context
        return self._post("/preflight", body)

    def verify_receipt(
        self,
        token: str,
        operation: Optional[str] = None,
        environment: Optional[str] = None,
        target_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        audience: Optional[str] = None,
        decision_result: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        """Verify a signed chain-receipt and optionally evaluate authorization.

        Maps to ``POST /api/v1/verify-receipt``.

        **A valid signature is not authorization.** ``valid`` / ``status`` speak
        to cryptographic authenticity (and lifecycle flags reflected in
        ``status``). Whether the receipt currently authorizes a stated intent is
        a separate question.

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
