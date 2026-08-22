"""Unit tests for the CodeRifts Python SDK.

Uses the standard library ``unittest`` framework (no extra test dependency).
The private ``_request`` helper is mocked so tests never hit the network.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from coderifts import (
    ApiError,
    AuthError,
    CodeRifts,
    CodeRiftsError,
    PreflightChangeSetContext,
    RateLimitError,
)
from coderifts.client import _Response


class TestResponseWrapper(unittest.TestCase):
    def test_attribute_and_nested_dict(self):
        r = _Response({"decision": "ALLOW", "nested": {"x": 1}})
        self.assertEqual(r.decision, "ALLOW")
        self.assertEqual(r.nested.x, 1)
        self.assertEqual(r["decision"], "ALLOW")
        self.assertIn("decision", r)
        self.assertEqual(r.to_dict()["decision"], "ALLOW")

    def test_missing_attribute(self):
        r = _Response({})
        with self.assertRaises(AttributeError):
            _ = r.missing

    def test_list_not_wrapped(self):
        r = _Response({"patterns": ["A", "B"]})
        self.assertEqual(r.patterns, ["A", "B"])


class TestClientConstruction(unittest.TestCase):
    def test_requires_api_key(self):
        with self.assertRaises(AuthError):
            CodeRifts(api_key="")

    def test_default_base_url_and_headers(self):
        c = CodeRifts(api_key="cr_test_key")
        self.assertTrue(c._base_url.endswith("/api/v1"))
        self.assertEqual(
            c._session.headers["Authorization"], "Bearer cr_test_key"
        )
        self.assertIn("coderifts-python-sdk/3.1.0", c._session.headers["User-Agent"])


class TestPreflightChangeSet(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key="cr_test_key")

    def test_posts_artifacts_context_and_required_preflight_mode(self):
        payload = {
            "decision": "ALLOW",
            "execution_action": "CONTINUE",
            "risk_score": 0,
            "safe_for_agent": True,
            "breaking_changes": 0,
            "patterns": [],
            "requires_migration": False,
            "evidence_quality": "LOW",
            "coderifts_version": "1.0",
            "timestamp": "2026-08-03T14:31:10.723Z",
            "decision_result": {"decision_id": "dec_x"},
            "control_envelope": {"execution_action": "CONTINUE"},
        }
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.preflight_change_set(
                artifacts=[
                    {
                        "id": "spec-main",
                        "type": "openapi",
                        "before": "{}",
                        "after": "{}",
                    }
                ],
                preflight_mode="authorize",
                context={
                    "operation": "merge",
                    "environment": "staging",
                    "base": "base-sha-aaa",
                    "head": "head-sha-bbb",
                },
            )
        req.assert_called_once_with(
            "POST",
            "/preflight",
            json={
                "artifacts": [
                    {
                        "id": "spec-main",
                        "type": "openapi",
                        "before": "{}",
                        "after": "{}",
                    }
                ],
                "preflight_mode": "authorize",
                "context": {
                    "operation": "merge",
                    "environment": "staging",
                    "base": "base-sha-aaa",
                    "head": "head-sha-bbb",
                },
            },
        )
        self.assertEqual(result.execution_action, "CONTINUE")
        self.assertEqual(result.decision, "ALLOW")
        self.assertEqual(result.breaking_changes, 0)
        self.assertEqual(result.decision_result.decision_id, "dec_x")
        self.assertIn("base", PreflightChangeSetContext.__annotations__)
        self.assertIn("head", PreflightChangeSetContext.__annotations__)

    def test_context_optional_but_preflight_mode_required(self):
        with patch.object(
            self.client, "_request", return_value={"decision": "ALLOW"}
        ) as req:
            self.client.preflight_change_set(
                artifacts=[{"id": "a"}], preflight_mode="analyze"
            )
        self.assertEqual(
            req.call_args.kwargs["json"],
            {"artifacts": [{"id": "a"}], "preflight_mode": "analyze"},
        )

    def test_missing_preflight_mode_is_typeerror_keyword_only(self):
        with self.assertRaises(TypeError):
            self.client.preflight_change_set(artifacts=[{"id": "a"}])  # type: ignore[call-arg]

    def test_invalid_preflight_mode_raises_valueerror(self):
        with self.assertRaises(ValueError) as ctx:
            self.client.preflight_change_set(
                artifacts=[{"id": "a"}],
                preflight_mode="maybe",  # type: ignore[arg-type]
            )
        self.assertIn("analyze", str(ctx.exception))
        self.assertIn("authorize", str(ctx.exception))

    def test_analyze_change_set_injects_mode(self):
        with patch.object(
            self.client, "_request", return_value={"analysis_outcome": "NO_BREAK_DETECTED"}
        ) as req:
            self.client.analyze_change_set(artifacts=[{"id": "a"}])
        self.assertEqual(
            req.call_args.kwargs["json"],
            {"artifacts": [{"id": "a"}], "preflight_mode": "analyze"},
        )

    def test_authorize_change_set_injects_mode(self):
        with patch.object(
            self.client, "_request", return_value={"execution_action": "CONTINUE"}
        ) as req:
            self.client.authorize_change_set(
                artifacts=[{"id": "a"}],
                context={"operation": "merge"},
            )
        self.assertEqual(
            req.call_args.kwargs["json"],
            {
                "artifacts": [{"id": "a"}],
                "preflight_mode": "authorize",
                "context": {"operation": "merge"},
            },
        )


class TestVerifyReceipt(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key="cr_test_key")

    def test_token_only(self):
        payload = {
            "valid": True,
            "status": "VERIFIED_CURRENT",
            "reason": None,
            "payload": {"v": 4},
            "currently_authorized": None,
            "authz_note": "status reflects signature+expiry only",
            "correlation_id": "cid",
        }
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.verify_receipt(token="tok.en")
        req.assert_called_once_with(
            "POST",
            "/verify-receipt",
            json={"token": "tok.en"},
        )
        self.assertTrue(result.valid)
        self.assertIsNone(result.currently_authorized)

    def test_with_intent_and_decision_result(self):
        payload = {
            "valid": True,
            "status": "VERIFIED_CURRENT",
            "currently_authorized": True,
            "authz_status": "VERIFIED_CURRENT",
            "authz_reason": "ok",
            "authz_state": "VALID",
            "correlation_id": "cid",
        }
        dr = {"decision_id": "dec_1", "decision_body_hash": "sha256:x"}
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.verify_receipt(
                token="tok.en",
                operation="merge",
                environment="staging",
                target_id="sha256:t",
                fingerprint="sha256:f",
                audience="agents",
                decision_result=dr,
            )
        self.assertEqual(
            req.call_args.kwargs["json"],
            {
                "token": "tok.en",
                "operation": "merge",
                "environment": "staging",
                "target_id": "sha256:t",
                "fingerprint": "sha256:f",
                "audience": "agents",
                "decision_result": dr,
            },
        )
        self.assertTrue(result.currently_authorized)
        self.assertEqual(result.authz_status, "VERIFIED_CURRENT")

    def test_with_scope_bound_intent_fields(self):
        """Scope-bound intent fields match server intended context (ID829)."""
        payload = {
            "valid": True,
            "status": "VERIFIED_CURRENT",
            "currently_authorized": True,
            "authz_status": "VERIFIED_CURRENT",
            "correlation_id": "cid",
        }
        indices = {"revocation": 0, "issuance": 1}
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.verify_receipt(
                token="tok.en",
                operation="merge",
                environment="staging",
                target_id="sha256:t",
                fingerprint="sha256:f",
                audience="agents",
                repository="acme/widgets",
                branch="main",
                pull_request=42,
                indices=indices,
            )
        self.assertEqual(
            req.call_args.kwargs["json"],
            {
                "token": "tok.en",
                "operation": "merge",
                "environment": "staging",
                "target_id": "sha256:t",
                "fingerprint": "sha256:f",
                "audience": "agents",
                "repository": "acme/widgets",
                "branch": "main",
                "pull_request": 42,
                "indices": indices,
            },
        )
        self.assertTrue(result.currently_authorized)

    def test_pull_request_accepts_string(self):
        payload = {
            "valid": True,
            "status": "VERIFIED_CURRENT",
            "currently_authorized": None,
            "correlation_id": "cid",
        }
        with patch.object(self.client, "_request", return_value=payload) as req:
            self.client.verify_receipt(
                token="tok.en",
                repository="org/repo",
                branch="feature/x",
                pull_request="99",
                indices={"n": 1},
            )
        body = req.call_args.kwargs["json"]
        self.assertEqual(body["repository"], "org/repo")
        self.assertEqual(body["branch"], "feature/x")
        self.assertEqual(body["pull_request"], "99")
        self.assertEqual(body["indices"], {"n": 1})

    def test_with_base_head_intent(self):
        """P0-5: documented verify_receipt contract includes base/head SHAs."""
        payload = {
            "valid": True,
            "status": "VERIFIED_CURRENT",
            "currently_authorized": False,
            "authz_reason": "head_mismatch",
            "correlation_id": "cid",
        }
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.verify_receipt(
                token="tok.en",
                operation="merge",
                repository="acme/api",
                base="base-sha-aaa",
                head="head-CALLER-DIFFERS",
            )
        body = req.call_args.kwargs["json"]
        self.assertEqual(body["base"], "base-sha-aaa")
        self.assertEqual(body["head"], "head-CALLER-DIFFERS")
        self.assertEqual(result.authz_reason, "head_mismatch")


class TestGetDecisionDetails(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key="cr_test_key")

    def test_by_decision_id(self):
        payload = {
            "decision": "ALLOW",
            "execution_action": "CONTINUE",
            "meta": {"decision_id": "dec_1", "retrieval_mode": "stored"},
        }
        with patch.object(self.client, "_request", return_value=payload) as req:
            result = self.client.get_decision_details(decision_id="dec_1")
        req.assert_called_once_with(
            "POST",
            "/decisions/lookup",
            json={"decision_id": "dec_1"},
        )
        self.assertEqual(result.execution_action, "CONTINUE")
        self.assertEqual(result.meta.retrieval_mode, "stored")

    def test_by_fingerprint(self):
        with patch.object(
            self.client, "_request", return_value={"decision": "ALLOW"}
        ) as req:
            self.client.get_decision_details(fingerprint="sha256:abc")
        self.assertEqual(
            req.call_args.kwargs["json"],
            {"fingerprint": "sha256:abc"},
        )

    def test_empty_body_still_posts(self):
        """Empty body is valid SDK usage; the API returns INVALID_INPUT."""
        with patch.object(
            self.client,
            "_request",
            side_effect=ApiError("INVALID_INPUT", status_code=400),
        ):
            with self.assertRaises(ApiError) as ctx:
                self.client.get_decision_details()
            self.assertEqual(ctx.exception.status_code, 400)


class TestRequestErrorMapping(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key="cr_test_key")

    def _mock_response(self, status_code, json_body=None, text="err"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        if json_body is not None:
            resp.json.return_value = json_body
        else:
            resp.json.side_effect = ValueError("no json")
        return resp

    def test_401_raises_auth(self):
        with patch.object(
            self.client._session,
            "request",
            return_value=self._mock_response(401),
        ):
            with self.assertRaises(AuthError):
                self.client._request("POST", "/preflight", json={})

    def test_429_raises_rate_limit(self):
        with patch.object(
            self.client._session,
            "request",
            return_value=self._mock_response(429),
        ):
            with self.assertRaises(RateLimitError):
                self.client._request("POST", "/preflight", json={})

    def test_400_raises_api_error(self):
        with patch.object(
            self.client._session,
            "request",
            return_value=self._mock_response(
                400, {"error": "INVALID_INPUT", "message": "bad"}
            ),
        ):
            with self.assertRaises(ApiError) as ctx:
                self.client._request("POST", "/preflight", json={})
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.message, "INVALID_INPUT")

    def test_timeout_raises_coderifts_error(self):
        import requests as req_lib

        with patch.object(
            self.client._session,
            "request",
            side_effect=req_lib.exceptions.Timeout(),
        ):
            with self.assertRaises(CodeRiftsError) as ctx:
                self.client._request("POST", "/preflight", json={})
            self.assertEqual(ctx.exception.code, "timeout_error")


if __name__ == "__main__":
    unittest.main()
