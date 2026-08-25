"""Unit tests for the CodeRifts Python SDK.

Uses the standard library ``unittest`` framework (no extra test dependency).
The private ``_request`` helper is mocked so tests never hit the network.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from coderifts import (
    CLOCK_SKEW_LEEWAY_MS,
    ApiError,
    AuthError,
    AuthorizeChangeSetResponse,
    BlastRadius,
    CodeRifts,
    CodeRiftsError,
    ExecutionAction,
    PreflightChangeSetContext,
    RateLimitError,
    declares_destructive_production,
    expiry_leeway_ms,
    is_issued_in_future,
    is_receipt_expired,
)
from coderifts.client import _Response, SDK_VERSION
from coderifts.execution_grant import GRANT_VERSION, compute_scope_hash, receipt_digest


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
        self.assertIn("coderifts-python-sdk/" + SDK_VERSION, c._session.headers["User-Agent"])


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
        for key in (
            "operation", "target_id", "environment", "fingerprint", "audience",
            "repository", "branch", "pull_request", "base", "head",
        ):
            self.assertIn(key, PreflightChangeSetContext.__annotations__)

    def test_preflight_sends_full_10_field_intent_context(self):
        ctx = {
            "operation": "merge",
            "target_id": "svc-1",
            "environment": "production",
            "fingerprint": "sha256:abc",
            "audience": "aud-1",
            "repository": "acme/api",
            "branch": "main",
            "pull_request": 42,
            "base": "base-sha",
            "head": "head-sha",
        }
        with patch.object(
            self.client, "_request", return_value={"decision": "ALLOW"}
        ) as req:
            self.client.preflight_change_set(
                artifacts=[{"id": "a"}],
                preflight_mode="authorize",
                context=ctx,
            )
        self.assertEqual(req.call_args.kwargs["json"]["context"], ctx)

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


class TestClockSkewLeeway(unittest.TestCase):
    def test_constant_is_30000(self):
        self.assertEqual(CLOCK_SKEW_LEEWAY_MS, 30_000)
        self.assertEqual(expiry_leeway_ms(None), CLOCK_SKEW_LEEWAY_MS)

    def test_exp_10s_past_is_current(self):
        now = 1_000_000_000_000
        self.assertFalse(is_receipt_expired(now - 10_000, now))

    def test_exp_40s_past_is_expired(self):
        now = 1_000_000_000_000
        self.assertTrue(is_receipt_expired(now - 40_000, now))

    def test_destructive_prod_not_guessed_1s_past_is_current(self):
        now = 1_000_000_000_000
        ctx = {"environment": "production", "operation": "deploy"}
        self.assertFalse(declares_destructive_production(ctx))
        self.assertEqual(expiry_leeway_ms(ctx), CLOCK_SKEW_LEEWAY_MS)
        self.assertFalse(is_receipt_expired(now - 1_000, now, ctx))

    def test_non_destructive_1s_past_is_current(self):
        now = 1_000_000_000_000
        self.assertFalse(
            is_receipt_expired(now - 1_000, now, {"environment": "staging", "operation": "merge"})
        )

    def test_iat_leeway_other_side(self):
        now = 1_000_000_000_000
        self.assertFalse(is_issued_in_future(now + 10_000, now))
        self.assertTrue(is_issued_in_future(now + 40_000, now))


class TestExecutionGrantHelpers(unittest.TestCase):
    def test_scope_hash_stable(self):
        self.assertEqual(GRANT_VERSION, "cr.exec.v1")
        a = compute_scope_hash("merge", "t", '{"ok":true}')
        b = compute_scope_hash("merge", "t", '{"ok":true}')
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("sha256:"))
        self.assertEqual(
            a,
            "sha256:bda9dac1974036a2e2de4e882a9207bed2dc6f0f4d360db5a60f877771172cbe",
        )
        self.assertEqual(
            receipt_digest("receipt.token"),
            "sha256:ceb96a1ffe90e672d769d6855873de498ef08ee694bf32f1ca5811833b26cf28",
        )

    def test_after_payload_canonical_sort_nul(self):
        from coderifts.execution_grant import after_payload_canonical, spec_str

        self.assertEqual(spec_str(None), "")
        self.assertEqual(spec_str("yaml-a"), "yaml-a")
        self.assertEqual(spec_str({"ok": True, "n": 1}), '{"ok":true,"n":1}')
        artifacts = [
            {"type": "openapi", "id": "b", "after": "yaml-b"},
            {"type": "openapi", "id": "a", "after": "yaml-a"},
        ]
        self.assertEqual(after_payload_canonical(artifacts), "yaml-a\x1fyaml-b")

    def test_preflight_forwards_include_execution_grant(self):
        client = CodeRifts(api_key="cr_test_key")
        with patch.object(client, "_request", return_value={"decision": "ALLOW"}) as req:
            client.preflight_change_set(
                artifacts=[{"id": "a"}],
                preflight_mode="authorize",
                context={"operation": "merge"},
                include_execution_grant=True,
            )
        self.assertEqual(req.call_args.kwargs["json"]["include_execution_grant"], True)

    def test_authorize_change_set_forwards_include_execution_grant(self):
        client = CodeRifts(api_key="cr_test_key")
        with patch.object(client, "_request", return_value={"decision": "ALLOW"}) as req:
            client.authorize_change_set(
                artifacts=[{"id": "a"}],
                context={"operation": "merge"},
                include_execution_grant=True,
            )
        self.assertEqual(req.call_args.kwargs["json"]["include_execution_grant"], True)
        self.assertEqual(req.call_args.kwargs["json"]["preflight_mode"], "authorize")

    def test_include_execution_grant_omitted_when_none(self):
        client = CodeRifts(api_key="cr_test_key")
        with patch.object(client, "_request", return_value={"decision": "ALLOW"}) as req:
            client.preflight_change_set(
                artifacts=[{"id": "a"}],
                preflight_mode="authorize",
                context={"operation": "merge"},
            )
        self.assertNotIn("include_execution_grant", req.call_args.kwargs["json"])


class TestV2ResponseTyping(unittest.TestCase):
    def test_authorize_typedict_names_v2_fields(self):
        keys = AuthorizeChangeSetResponse.__annotations__
        for field in (
            "execution_action",
            "receipt_kind",
            "blast_radius",
            "execution_grant",
            "chain_receipt",
            "decision",
        ):
            self.assertIn(field, keys)
        self.assertIn("endpoints", BlastRadius.__annotations__)
        self.assertEqual(
            ExecutionAction.__args__,
            ("CONTINUE", "CONTINUE_WITH_MONITORING", "REQUEST_APPROVAL", "STOP"),
        )

    def test_authorize_response_surfaces_v2_fields_from_wire(self):
        client = CodeRifts(api_key="cr_test_key")
        payload = {
            "preflight_mode": "authorize",
            "decision": "ALLOW",
            "execution_action": "CONTINUE",
            "receipt_kind": "operation_authorization",
            "chain_receipt": "tok.en",
            "execution_grant": "grant.tok",
            "blast_radius": {
                "endpoints": 1,
                "fields": 2,
                "params": 0,
                "consumers_declared": 0,
                "consumers_observed": 0,
                "graph_source": "none",
            },
        }
        with patch.object(client, "_request", return_value=payload):
            result = client.authorize_change_set(
                artifacts=[{"id": "a"}],
                context={"operation": "merge"},
                include_execution_grant=True,
            )
        self.assertEqual(result.receipt_kind, "operation_authorization")
        self.assertEqual(result.execution_action, "CONTINUE")
        self.assertEqual(result.execution_grant, "grant.tok")
        self.assertEqual(result.blast_radius.endpoints, 1)

    def test_previous_receipt_and_idempotency_key_forwarded(self):
        client = CodeRifts(api_key="cr_test_key")
        with patch.object(client, "_request", return_value={"decision": "ALLOW"}) as req:
            client.preflight_change_set(
                artifacts=[{"id": "a"}],
                preflight_mode="authorize",
                context={"operation": "merge"},
                previous_receipt="prev.tok",
                idempotency_key="idem-1",
            )
        body = req.call_args.kwargs["json"]
        self.assertEqual(body["previous_receipt"], "prev.tok")
        self.assertEqual(body["idempotency_key"], "idem-1")


class TestParityRestMethods(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key="cr_test_key")

    def test_preflight_check_posts_agent_preflight_and_sets_safe(self):
        raw = {
            "decision": "WARN",
            "omega_api": 12,
            "reflex_triggers": [],
            "affected_tools": [],
        }
        with patch.object(self.client, "_request", return_value=raw) as req:
            result = self.client.preflight_check(
                tool_name="get_customer",
                old_spec="{}",
                new_spec="{}",
            )
        req.assert_called_once_with(
            "POST",
            "/agent/preflight",
            json={
                "tool_name": "get_customer",
                "old_spec": "{}",
                "new_spec": "{}",
            },
        )
        self.assertTrue(result.safe)
        self.assertEqual(result.decision, "WARN")

    def test_diff_posts_before_after(self):
        with patch.object(
            self.client, "_request", return_value={"should_block": False, "risk_score": 0}
        ) as req:
            result = self.client.diff(before="a", after="b", branch_name="main")
        req.assert_called_once_with(
            "POST",
            "/diff",
            json={"before": "a", "after": "b", "branch_name": "main"},
        )
        self.assertFalse(result.should_block)

    def test_score_mcp_sends_spec_type(self):
        with patch.object(
            self.client, "_request", return_value={"overall_score": 80, "band": "A"}
        ) as req:
            result = self.client.score_mcp(manifest={"tools": []})
        req.assert_called_once_with(
            "POST",
            "/agent-readiness-score",
            json={"spec": {"tools": []}, "spec_type": "mcp"},
        )
        self.assertEqual(result.overall_score, 80)

    def test_get_ledger_get_query_from_underscore(self):
        with patch.object(
            self.client, "_request", return_value={"total": 0, "entries": []}
        ) as req:
            result = self.client.get_ledger(
                repo="acme/api",
                decision="BLOCK",
                from_="2026-01-01",
                to="2026-02-01",
                limit=10,
            )
        req.assert_called_once_with(
            "GET",
            "/ledger",
            params={
                "repo": "acme/api",
                "decision": "BLOCK",
                "from": "2026-01-01",
                "to": "2026-02-01",
                "limit": 10,
            },
        )
        self.assertEqual(result.total, 0)

    def test_simulate_policy_posts_yaml_and_specs(self):
        with patch.object(
            self.client,
            "_request",
            return_value={"effective_action": "ALLOW", "matched_rules": []},
        ) as req:
            result = self.client.simulate_policy(
                policy_yaml="rules: []",
                old_spec="{}",
                new_spec="{}",
            )
        req.assert_called_once_with(
            "POST",
            "/policy-simulator",
            json={
                "policy_yaml": "rules: []",
                "old_spec": "{}",
                "new_spec": "{}",
            },
        )
        self.assertEqual(result.effective_action, "ALLOW")

    def test_explain_decision_is_client_side(self):
        with patch.object(self.client, "_request") as req:
            result = self.client.explain_decision(
                omega_api=0,
                decision="ALLOW",
                omega_components={"S_contract": 0},
            )
        req.assert_not_called()
        self.assertIn("ALLOW", result.summary)
        self.assertEqual(result.components[0]["name"], "S_contract")

    def test_how_to_unblock_block_lists_steps(self):
        result = self.client.how_to_unblock(
            decision="BLOCK",
            breaking_changes=[
                {"type": "remove", "path": "/x", "description": "gone"},
            ],
            reflex_triggers=[{"rule": "auth-scope"}],
        )
        self.assertGreaterEqual(len(result.actions), 2)
        self.assertEqual(result.actions[0]["step"], 1)

    def test_how_to_unblock_non_block(self):
        """"No unblock needed" now requires a READABLE proceed action.

        Previously this passed ``decision="ALLOW"`` alone and asserted the
        "no unblock needed" wording — pinning the fail-open this release fixes.
        The decision label alone is not permission; the control input is
        ``execution_action``.
        """
        result = self.client.how_to_unblock(
            decision="ALLOW", execution_action="CONTINUE"
        )
        self.assertEqual(len(result.actions), 1)
        self.assertIn("no unblock", result.actions[0]["description"])

    def test_how_to_unblock_decision_label_alone_is_not_permission(self):
        result = self.client.how_to_unblock(decision="ALLOW")
        rendered = " ".join(a["description"] for a in result.actions)
        self.assertNotIn("no unblock", rendered)
        self.assertIn("treat as STOP", rendered)


if __name__ == "__main__":
    unittest.main()
