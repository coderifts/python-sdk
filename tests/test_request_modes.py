"""Audit P1-2 — the two mutually exclusive /v1/preflight request modes.

Python cannot express this as a type-level union the way the TypeScript SDK does
(``CallerArtifactsRequest | ServerDerivedRequest``), so the rule is enforced at RUNTIME by
``_assert_request_mode`` and mirrored in the TypedDicts and docstrings. These tests pin the
guard: the ValueError must NAME the rule, and the request must be refused BEFORE any HTTP call.

Server truth (coderifts-app, read-only reference):
  mode A  artifacts[]           derivation absent
  mode B  derivation="server"   artifacts REJECTED (400 INVALID_INPUT),
                                context.repository + base + head REQUIRED
                                (400 derivation_requires_base_head without base AND head)
"""

import unittest
from unittest import mock

from coderifts.client import CodeRifts, _assert_request_mode


ARTIFACT = {"id": "api", "type": "openapi", "before": "a", "after": "b"}
CTX_B = {"repository": "owner/repo", "base": "main", "head": "feature"}


def _client():
    return CodeRifts(api_key="cr_live_test")


class TestModeGuardUnit(unittest.TestCase):
    """The guard in isolation."""

    def test_mode_a_accepts_artifacts_without_derivation(self):
        _assert_request_mode([ARTIFACT], None, None)

    def test_mode_b_accepts_derivation_with_repository_base_head(self):
        _assert_request_mode(None, "server", CTX_B)

    def test_neither_artifacts_nor_derivation_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode(None, None, None)
        self.assertIn("artifacts[] is required", str(cm.exception))
        self.assertIn('derivation="server"', str(cm.exception))

    def test_both_sources_refused_naming_the_rule(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode([ARTIFACT], "server", CTX_B)
        msg = str(cm.exception)
        self.assertIn("forbids caller-supplied artifacts[]", msg)
        self.assertIn("one source of truth per request", msg)

    def test_missing_base_refused_naming_the_server_error_code(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode(None, "server", {"repository": "o/r", "head": "b"})
        msg = str(cm.exception)
        self.assertIn("context.base", msg)
        self.assertIn("derivation_requires_base_head", msg)

    def test_missing_head_refused(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode(None, "server", {"repository": "o/r", "base": "a"})
        self.assertIn("context.head", str(cm.exception))

    def test_missing_repository_refused(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode(None, "server", {"base": "a", "head": "b"})
        self.assertIn("context.repository", str(cm.exception))

    def test_blank_base_counts_as_missing(self):
        with self.assertRaises(ValueError):
            _assert_request_mode(None, "server", {"repository": "o/r", "base": "  ", "head": "b"})

    def test_derivation_other_than_server_refused(self):
        with self.assertRaises(ValueError) as cm:
            _assert_request_mode(None, "client", CTX_B)
        self.assertIn('derivation must be "server" when set', str(cm.exception))

    def test_empty_artifacts_list_is_not_a_change_set(self):
        with self.assertRaises(ValueError):
            _assert_request_mode([], None, None)


class TestRequestBodyAssembly(unittest.TestCase):
    """What actually goes on the wire, with the transport mocked out."""

    def _capture(self, **kwargs):
        c = _client()
        with mock.patch.object(c, "_post", return_value="RESP") as post:
            out = c.preflight_change_set(**kwargs)
        self.assertEqual(out, "RESP")
        self.assertEqual(post.call_args[0][0], "/preflight")
        return post.call_args[0][1]

    def test_mode_a_body_carries_artifacts_and_no_derivation(self):
        body = self._capture(artifacts=[ARTIFACT], preflight_mode="authorize")
        self.assertEqual(body["artifacts"], [ARTIFACT])
        self.assertNotIn("derivation", body)

    def test_mode_b_body_carries_derivation_and_no_artifacts(self):
        body = self._capture(derivation="server", preflight_mode="authorize", context=CTX_B)
        self.assertEqual(body["derivation"], "server")
        self.assertNotIn("artifacts", body, "artifacts must not be sent on the derived path")
        self.assertEqual(body["context"]["repository"], "owner/repo")

    def test_state_nonce_is_sent_as_a_top_level_request_field(self):
        body = self._capture(
            artifacts=[ARTIFACT],
            preflight_mode="authorize",
            include_execution_grant=True,
            state_nonce="nonce-from-executor-state-challenge",
        )
        self.assertEqual(body["state_nonce"], "nonce-from-executor-state-challenge")
        self.assertTrue(body["include_execution_grant"])

    def test_state_nonce_omitted_when_absent_bearer_default(self):
        body = self._capture(artifacts=[ARTIFACT], preflight_mode="authorize")
        self.assertNotIn("state_nonce", body, "absent => BEARER grant, key omitted not null")

    def test_state_nonce_works_on_the_server_derived_path_too(self):
        body = self._capture(
            derivation="server", preflight_mode="authorize", context=CTX_B, state_nonce="n1"
        )
        self.assertEqual(body["state_nonce"], "n1")

    def test_misuse_is_refused_BEFORE_any_http_call(self):
        c = _client()
        with mock.patch.object(c, "_post") as post:
            with self.assertRaises(ValueError):
                c.preflight_change_set(
                    artifacts=[ARTIFACT], derivation="server",
                    preflight_mode="authorize", context=CTX_B,
                )
            post.assert_not_called()


class TestWrapperDelegation(unittest.TestCase):
    """analyze/authorize must forward the new params, not silently drop them."""

    def _capture(self, method, **kwargs):
        c = _client()
        with mock.patch.object(c, "_post", return_value="RESP") as post:
            getattr(c, method)(**kwargs)
        return post.call_args[0][1]

    def test_analyze_forwards_derivation(self):
        body = self._capture("analyze_change_set", derivation="server", context=CTX_B)
        self.assertEqual(body["derivation"], "server")
        self.assertEqual(body["preflight_mode"], "analyze")
        self.assertNotIn("artifacts", body)

    def test_authorize_forwards_derivation_and_state_nonce(self):
        body = self._capture(
            "authorize_change_set", derivation="server", context=CTX_B, state_nonce="n1"
        )
        self.assertEqual(body["derivation"], "server")
        self.assertEqual(body["state_nonce"], "n1")
        self.assertEqual(body["preflight_mode"], "authorize")

    def test_analyze_mode_a_still_works(self):
        body = self._capture("analyze_change_set", artifacts=[ARTIFACT])
        self.assertEqual(body["artifacts"], [ARTIFACT])
        self.assertEqual(body["preflight_mode"], "analyze")

    def test_wrapper_misuse_also_refused(self):
        c = _client()
        with mock.patch.object(c, "_post") as post:
            with self.assertRaises(ValueError):
                c.authorize_change_set(artifacts=[ARTIFACT], derivation="server", context=CTX_B)
            post.assert_not_called()


class TestResponseTyping(unittest.TestCase):
    """The response shapes these paths add. Python types are advisory; round-trip the dicts."""

    def test_derivation_envelope_round_trips(self):
        import json
        from coderifts.types import DerivationEnvelope  # noqa: F401  (TypedDict, advisory)

        d = {"source": "github_compare", "base_sha": "aaa", "head_sha": "bbb"}
        self.assertEqual(json.loads(json.dumps(d)), d)

    def test_server_derived_is_a_known_completeness_mode(self):
        from coderifts.types import COMPLETENESS_MODES

        self.assertIn("SERVER_DERIVED", COMPLETENESS_MODES)
        self.assertIn("BOUND_ATTESTED", COMPLETENESS_MODES)
        self.assertNotIn("CALLER_DERIVED", COMPLETENESS_MODES)

    def test_authority_envelope_bound_and_unbound(self):
        bound = {
            "audience": "acme",
            "tenant_scope": "bound",
            "binding_proven_at": "2026-08-24T00:00:00Z",
        }
        unbound = {"audience": None, "tenant_scope": "unbound"}
        self.assertEqual(bound["tenant_scope"], "bound")
        self.assertNotIn("binding_proven_at", unbound)


if __name__ == "__main__":
    unittest.main()


class TestExecutionGrantV2Request(unittest.TestCase):
    """The v2 binding on the preflight request (roadmap 1214).

    The 2026-08-30 audit (5.2) found the request API exposed only
    ``include_execution_grant`` + ``state_nonce`` while the verifier side was
    already v2.

    MEASURED against the live server (coderifts-app ``src/change-set.js``
    :1265-1285): it reads ``grant_version`` and five binding fields from the
    request body's TOP LEVEL, with ``context.<same name>`` as a fallback. So
    these are fields the server actually consumes, not a shape invented here.
    """

    def _capture(self, **kwargs):
        c = _client()
        with mock.patch.object(c, "_post", return_value="RESP") as post:
            c.preflight_change_set(**kwargs)
        return post.call_args[0][1]

    BINDING = {
        "executor_id": "svc-deployer",
        "adapter_id": "postgres",
        "target_uri": "postgres://prod/articles",
        "tenant_id": "acme",
        "expected_state_token": 'W/"etag-9"',
    }

    def test_the_five_binding_fields_reach_the_body_at_top_level(self):
        body = self._capture(
            artifacts=[ARTIFACT],
            preflight_mode="authorize",
            include_execution_grant=True,
            grant_version="v2",
            execution_grant_binding=dict(self.BINDING),
        )
        self.assertEqual(body["grant_version"], "v2")
        for key, value in self.BINDING.items():
            self.assertEqual(body[key], value, "{} did not reach the body".format(key))
            # TOP level, where the server reads it — not nested under context.
            self.assertNotIn(key, body.get("context", {}))

    def test_a_partial_binding_sends_only_what_was_given(self):
        # An unstated field must not become an empty string on the wire: the
        # server's fallback is a real behaviour, and an empty value would
        # suppress it while looking like a binding.
        body = self._capture(
            artifacts=[ARTIFACT],
            preflight_mode="authorize",
            grant_version="v2",
            execution_grant_binding={"executor_id": "only-this"},
        )
        self.assertEqual(body["executor_id"], "only-this")
        for absent in ("adapter_id", "target_uri", "tenant_id", "expected_state_token"):
            self.assertNotIn(absent, body)

    def test_a_key_the_server_does_not_read_is_not_forwarded(self):
        # ExecutionGrantV2 carries fields the SERVER mints (kid, grant_id,
        # receipt_hash, ...). A caller passing one must not have it travel:
        # it would be ignored server-side and read like a binding that took.
        body = self._capture(
            artifacts=[ARTIFACT],
            preflight_mode="authorize",
            grant_version="v2",
            execution_grant_binding={
                "executor_id": "e",
                "kid": "k1",
                "grant_id": "g1",
                "receipt_hash": "sha256:x",
                "policy_hash": "sha256:p",
            },
        )
        self.assertEqual(body["executor_id"], "e")
        for minted in ("kid", "grant_id", "receipt_hash", "policy_hash"):
            self.assertNotIn(minted, body, "{} was forwarded but the server mints it".format(minted))

    def test_no_binding_and_no_version_leaves_the_body_as_before(self):
        # BACK-COMPAT: the v1 shape is untouched when the new kwargs are absent.
        body = self._capture(
            artifacts=[ARTIFACT],
            preflight_mode="authorize",
            include_execution_grant=True,
            state_nonce="n1",
        )
        self.assertEqual(body["include_execution_grant"], True)
        self.assertEqual(body["state_nonce"], "n1")
        for v2key in ("grant_version", "executor_id", "adapter_id", "target_uri", "tenant_id"):
            self.assertNotIn(v2key, body)

    def test_grant_version_alone_is_allowed(self):
        # Measured server behaviour: a v2 request with no stated identity is
        # NOT refused — it binds the server's defaults. The client must not
        # invent a requirement the server does not have.
        body = self._capture(
            artifacts=[ARTIFACT], preflight_mode="authorize", grant_version="v2",
        )
        self.assertEqual(body["grant_version"], "v2")
        self.assertNotIn("executor_id", body)

    def test_authorize_wrapper_forwards_both_kwargs(self):
        c = _client()
        with mock.patch.object(c, "_post", return_value="RESP") as post:
            c.authorize_change_set(
                [ARTIFACT],
                context={"operation": "merge"},
                include_execution_grant=True,
                grant_version="v2",
                execution_grant_binding={"executor_id": "e7"},
            )
        body = post.call_args[0][1]
        self.assertEqual(body["preflight_mode"], "authorize")
        self.assertEqual(body["grant_version"], "v2")
        self.assertEqual(body["executor_id"], "e7")

    def test_analyze_does_not_take_them(self):
        # analyze mints no grant, so a binding parameter there would be a
        # promise the mode cannot keep.
        import inspect

        params = inspect.signature(_client().analyze_change_set).parameters
        self.assertNotIn("grant_version", params)
        self.assertNotIn("execution_grant_binding", params)


class TestExecutionGrantV2RequestType(unittest.TestCase):
    """The request type is DERIVED from the canonical one, not a parallel copy."""

    def test_request_fields_are_a_subset_of_the_canonical_v2_type(self):
        from coderifts.types import (
            EXECUTION_GRANT_V2_REQUEST_FIELDS,
            ExecutionGrantV2,
            ExecutionGrantV2Request,
        )

        canonical = set(ExecutionGrantV2.__annotations__)
        request = set(EXECUTION_GRANT_V2_REQUEST_FIELDS)
        self.assertTrue(
            request <= canonical,
            "the request fields drifted from ExecutionGrantV2: {}".format(request - canonical),
        )
        self.assertEqual(set(ExecutionGrantV2Request.__annotations__), request)

    def test_the_minted_fields_are_deliberately_excluded(self):
        from coderifts.types import EXECUTION_GRANT_V2_REQUEST_FIELDS

        for minted in (
            "kid", "grant_id", "receipt_hash", "after_payload_hash",
            "nonce_hash", "policy_hash", "audience_hash", "v",
        ):
            self.assertNotIn(minted, EXECUTION_GRANT_V2_REQUEST_FIELDS)

    def test_every_request_field_is_one_the_server_reads(self):
        # Pinned against the measured server list (change-set.js:1276-1281).
        # If the server grows a sixth, this fails and names it — which is the
        # prompt to expose it, not to guess.
        from coderifts.types import EXECUTION_GRANT_V2_REQUEST_FIELDS

        server_reads = {
            "executor_id", "adapter_id", "target_uri", "tenant_id", "expected_state_token",
        }
        self.assertEqual(set(EXECUTION_GRANT_V2_REQUEST_FIELDS), server_reads)
