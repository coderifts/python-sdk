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
