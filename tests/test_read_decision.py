"""Tests for read_decision and the two advisory helpers rebuilt on top of it.

Covers the fail-open fix: unknown / absent / None input must read as STOP with a
named reason, must never render "safe to proceed", and must never render
"no unblock needed". Includes a source-level assertion that no helper branches
on ``decision`` the way the @coderifts/conformance branch-on-decision fixture
does (prose mentions of ``decision`` are allowed).
"""

from __future__ import annotations

import ast
import inspect
import unittest

from coderifts import (
    EXECUTION_ACTIONS,
    UNREADABLE_DECISION,
    CodeRifts,
    DecisionRead,
    read_decision,
)
from coderifts import client as client_module
from coderifts import decision as decision_module
from coderifts.client import _Response

API_KEY = "test-key-not-a-secret"

# Measured from @coderifts/sdk 3.7.0 readDecision (dist/esm/decision.js).
CANONICAL_ACTIONS = (
    "CONTINUE",
    "CONTINUE_WITH_MONITORING",
    "REQUEST_APPROVAL",
    "STOP",
)

UNREADABLE_INPUTS = (
    ("empty_dict", {}),
    ("none", None),
    ("string", "nope"),
    ("integer", 7),
    ("list", []),
    ("unknown_action", {"execution_action": "BANANA"}),
    ("misspelled_action", {"execution_action": "CONTINUE_WITH_MONITORNG"}),
    ("lowercase_action", {"execution_action": "continue"}),
    ("none_action", {"execution_action": None}),
    ("unknown_decision", {"decision": "MAYBE"}),
    ("legacy_allow_decision_only", {"decision": "ALLOW"}),
    ("analyze_response", {"receipt_kind": "NONE", "may_execute": False}),
    ("error_body", {"error": "unauthorized"}),
    ("envelope_without_action", {"decision_result": {"decision": "ALLOW"}}),
    ("envelope_not_a_dict", {"decision_result": "ALLOW"}),
)


class TestReadDecisionFailClosed(unittest.TestCase):
    def test_unknown_absent_and_none_read_as_stop_with_named_reason(self):
        for label, payload in UNREADABLE_INPUTS:
            with self.subTest(label):
                result = read_decision(payload)
                self.assertEqual(result.execution_action, "STOP")
                self.assertEqual(result.reason, UNREADABLE_DECISION)
                self.assertTrue(result.unreadable)

    def test_never_raises_on_hostile_input(self):
        class Exploding:
            def to_dict(self):
                raise RuntimeError("boom")

        for payload in (Exploding(), object(), b"bytes", 3.5, True):
            with self.subTest(repr(payload)[:24]):
                self.assertEqual(read_decision(payload).execution_action, "STOP")


class TestReadDecisionCanonicalActions(unittest.TestCase):
    def test_each_canonical_action_maps_from_top_level(self):
        for action in CANONICAL_ACTIONS:
            with self.subTest(action):
                result = read_decision({"execution_action": action})
                self.assertEqual(result.execution_action, action)
                self.assertIsNone(result.reason)

    def test_each_canonical_action_maps_from_envelope(self):
        for action in CANONICAL_ACTIONS:
            with self.subTest(action):
                result = read_decision(
                    {"decision_result": {"execution_action": action}}
                )
                self.assertEqual(result.execution_action, action)
                self.assertIsNone(result.reason)

    def test_allowlist_matches_canonical_actions(self):
        self.assertEqual(EXECUTION_ACTIONS, frozenset(CANONICAL_ACTIONS))

    def test_envelope_wins_over_top_level(self):
        result = read_decision(
            {
                "execution_action": "CONTINUE",
                "decision_result": {"execution_action": "STOP", "decision": "BLOCK"},
            }
        )
        self.assertEqual(result.execution_action, "STOP")

    def test_envelope_carries_receipt_and_decision_as_context(self):
        envelope = {
            "execution_action": "REQUEST_APPROVAL",
            "decision": "REQUIRE_APPROVAL",
            "receipt": {"id": "r1"},
        }
        result = read_decision({"decision_result": envelope})
        self.assertEqual(result.decision, "REQUIRE_APPROVAL")
        self.assertEqual(result.envelope, envelope)
        self.assertEqual(result.receipt, {"id": "r1"})

    def test_decision_is_carried_but_never_promoted(self):
        result = read_decision({"decision": "ALLOW"})
        self.assertEqual(result.decision, "ALLOW")
        self.assertEqual(result.execution_action, "STOP")

    def test_accepts_response_wrapper(self):
        result = read_decision(_Response({"execution_action": "CONTINUE"}))
        self.assertEqual(result.execution_action, "CONTINUE")
        self.assertIsNone(result.reason)

    def test_result_is_immutable(self):
        result = read_decision({"execution_action": "STOP"})
        with self.assertRaises(Exception):
            result.execution_action = "CONTINUE"  # type: ignore[misc]

    def test_docstring_states_it_does_not_verify_a_receipt(self):
        self.assertIn("does **not** verify a receipt", read_decision.__doc__)


class TestExplainDecisionAdvisory(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key=API_KEY)

    def test_unknown_value_says_treat_as_stop(self):
        for label, payload in UNREADABLE_INPUTS:
            with self.subTest(label):
                summary = self.client.explain_decision(
                    0.5, "ALLOW", response=payload
                ).summary
                self.assertIn("treat as STOP", summary)
                self.assertNotIn("safe to proceed", summary)

    def test_no_control_input_at_all_says_treat_as_stop(self):
        summary = self.client.explain_decision(0.5, "ALLOW").summary
        self.assertIn("treat as STOP", summary)
        self.assertNotIn("safe to proceed", summary)

    def test_never_says_safe_to_proceed_for_any_decision_label(self):
        for label in ("ALLOW", "WARN", "REQUIRE_APPROVAL", "BLOCK", "BOGUS", ""):
            with self.subTest(label):
                self.assertNotIn(
                    "safe to proceed",
                    self.client.explain_decision(0.1, label).summary,
                )

    def test_each_canonical_action_renders_its_own_sentence(self):
        for action in CANONICAL_ACTIONS:
            with self.subTest(action):
                out = self.client.explain_decision(
                    0.1, "ALLOW", execution_action=action
                )
                self.assertIn(action, out.summary)
                self.assertEqual(out.execution_action, action)
                self.assertIsNone(out.reason)

    def test_continue_does_not_borrow_the_old_safe_wording(self):
        out = self.client.explain_decision(0.1, "ALLOW", execution_action="CONTINUE")
        self.assertIn("may proceed", out.summary)
        self.assertNotIn("safe to proceed", out.summary)

    def test_decision_still_appears_in_prose(self):
        summary = self.client.explain_decision(
            0.42, "REQUIRE_APPROVAL", execution_action="REQUEST_APPROVAL"
        ).summary
        self.assertIn("REQUIRE_APPROVAL", summary)
        self.assertIn("0.42", summary)

    def test_response_payload_takes_precedence_over_scalar(self):
        out = self.client.explain_decision(
            0.1,
            "ALLOW",
            execution_action="CONTINUE",
            response={"execution_action": "STOP", "decision": "BLOCK"},
        )
        self.assertEqual(out.execution_action, "STOP")

    def test_components_and_trigger_count_still_rendered(self):
        out = self.client.explain_decision(
            0.7,
            "BLOCK",
            reflex_triggers=[{"rule": "r1"}, {"rule": "r2"}],
            omega_components={"breaking_changes": 3.0, "ignored": "text"},
            execution_action="STOP",
        )
        self.assertIn("2 reflex rule(s) triggered", out.summary)
        self.assertEqual(len(out.components), 1)


class TestHowToUnblockAdvisory(unittest.TestCase):
    def setUp(self):
        self.client = CodeRifts(api_key=API_KEY)

    def test_unknown_value_does_not_say_no_unblock_needed(self):
        for label, payload in UNREADABLE_INPUTS:
            with self.subTest(label):
                out = self.client.how_to_unblock("ALLOW", response=payload)
                rendered = " ".join(a["description"] for a in out.actions)
                self.assertNotIn("no unblock needed", rendered)
                self.assertIn("treat as STOP", rendered)
                self.assertEqual(out.execution_action, "STOP")

    def test_no_control_input_at_all_does_not_say_no_unblock_needed(self):
        out = self.client.how_to_unblock("ALLOW")
        rendered = " ".join(a["description"] for a in out.actions)
        self.assertNotIn("no unblock needed", rendered)
        self.assertIn("treat as STOP", rendered)

    def test_unknown_value_still_renders_the_fix_steps(self):
        out = self.client.how_to_unblock(
            "BOGUS",
            breaking_changes=[{"type": "removed", "path": "/u", "description": "gone"}],
            reflex_triggers=[{"rule": "r1"}],
            response={"execution_action": "BANANA"},
        )
        rendered = " ".join(a["description"] for a in out.actions)
        self.assertIn("Fix 1 breaking change(s)", rendered)
        self.assertIn("Resolve reflex rule: r1", rendered)
        self.assertIn("override", rendered)

    def test_stop_renders_the_fix_steps(self):
        out = self.client.how_to_unblock(
            "BLOCK",
            breaking_changes=[{"type": "removed", "path": "/u", "description": "gone"}],
            execution_action="STOP",
        )
        rendered = " ".join(a["description"] for a in out.actions)
        self.assertIn("Fix 1 breaking change(s)", rendered)
        self.assertNotIn("no unblock needed", rendered)

    def test_request_approval_asks_for_approval_not_no_unblock_needed(self):
        out = self.client.how_to_unblock(
            "REQUIRE_APPROVAL", execution_action="REQUEST_APPROVAL"
        )
        rendered = " ".join(a["description"] for a in out.actions)
        self.assertNotIn("no unblock needed", rendered)
        self.assertIn("manual approval is required", rendered)

    def test_no_unblock_needed_only_for_readable_proceed_actions(self):
        for action in ("CONTINUE", "CONTINUE_WITH_MONITORING"):
            with self.subTest(action):
                out = self.client.how_to_unblock("ALLOW", execution_action=action)
                rendered = " ".join(a["description"] for a in out.actions)
                self.assertIn("no unblock needed", rendered)
                self.assertEqual(out.execution_action, action)

    def test_decision_still_appears_in_prose(self):
        out = self.client.how_to_unblock("ALLOW", execution_action="CONTINUE")
        self.assertIn("ALLOW", out.actions[0]["description"])

    def test_steps_are_numbered_consecutively(self):
        out = self.client.how_to_unblock(
            "BLOCK",
            breaking_changes=[{"type": "removed", "path": "/u", "description": "gone"}],
            reflex_triggers=[{"rule": "r1"}],
            execution_action="STOP",
        )
        self.assertEqual(
            [a["step"] for a in out.actions], list(range(1, len(out.actions) + 1))
        )


def _branch_tests_referencing_decision(module):
    """Names of functions in `module` that branch on a `decision` value."""
    return _branch_tests_in_tree(ast.parse(inspect.getsource(module)))


def _branch_tests_in_tree(tree):
    """Names of functions whose IF/WHILE/ternary tests compare a `decision` value.

    This is the @coderifts/conformance branch-on-decision fixture pattern:
    `if (d === 'ALLOW') ...` where `d` is `response.decision`.

    Scope note: this detects BRANCHES, which is what the fixture does. It does
    not flag a comparison used in an assignment (e.g. deriving a boolean from
    `decision`); see the report for `preflight_check`.
    """
    offenders = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            tests = []
            if isinstance(node, (ast.If, ast.While, ast.IfExp)):
                tests = [node.test]
            for test in tests:
                for cmp_node in ast.walk(test):
                    if not isinstance(cmp_node, ast.Compare):
                        continue
                    # Presence checks on an optional request parameter
                    # (`if decision is not None`) select no outcome; a VALUE
                    # comparison (==, !=, in, not in) is the fixture pattern.
                    if not any(
                        isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn))
                        for op in cmp_node.ops
                    ):
                        continue
                    for ref in ast.walk(cmp_node):
                        named = (
                            (isinstance(ref, ast.Name) and ref.id == "decision")
                            or (
                                isinstance(ref, ast.Attribute)
                                and ref.attr == "decision"
                            )
                            or (
                                isinstance(ref, ast.Constant)
                                and ref.value == "decision"
                            )
                        )
                        if named:
                            offenders.append(func.name)
    return sorted(set(offenders))


class TestNoHelperBranchesOnDecision(unittest.TestCase):
    """Source-level guard: prose may mention `decision`; no branch may read it."""

    def test_client_module_has_no_branch_on_decision(self):
        self.assertEqual(_branch_tests_referencing_decision(client_module), [])

    def test_decision_module_has_no_branch_on_decision(self):
        self.assertEqual(_branch_tests_referencing_decision(decision_module), [])

    def test_the_fixture_pattern_is_actually_detected(self):
        """The guard must fail deliberately-wrong subjects, or it proves nothing.

        Mirrors @coderifts/conformance subjects/branch-on-decision.js, plus the
        two shapes this SDK actually shipped (`!=` and `in`).
        """
        wrong_subjects = (
            "def decide(r):\n"
            "    decision = r['decision']\n"
            "    if decision == 'ALLOW':\n"
            "        return 'proceed'\n"
            "    return 'halt'\n",
            "def decide(decision):\n"
            "    if decision != 'BLOCK':\n"
            "        return 'no unblock needed'\n"
            "    return 'steps'\n",
            "def decide(decision):\n"
            "    if decision in ('ALLOW', 'WARN'):\n"
            "        return 'safe'\n"
            "    return 'halt'\n",
            "def decide(r):\n"
            "    return 'proceed' if r.decision == 'ALLOW' else 'halt'\n",
        )
        for source in wrong_subjects:
            with self.subTest(source.splitlines()[1].strip()):
                self.assertEqual(
                    _branch_tests_in_tree(ast.parse(source)), ["decide"]
                )

    def test_presence_check_on_the_optional_filter_is_not_flagged(self):
        """`if decision is not None` (a query filter) selects no outcome."""
        benign = (
            "def get_ledger(decision=None):\n"
            "    params = {}\n"
            "    if decision is not None:\n"
            "        params['decision'] = decision\n"
            "    return params\n"
        )
        self.assertEqual(_branch_tests_in_tree(ast.parse(benign)), [])

    def test_helper_prose_may_still_mention_decision(self):
        client = CodeRifts(api_key=API_KEY)
        self.assertIn(
            "Decision: ALLOW",
            client.explain_decision(0.1, "ALLOW", execution_action="CONTINUE").summary,
        )


class TestDecisionReadShape(unittest.TestCase):
    def test_defaults_are_fail_closed_friendly(self):
        result = DecisionRead(execution_action="STOP")
        self.assertIsNone(result.decision)
        self.assertIsNone(result.envelope)
        self.assertIsNone(result.receipt)
        self.assertIsNone(result.reason)
        self.assertFalse(result.unreadable)


if __name__ == "__main__":
    unittest.main()
