"""HERMETIC cross-language parity (1456) — this side against a repo-internal golden oracle.

WHAT WAS MEASURED, AND WHY A SKIP IS NOT A PROOF
------------------------------------------------
The TypeScript SDK compared itself against three sibling checkouts under ``$HOME`` — including
``receipt-verifier/verify_grant.py`` for the Python comparison. On a clean clone none of them
exists, so the comparison skipped: honest, and then the release was gated on a check that did not
run. This package was not part of that comparison at all, and it carries its OWN
``compute_scope_hash`` — a fourth transcription of the same rule.

HOW A GOLDEN SET REMOVES THE SIBLING
------------------------------------
The two languages do not need to meet; they need to agree, and agreement is transitive. If this
side matches the golden file and the TypeScript side matches the SAME file, the two match each
other. The oracle is committed in BOTH packages, byte-identical, pinned by sha256, and each side
asserts only its own computation.

``GOLDEN.sha256`` holds the same digest in both repos. A copy that drifts fails its own test before
it can quietly diverge from the other — which is what makes two files one oracle.

RELEASE-BLOCKING. There is no skip path: the fixture lives in this repository.
"""

import hashlib
import json
import os

import pytest

from coderifts.execution_grant import after_payload_canonical, compute_scope_hash

DIR = os.path.join(os.path.dirname(__file__), "fixtures", "xlang")
FILE = os.path.join(DIR, "scope-hash.golden.json")
PIN = os.path.join(DIR, "GOLDEN.sha256")

with open(FILE, "rb") as fh:
    RAW = fh.read()
GOLDEN = json.loads(RAW.decode("utf-8"))


def test_golden_matches_its_pin():
    """The same digest the TypeScript package records — that is what makes it one oracle."""
    with open(PIN, "r", encoding="utf-8") as fh:
        want = fh.read().strip().split()[0]
    assert len(want) == 64
    assert hashlib.sha256(RAW).hexdigest() == want


def test_the_set_is_not_thin():
    assert GOLDEN["schema"] == "cr.xlang.scope-hash-golden.v1"
    assert len(GOLDEN["scope_hash"]) >= 10
    assert len(GOLDEN["after_payload_canonical"]) >= 5
    names = " | ".join(v["name"] for v in GOLDEN["scope_hash"])
    for need in ("absent", "separator", "UTF-8", "NUL"):
        assert need in names, 'no vector covers "%s"' % need


@pytest.mark.parametrize(
    "vector", GOLDEN["scope_hash"], ids=[v["name"] for v in GOLDEN["scope_hash"]]
)
def test_scope_hash_matches_golden(vector):
    """An ABSENT key is None here and `undefined` there — both must hash like the empty string."""
    args = vector["args"]
    got = compute_scope_hash(
        args.get("operation"), args.get("target_id"), args.get("after_payload")
    )
    assert got == vector["expected"]


@pytest.mark.parametrize(
    "vector",
    GOLDEN["after_payload_canonical"],
    ids=[v["name"] for v in GOLDEN["after_payload_canonical"]],
)
def test_canonical_input_matches_golden(vector):
    assert after_payload_canonical(vector["artifacts"]) == vector["expected"]


def test_the_oracle_bites():
    """All sides agreeing could mean all sides are wrong in the same way.

    A golden file generated from one implementation would enshrine that implementation's mistake,
    so the separator is shown to be load-bearing rather than assumed.
    """
    v = GOLDEN["scope_hash"][0]
    a = v["args"]
    wrong = "|".join(
        [
            a.get("operation") or "",
            a.get("target_id") or "",
            a.get("after_payload") or "",
        ]
    )
    assert "sha256:" + hashlib.sha256(wrong.encode("utf-8")).hexdigest() != v["expected"]
