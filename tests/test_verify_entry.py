"""The cross-language verify entry — and the boundary it must not overstate.

The value of `python -m coderifts.verify` is that a SECOND implementation, in another language,
computes the same digests from the same bytes. That is only worth something if it can fail, and
only honest if it never implies it checked a signature.
"""

from __future__ import annotations

import json
import os
import shutil

import pytest

from coderifts.verify import verify

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "..", "coderifts-conformance", "fixtures", "recorded", "end-to-end")
PROOF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "..", "coderifts-conformance", "proof")
PAYLOAD = os.path.join(PROOF, "authorized-payload.yaml")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(os.path.join(FIXTURE, "transcript.json")),
    # LOUD. A silent skip would report a comparison that never ran as a passing one.
    reason="coderifts-conformance is not checked out beside this repo — the cross-language "
           "comparison was NOT run (not passed)",
)


def test_the_shipped_capture_matches():
    code, lines = verify(FIXTURE, PAYLOAD)
    assert code == 0, "\n".join(lines)
    body = "\n".join(lines)
    assert "receipt_digest(chain_receipt) == grant.receipt_hash" in body
    assert "ONE grant id across issuance, consume, attestation and transition" in body


def test_a_wrong_payload_is_caught(tmp_path):
    # Without this the digest checks could be comparing a value with itself.
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text("openapi: 3.0.3\n")
    code, lines = verify(FIXTURE, str(wrong))
    assert code == 1
    assert any("MISMATCH" in ln and "after_payload_hash" in ln for ln in lines)


def test_a_missing_payload_is_NOT_RUN_never_passed(tmp_path):
    # An unchecked value must not read like a checked one. The digest checks simply do not happen
    # without the bytes, and the output has to say that rather than fall silent.
    empty = tmp_path / "nowhere"
    empty.mkdir()
    shutil.copy(os.path.join(FIXTURE, "transcript.json"), empty / "transcript.json")
    code, lines = verify(str(empty), None)
    body = "\n".join(lines)
    assert "NOT RUN" in body
    assert "check(s) NOT RUN" in body


def test_two_grant_negative_is_caught_here_too():
    neg = os.path.join(PROOF, "negatives", "two-grant")
    if not os.path.isdir(neg):
        pytest.skip("the two-grant negative is not present — NOT RUN, not passed")
    code, lines = verify(neg, PAYLOAD)
    assert code == 1
    assert any("different grant ids" in ln for ln in lines)


def test_the_tampered_negative_PASSES_here_and_the_output_says_why():
    """The boundary, asserted rather than promised.

    A flipped signature does not change a digest, so this entry cannot see it — and pretending
    otherwise would be the more dangerous failure. The Node verify refuses it; this one must both
    pass it AND print that no signature was checked.
    """
    neg = os.path.join(PROOF, "negatives", "tampered-attestation")
    if not os.path.isdir(neg):
        pytest.skip("the tampered negative is not present — NOT RUN, not passed")
    code, lines = verify(neg, PAYLOAD)
    assert code == 0
    body = "\n".join(lines)
    # The boundary sentence, matched by its CLAIM rather than by its old phrasing. It used to read
    # "No signature was verified here: this package is requests-only and carries no Ed25519" — one
    # sentence carrying two facts, and shipping `coderifts-sdk[verify]` made the second one false
    # while the first stayed true. The wording moved; what must hold is that THIS COMMAND still
    # states it read no signature, and that the output no longer denies the package has Ed25519.
    assert "No signature was verified by THIS command" in body
    assert "carries no Ed25519" not in body, (
        "the output still tells the reader this package has no Ed25519 — `coderifts-sdk[verify]` "
        "ships coderifts.verify_receipt, so that is now false"
    )
    assert "coderifts-sdk[verify]" in body, (
        "the output names other packages for offline verification but not the extra in this one"
    )
    assert "npx @coderifts/conformance" in body


def test_the_output_never_claims_a_signature_was_checked():
    _, lines = verify(FIXTURE, PAYLOAD)
    body = "\n".join(lines).lower()
    for overclaim in ("signature verifies", "signature valid", "verified signature"):
        assert overclaim not in body, "the output implies a signature check it did not do"
