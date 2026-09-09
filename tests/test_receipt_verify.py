"""FULL LOCAL Ed25519 verification, and the boundaries around it.

── WHY A CORPUS AND NOT A HAPPY PATH ───────────────────────────────────────────────────────

This is a SECOND Python implementation of a format `coderifts-verifier` already verifies, and a
THIRD in the ecosystem counting the node core. Two verifiers of one format disagreeing is a defect
this ecosystem has already paid for; the only thing that makes a third safe is parity proved
against the first, on ITS corpus, byte for byte — not a valid receipt passing here.

The node core ships 16 vectors with expected verdicts, including four tampered bodies, a wrong
kid, a truncated token, garbage base64, an expired v4, a v4-as-v3 downgrade and an unsupported v5.
Every one is run through this module and compared with what the node core ACTUALLY returns — not
with the vectors' recorded expectations, which would let both drift together.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from coderifts.receipt_verify import (
    keyring_from_document,
    reconstruct_signed_input,
    verify_receipt,
)

CORE = os.path.join(os.path.expanduser("~"), "receipt-verifier")
VECTORS = os.path.join(CORE, "test", "vectors.json")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(VECTORS),
    # LOUD. A silent skip would report a comparison that never ran as a passing one.
    reason="receipt-verifier is not checked out beside this repo — the cross-language parity was "
           "NOT run (not passed)",
)


@pytest.fixture(scope="module")
def corpus():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def ring(corpus):
    return {corpus["kid"]: {"public_key_pem": corpus["public_key_pem"], "status": "active"}}


@pytest.fixture(scope="module")
def node_verdicts(corpus):
    """What the NODE CORE actually returns, asked at test time.

    Not the vectors' recorded `expected` block: that is what both implementations were written
    against, and comparing against it would let them drift together while both looked correct.
    """
    script = r"""
const V = require(process.argv[1]);
const { verifyReceipt } = require(process.argv[2]);
const crypto = require('crypto');
const ring = new Map([[V.kid, { publicKey: crypto.createPublicKey(V.public_key_pem), status: 'active' }]]);
const out = {};
for (const v of V.vectors) {
  const r = verifyReceipt(v.token, { ctx: { keyring: ring, expectedKid: null }, ...(v.now ? { now: v.now } : {}) });
  out[v.name] = { valid: r.valid, status: r.status, reason: r.reason || null };
}
process.stdout.write(JSON.stringify(out));
"""
    proc = subprocess.run(
        ["node", "-e", script, VECTORS, os.path.join(CORE, "verify.js")],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        pytest.skip(f"the node core could not be run — parity NOT checked: {proc.stderr[:160]}")
    return json.loads(proc.stdout)


def test_every_vector_reaches_the_same_verdict_as_the_node_core(corpus, ring, node_verdicts):
    """Byte-for-byte parity, including the fields a caller might branch on.

    `reason` is compared too. An implementation that helpfully added one where the other emits
    none would make a consumer branching on it see a value from Python and null from node — small,
    and exactly the divergence class two verifiers exist to avoid. (Measured: this caught two.)
    """
    mismatches = []
    for vec in corpus["vectors"]:
        r = verify_receipt(vec["token"], ring, now=vec.get("now"))
        mine = {"valid": r["valid"], "status": r.get("status"), "reason": r.get("reason")}
        if mine != node_verdicts[vec["name"]]:
            mismatches.append(f"{vec['name']}: node={node_verdicts[vec['name']]} python={mine}")
    assert not mismatches, "\n".join(mismatches)
    assert len(corpus["vectors"]) >= 16, "the corpus shrank — parity over fewer cases is weaker"


def test_a_valid_receipt_verifies(corpus, ring):
    valid = [v for v in corpus["vectors"] if v["expected"].get("valid") is True]
    assert valid, "the corpus has no positive case — refusing everything would pass"
    for vec in valid:
        r = verify_receipt(vec["token"], ring, now=vec.get("now"))
        assert r["valid"] is True, f"{vec['name']}: {r}"
        assert r["status"] == "VERIFIED_CURRENT"


def test_a_tampered_signature_is_refused(corpus, ring):
    """One BIT of the decoded signature — not the last base64 character.

    An Ed25519 signature is 64 bytes in 86 base64url characters, so the final character carries
    four bits that decode to nothing: flipping it is a NO-OP for 16 of 64 possible last characters.
    That mutation was live in this ecosystem's own controls once.
    """
    import base64
    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    head, _, sig_b64 = vec["token"].rpartition(".")
    sig = bytearray(base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4)))
    original = bytes(sig)
    sig[0] ^= 0x01
    assert bytes(sig) != original, "the mutation did not change the signature bytes"
    tampered = head + "." + base64.urlsafe_b64encode(bytes(sig)).decode().rstrip("=")
    r = verify_receipt(tampered, ring, now=vec.get("now"))
    assert r["valid"] is False
    assert r["status"] == "INVALID_SIGNATURE"
    assert r["reason"] == "signature_mismatch"


def test_a_tampered_payload_is_refused(corpus, ring):
    """The corpus's own body-tamper vectors: fp, reg, ir, and a reordered v3."""
    tampered = [v for v in corpus["vectors"]
                if v["expected"].get("reason") == "signature_mismatch"]
    assert len(tampered) >= 4, "the body-tamper vectors are missing"
    for vec in tampered:
        r = verify_receipt(vec["token"], ring, now=vec.get("now"))
        assert r["valid"] is False, f"{vec['name']} was accepted"
        assert r["reason"] == "signature_mismatch", f"{vec['name']}: {r}"


def test_the_signed_input_is_rebuilt_from_the_body_not_the_encoded_segment(corpus):
    """The FROZEN rule (RECEIPT_FORMAT.md §3), and why it is rebuilt.

    The encoded payload is what an attacker hands you; signing over it would only verify that they
    encoded their own bytes consistently.
    """
    body = {"v": 4, "kid": "k", "fp": "f", "prev": "p", "caller": "c", "ts": "t",
            "reg": "r", "ir": "i", "expires_at": "e", "bh": "b"}
    assert reconstruct_signed_input(body) == "crchain.v1|k|f|p|c|t|r|i|e|b"
    assert reconstruct_signed_input({**body, "v": 3}) == "crchain.v1|k|f|p|c|t|r|i"
    assert reconstruct_signed_input({**body, "v": 1}) == "crchain.v1|k|f|p|c|t"


def test_an_unknown_key_status_fails_closed(corpus):
    """A word this build does not understand must never read as a healthy key."""
    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    ring = {corpus["kid"]: {"public_key_pem": corpus["public_key_pem"], "status": "quarantined"}}
    r = verify_receipt(vec["token"], ring, now=vec.get("now"))
    assert r["valid"] is False
    assert r["status"] == "UNKNOWN_KEY_STATUS"


def test_a_revoked_key_is_refused(corpus):
    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    ring = {corpus["kid"]: {"public_key_pem": corpus["public_key_pem"], "status": "revoked"}}
    assert verify_receipt(vec["token"], ring, now=vec.get("now"))["valid"] is False


def test_keyring_from_document_ignores_unusable_rows(corpus):
    doc = {"keys": [
        {"kid": corpus["kid"], "public_key_pem": corpus["public_key_pem"]},
        {"kid": "no-pem"},
        {"public_key_pem": "no-kid"},
        "not-a-mapping",
    ]}
    ring = keyring_from_document(doc)
    assert list(ring) == [corpus["kid"]]


def test_no_network_is_reachable_from_a_verify(corpus, ring, monkeypatch):
    """Asserted, not assumed — and the trap is proved live first.

    A trap that never fires and a trap that is not installed look identical.
    """
    import socket
    tripped = []
    real_create = socket.create_connection
    real_sock = socket.socket

    def boom(*a, **k):
        tripped.append("socket")
        raise AssertionError("the local verify opened a socket")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "socket", boom)

    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    assert verify_receipt(vec["token"], ring, now=vec.get("now"))["valid"] is True
    assert tripped == []

    # The trap IS live: a real attempt trips it.
    with pytest.raises(AssertionError):
        socket.create_connection(("127.0.0.1", 1))
    monkeypatch.setattr(socket, "create_connection", real_create)
    monkeypatch.setattr(socket, "socket", real_sock)


def test_the_verdict_carries_its_ceiling(corpus, ring):
    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    text = "\n".join(verify_receipt(vec["token"], ring, now=vec.get("now"))["does_not_prove"])
    assert "not authorization" in text
    assert "REVOCATION" in text
    assert "property of a set" in text


def test_without_the_extra_it_raises_and_does_not_degrade(monkeypatch, corpus, ring):
    """The one behaviour that must never soften.

    A partial check reported as a verification is worse than no verification, because it is
    counted as one.
    """
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name.startswith("cryptography"):
            raise ImportError("No module named cryptography")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    for mod in [m for m in list(sys.modules) if m.startswith("cryptography")]:
        monkeypatch.delitem(sys.modules, mod, raising=False)

    vec = next(v for v in corpus["vectors"] if v["expected"].get("valid") is True)
    with pytest.raises(ImportError) as exc:
        verify_receipt(vec["token"], ring, now=vec.get("now"))
    assert "coderifts-sdk[verify]" in str(exc.value)
    assert "does NOT fall back" in str(exc.value)
