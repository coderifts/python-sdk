"""Cross-language verification of a CodeRifts one-grant capture.

    python -m coderifts.verify <fixture-dir> [--payload <file>]

── WHAT THIS IS, AND WHAT IT IS NOT ────────────────────────────────────────────────────────

This re-derives two values from the capture's OWN BYTES using this package's primitives, and
compares them with what the transcript carries:

    receipt_digest(chain_receipt)   ==  the grant's receipt_hash
    sha256(authorized payload)      ==  the grant's after_payload_hash
                                    ==  the correlation's scope_hash
                                    ==  the evidence root's scope_hash
                                    ==  the observation's contract_blob_digest

That is a CROSS-LANGUAGE CHECK: Python computes the same digests the Node/TypeScript side
computed, so the capture is not node-only and its hash recipes are reproducible in another
implementation.

IT IS NOT A SIGNATURE CHECK. This package depends only on ``requests`` and deliberately does not
carry Ed25519 (see execution_grant.py). Nothing here establishes that the issuer signed the grant,
that the executor signed the attestation, or that the evidence root binds the set. A capture whose
every signature was forged would pass this and fail the Node verify — which is why the Node verify
is the one that decides, and this one only proves the arithmetic travels.

Exit codes: 0 every re-derivation matched · 1 a mismatch · 2 the capture could not be read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from .execution_grant import receipt_digest, sha256hex

_OK = "  ok      "
_BAD = "  MISMATCH "
_SKIP = "  NOT RUN "


def _b64url_json(segment: str) -> Dict[str, Any]:
    """Decode a base64url segment that carries JSON, padding as needed."""
    pad = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(pad))


def _grant_payload(token: str) -> Dict[str, Any]:
    return _b64url_json(str(token).split(".")[0])


def _read(directory: str, name: str) -> Dict[str, Any]:
    with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


def _payload_bytes(directory: str, explicit: Optional[str]) -> Optional[bytes]:
    """The AUTHORIZED bytes — the thing the grant bound.

    A capture does not carry them: the grant binds their digest, and shipping the digest twice
    would prove nothing. So they travel beside it, and when they are absent that check is reported
    as NOT RUN rather than passed. An unchecked value must never read like a checked one.
    """
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    else:
        parent = os.path.dirname(os.path.abspath(directory))
        candidates.extend([
            os.path.join(directory, "authorized-payload.yaml"),
            os.path.join(parent, "authorized-payload.yaml"),
            os.path.join(parent, "proof", "authorized-payload.yaml"),
        ])
    for candidate in candidates:
        if os.path.isfile(candidate):
            with open(candidate, "rb") as handle:
                return handle.read()
    return None


def verify(directory: str, payload_file: Optional[str] = None) -> Tuple[int, List[str]]:
    lines: List[str] = []
    failures = 0
    skipped = 0

    try:
        transcript = _read(directory, "transcript.json")
    except Exception as exc:  # noqa: BLE001 - the message is the useful part
        return 2, ["  ERROR    cannot read transcript.json: {}".format(exc)]

    issuance = transcript.get("issuance") or {}
    token = issuance.get("execution_grant")
    if not isinstance(token, str) or not token:
        return 2, ["  ERROR    the transcript carries no issuance.execution_grant"]
    try:
        grant = _grant_payload(token)
    except Exception as exc:  # noqa: BLE001
        return 2, ["  ERROR    the execution_grant does not decode: {}".format(exc)]

    def check(name: str, got: Any, want: Any, note: str = "") -> None:
        nonlocal failures
        if got == want:
            lines.append("{}{}".format(_OK, name))
        else:
            failures += 1
            lines.append("{}{}\n             computed {}\n             capture  {}{}".format(
                _BAD, name, got, want, ("\n             " + note) if note else ""))

    lines.append("  capture   {}".format(os.path.abspath(directory)))
    lines.append("  grant     {} ({} on {})".format(
        grant.get("grant_id") or grant.get("jti"), grant.get("operation"), grant.get("target_uri")))
    lines.append("")

    # 1 — the receipt digest, from the capture's own bytes.
    chain_receipt = issuance.get("chain_receipt")
    if isinstance(chain_receipt, str) and chain_receipt:
        check("receipt_digest(chain_receipt) == grant.receipt_hash",
              receipt_digest(chain_receipt), grant.get("receipt_hash"))
    else:
        skipped += 1
        lines.append("{}receipt_digest — the capture carries no chain_receipt".format(_SKIP))

    # 2 — the authorized payload's digest, against every place the capture records it.
    payload = _payload_bytes(directory, payload_file)
    if payload is None:
        skipped += 1
        lines.append("{}after_payload_hash — the authorized bytes were not supplied "
                     "(--payload <file>), so nothing was re-derived".format(_SKIP))
    else:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        lines.append("  payload   {} bytes -> {}".format(len(payload), digest))
        check("sha256(payload) == grant.after_payload_hash", digest, grant.get("after_payload_hash"))
        correlation = transcript.get("correlation") or {}
        check("sha256(payload) == correlation.scope_hash", digest, correlation.get("scope_hash"))
        root = transcript.get("evidence_root") or {}
        check("sha256(payload) == evidence_root.scope_hash", digest, root.get("scope_hash"))
        transition = transcript.get("target_state_transition") or {}
        observation = transition.get("observation") or {}
        if observation.get("contract_blob_digest") is not None:
            # The bytes the OBSERVER hashed at the commit it read — a different route to the same
            # value, and the one that ties the authorization to what is actually in the target.
            check("sha256(payload) == observation.contract_blob_digest",
                  digest, observation.get("contract_blob_digest"))

    # 3 — the identity the whole capture must agree on, re-read rather than restated.
    transition = transcript.get("target_state_transition") or {}
    continuity = (transcript.get("continuity") or {}).get("identities") or {}
    grant_id = grant.get("grant_id") or grant.get("jti")
    seen = {
        "issuance": grant_id,
        "consume (ledger)": continuity.get("consumed_jti"),
        "transition": (transition.get("grant") or {}).get("grant_id"),
    }
    attestation = transition.get("attestation")
    if isinstance(attestation, str) and attestation.count("|") == 3:
        try:
            seen["attestation"] = _b64url_json(attestation.split("|")[2]).get("grant_jti")
        except Exception:  # noqa: BLE001
            seen["attestation"] = "(undecodable)"
    unique = {v for v in seen.values() if v is not None}
    lines.append("")
    for name, value in seen.items():
        lines.append("  {:<18} {}".format(name, value))
    if len(unique) == 1:
        lines.append("{}ONE grant id across issuance, consume, attestation and transition".format(_OK))
    else:
        failures += 1
        lines.append("{}{} different grant ids — this capture runs on more than one "
                     "authorization".format(_BAD, len(unique)))

    lines.append("")
    lines.append("  CROSS-LANGUAGE DIGEST CHECK ONLY. No signature was verified here: this package "
                 "is requests-only and")
    lines.append("  carries no Ed25519. Run `npx @coderifts/conformance --assurance END_TO_END` for "
                 "the full verify.")
    if skipped:
        lines.append("  {} check(s) NOT RUN — reported as not run, never as passed.".format(skipped))
    return (1 if failures else 0), lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m coderifts.verify",
                                     description="Cross-language digest check of a CodeRifts capture.")
    parser.add_argument("fixture", help="directory holding transcript.json")
    parser.add_argument("--payload", help="the authorized bytes the grant bound")
    args = parser.parse_args(argv)
    code, lines = verify(args.fixture, args.payload)
    for line in lines:
        print(line)
    print("")
    print("  RESULT    {}".format("MATCH (exit 0)" if code == 0
                                  else ("MISMATCH (exit 1)" if code == 1 else "UNREADABLE (exit 2)")))
    return code


if __name__ == "__main__":
    sys.exit(main())
