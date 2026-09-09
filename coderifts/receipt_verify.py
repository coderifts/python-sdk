"""FULL LOCAL receipt verification — Ed25519, offline, no CodeRifts call.

    pip install coderifts-sdk[verify]

    from coderifts import verify_receipt, keyring_from_document
    v = verify_receipt(token, keyring_from_document(keys_doc))
    if not v["valid"]:
        raise RuntimeError(f'{v["status"]}: {v.get("reason")}')

── WHY THE CRYPTO IS AN EXTRA ──────────────────────────────────────────────────────────────

This package's install profile is ``requests`` and nothing else, which is why it works on hosts
that cannot build a wheel. Most callers here talk to the API and never verify anything. Making the
signature path optional keeps that install intact and gives the callers who DO verify a real one.

``cryptography`` over ``pynacl``, measured:

* ``coderifts-verifier`` — this ecosystem's dedicated Python verifier — already depends on
  ``cryptography>=41``. Choosing ``pynacl`` here would mean ONE receipt format verified by TWO
  crypto stacks inside one ecosystem, and would make the eventual consolidation (this module
  delegating to that package once it is published) a dependency swap for every user.
* ``cryptography`` ships wheels for every platform this SDK targets and is already present in most
  environments that have a Python toolchain at all; ``pynacl`` is thinner but adds a second native
  stack next to one that is usually already there.
* ``pynacl`` is the smaller binding and that is a real advantage. It is not worth splitting the
  ecosystem's crypto for.

── WHY THIS CODE EXISTS AT ALL, SAID PLAINLY ───────────────────────────────────────────────

It is a SECOND Python implementation of a format ``coderifts-verifier`` already verifies. That is
a cost, not a feature: two verifiers of one format disagreeing is a defect this ecosystem has
already paid for once.

MEASURED before writing it: ``coderifts-verifier`` is NOT on PyPI (``pip index versions`` finds no
distribution), so an extra that merely depended on it could not resolve for anyone. When it is
published, the honest move is to make ``[verify]`` depend on it and delete this module's signature
path — the parity suite below is what will make that swap safe.

── WHAT IS COVERED, AND WHAT IS NOT ────────────────────────────────────────────────────────

Covered: the FROZEN signed-bytes rule (RECEIPT_FORMAT.md §3) for v1–v4, unknown/retired/revoked
key status, expiry with the 30s clock-skew leeway, and the structural refusals. Proven against the
node core's own 16-vector corpus, not against this file's idea of the format.

NOT covered, and it is not covered by any local verifier: REVOCATION as of now, and the issuer's
clock. A key compromised a minute ago still verifies here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from typing import Any, Dict, Mapping, Optional

SIGNED_PREFIX = "crchain.v1"
MAX_SUPPORTED_V = 4
#: The same 30s the node core applies. A receipt that expired within the leeway is still current.
CLOCK_SKEW_LEEWAY_MS = 30_000
#: Statuses this verifier understands. Anything else FAILS CLOSED — an operator who marked a key
#: with a word this build does not know must not be told the key is fine.
KNOWN_STATUSES = frozenset({"active", "retired", "revoked", None})

_INSTALL_HINT = (
    "coderifts-sdk was installed without the signature-verification extra.\n"
    "    pip install 'coderifts-sdk[verify]'\n"
    "This function does NOT fall back to the digest cross-check: a partial check reported as a "
    "verification is worse than no verification, because it is counted as one. If you want the "
    "cross-check, call cross_check_receipt() and read what it says it is."
)


def _ed25519():
    """The crypto backend, imported at call time so a requests-only install stays importable."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            load_pem_public_key,
        )
    except ImportError as exc:  # pragma: no cover - exercised by the no-extra test
        raise ImportError(_INSTALL_HINT) from exc
    return Ed25519PublicKey, load_pem_public_key


def _b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _fail(status: str, reason: str, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"valid": False, "status": status, "reason": reason}
    if payload is not None:
        out["payload"] = dict(payload)
    return out


def reconstruct_signed_input(body: Mapping[str, Any]) -> str:
    """The FROZEN signed bytes (RECEIPT_FORMAT.md §3), rebuilt from the body's own fields.

    Rebuilt, never read back from the encoded segment: the encoded payload is what an attacker
    hands you, and signing over it would verify that they encoded their own bytes consistently.
    """
    v = body.get("v")
    parts = [
        SIGNED_PREFIX,
        str(body.get("kid", "")),
        str(body.get("fp", "")),
        str(body.get("prev", "")),
        str(body.get("caller", "")),
        str(body.get("ts", "")),
    ]
    if isinstance(v, int) and v >= 2:
        parts.append(str(body.get("reg", "")))
    if isinstance(v, int) and v >= 3:
        parts.append(str(body.get("ir", "")))
    if isinstance(v, int) and v >= 4:
        parts.append(str(body.get("expires_at", "")))
        parts.append(str(body.get("bh", "")))
    return "|".join(parts)


def _has_delimiter(body: Mapping[str, Any]) -> bool:
    """A signed field containing `|` would let a v4 body re-split as a v3 one.

    This is the cross-version re-split guard, and it is why the corpus's `downgrade_v4_as_v3`
    vector is refused as INVALID_SIGNATURE/delimiter_in_field rather than as a bad signature.
    """
    for key in ("kid", "fp", "prev", "caller", "ts", "reg", "ir", "expires_at", "bh"):
        value = body.get(key)
        if isinstance(value, str) and "|" in value:
            return True
    return False


def keyring_from_document(doc: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """kid → entry, from a `.well-known/coderifts-keys.json`-shaped document.

    The keys are PINNED BY THE CALLER and never fetched here. A verifier that downloads the key it
    is about to trust has verified nothing an attacker on the path could not arrange.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for k in (doc or {}).get("keys", []) or []:
        if not isinstance(k, Mapping):
            continue
        kid, pem = k.get("kid"), k.get("public_key_pem")
        if not isinstance(kid, str) or not isinstance(pem, str):
            continue
        out[kid] = {"public_key_pem": pem, "status": k.get("status", "active")}
    return out


def verify_receipt(
    token: str,
    keyring: Mapping[str, Mapping[str, Any]],
    *,
    expected_kid: Optional[str] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify a chain receipt LOCALLY. No network, no API key, full Ed25519.

    :param token:    the receipt token
    :param keyring:  kid → {public_key_pem, status}; see :func:`keyring_from_document`
    :param now:      milliseconds since epoch, for expiry. Absent = the host clock.
    :raises ImportError: when installed without the ``[verify]`` extra. It does NOT quietly
        degrade to the digest cross-check — a partial check reported as a verification is worse
        than none, because it is counted as one.
    """
    Ed25519PublicKey, load_pem_public_key = _ed25519()

    if not isinstance(token, str) or not token:
        return _fail("MALFORMED", "malformed_structure")
    segments = token.split(".")
    if len(segments) != 2 or not all(segments):
        return _fail("MALFORMED", "malformed_structure")
    try:
        body = json.loads(_b64url(segments[0]))
    except (ValueError, binascii.Error):
        return _fail("MALFORMED", "bad_json")
    if not isinstance(body, dict):
        return _fail("MALFORMED", "bad_json")

    v = body.get("v")
    if isinstance(v, int) and v > MAX_SUPPORTED_V:
        # NO `reason`, matching the node core exactly. MEASURED against its 16-vector corpus: it
        # emits `{valid, status}` here and on VERIFIED_EXPIRED, and a Python that helpfully added
        # one would make a consumer branching on `reason` see a value from one implementation and
        # nothing from the other. That is the divergence class two verifiers of one format are for.
        return {"valid": False, "status": "UNSUPPORTED_VERSION", "payload": dict(body)}
    if _has_delimiter(body):
        return _fail("INVALID_SIGNATURE", "delimiter_in_field", body)

    kid = body.get("kid")
    if expected_kid is not None and kid != expected_kid:
        return _fail("UNKNOWN_KEY", "unknown_kid", body)
    entry = (keyring or {}).get(kid)
    if not entry:
        return _fail("UNKNOWN_KEY", "unknown_kid", body)
    status = entry.get("status", "active")
    if status not in KNOWN_STATUSES:
        return _fail("UNKNOWN_KEY_STATUS", "unknown_key_status", body)
    if status == "revoked":
        return _fail("UNKNOWN_KEY", "revoked_kid", body)

    try:
        key = load_pem_public_key(str(entry["public_key_pem"]).encode("utf-8"))
    except Exception:  # noqa: BLE001 - a key we cannot load is a key we do not trust
        return _fail("UNKNOWN_KEY", "unloadable_key", body)
    if not isinstance(key, Ed25519PublicKey):
        return _fail("UNKNOWN_KEY", "not_ed25519", body)

    message = reconstruct_signed_input(body).encode("utf-8")
    try:
        key.verify(_b64url(segments[1]), message)
    except (binascii.Error, ValueError):
        return _fail("INVALID_SIGNATURE", "signature_mismatch", body)
    except Exception:  # noqa: BLE001 - cryptography raises InvalidSignature
        return _fail("INVALID_SIGNATURE", "signature_mismatch", body)

    if status == "retired":
        # The signature is authentic and the key is no longer issuing. Historical, not current.
        return {"valid": False, "status": "RETIRED_KEY_VALID_AT_ISSUE",
                "reason": "retired_kid", "payload": dict(body)}

    expires_at = body.get("expires_at")
    if isinstance(expires_at, str) and expires_at:
        try:
            from datetime import datetime  # noqa: PLC0415
            exp_ms = int(datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            return _fail("MALFORMED", "bad_expires_at", body)
        current = int(time.time() * 1000) if now is None else int(now)
        if exp_ms + CLOCK_SKEW_LEEWAY_MS < current:
            # No `reason` — see UNSUPPORTED_VERSION above.
            return {"valid": False, "status": "VERIFIED_EXPIRED", "payload": dict(body)}

    return {"valid": True, "status": "VERIFIED_CURRENT", "payload": dict(body),
            "does_not_prove": [
                "that the receipt AUTHORIZES the action you are about to take — a valid signature "
                "is authenticity, not authorization",
                "that the signing key is still trusted — REVOCATION and the issuer's clock are "
                "invisible to any local verifier, including this one",
                "that these bytes came from the run you think they did — this checks ONE token, "
                "and 'one run' is a property of a set (cr.evidence.root.v1)",
            ]}


def verify_available() -> bool:
    """True when the ``[verify]`` extra is installed. Never used to soften a verdict."""
    try:
        _ed25519()
        return True
    except ImportError:
        return False


__all__ = ["verify_receipt", "keyring_from_document", "reconstruct_signed_input",
           "verify_available", "CLOCK_SKEW_LEEWAY_MS"]
