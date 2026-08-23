"""cr.exec.v1 helpers — scope_hash only.

Ed25519 verify is NOT ported here: this package depends only on ``requests``.
Offline grant verification lives in coderifts-app and @coderifts/sdk.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

NUL = "\x1f"
GRANT_VERSION = "cr.exec.v1"


def sha256hex(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def spec_str(value: Any) -> str:
    """Match JS specStr: null→''; string as-is; object JSON.stringify (compact, insertion order).

    Not RFC 8785. ensure_ascii=False so unicode matches Node JSON.stringify.
    Whole floats still differ (JS 1.0 → '1'; Python → '1.0'); prefer string after on the wire.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def after_payload_canonical(artifacts: Sequence[Mapping[str, Any]]) -> str:
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
        return ""

    def key(a: Mapping[str, Any]) -> str:
        t = a.get("type")
        i = a.get("id")
        return "{}{}{}".format("" if t is None else str(t), NUL, "" if i is None else str(i))

    ordered = sorted([a for a in artifacts if isinstance(a, Mapping)], key=key)
    return NUL.join(spec_str(a.get("after")) for a in ordered)


def compute_scope_hash(
    operation: Optional[str] = None,
    target_id: Optional[str] = None,
    after_payload: Optional[str] = None,
) -> str:
    preimage = NUL.join(
        [
            "" if operation is None else str(operation),
            "" if target_id is None else str(target_id),
            "" if after_payload is None else str(after_payload),
        ]
    )
    return "sha256:" + sha256hex(preimage)


def receipt_digest(token: str) -> str:
    return "sha256:" + sha256hex(str(token))
