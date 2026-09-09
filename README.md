# coderifts-sdk

## Verifying a receipt offline

With the `[verify]` extra this SDK is a **full offline verifier**: local Ed25519, no network, no
API key, no call to CodeRifts.

```bash
pip install 'coderifts-sdk[verify]'
```
```python
from coderifts import verify_receipt, keyring_from_document

v = verify_receipt(token, keyring_from_document(keys_doc))
if not v["valid"]:
    raise RuntimeError(f'{v["status"]}: {v.get("reason")}')
```

The keyring is **pinned by you and never fetched**. A verifier that downloads the key it is about
to trust has verified nothing an attacker on the path could not arrange.

### Without the extra

`pip install coderifts-sdk` stays **requests-only** — that install works on hosts that cannot build
a wheel, and most callers here talk to the API and never verify anything.

Calling `verify_receipt` without the extra raises `ImportError` naming it. It does **not** fall
back to the digest cross-check: a partial check reported as a verification is worse than none,
because it is counted as one.

### `cross_check_receipt` is not a verification

`cross_check_receipt(capture_dir)` (also `python -m coderifts.verify`) re-derives the **scope hash**
and the **receipt digest** from a capture's own bytes and compares them with what the transcript
carries. It proves a second implementation computes the same digests from the same bytes. It reads
**no signature** — a capture whose every signature was forged passes it.

### Cross-language parity, proved

`verify_receipt` is checked against the node core's own 16-vector corpus — four tampered bodies, a
wrong kid, a truncated token, garbage base64, an expired v4, a v4-as-v3 downgrade, an unsupported
v5 — and compared with what the node core **actually returns**, not with the vectors' recorded
expectations. Byte for byte, `valid` / `status` / `reason`, 16/16.

### What a `valid: true` does not say

Carried on the verdict as `does_not_prove`:

- **not authorization.** A valid signature is authenticity. Whether the receipt permits the action
  you are about to take is a different question.
- **not revocation.** A key compromised a minute ago still verifies. No local verifier can know —
  the server path is the only one that can, and its answer is a convenience mirror, not the proof.
- **not one run.** This checks ONE token; "these tokens came from one run" is a property of a set
  (`cr.evidence.root.v1`).

| I want to… | Use |
| --- | --- |
| call the API (preflight, authorize, decisions) | this package, requests-only |
| **verify a receipt offline, in Python** | **`verify_receipt`** — needs `[verify]` |
| re-derive digests without crypto | `cross_check_receipt` — not a verification |
| verify a receipt offline, in Node | `@coderifts/sdk` → `verifyReceipt(token, { keyring })` |
| grade a whole capture | `npx @coderifts/conformance --assurance END_TO_END` |

Why `cryptography` and not `pynacl`: `coderifts-verifier` — this ecosystem's dedicated Python
verifier — already depends on `cryptography>=41`. Choosing `pynacl` would put one receipt format
behind two crypto stacks in one ecosystem. `pynacl` is the thinner binding and that is a real
advantage; it is not worth splitting the ecosystem's crypto for.

## Surface vs TypeScript SDK

| Capability | Python | TypeScript 3.10.0 | Notes |
|------------|--------|------------------|-------|
| `preflight_change_set` / `analyze_change_set` / `authorize_change_set` | yes | `preflightChangeSet` / `analyzeChangeSet` / `authorizeChangeSet` | `POST /api/v1/preflight` |
| `verify_receipt` | yes | `verifyReceipt` | `POST /api/v1/verify-receipt` |
| `get_decision_details` | yes | `getDecisionDetails` | `POST /api/v1/decisions/lookup` |
| `preflight_check` | yes (3.2.0) | `preflightCheck` | `POST /api/v1/agent/preflight` |
| `diff` | yes (3.2.0) | `diff` | `POST /api/v1/diff` |
| `score_mcp` | yes (3.2.0) | `scoreMcp` | `POST /api/v1/agent-readiness-score` |
| `get_ledger` | yes (3.2.0) | `getLedger` | `GET /api/v1/ledger` (`from_` → query `from`) |
| `simulate_policy` | yes (3.2.0) | `simulatePolicy` | `POST /api/v1/policy-simulator` |
| `explain_decision` | yes (3.2.0) | `explainDecision` | client-side; no HTTP |
| `how_to_unblock` | yes (3.2.0) | `howToUnblock` | client-side; no HTTP |
| `read_decision` | yes (3.4.0) | `readDecision` | Fail-closed guard helper. No legacy `decision`→action arm (see below). |
| `verifyExecutionGrant` | **no** | `verifyExecutionGrant` | Offline Ed25519. Python has no crypto dep; helpers `compute_scope_hash` / `receipt_digest` / `after_payload_canonical` only. |
| waiver / deploy-gate / publish-gate | **no** | **no** | Not on the TS client. Not invented here. |
| MCP client | **no** | **no** | Out of scope. |

## Installation

```bash
pip install coderifts-sdk
```

Requires Python 3.9+ and `requests`.

## Tests

Third-party test dependency is **pytest only** (measured against `tests/` imports;
`unittest` is stdlib, `requests` is the runtime dep). From a fresh venv:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

The published artifact (not the working tree) is checked by:

```bash
make packed-install
# or: bash scripts/check-packed-install.sh
```

That runs `python -m build`, installs the **wheel** into a fresh venv, imports
`from coderifts import CodeRifts` (README Quick start), then `pytest` against
the installed package.

## Quick start

```python
from coderifts import CodeRifts, CodeRiftsError

client = CodeRifts(api_key="cr_live_...")
```

### `preflight_change_set` / `analyze_change_set` / `authorize_change_set`

#### Two request modes

**Server-derived (the production path)** — the server lists the change set from the repository:

```python
result = client.authorize_change_set(
    derivation="server",
    context={"repository": "owner/repo", "base": "main", "head": "feature", "operation": "merge"},
)
```

**Caller-supplied artifacts** — you assemble the complete base→head set yourself:

```python
result = client.authorize_change_set(
    artifacts=[{"id": "api", "type": "openapi", "before": old_yaml, "after": new_yaml}],
    context={"operation": "merge"},
)
```

The two are mutually exclusive. Python cannot express that as a type-level union the way the
TypeScript SDK does, so it is a runtime guard: mixing them raises a `ValueError` that names the
rule, **before** any HTTP call. For an ATOMIC-profile grant, pass `state_nonce=` from your
executor's state-challenge alongside `include_execution_grant=True`.

**Required** keyword-only `preflight_mode='analyze'|'authorize'` (Decision Spec v2;
server returns HTTP 400 if omitted). Prefer the wrappers so the two meanings
cannot be mixed.

Branch on **`execution_action`** (proceed signal, authorize). Closed set:
`CONTINUE` | `CONTINUE_WITH_MONITORING` | `REQUEST_APPROVAL` | `STOP`.
Unrecognised → treat as STOP. Use **`decision`** for the explanation label.
Analyze is informational (risk-only), not permission.

v2 fields on authorize: `receipt_kind` (`operation_authorization` | `NONE`),
`chain_receipt`, optional `execution_grant`, `blast_radius` (counts, not a score).

```python
before = open("openapi-before.json").read()
after = open("openapi-after.json").read()
artifacts = [
    {
        "id": "spec-main",
        "type": "openapi",
        "before": before,
        "after": after,
    }
]

# Risk-only
risk = client.analyze_change_set(artifacts=artifacts)
print(risk.analysis_outcome, risk.receipt_kind)  # receipt_kind == "NONE"

# Operation-bound authorize (requires context.operation; may mint a receipt)
result = client.authorize_change_set(
    artifacts=artifacts,
    context={
        "operation": "merge",
        "environment": "staging",
    },
    include_execution_grant=True,  # opt-in; cr.exec.v1 unless grant_version says otherwise
)

# The same call asking for a cr.exec.v2 grant, bound to a stated identity.
# Omitting `execution_grant_binding` still issues a v2 grant — bound to the
# server's defaults (executor_id "local", adapter_id "fs", tenant_id "default",
# a target_uri derived from the repository and head sha) rather than to an
# identity you named.
result = client.authorize_change_set(
    artifacts=artifacts,
    context={"operation": "merge", "environment": "staging"},
    include_execution_grant=True,
    grant_version="v2",
    execution_grant_binding={
        "executor_id": "svc-deployer",
        "adapter_id": "postgres",
        "target_uri": "postgres://prod/articles",
        "tenant_id": "acme",
        "expected_state_token": 'W/"etag-9"',
    },
)
print(result.receipt_kind)   # "execution_grant_v2" when a v2 grant was minted

print(result.execution_action)   # e.g. "CONTINUE"
print(result.decision)           # e.g. "ALLOW"
print(result.receipt_kind)       # "operation_authorization" | "execution_grant_v2" | "NONE"
print(result.breaking_changes)   # integer count, not a list
print(getattr(result, "execution_grant", None))  # grant token when opted in
print(getattr(result, "blast_radius", None))

token = result.chain_receipt
decision_id = result.decision_result.decision_id
```

### `verify_receipt`

A **valid signature is not authorization.** `currently_authorized` is
`True` / `False` / `None` — `None` means authorization was not evaluated.
Expiry uses 30s clock-skew leeway (`CLOCK_SKEW_LEEWAY_MS`); 0s for destructive
operations in production when the intended context declares them. The SDK does
not compare expiry locally — the server does.

This is a **REST** verify. Offline grant verification is TS/app/`receipt-verifier`.

```python
# Cryptographic check only
check = client.verify_receipt(token=token)
print(check.valid, check.status)
print(check.currently_authorized)  # often None without intent context

# With intent + the body-bound decision envelope for full authorization
authz = client.verify_receipt(
    token=token,
    operation="merge",
    environment="staging",
    target_id=result.decision_result.artifact_digest,
    fingerprint=result.verdict_fingerprint,
    decision_result=result.decision_result.to_dict(),
)
print(authz.currently_authorized)  # True / False once evaluable
print(getattr(authz, "authz_status", None))
```

Grant helpers (no Ed25519):

```python
from coderifts import compute_scope_hash, receipt_digest

print(receipt_digest(token))
print(compute_scope_hash("merge", "sha256:tgt", after))
```

### `get_decision_details`

Look up a stored decision by **`decision_id`** or **`fingerprint`**.

```python
stored = client.get_decision_details(decision_id=decision_id)
print(stored.execution_action)
print(stored.decision)
print(stored.meta.source)
```

### Other REST methods (TS parity)

```python
client.diff(before=before, after=after)
client.score_mcp(manifest={"tools": []})
client.get_ledger(repo="acme/api", from_="2026-01-01", limit=20)
client.simulate_policy(policy_yaml="rules: []", old_spec=before, new_spec=after)
```

## Reading a decision (start here)

`read_decision(payload)` is the one correct entry point for turning any
CodeRifts response into a go / no-go. It is fail-closed and it never lets
`decision` drive control flow.

```python
from coderifts import CodeRifts, read_decision

client = CodeRifts(api_key="cr_live_...")
response = client.authorize_change_set(artifacts=artifacts, context={"operation": "deploy"})

read = read_decision(response)
if read.execution_action == "CONTINUE":
    deploy()
elif read.execution_action == "CONTINUE_WITH_MONITORING":
    deploy_with_monitoring()
else:  # REQUEST_APPROVAL, STOP, or anything unreadable
    halt(read.decision, read.reason)
```

**`execution_action` is the control input.** `decision` (`ALLOW` / `WARN` /
`REQUIRE_APPROVAL` / `BLOCK`) is the governance *explanation* label: log it,
print it, put it in a PR comment — never branch on it. That is the agent-host
rule `not_for_control_flow_use_execution_action`, and `@coderifts/conformance`
ships a deliberately-wrong `branch-on-decision` subject that the suite fails.

Resolution order, and what falls closed:

| Input | Result |
|-------|--------|
| `decision_result.execution_action` (envelope) | that action, plus `envelope` / `receipt` |
| top-level `execution_action` | that action |
| unknown / misspelled / lowercase action | `STOP`, `reason="UNREADABLE_DECISION"` |
| `{}`, `None`, a string, an error body | `STOP`, `reason="UNREADABLE_DECISION"` |
| `decision` only, with no execution action | `STOP`, `reason="UNREADABLE_DECISION"` |
| an **analyze** response | `STOP` — analyze is informational, not permission |

`read_decision` never raises, so a guard may call it on any value.

**What it does not do: it does not verify a receipt.** A returned `receipt` is
transported, not validated — nothing here checks a signature, a chain link or
an expiry. The Python SDK has no crypto dependency; use the app or the
TypeScript kernel for offline Ed25519 verification.

### `explain_decision` / `how_to_unblock` are prose, not gates

Both render human-readable copy. Neither is a permission check — always gate on
`read_decision`. Their control input is `execution_action`, passed either as a
full payload (preferred) or as the scalar:

```python
client.explain_decision(omega_api=0.62, decision="BLOCK", response=response).summary
client.how_to_unblock(decision="BLOCK", breaking_changes=bcs, response=response).actions
```

Given an unreadable or absent execution action they say the action is
unrecognised and must be treated as STOP. `explain_decision` never reports a
change as "safe to proceed", and `how_to_unblock` never says "no unblock
needed" — that wording is reserved for a readable `CONTINUE` /
`CONTINUE_WITH_MONITORING`.

## Error handling

```python
from coderifts import CodeRifts, ApiError, AuthError, RateLimitError, CodeRiftsError

try:
    client.authorize_change_set(artifacts=[...], context={"operation": "merge"})
except AuthError as e:
    print("auth", e.message)
except RateLimitError as e:
    print("rate limit", e.message)
except ApiError as e:
    print(e.status_code, e.message)
except CodeRiftsError as e:
    print(e.code, e.message)
```

## Response access

Return values are thin wrappers around the JSON object:

```python
result.decision                 # attribute
result["decision"]              # item
"decision" in result            # membership
result.to_dict()                # full dict
result.decision_result.decision_id  # nested dicts wrap too
```

## License

MIT
