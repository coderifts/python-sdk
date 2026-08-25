# coderifts-sdk

Python SDK for [CodeRifts](https://coderifts.com) — API governance for AI agents.

**v3.2.0** (ID75) closes REST method parity with `@coderifts/sdk` 3.3.0.
Decision Spec v2 still requires top-level `preflight_mode` on preflight.
PyPI publishes are a separate, manual flow (do not `twine upload` from this
checkout). Offline Ed25519 verification is **not** in this package (`requests`
only) — use `@coderifts/sdk`, `coderifts-app`, or `receipt-verifier`.

## Surface vs TypeScript SDK

| Capability | Python | TypeScript 3.3.0 | Notes |
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
    include_execution_grant=True,  # opt-in cr.exec.v1 grant
)

print(result.execution_action)   # e.g. "CONTINUE"
print(result.decision)           # e.g. "ALLOW"
print(result.receipt_kind)       # "operation_authorization" | "NONE"
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
