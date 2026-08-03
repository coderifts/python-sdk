# coderifts-sdk

Python SDK for [CodeRifts](https://coderifts.com) — API governance for AI agents.

**v2.0.0** exposes only the three canonical tools (the same surface agents see by
default over MCP). Other live REST endpoints may be added later, additively.

| Method | HTTP |
|--------|------|
| `preflight_change_set` | `POST /api/v1/preflight` |
| `verify_receipt` | `POST /api/v1/verify-receipt` |
| `get_decision_details` | `POST /api/v1/decisions/lookup` |

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

### `preflight_change_set`

Branch on **`execution_action`** (proceed signal). Use **`decision`** for the
explanation label.

```python
before = open("openapi-before.json").read()
after = open("openapi-after.json").read()

result = client.preflight_change_set(
    artifacts=[
        {
            "id": "spec-main",
            "type": "openapi",
            "before": before,
            "after": after,
        }
    ],
    context={
        "operation": "merge",
        "environment": "staging",
    },
)

print(result.execution_action)   # e.g. "CONTINUE"
print(result.decision)           # e.g. "ALLOW"
print(result.risk_score)
print(result.breaking_changes)   # integer count, not a list
print(result.safe_for_agent)

# Signed receipt for later verification (when present)
token = result.chain_receipt
decision_id = result.decision_result.decision_id
```

### `verify_receipt`

A **valid signature is not authorization.** `currently_authorized` is
`True` / `False` / `None` — `None` means authorization was not evaluated.

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

### `get_decision_details`

Look up a stored decision by **`decision_id`** or **`fingerprint`**.

```python
stored = client.get_decision_details(decision_id=decision_id)
# or: stored = client.get_decision_details(fingerprint=result.verdict_fingerprint)

print(stored.execution_action)
print(stored.decision)
print(stored.meta.source)
```

## Error handling

```python
from coderifts import CodeRifts, ApiError, AuthError, RateLimitError, CodeRiftsError

try:
    client.preflight_change_set(artifacts=[...])
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
