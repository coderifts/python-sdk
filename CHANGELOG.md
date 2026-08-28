# Changelog

All notable changes to `coderifts-sdk` are documented here.

## [3.6.0]

Additive. `preflight_change_set` / `analyze_change_set` / `authorize_change_set`
accept a per-request `scm_token` kwarg, sent only as `X-Coderifts-Scm-Token`.
Never stored on the client, never placed in the JSON body, never present in
thrown error text. `context.platform` is `github` | `gitlab` | `bitbucket`.
Server-derivation error text is platform-neutral (SCM provider, not GitHub App).

## [3.5.0]

**BREAKING, and deliberately so.** `preflight_check().safe` changes from
fail-open to fail-closed. This is the last fail-open in the SDK.

### The defect

`preflight_check` did this:

```python
decision = raw.get("decision") or "ALLOW"        # an omitted field became ALLOW
body["safe"] = decision in ("ALLOW", "WARN")
```

A server that returned no `decision` produced `safe=True`. Callers gate on this
(`if res.safe: deploy()`), so a silent server manufactured a permission. Unlike
the advisory helpers, which produced misleading *prose*, this produced a
permission-shaped boolean in the wrong direction.

### Why breaking rather than deprecate-and-remove

Peter's call, and the reasoning is worth recording:

1. **No evidence of an external consumer gating on `safe`.** Telemetry only
   started yesterday, so a deprecation window would be a guess dressed as
   caution.
2. **This release closes a class, not a case.** Today's work removed the
   fail-open class across both SDKs. Leaving one documented exception recreates
   the "almost fixed" state that two audits already found.
3. **The failure direction is asymmetric.** A halted pipeline is repairable in
   minutes. A silently-passed deploy is not. When the two error costs are that
   unequal, the default belongs on the recoverable side.

### Changed

- **`safe` is now granted, not merely un-refused.** It is derived from
  `read_decision` and is `True` only when the response carried an explicit
  `CONTINUE`. Absent, unknown, unrecognised or unreadable input yields `False`.
- **A legacy `decision`-only response no longer grants `safe`.** New exported
  predicate `has_explicit_execution_action` draws the line between *reading* a
  decision and *granting* a permission, and keeps `safe` byte-identical to the
  TypeScript SDK.
- **The fabricated `decision` local is gone.** `decision` is now passed through
  exactly as the server sent it, so it is absent from the response when the
  server omitted it (it was previously always present, because it was invented).
- No new vocabulary: the closed `EXECUTION_ACTIONS` set and
  `UNREADABLE_DECISION` from 3.4.0 are reused unchanged.

### Migration

Read the decision via `read_decision` and branch on `execution_action`. `safe`
now means "we verified it is safe", not "we did not see a reason it is not" — if
you gated on `safe`, a server that omits the field will now stop you instead of
waving you through.

```python
read = read_decision(res)
if read.execution_action == "CONTINUE":
    deploy()
```

Parity: identical semantics and failure direction to `@coderifts/sdk` 3.9.0; the
`safe` parity table is duplicated verbatim in both test suites.

### Note on 3.4.0

3.4.0 shipped `read_decision` (the fail-closed reader this release builds on) but
was never given a CHANGELOG entry. Recorded here so the gap between 3.3.0 and
3.5.0 is not mistaken for a missing release.

## [3.3.0]

Audit P1-2 — server-derivation and the ATOMIC-grant nonce are now reachable from the SDK.
Additive: existing caller-artifacts code is unchanged.

### Added
- **`derivation="server"` mode** on `preflight_change_set` / `analyze_change_set` /
  `authorize_change_set`. `artifacts` is now optional; supply either it or `derivation`.
- **`state_nonce=` keyword** — the ATOMIC-profile nonce is a REQUEST INPUT, not a server echo.
  Obtain it from your executor's state-challenge; with `include_execution_grant` the server
  copies it into the signed grant. Absent => BEARER grant.
- **Runtime mode guard** raising a `ValueError` that NAMES the broken rule. Python cannot express
  the two modes as a type-level union the way the TypeScript SDK does
  (`CallerArtifactsRequest | ServerDerivedRequest`), so the rule is enforced at runtime and
  mirrored in the TypedDicts and docstrings. Misuse is refused BEFORE any HTTP call.
- **Response types** `DerivationEnvelope`, `AuthorityEnvelope`, and `COMPLETENESS_MODES`
  (including `SERVER_DERIVED`).

### Notes
- The server remains the authority. The guard fails fast with a readable message; it does not
  duplicate policy. Every condition it raises on is one the API already rejects.

## [3.2.0]

ID75 Python parity with `@coderifts/sdk` 3.3.0 REST surface. Minor bump (new
public methods). **Not published** — PyPI remains Peter's manual flow
(PyPI currently 1.0.1; this repo's version line is 3.x).

### Added
- REST: ``preflight_check``, ``diff``, ``score_mcp``, ``get_ledger``,
  ``simulate_policy`` (same endpoints as the TypeScript client; ``from_`` →
  query ``from``).
- Client-side (no HTTP): ``explain_decision``, ``how_to_unblock``.
- TypedDicts: ``AuthorizeChangeSetResponse`` (``execution_action``,
  ``receipt_kind``, ``execution_grant``, ``blast_radius``), ``BlastRadius``,
  closed ``ExecutionAction`` / ``Decision`` / ``AuthorizeReceiptKind``.
- ``preflight_change_set`` forwards ``previous_receipt`` and ``idempotency_key``.

### Not in this package (intentional)
- Offline Ed25519 ``verifyExecutionGrant`` (no crypto dep).
- ``readDecision`` / tool-table (TS + agent-guard).

## [3.1.0]

Additive — optional `base` / `head` on the documented intended-context contract
(parity with the REST Action / TS SDK / MCP schemas). Existing callers unchanged.

### Added
- **`PreflightChangeSetContext`** — typed context contract (`TypedDict`, all
  fields optional) including ``base`` / ``head`` (PR/commit SHAs).
- **`verify_receipt(..., base=None, head=None)`** — intended source SHAs
  forwarded on the wire; the server signed-wins against the envelope.

## [3.0.0]

**Breaking** — Decision Spec v2 alignment. The live server requires top-level
`preflight_mode` on `POST /api/v1/preflight` (HTTP 400 if omitted). SDK 2.0.0
did not send it, so every `preflight_change_set` call 400ed against the current
API (Python half of ID804 P0).

### Breaking
- **`preflight_change_set(..., *, preflight_mode, context=None)`** — `preflight_mode`
  is a **required keyword-only** argument (`'analyze' | 'authorize'`). Positional
  second-arg `context` is no longer valid. Callers must pass
  `preflight_mode=` (or use the wrappers below). Top-level on the JSON body —
  not nested under `context`.

### Added
- **`analyze_change_set(artifacts, context=None)`** — sets `preflight_mode='analyze'`
  (informational risk only; not permission).
- **`authorize_change_set(artifacts, context=None)`** — sets `preflight_mode='authorize'`.
  Server requires non-empty `context.operation` (HTTP 400 otherwise).
- Fast fail: invalid `preflight_mode` raises `ValueError` before the HTTP call.
