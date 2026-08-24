# Changelog

All notable changes to `coderifts-sdk` are documented here.

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
