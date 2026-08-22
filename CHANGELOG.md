# Changelog

All notable changes to `coderifts-sdk` are documented here.

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
