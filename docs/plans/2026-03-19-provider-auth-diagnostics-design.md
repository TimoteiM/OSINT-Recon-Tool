# Provider Auth Diagnostics Design

**Date:** 2026-03-19

## Goal

Improve the live provider integrations so they distinguish invalid credentials, valid credentials without access, unsupported credential shape, and provider-side failures for HIBP, Hunter, Censys, and ProjectDiscovery.

## Root Causes

### HIBP

The app still mixes an older authenticated path with an outdated `unifiedsearch` check. HIBP v3 domain search is restricted to domains already verified in the domain-search dashboard. The current implementation does not distinguish:

- missing or invalid API key
- valid key but domain not verified/subscribed
- endpoint or subscription restrictions

### Hunter

The app reads only one key path in practice and treats any `401` as generic failure. The user has both `Hunter_API_KEY` and `HunterIO_API_KEY`, so the runtime should make a deterministic attempt order and report exactly what happened.

### Censys

The current implementation calls the legacy search endpoint with a bearer token, but the legacy search docs require HTTP basic auth with API ID and secret. A single-token value should not be silently treated as valid for the legacy endpoint.

### ProjectDiscovery

The current implementation records only the HTTP status. For `500` responses, the app should preserve the provider response details so the operator can tell whether the issue is transient or a bad request.

## Design Decisions

### 1. Body-aware provider diagnostics

Add small helpers that inspect response body JSON/text and convert provider responses into clearer notes. The UI already renders provider notes, so this gives the user much better operator feedback without needing a UI redesign.

### 2. HIBP should validate access before searching a domain

Use `GET /api/v3/subscribeddomains` first:

- `401`: invalid or missing key
- `403`: authenticated but access/user-agent problem
- `200` + domain absent: key is valid, but the target domain is not verified/subscribed

Only if the domain is present should the app call `breacheddomain/{domain}`. This removes the misleading generic auth note and replaces it with a precise access explanation.

### 3. Hunter should try configured keys deterministically

Use authenticated domain search with:

1. `Hunter_API_KEY`
2. `HunterIO_API_KEY`

If the first returns `401` and the second exists, retry once with the second key. Record which class of failure occurred:

- both keys rejected
- no emails found
- rate limit / quota style response

### 4. Censys should require the right credential shape

The current implementation is against the legacy search endpoint, so it should support `Censys_API_KEY` only when it contains a legacy API ID and secret pair in a parseable format such as `id:secret`. If a single token is configured, the provider should explain that the current integration expects legacy `API_ID:API_SECRET` credentials for the endpoint in use.

This is better than pretending the token is valid and returning a bare `401`.

### 5. ProjectDiscovery should surface response details

On non-200 responses, include a concise body-derived note when available, especially for `500` responses, so the user can distinguish upstream service issues from local auth issues.

## Testing Strategy

Follow TDD for these cases:

- HIBP invalid key vs verified-domain access vs domain-not-subscribed
- Hunter key fallback and dual-key rejection
- Censys credential-shape validation and legacy auth format
- ProjectDiscovery body-aware diagnostics

Then rerun Python tests, Node tests, typecheck, build, and live API smoke tests.
