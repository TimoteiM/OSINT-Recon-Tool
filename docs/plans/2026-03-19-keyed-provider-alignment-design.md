# Keyed Provider Alignment Design

**Date:** 2026-03-19

## Goal

Align the application with the API-keyed providers the user has already configured locally, using the exact `.env` names already present on the machine, and make the provider list reflect what is truly implemented versus catalog-only.

## Current State

- `Brave Search` is implemented and keyed, but the provider catalog and runtime need to stay aligned with the configured env naming.
- `RocketReach` is implemented through the Python SDK, but its env contract should match the local `.env`.
- `Have I Been Pwned` is only partially wired and still uses limited or outdated request flows.
- `Hunter` has partial public/API logic, but the authenticated path is not aligned with the user’s configured env names.
- `ProjectDiscovery` and `Censys` are present in the provider catalog but are not real runtime providers yet.
- `.env.example` only documents a subset of currently supported keyed providers.

## Design Decisions

### 1. Keep the existing `.env` names as the source of truth

The backend should read the exact variable names already defined in the user’s `.env` file instead of forcing a rename. This avoids local churn and keeps the contract stable for future provider keys.

### 2. Support provider-specific auth correctly

- `Brave Search` should keep using the provider’s required subscription-token header.
- `Have I Been Pwned` should use the current authenticated header pattern and include a valid `user-agent`.
- `Hunter` should use the authenticated domain-search API path with the existing Hunter key names from `.env`.
- `ProjectDiscovery Chaos` should use the configured API key for authenticated subdomain lookups.
- `Censys` should consume the existing token format from `.env` and translate it into the header/auth shape expected by the API version we implement.

### 3. Make the provider catalog truthful

Providers that are implemented and runnable should be selectable and documented as such. Providers that remain unimplemented should stay non-selectable with limits that explicitly say so.

## Implementation Outline

### Runtime auth helpers

Add small helper functions in `osint_engine.py` that:

- read the configured env names for each provider
- normalize provider-specific credentials
- expose correctly shaped headers/auth for each API call

This keeps provider wiring centralized and makes tests easy to target.

### Provider integrations

- Upgrade `HIBP` to use current authenticated requests and record exact provider evidence or failure notes.
- Upgrade `Hunter` to use the authenticated domain-search API with the configured key names.
- Implement `ProjectDiscovery` as a real subdomain provider in the DNS/subdomain collection path.
- Implement `Censys` as a real infrastructure/subdomain provider with explicit provider results.

### Provider catalog updates

Update `shared/osint-providers.ts` so:

- keyed providers that truly run are selectable
- status/auth/details/limits describe the real implementation
- `ProjectDiscovery` and `Censys` stop looking like hypothetical entries once wired

## Error Handling

Each provider should continue using the current provider-status model:

- `ok` when it runs successfully
- `skipped` when not selected or key is missing
- explicit notes for `401`, `403`, malformed responses, and empty-but-successful results

## Testing Strategy

Follow TDD:

1. Add failing tests for env-name handling and auth helpers.
2. Add failing tests for each provider integration path:
   - authenticated HIBP headers
   - authenticated Hunter query
   - ProjectDiscovery subdomain collection
   - Censys credential parsing and result recording
3. Implement the minimum code to pass.
4. Run Python tests, Node tests, typecheck, and build.
5. Smoke-test the live server with at least one keyed-provider request.
