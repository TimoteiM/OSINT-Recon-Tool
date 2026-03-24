# SpiderFoot Auth Email Enrichment Design

**Goal:** Wire authenticated SpiderFoot email and breach modules to the app's existing `.env` keys, while keeping unauthenticated email modules enabled as fallback for `spiderfoot_deep`.

## Problem

`SpiderFoot Deep` now runs broader enrichment modules, but it still does not receive API credentials for the modules that require them. That means:

- `sfp_hunter` exists in the deep module list but runs unconfigured
- `sfp_haveibeenpwned` exists in the deep module list but runs unconfigured
- `sfp_dehashed` exists in the deep module list but runs unconfigured
- fallback public modules like `sfp_skymem` and `sfp_emailformat` can run, but they are not enough to consistently surface target-domain emails

The app already has these credentials in `.env`, but the current SpiderFoot integration does not translate them into SpiderFoot module options.

## Desired Outcome

- `SpiderFoot Deep` should use authenticated email/breach modules when keys exist.
- Missing keys should not fail the scan.
- Unauthenticated fallback modules should remain enabled and continue to run best-effort.
- The lightweight `spiderfoot` provider should remain unchanged.

## Recommended Approach

Inject SpiderFoot module options at deep-scan start time.

This fits the current app architecture because `spiderfoot_deep` already has its own scan configuration in `server/spiderfoot-jobs.ts`. The app can derive a module-option map from `.env`, then apply it only for deep enrichment scans.

## Configuration Mapping

Initial env-to-module option mapping:

- `Hunter_API_KEY` or `HunterIO_API_KEY` -> `sfp_hunter.api_key`
- `HaveIBeenPwned_API_KEY` -> `sfp_haveibeenpwned.api_key`

`sfp_dehashed` is bundled, but the current repo does not expose a DeHashed API credential in `.env.example`, so it should stay in the deep module list as future-ready but remain unconfigured for now unless the environment adds a matching key later.

Unauthenticated fallback modules remain enabled:

- `sfp_skymem`
- `sfp_emailformat`

## Data Flow

1. The app loads `.env` as it already does.
2. When `spiderfoot_deep` starts, the backend builds:
   - deep scan config
   - deep module-option map from env
3. The app applies those module options to SpiderFoot before or during scan setup.
4. SpiderFoot runs authenticated modules when configured and silently falls back to unauthenticated modules when not.
5. Existing event normalization continues to feed:
   - `identities.emails`
   - `provider_results.spiderfoot_deep.breach_hints`
   - existing social/account normalization

## Error Handling

- Missing env vars should simply omit the module option from the applied config.
- A failed authenticated module should not abort the whole scan.
- If SpiderFoot rejects an option update, the backend should surface that as a provider note or job error only if it blocks scan startup.

## Testing Strategy

Use TDD around the config-building layer.

Tests should verify:

- deep scan config still enables unauthenticated fallback modules
- env values map into SpiderFoot module options correctly
- missing env values do not produce empty or invalid options
- lightweight `spiderfoot` does not get deep-only auth config

## Files Expected To Change

- `server/spiderfoot-jobs.ts`
- `server/spiderfoot-jobs.test.ts`
- `.env.example` only if we decide to document new optional SpiderFoot-specific env names

