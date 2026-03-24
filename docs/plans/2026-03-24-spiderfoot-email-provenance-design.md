# SpiderFoot Email Provenance Design

## Goal

Add provenance tracking for SpiderFoot-discovered emails so the app can tell which SpiderFoot module found each email, whether that module is API-backed, and which event/source row produced it, without changing the existing `emails` behavior.

## Approach

Keep the current `emails: string[]` data path intact and introduce a parallel metadata collection named `email_sources`. This avoids breaking the existing dashboard, scoring, merge behavior, and provider result rendering while still preserving provenance for new scans.

## Data Model

- `provider_results.spiderfoot.email_sources`
- `provider_results.spiderfoot_deep.email_sources`
- `identities.email_sources`

Each record should include:

- `email`
- `module`
- `module_type`
- `event_type`
- `source`
- `api_backed`

`module_type` is a lightweight app-level label such as `api`, `public`, or `unknown`. `api_backed` is the boolean used for quick UI explanation and filtering.

## Backend Behavior

When SpiderFoot returns an `EMAILADDR` or `EMAILADDR_GENERIC` event:

- continue storing the normalized email in `provider_result.emails`
- also store a normalized provenance record in `provider_result.email_sources`
- deduplicate provenance by a stable key based on email, module, event type, and source

Module classification should be derived from the SpiderFoot module name in the event row:

- `sfp_hunter`, `sfp_haveibeenpwned`, `sfp_dehashed` => API-backed
- `sfp_skymem`, `sfp_emailformat` => public/no-auth
- everything else => unknown

## Frontend Behavior

The Identities tab should keep showing the existing email list. If provenance is present, each email can render a small secondary line showing the discovering module and whether it was API-backed or public. Missing provenance should not affect display.

## Compatibility

- Existing scans and cached reports remain valid because `emails` stays unchanged.
- New provenance fields are optional and additive.
- Older reports simply show emails without provenance.

## Testing

- prove `EMAILADDR` still populates `emails`
- prove `EMAILADDR_GENERIC` still populates `emails`
- prove provenance records are captured for both
- prove the top-level SpiderFoot partial report exposes `identities.email_sources`
- prove UI merge logic does not lose email strings when provenance exists
