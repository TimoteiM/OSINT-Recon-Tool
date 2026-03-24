# Sherlock Social Attribution Design

**Date:** 2026-03-20

## Goal

Make social-profile results attributable in the UI and integrate Sherlock as a selectable provider for brand-handle discovery plus possible impersonation detection.

## Current Problems

- The `Identities` panel shows merged social profiles without telling the operator which strategy found them.
- Existing slug/probe-based social discovery is not exposed as a visible provider, so the `Providers` tab can look empty while `Identities` still shows social findings.
- The app has no dedicated impersonation view for suspicious brand-like social handles.
- Sherlock is not installed or integrated in the current workspace.

## Design

### 1. Add explicit social attribution

- Keep the current merged `Social Media Presence` section for likely legitimate profiles.
- Include the discovery `source` with each social profile so the operator can tell whether it came from:
  - `social_probe`
  - `wikidata`
  - `duckduckgo`
  - `brave`
  - homepage extraction if applicable in the future

### 2. Introduce a visible internal provider for slug probing

- Add a visible provider `social_probe` to the provider catalog.
- Record current slug/probe-discovered social profiles under `provider_results.social_probe.social_profiles`.
- Keep it categorized under `Social Presence` and mark it as active/internal.

### 3. Add Sherlock as a selectable provider

- Install Sherlock into the local Python environment.
- Add `sherlock` to the provider catalog as a selectable `Social Presence` provider.
- Run Sherlock against:
  - exact brand-handle candidates derived from company/domain
  - a limited set of near-match suspicious candidates for impersonation detection

### 4. Separate legitimate profiles from impersonation candidates

- Keep legitimate profiles in the existing `Social Media Presence` section.
- Add a new `Possible Impersonation` section under `Identities`.
- Sherlock contributes:
  - legitimate-looking discovered handles
  - suspicious near-match handles with a reason such as:
    - separator variation
    - extra suffix/prefix
    - regional suffix
    - support/help/careers variation

### 5. Preserve provider detail in the Providers tab

- `social_probe` provider card should show the legitimate profiles it found.
- `sherlock` provider card should show:
  - confirmed social hits
  - suspicious impersonation candidates
  - notes when Sherlock is not installed or returns no matches

## Testing

Use TDD to cover:

- source labels in merged social profiles
- `social_probe` provider attribution
- Sherlock execution/parsing via mocked CLI output
- impersonation result separation
- frontend rendering of `Possible Impersonation`
