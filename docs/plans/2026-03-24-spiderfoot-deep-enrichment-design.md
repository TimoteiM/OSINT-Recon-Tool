# SpiderFoot Deep Enrichment Design

**Goal:** Turn `SpiderFoot Deep` into a real email/leak/social enrichment mode and only surface clean, clickable profile-style identity findings in the Identities tab.

## Problem

The current `spiderfoot_deep` flow requests broader event types, but it still launches SpiderFoot with the passive use case and an empty module list. In practice that means the provider mostly repeats domain, host, and mention-style findings.

The backend also forwards noisy SpiderFoot-derived identity candidates directly into the app state. The Identities tab then renders raw strings such as usernames, affiliate-domain hints, and encoded `SFURL` fragments as if they were meaningful impersonation links.

## Desired Outcome

- `SpiderFoot Deep` should prioritize email, leak, social-profile, and account discovery over generic passive enumeration.
- `Emails` should receive SpiderFoot-discovered addresses when they match the target domain.
- `Social Media Presence` should show validated platform profiles with clickable URLs.
- `Possible Impersonation` should only show clean, clickable profile-style candidates.
- Weak or malformed SpiderFoot signals should remain internal or provider-scoped, not appear in the Identities tab.

## Approach

### 1. Separate Deep Scan Configuration

Keep the existing `spiderfoot` provider as the lighter background scan. For `spiderfoot_deep`, introduce a dedicated launch configuration in `server/spiderfoot-jobs.ts` that:

- uses a broader SpiderFoot use case than plain passive
- keeps the deep event type list focused on email, leak, account, social, and related findings
- optionally pins a curated module list when available so the scan favors enrichment modules rather than broad generic discovery

This makes `spiderfoot_deep` intentionally slower and noisier, but better aligned with the user’s goals.

### 2. Normalize SpiderFoot Identity Signals on the Backend

Treat the backend as the normalization boundary. Raw SpiderFoot events should be parsed into app-shaped data before being merged into `ReconData`.

Normalization rules:

- `EMAILADDR` events become `identities.emails` when they match the target domain.
- `SOCIAL_MEDIA` and account-style events are parsed for a real URL and normalized into:
  - `identities.social_profiles` when the URL maps cleanly to a recognized platform
  - `identities.impersonation_candidates` when the URL is clickable and profile-like but should remain a candidate
- `LEAKSITE_URL`, `LEAKSITE_CONTENT`, and compromised-email events become `provider_results.spiderfoot_deep.breach_hints`.

Weak signals must be filtered out:

- bare usernames with no URL
- affiliate-domain hints with no profile URL
- malformed or encoded `SFURL` fragments that do not parse into valid links
- unrelated generic hosts that do not map to a supported profile platform

### 3. Tighten the UI Contract

The frontend in `client/src/pages/Dashboard.tsx` should render only normalized identity findings:

- `Social Media Presence` should display supported social profiles from `identities.social_profiles`.
- `Possible Impersonation` should render only candidates that contain a valid URL and a clean display label.

The UI should no longer try to interpret raw SpiderFoot payloads. If the backend cannot normalize a candidate into a clean clickable profile, it should not appear in this section.

## Data Model Notes

The current identity shape is already close to what we need:

- `social_profiles: Record<string, { url: string; status: string; source?: string }>`
- `impersonation_candidates?: Array<{ platform?: string; username?: string; url?: string; matched_candidate?: string; reason?: string; source?: string }>`

We can keep this shape, but the backend must guarantee stronger semantics for SpiderFoot Deep:

- `social_profiles` only contains validated clickable links
- `impersonation_candidates` only contains clickable profile-style URLs with human-readable labels

## Error Handling

- If a deep scan cannot start, the app keeps the current job error behavior.
- If a specific SpiderFoot event is malformed, it should be ignored rather than surfaced as a broken identity card.
- If SpiderFoot emits no strong email/leak/social findings, the provider can still complete successfully with partial status and provider notes.

## Testing Strategy

Use TDD around the backend normalization and UI rendering boundaries.

Backend tests should cover:

- deep provider uses the new scan configuration
- valid social/account URLs populate `social_profiles`
- valid candidate profile URLs populate `impersonation_candidates`
- usernames without URLs are ignored
- malformed `SFURL` payloads are decoded or ignored correctly
- breach/leak events are preserved as hints

Frontend tests should cover:

- social profile section renders clickable links from normalized SpiderFoot results
- impersonation section excludes non-clickable/noisy candidates
- merged SpiderFoot job results update identities cleanly

## Files Expected To Change

- `server/spiderfoot-jobs.ts`
- `server/spiderfoot-jobs.test.ts`
- `client/src/pages/Dashboard.tsx`
- possibly `server/routes.ts` only if contract adjustments are needed

