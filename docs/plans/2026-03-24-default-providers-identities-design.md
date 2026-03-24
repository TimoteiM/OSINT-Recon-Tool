# Default Providers And Identities Enrichment Design

## Summary

The app should start with every `selectable: true` provider enabled by default so the operator can run a near-full scan without manually checking boxes during the provider testing phase. Long-running providers such as `spiderfoot` and `spiderfoot_deep` should continue to behave as progressive/background sources so the initial report renders quickly and then enriches in real time.

At the same time, the Identities tab should become a canonical, deduplicated view. Different providers may discover the same email address, profile URL, or impersonation target, but the UI should present a single enriched item rather than repeated cards. Provenance should remain visible where available, but duplicates should collapse into one best entry.

## Approach

### Provider defaults

Change the default-selection helper to return all selectable provider IDs instead of only the current subset marked `defaultSelected`. This keeps the provider catalog intact while making the testing workflow the default behavior.

### Long-running providers

Keep the existing background/live-progress flow for `spiderfoot` and `spiderfoot_deep`. No new long-running orchestration will be added unless the provider already supports progressive updates. This keeps the behavior stable while still making the default scan broader.

### Identities enrichment and dedupe

The Identities tab will normalize and deduplicate:

- Emails by lowercased address
- Email provenance by lowercased address plus strongest available metadata
- Social profiles by normalized platform plus normalized URL
- Impersonation candidates by normalized clickable URL, keeping the cleanest candidate label/reason

This dedupe should happen in a shared client-side normalization layer used by the Identities tab and any live SpiderFoot merge path, so the view remains stable whether data arrives all at once or incrementally.

## Data handling

### Emails

The canonical email list remains `identities.emails`, but the UI should render a unique set only. When multiple provenance entries exist for the same email, prefer the richer record:

1. Has module/source metadata
2. Has `api_backed`
3. Has event type

### Social profiles

The existing `social_profiles` object already reduces some duplication, but additional normalization is needed when different providers emit equivalent URLs with small variations like trailing slashes or host casing. The UI should render a single profile card per normalized platform/URL pair.

### Impersonation candidates

Reuse the existing impersonation cleanup helper and extend the Identities pipeline so duplicate candidate records do not survive when multiple providers or live updates emit the same final profile URL.

## Error handling and compatibility

- Default selection should include API-key-dependent providers even when keys are missing.
- Missing keys should continue to show as skipped/limited provider results, not hard failures.
- Live SpiderFoot updates should merge into the deduplicated identities view without causing repeated entries.

## Testing

Add tests for:

- all selectable providers becoming default-selected
- request serialization staying compatible with the existing provider request path
- identities deduping emails with duplicate provenance
- identities deduping social profiles and impersonation candidates during live merges

