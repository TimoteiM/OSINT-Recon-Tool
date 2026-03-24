# Google Curation And Baidu Removal Design

**Date:** 2026-03-19

## Goal

Remove `Baidu` from the provider list and runtime, improve `Google` so it captures compact, relevant domain evidence, and make `Censys` clearly communicate that an org-enabled account is required for the current Platform search integration.

## Current Problems

- `Baidu` is selectable and returns noisy raw HTML-derived evidence that takes too much space in the provider results view.
- `Google` currently behaves like a raw HTML blob scraper, so it can surface internal Google URLs or weak snippets instead of curated OSINT evidence.
- `Censys` now uses the correct Platform PAT flow, but the provider metadata does not clearly explain that a personal/free PAT without organization context cannot use the current search endpoint.

## Design

### 1. Remove Baidu completely

- Delete `baidu` from the shared provider catalog.
- Remove all `baidu` runtime logic from website discovery, passive search evidence collection, and discovery attribution.
- Remove Baidu-specific tests.

### 2. Curate Google evidence

- Keep `google` as a selectable provider.
- Replace the current “extract every URL from raw HTML” behavior with structured result extraction.
- Capture only high-signal evidence:
  - emails that match the target domain
  - important mentions tied to the input domain
  - social/forum/news/docs/jobs/web hits when available
- Limit the number of rendered Google hits per category so the provider card stays compact.
- Trim snippets and ignore internal Google result/support URLs.

### 3. Clarify Censys account requirement

- Keep `censys` selectable.
- Update provider metadata so the UI clearly reflects that the current search integration requires an org-enabled account for Platform API search.
- Preserve the runtime diagnostic note that distinguishes valid PAT usage from the missing organization context.

## Testing

Use TDD to:

- remove Baidu expectations from the catalog and engine tests
- add Google tests that prove curated extraction and compact mention capture
- verify the Censys catalog wording stays aligned with the current runtime behavior
