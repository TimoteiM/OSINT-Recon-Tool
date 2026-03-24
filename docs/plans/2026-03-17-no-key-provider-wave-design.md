# No-Key Provider Wave Design

**Goal:** Implement the remaining cataloged providers that do not require API keys so they can be selected and compared in the frontend benchmark workflow.

**Problem**

The provider selection UI currently shows more visible providers than working selectable providers. Several providers are listed in the catalog as public or no-key services but are still placeholders in the backend. That makes the comparison surface incomplete and weakens the user’s ability to evaluate all practical no-key options.

**Approved Scope**

Implement this wave for:
- `subdomaincenter`
- `subdomainfinderc99`
- `thc`
- `windvane`
- `baidu`
- `yahoo`

**Provider Roles**

- `subdomaincenter`, `subdomainfinderc99`, `thc`
  - passive subdomain sources
  - record exact subdomains and notes

- `baidu`, `yahoo`
  - search-engine sources
  - support website discovery, search mentions, and search-based email/social enrichment

- `windvane`
  - best-effort search/intelligence source
  - implement only if the public response is stable enough
  - otherwise expose explicit notes so it can still be compared fairly

**Data Model**

Reuse the existing provider result model:
- `status`
- `notes`
- `subdomains`
- `emails`
- `social_profiles`
- `mentions`

No new top-level response fields are needed.

**UX**

- Make all six providers selectable in the provider checklist
- Show exact evidence in the `Providers` tab
- Preserve diagnostic notes when a provider is blocked, stale, or empty

**Testing**

- Add Python tests for each integration path
- Use failing tests first
- Add catalog coverage if selectable flags change

**Benchmark Follow-up**

After implementation, rerun the provider benchmark so these six providers can be compared against the current keep/conditional/drop shortlist.
