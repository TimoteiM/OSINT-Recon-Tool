# Google Provider Design

**Goal:** Add Google as a first-class selectable discovery provider that can contribute website discovery, mentions, emails, and social-profile evidence alongside Brave, DuckDuckGo, and Baidu.

**Problem**

The current application has several search-based providers, but Google is not one of them. For OSINT evaluation, the operator wants Google available as a visible, comparable provider rather than an internal fallback. That means the app must expose Google in the selection list and attribute its exact findings in the provider results view.

**Approved Direction**

- Add `google` as a selectable `Discovery` provider
- Use lightweight Google HTML scraping, not an API integration
- Record exact provider evidence:
  - website discovery wins
  - search mentions
  - email dork matches
  - social-profile matches when discovered through Google search
- Keep the integration diagnostic-first so blocked or challenge responses are visible in provider notes

**Integration Points**

- `shared/osint-providers.ts`
  - add the provider metadata

- `osint_engine.py`
  - add Google website discovery
  - add Google passive search evidence in email harvesting
  - add Google social fallback support
  - add provider attribution and diagnostic notes

- `osint_engine_test.py`
  - add tests for Google website discovery and evidence capture

- `server/provider-catalog.test.ts`
  - assert Google is selectable

**Behavior**

Google should behave similarly to the other search providers:
- selectable before a scan
- visible in the provider results after a scan
- if successful, it records exact findings
- if blocked, rate-limited, or challenged, it records explicit notes instead of silently failing

**Testing**

- failing tests first
- targeted tests for Google discovery and evidence capture
- full Python, provider catalog, typecheck, and build verification afterward
