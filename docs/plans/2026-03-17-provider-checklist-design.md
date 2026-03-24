# Provider Checklist Design

**Goal:** Add a frontend provider checklist that shows every OSINT/recon provider, explains what evidence each one can contribute, and lets the operator choose which currently supported providers are used for a domain recon run.

**Context**

The current application accepts only a company/domain string and runs the Python engine with a fixed set of sources. The operator cannot see which providers are available, which require API keys, what each provider contributes, or which ones are currently integrated. That makes evaluation difficult when deciding what should stay in the final OSINT repository.

**Design Summary**

1. Introduce a shared provider catalog that defines every provider shown in the frontend.
2. Mark each provider with:
   - implementation status
   - auth requirement
   - cost note
   - reliability
   - what evidence it provides
   - why it is useful
   - known limitations
3. Use that catalog to render a detailed provider checklist in the dashboard before scan submission.
4. Only allow selection of providers that are currently active or partially active in the codebase. Planned and key-gated-but-unimplemented providers remain visible but disabled.
5. Send the selected provider IDs to the backend and into the Python engine so supported sources can be turned on or off for the current investigation.
6. Record selected providers in the recon result metadata so the scan output shows which sources were enabled.

**User Experience**

- The operator sees all providers in one place.
- The operator can review what each provider returns before scanning.
- The operator can select or deselect supported providers without editing code.
- The operator can distinguish between:
  - available now
  - limited in current app
  - needs API key
  - planned / not implemented

**Frontend Layout**

- Keep the existing target entry form at the top.
- Add a new `Provider Selection` panel directly under the target input.
- Show:
  - selection summary
  - quick legend of statuses
  - scrollable provider grid
- Each provider card includes:
  - checkbox
  - provider name
  - category
  - status badge
  - evidence chips
  - auth/cost/reliability rows
  - short `Why keep it`
  - short `Known limits`

**Backend and Engine Behavior**

- Extend `POST /api/recon` to accept `sources: string[]`.
- Validate source IDs against the shared provider catalog.
- Pass the selected IDs into the Python engine using environment configuration.
- Gate supported source calls in Python based on those selected IDs.
- Keep internal fallback behavior for direct domain handling so valid domains still resolve.

**Initial Supported Toggle Scope**

The first implementation should toggle sources already present in the codebase:

- `duckduckgo`
- `bing`
- `crtsh`
- `whois`
- `ssl_inspection`
- `direct_dns`
- `ipwhois`
- `port_scan`
- `tech_fingerprint`
- `wikidata`
- `theharvester`
- `recon_ng`
- `hunter`
- `phonebook_cz`
- `github_code`
- `github_repos`
- `hibp`
- `dehashed`

Providers that are visible but not yet wired should remain disabled in the UI.

**Testing Strategy**

- Add test-first coverage for:
  - provider catalog defaults and selectable filtering
  - Node runner propagation of selected providers into the Python process environment
  - route validation of source IDs
- Verify TypeScript and production build still pass.

**Out of Scope for This Pass**

- Per-provider runtime contribution counts such as `added 3 emails`
- API-key storage UI
- New third-party integrations beyond the sources already in the codebase
