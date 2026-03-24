# Free Provider Wave Design

## Scope

Add a first wave of newly selectable providers that can be implemented with low friction in the current OSINT engine:
- `brave`
- `bufferoverun`
- `hackertarget`
- `rapiddns`
- `threatminer`
- `urlscan`

Also add `BRAVE_SEARCH_API_KEY` to local configuration so Brave Search can be enabled immediately on this machine.

## Product Shape

The existing provider checklist already exposes candidate providers and the `Providers` results tab already shows provider-scoped evidence. This wave should turn the selected providers above into real backend integrations so the operator can:
- select them before a scan
- run recon with the chosen subset
- inspect exact evidence returned by each provider afterward

The app should continue to preserve duplicates across providers because evaluation is the goal.

## Architecture

The Python engine remains the single orchestration point. New providers will plug into the existing phases instead of creating a separate pipeline:
- Brave will augment website discovery, search-based social fallback, and passive email dorking.
- BufferOverrun, RapidDNS, Hackertarget, ThreatMiner, and Urlscan will augment DNS/subdomain discovery.
- Each provider will write exact findings into `provider_results`.

This keeps the merged analyst view stable while the `Providers` tab becomes richer and more useful for provider evaluation.

## Provider Roles

### Brave Search

Use the official API when `BRAVE_SEARCH_API_KEY` is present and the provider is selected.

Contribution points:
- website discovery fallback in `find_website()`
- social discovery fallback in `discover_social_profiles()`
- passive email dorking in `run_emailharvest_passive()`

Expected evidence:
- websites
- social profile URLs
- emails found through result snippets or result pages

Failure behavior:
- if the key is missing, mark `brave` as skipped with a clear note

### BufferOverrun

Use the public `tls.bufferover.run` endpoint to enumerate passive subdomains from certificate data.

Expected evidence:
- subdomains

### RapidDNS

Use the public RapidDNS HTML results page and extract matching subdomains for the target domain.

Expected evidence:
- subdomains

### Hackertarget

Use the public host-search endpoint for domain-linked hosts.

Expected evidence:
- subdomains or related hosts

### ThreatMiner

Use the public API for passive domain relations.

Expected evidence:
- subdomains

### Urlscan

Use the public search endpoint for results linked to the target domain.

Expected evidence:
- subdomains
- URLs or hosting hints where useful

## Provider Catalog Changes

Update the shared provider catalog so these providers become selectable:
- `brave`: `needs_api_key`, selectable `true`
- `bufferoverun`: active or limited depending on the final public behavior observed, selectable `true`
- `hackertarget`: active/limited, selectable `true`
- `rapiddns`: active/limited, selectable `true`
- `threatminer`: active/limited, selectable `true`
- `urlscan`: active/limited, selectable `true`

They should remain off by default for now, except possibly `rapiddns` and `urlscan` if they prove consistently useful during tests.

## Data Flow

1. Frontend sends `sources` as it already does.
2. Node runner passes the selected source list and env through to Python.
3. Python checks `source_enabled(provider_id)` before hitting a provider.
4. Provider-specific evidence is written into `provider_results`.
5. Existing merged sections continue to use aggregated data.
6. The `Providers` tab renders exact provider evidence without deduping across providers.

## Error Handling

- Missing Brave key: mark provider skipped, not error.
- Provider request failure: log internally, keep scan successful, and keep partial results.
- Parse issues from fragile public HTML: fail softly and record no findings.

## Testing

Add focused tests first for:
- Brave key gating
- Brave website discovery contribution
- new passive subdomain provider extraction helpers
- provider catalog selectability updates
- provider result attribution for each new provider

After code changes:
- run Python unit tests
- run Node tests
- run typecheck and build
- run one live scan and confirm the new providers appear in `provider_results`
