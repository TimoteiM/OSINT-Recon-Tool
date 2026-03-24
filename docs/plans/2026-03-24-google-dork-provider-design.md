# Google Dork Provider Design

## Goal

Replace the old generic `google` provider with a new `GoogleDorkProvider` that performs bounded, API-based search intelligence using the Brave Search API and feeds normalized findings into the existing provider pipeline.

## Constraints

- Do not scrape Google directly.
- Use Brave Search API for query execution.
- Keep the implementation modular and production-ready.
- Fit into the existing Python-based provider pipeline.
- Preserve compatibility with the app's provider-result model and aggregated analysis structure.

## Recommended Approach

Implement the provider in Python within the existing engine path. The main provider logic should live in a dedicated helper module, then be called from `osint_engine.py` like the rest of the recon providers.

This keeps the integration consistent with the existing architecture:

- provider selection still flows through `OSINT_SELECTED_SOURCES`
- search-time normalization still happens in Python
- the frontend continues to consume provider results through the same response shape

## Provider Shape

Create a Python module exposing:

- `generate_dorks(domain: str, mode: str = "light") -> dict[str, list[str]]`
- `search_dork(query: str, api_key: str) -> list[dict[str, str]]`
- `GoogleDorkProvider`

The provider should support two modes:

- `light`
  - high-signal dorks only
  - intended for normal interactive recon runs
- `full`
  - larger bounded dork set
  - intended for deeper enrichment

## Dork Categories

The dork generator should return categorized query lists for:

- `subdomains`
- `emails`
- `social`
- `sensitive`
- `admin_panels`

The generator should be table-driven so new categories or queries can be added without rewriting provider logic.

## Query Execution

`search_dork()` should call Brave Search API and parse only the fields the app needs:

- `title`
- `url`
- `snippet`

It should handle:

- missing API key
- non-200 API responses
- timeouts
- rate limiting

Failures should not crash the whole provider. Per-query failures should become provider notes, while partial findings remain usable.

## Normalization

The provider should normalize every result into:

```python
{
    "source": "google_dork",
    "category": str,
    "query": str,
    "url": str,
    "title": str,
    "snippet": str,
}
```

These findings should be suitable for:

- `analysis.threat_intelligence.findings`
- `provider_results.google_dorks.mentions`

Email extraction should also populate the provider's `emails` list when the result text contains matching target-domain addresses.

## Integration

Provider catalog changes:

- remove old `google`
- add `google_dorks`

Selection compatibility:

- old `google` selections should be aliased to `google_dorks` in the provider-sanitization path so stale requests do not break

Engine integration:

- instantiate the provider only when `google_dorks` is selected
- append normalized findings to `analysis.threat_intelligence.findings`
- also write bounded provider evidence into the existing app-friendly result buckets such as `mentions` and `emails`

## Error Handling

The provider should degrade gracefully:

- missing Brave API key -> mark provider skipped with a clear note
- blocked/rate-limited query -> add provider note and continue
- timeout on one query -> preserve partial results from completed queries

The provider should only become an error if no meaningful execution path remains and the failure is provider-wide.

## Testing Strategy

Tests should cover:

- provider catalog replacement (`google` out, `google_dorks` in)
- legacy selection aliasing
- dork generation in `light` and `full` modes
- Brave response parsing
- duplicate URL suppression
- partial success when one query fails
- normalized findings appended to `analysis.threat_intelligence.findings`

## Non-Goals

- Do not build async execution in this iteration.
- Do not redesign the frontend around a new findings UI.
- Do not perform unrestricted Google-style search scraping.
