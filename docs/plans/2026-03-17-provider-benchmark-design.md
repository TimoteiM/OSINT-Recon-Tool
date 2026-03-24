# Provider Benchmark Design

**Goal:** Evaluate all currently selectable OSINT providers across a representative 50-domain sample and produce an explicit keep/conditional/drop recommendation for each provider.

**Problem**

The application now exposes many selectable providers, but their real value varies widely. Some providers are strong and consistently productive, some are blocked by auth or stale public endpoints, and some only contribute narrow enrichment. A structured benchmark is needed before deciding which providers should stay in the shortlist.

**Approved Direction**

- Use a representative 50-domain public sample chosen by the evaluator.
- Run the benchmark directly through `osint_engine.py`, not through the browser or Node API.
- Include all currently selectable providers, including weak or failing ones, so the final report can explicitly recommend dropping them where appropriate.
- Capture both positive findings and failure modes.

**Sample Design**

The 50 domains should cover a mix of:
- large technology vendors
- finance and payments
- retail and e-commerce
- telecom and infrastructure
- travel and hospitality
- healthcare and pharma
- manufacturing and industrial
- media and public-sector-adjacent organizations

The sample does not need to reflect a single client environment. It should be broad enough to expose which providers generalize well.

**Metrics**

For each provider, collect:
- number of domains with any findings
- total findings by evidence type
- dominant evidence types
- common failure modes such as `401`, `403`, stale HTML, or empty results
- recommendation:
  - `Keep`
  - `Conditional`
  - `Drop`

**Decision Logic**

- `Keep`: strong signal, broad coverage, stable behavior, or essential baseline value
- `Conditional`: useful but narrow, inconsistent, or dependent on auth / environment
- `Drop`: stale, blocked, empty, or low-value relative to maintenance cost

**Output**

The final report should contain:
- the 50 tested domains
- provider-by-provider comparison
- notable failure patterns
- shortlist recommendation for the OSINT repository
- a clear distinction between:
  - implemented and valuable
  - implemented but weak
  - implemented but blocked by auth or broken public access
