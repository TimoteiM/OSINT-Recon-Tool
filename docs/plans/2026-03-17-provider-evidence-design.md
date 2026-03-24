# Provider Evidence Design

**Goal:** After a scan completes, show the exact findings gathered by each selected provider in a dedicated results view, with duplicates allowed under each provider.

**Problem**

The current application merges all findings into domain-wide result sections such as DNS, identities, and technologies. That is useful for a final analyst summary, but it does not show which provider actually contributed each artifact. For provider evaluation and shortlist decisions, the operator needs provider-by-provider evidence with exact gathered details.

**Approved UX Direction**

- Keep the current merged results tabs unchanged.
- Add a new `Providers` tab to the result area.
- Show one card per selected provider.
- Each provider card shows the exact details that provider gathered.
- Duplicates are allowed and should remain visible under each provider.

**Data Model**

Add a new top-level result field:

```json
{
  "provider_results": {
    "rocketreach": {
      "status": "ok",
      "notes": [],
      "emails": ["alice@example.com", "carol@example.com"],
      "social_profiles": [],
      "subdomains": [],
      "repos": [],
      "breach_hints": []
    }
  }
}
```

Each provider entry should contain:
- `status`: `ok | skipped | error`
- `notes`: string array
- exact result arrays by evidence type
- optional `error` string

**Implementation Scope**

First pass should cover providers already integrated in the engine, with exact findings where we already have access to them:
- `direct_dns`
- `crtsh`
- `whois`
- `ssl_inspection`
- `ipwhois`
- `port_scan`
- `tech_fingerprint`
- `duckduckgo`
- `bing`
- `wikidata`
- `theharvester`
- `recon_ng`
- `rocketreach`
- `hunter`
- `phonebook_cz`
- `github_code`
- `github_repos`
- `hibp`
- `dehashed`

The provider results should be additive and not replace the existing merged report.

**Frontend**

Add a `Providers` tab in the dashboard. Each card should show:
- provider label
- status badge
- notes or error
- grouped findings such as:
  - emails
  - subdomains
  - social profiles
  - repos
  - breach hints
  - DNS/WHOIS/SSL/tech summaries when applicable

**Testing**

- Add Python tests verifying provider-specific results are returned separately.
- Add TypeScript tests for the result contract where practical.
- Verify duplicates remain visible across different provider cards.
