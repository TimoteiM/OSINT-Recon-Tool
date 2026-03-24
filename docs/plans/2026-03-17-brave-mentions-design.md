# Brave Mentions Design

**Goal:** Extend Brave Search from email-only evidence capture into a broader mention source that records raw domain mentions, including forums, news, documents, jobs, and other web hits.

**Problem**

The current Brave integration is narrower than the provider label suggests. We already use Brave for website discovery, social fallback, and email extraction, but in the provider evidence view we usually only persist Brave emails. That makes the Brave card look artificially weak even when Brave returned useful search hits about the target domain.

For provider evaluation, the operator needs to inspect the exact Brave evidence, not just the structured emails extracted from those hits.

**Approved UX Direction**

- Keep existing Brave email extraction.
- Add a new Brave evidence bucket for raw mentions.
- Show exact Brave hits in the `Providers` tab.
- Include forum hits, news/articles, documents, jobs, social mentions, and generic web mentions.
- Preserve duplicates when multiple Brave queries surface overlapping results.

**Data Model**

Extend provider result entries with a `mentions` array:

```json
{
  "provider_results": {
    "brave": {
      "status": "ok",
      "notes": [],
      "emails": ["info@example.com"],
      "mentions": [
        {
          "category": "forum",
          "title": "Example thread on Reddit",
          "url": "https://www.reddit.com/r/example/comments/123",
          "snippet": "Discussion mentioning example.com",
          "source_domain": "reddit.com",
          "matched_domain": "example.com",
          "query": "\"example.com\""
        }
      ]
    }
  }
}
```

Each mention should include:
- `category`
- `title`
- `url`
- `snippet`
- `source_domain`
- `matched_domain`
- `query`

**Classification**

Use lightweight classification based on source domain, URL, and hit text:
- `forum`
- `news`
- `social`
- `docs`
- `jobs`
- `web`
- `other`

This should stay heuristic and transparent rather than trying to fully normalize external content.

**Implementation Scope**

First pass should:
- capture Brave hits for domain mention queries
- keep existing Brave email extraction
- classify Brave hits into categories
- persist those hits under `provider_results["brave"]["mentions"]`
- render grouped mention sections in the frontend provider card

**Frontend**

The Brave provider card should show:
- `Emails`
- `Mentions`
- grouped mention subsections where present:
  - `Forums`
  - `News / Articles`
  - `Documents`
  - `Jobs`
  - `Social Mentions`
  - `Web Mentions`

If Brave returned hits but no emails, the card should still look useful by showing those mention sections.

**Testing**

- Add Python tests for Brave mention capture.
- Add Python tests for forum classification.
- Verify the frontend renders Brave mentions without breaking other provider cards.
