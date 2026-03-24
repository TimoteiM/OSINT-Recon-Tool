# Sherlock Bounded Scan and SpiderFoot Integration Design

## Context

The current Sherlock integration proves the provider model works, but it is too expensive for the live recon path. It generates several candidate usernames, runs the full Sherlock site set for each one, and treats a timeout as a provider-level error even if partial results were already found. In practice that means the UI often shows `Timed out after 90s` and no exact findings, which is not a useful analyst experience.

At the same time, SpiderFoot is a good fit for this application because it can run locally from the command line and gather several evidence types that already map well to the app's merged results and provider cards.

## Goals

- Make Sherlock fast enough to be useful in normal domain recon runs.
- Preserve partial Sherlock findings instead of erasing them behind a timeout note.
- Keep suspicious-handle discovery in a separate `Possible Impersonation` bucket.
- Add SpiderFoot as a first-class selectable CLI provider.
- Normalize SpiderFoot output into the app's existing evidence model instead of dumping raw scan artifacts.

## Non-Goals

- Do not build a SpiderFoot web service or background daemon.
- Do not expose all raw SpiderFoot event types in the UI.
- Do not redesign the provider results UI structure.
- Do not turn Sherlock into a fully asynchronous second-pass workflow in this iteration.

## Recommended Approach

### 1. Bound Sherlock aggressively

Sherlock should operate on a small, high-signal candidate set derived from the domain and company name. The candidate list should prioritize likely legitimate brand handles first and only test a handful of suspicious variants for impersonation.

The scan should also be constrained by platform. Instead of letting Sherlock fan out across every supported site, the app should target the same platforms already represented in the UI, such as GitHub, Twitter/X, Facebook, Instagram, YouTube, TikTok, Reddit, and LinkedIn.

### 2. Preserve partial Sherlock results

If some candidates complete successfully and a later candidate times out, the provider should remain `ok` or `limited` with a diagnostic note that partial results were returned before timeout. The note should stop implying that nothing useful was captured.

### 3. Add SpiderFoot as a narrowed CLI provider

SpiderFoot should be integrated in the same spirit as `theHarvester` and `sherlock`: invoked locally, parsed locally, and reduced to evidence the app already knows how to display. The first version should only extract:

- emails
- subdomains
- social profile URLs
- mentions / related URLs
- hosting or IP clues when they are easy to map cleanly

This keeps the provider comparable with the rest of the app and avoids flooding the UI with SpiderFoot-internal event types.

## Data Model Changes

### Sherlock

- Keep `social_profiles` and `impersonation_candidates`.
- Add notes such as:
  - `Timed out after partial scan; returning collected Sherlock hits`
  - `No Sherlock social hits found`
- Do not mark the provider `error` if partial findings exist.

### SpiderFoot

SpiderFoot should write into the existing provider result fields:

- `emails`
- `subdomains`
- `social_profiles`
- `mentions`
- `hosting` when applicable

SpiderFoot should also merge relevant findings into the existing aggregate sections so the analyst view stays consistent.

## Runtime Behavior

### Sherlock

- derive a smaller candidate set
- limit suspicious variants to a few strongest impersonation patterns
- run a curated site list only
- keep legitimate and suspicious results separate
- on timeout:
  - if no findings were collected, report a timeout note
  - if findings were collected, keep them and add a partial-scan note

### SpiderFoot

- discover the CLI locally
- run a constrained scan for a domain target
- capture machine-readable output if available, otherwise parse stable textual output
- normalize the useful results into provider evidence
- skip cleanly if SpiderFoot is not installed

## UI Expectations

No large UI redesign is needed.

- `Providers` gets a new `SpiderFoot` card.
- `Identities` continues to show merged legitimate social profiles with source labels.
- `Possible Impersonation` continues to show suspicious Sherlock results separately.

## Testing Strategy

Use TDD for both phases.

### Sherlock tests

- candidate generation is smaller and deterministic
- timeout after partial success keeps captured findings
- suspicious results remain separate
- provider notes are accurate and non-duplicative

### SpiderFoot tests

- provider catalog exposes `spiderfoot` as selectable
- CLI-not-found path is explicit
- parser maps SpiderFoot findings into the right provider result buckets
- merged aggregate results receive SpiderFoot findings where appropriate

## Risks

- Sherlock may still be slow on some targets if the selected sites are too broad.
- SpiderFoot installation footprint may be heavier than other tools, especially on Windows.
- SpiderFoot output formats can vary by version, so the parser should target the most stable machine-readable form available.

## Success Criteria

- Sherlock no longer commonly ends with a blank provider card plus `Timed out after 90s`.
- Live scans retain partial Sherlock findings when available.
- SpiderFoot appears in the provider selection list and produces exact provider-owned evidence in the `Providers` tab.
- Full tests, typecheck, and build stay green after the change.
