# SpiderFoot Deep Design

## Goal

Add a second SpiderFoot provider mode, `SpiderFoot Deep`, that keeps the current live passive SpiderFoot flow intact while expanding email, breach, credential-exposure, and possible impersonation coverage.

## Approach

The app will treat `spiderfoot` and `spiderfoot_deep` as two separate selectable providers. Both continue to run as background SpiderFoot API jobs with live polling, but they use different SpiderFoot event profiles:

- `spiderfoot`: current lighter passive profile for fast interactive discovery
- `spiderfoot_deep`: broader event coverage for:
  - email discovery
  - compromised email / password / hash signals
  - leak site references
  - account and affiliate signals that can become impersonation candidates

If both are selected, `spiderfoot_deep` wins for the background scan so we do not launch two overlapping SpiderFoot scans against the same target in the same request.

## Data Mapping

`SpiderFoot Deep` extends the existing provider result shape instead of inventing a new UI model:

- `EMAILADDR` -> `emails`
- `EMAILADDR_COMPROMISED`, `PASSWORD_COMPROMISED`, `HASH_COMPROMISED`, `MALICIOUS_EMAILADDR`, `LEAKSITE_URL`, `LEAKSITE_CONTENT` -> `breach_hints`
- `SOCIAL_MEDIA`, suspicious `LINKED_URL_EXTERNAL`, `USERNAME`, `ACCOUNT_EXTERNAL_*_COMPROMISED`, `AFFILIATE_DOMAIN_NAME`, `AFFILIATE_INTERNET_NAME` -> `impersonation_candidates`
- domain, hosting, social, and mention behavior from the current SpiderFoot flow stay in place

These findings remain explicitly labeled as `possible` or `candidate` when SpiderFoot alone cannot prove ownership or impersonation.

## UI / UX

The provider picker gets a new entry: `SpiderFoot Deep`.

The existing live polling UI stays the same, but it becomes provider-aware:

- if the job is for `spiderfoot`, update the `SpiderFoot` card
- if the job is for `spiderfoot_deep`, update the `SpiderFoot Deep` card

Deep-mode findings also merge into the shared identities and DNS sections so the report evolves in place while the scan is running.

## Safety / Limits

- Deep mode is slower and noisier by design
- it still uses the current in-memory job store
- it will not claim confirmed impersonation; only `possible impersonation / related account` style candidates
- passing SpiderFoot-native API keys is out of scope for this first deep-mode version
