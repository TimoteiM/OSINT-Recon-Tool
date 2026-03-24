# Provider Auth Diagnostics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make HIBP, Hunter, Censys, and ProjectDiscovery report exact auth/access failures instead of generic 401/500 notes, while keeping the current `.env` names unchanged.

**Architecture:** Add response-diagnostic helpers in `osint_engine.py`, update each provider integration to use endpoint-appropriate auth validation, and keep the frontend unchanged so the richer notes flow directly into the existing provider cards.

**Tech Stack:** Python, unittest, Node.js, TypeScript

---

### Task 1: Add failing tests for provider-auth diagnostics

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Write the failing tests**

- Add tests for:
  - HIBP notes when the key is valid but the domain is not subscribed
  - HIBP notes when the key is invalid
  - Hunter retrying `HunterIO_API_KEY` after `Hunter_API_KEY` gets a `401`
  - Hunter noting that both configured keys were rejected
  - Censys noting that a single token is not valid for the legacy endpoint
  - Censys using basic auth when `Censys_API_KEY` is shaped as `id:secret`
  - ProjectDiscovery recording response-body details for `500`

**Step 2: Run test to verify it fails**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test -v
```

Expected: failures on missing diagnostics/auth handling.

**Step 3: Write minimal implementation**

- Add the auth-diagnostic helpers and provider-specific handling.

**Step 4: Run test to verify it passes**

Run the same Python test command and confirm the new tests pass.

### Task 2: Update HIBP and Hunter runtime behavior

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`

**Step 1: Implement HIBP subscribed-domain validation**

- Query `subscribeddomains`
- map status/body into precise notes
- call domain search only when the target domain is subscribed

**Step 2: Implement Hunter key fallback**

- try `Hunter_API_KEY`
- retry with `HunterIO_API_KEY` on `401`
- record precise notes for rejected keys or empty success

**Step 3: Run targeted tests**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_hibp_uses_subscribed_domains_to_report_unverified_domain osint_engine_test.OsintEngineTests.test_hunter_retries_with_hunterio_key_after_primary_401 -v
```

Expected: pass.

### Task 3: Update Censys and ProjectDiscovery diagnostics

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`

**Step 1: Implement Censys credential-shape validation**

- parse `Censys_API_KEY`
- if single token, record a credential-shape note
- if `id:secret`, send HTTP basic auth to the legacy endpoint

**Step 2: Improve ProjectDiscovery error notes**

- append concise response-body detail to `500` or other non-200 notes when available

**Step 3: Run targeted tests**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_censys_notes_when_single_token_cannot_authenticate_legacy_search osint_engine_test.OsintEngineTests.test_projectdiscovery_includes_response_body_in_error_note -v
```

Expected: pass.

### Task 4: Full verification and live smoke test

**Files:**
- Verify only

**Step 1: Run the automated checks**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts
npm run check
npm run build
```

**Step 2: Restart the live app and smoke-test**

- confirm `/api/health`
- call `/api/recon` with:
  - `hibp,hunter`
  - `censys,projectdiscovery`

**Step 3: Report actual behavior**

- what now works
- what now fails with clearer diagnostics
- any remaining provider limitations
