# Free Provider Wave Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Brave Search and a first wave of freely implementable providers so they can be selected before a scan and inspected afterward in the Providers tab.

**Architecture:** Extend the existing Python OSINT engine with small provider-specific helpers that plug into website discovery, passive email collection, and passive subdomain enumeration. Keep the current merged report intact while enriching `provider_results` so every provider shows exact evidence independently.

**Tech Stack:** Python, requests, Node/TypeScript, React, shared provider catalog, unittest, Node test runner

---

### Task 1: Add failing tests for the new provider contracts

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Test: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing tests**

Add Python tests for:
- Brave being skipped when `BRAVE_SEARCH_API_KEY` is missing
- Brave website discovery succeeding from API results
- passive subdomain helpers returning provider-scoped findings for BufferOverrun / RapidDNS / Hackertarget / ThreatMiner / Urlscan

Add TypeScript tests for:
- the new providers being selectable in the shared catalog

**Step 2: Run tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL on missing Brave/provider helper behavior

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: FAIL on catalog expectations

**Step 3: Write minimal implementation**

Only after seeing failures, implement the minimal provider helpers and catalog changes needed to satisfy the tests.

**Step 4: Run the tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: PASS

### Task 2: Wire Brave Search into discovery and email gathering

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env.example`

**Step 1: Write the failing test**

Add a test that expects Brave website discovery and Brave provider notes/results when selected and configured.

**Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because Brave is not used yet

**Step 3: Write minimal implementation**

Implement:
- Brave API helper
- Brave fallback in `find_website()`
- Brave social/email fallback support
- `.env.example` entry for `BRAVE_SEARCH_API_KEY`

**Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 3: Wire free passive subdomain providers into DNS enrichment

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`

**Step 1: Write the failing test**

Add tests that expect passive subdomains from:
- `bufferoverun`
- `rapiddns`
- `hackertarget`
- `threatminer`
- `urlscan`

**Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because those providers are not first-class integrations yet

**Step 3: Write minimal implementation**

Implement small helpers and merge their findings into:
- `dns.subdomains`
- provider-specific `provider_results`

Update the catalog entries to selectable states.

**Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 4: Verify app contract and build output

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Add local config**

Add `BRAVE_SEARCH_API_KEY` to local `.env`.

**Step 2: Run project verification**

Run: `node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
Expected: PASS

Run: `npm run check`
Expected: PASS

Run: `npm run build`
Expected: PASS

**Step 3: Verify live behavior**

Run a live POST to `http://localhost:5000/api/recon` with a source list including Brave and at least one new free provider.
Expected:
- `200` response
- `provider_results` includes the selected providers
- exact provider evidence is visible for the new integrations
