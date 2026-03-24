# Google Dork Provider Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the old `google` provider with a Brave Search API-backed `google_dorks` provider that generates bounded dorks, normalizes results, and appends findings into the existing analysis pipeline.

**Architecture:** Add a dedicated Python provider helper for dork generation, Brave query execution, aggregation, and normalization, then integrate it into `osint_engine.py`. Update provider selection/catalog code so `google_dorks` is the visible provider while legacy `google` selections still map safely to it.

**Tech Stack:** Python, requests-based Brave Search API calls, existing OSINT engine/provider result pipeline, TypeScript shared provider catalog

---

### Task 1: Replace the provider catalog entry

**Files:**
- Modify: `shared/osint-providers.ts`
- Test: `server/provider-catalog.test.ts`

**Step 1: Write the failing test**

Add assertions that:
- `google_dorks` exists and is selectable
- `google` is no longer selectable in the catalog

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/provider-catalog.test.ts`

Expected: FAIL because the catalog still exposes `google`.

**Step 3: Write minimal implementation**

Replace the old `google` catalog entry with `google_dorks`, with accurate metadata describing Brave-powered dork-based intelligence.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/provider-catalog.test.ts`

Expected: PASS

### Task 2: Add legacy provider-id aliasing

**Files:**
- Modify: `shared/osint-providers.ts`
- Test: `server/recon-runner.test.ts`

**Step 1: Write the failing test**

Add a test proving a selected source list containing `google` is sanitized into `google_dorks`.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/recon-runner.test.ts`

Expected: FAIL because legacy `google` is not mapped.

**Step 3: Write minimal implementation**

Add alias handling in the provider sanitization helper so stale selections remain compatible.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/recon-runner.test.ts`

Expected: PASS

### Task 3: Add the Python Google Dork provider helper

**Files:**
- Create: `google_dork_provider.py`
- Test: `osint_engine_test.py`

**Step 1: Write the failing test**

Add Python tests for:
- `generate_dorks(domain, mode="light")`
- `generate_dorks(domain, mode="full")`
- duplicate URL suppression
- Brave result parsing and normalization

**Step 2: Run test to verify it fails**

Run: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests -v`

Expected: FAIL because the provider module does not exist yet.

**Step 3: Write minimal implementation**

Implement:
- `generate_dorks()`
- `search_dork()`
- `GoogleDorkProvider.run()`
- `GoogleDorkProvider.normalize()`

Use Brave Search API only and keep the provider table-driven and extendable.

**Step 4: Run test to verify it passes**

Run: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests -v`

Expected: PASS

### Task 4: Integrate the provider into the engine

**Files:**
- Modify: `osint_engine.py`
- Test: `osint_engine_test.py`

**Step 1: Write the failing test**

Add a test proving:
- selecting `google_dorks` runs the provider
- normalized findings are appended into `analysis.threat_intelligence.findings`
- provider results capture `mentions` and `emails`
- partial query failures preserve completed findings

**Step 2: Run test to verify it fails**

Run: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_google_dorks_provider_integration -v`

Expected: FAIL because engine integration does not exist yet.

**Step 3: Write minimal implementation**

Wire the new provider into the engine's provider execution flow and merge its normalized output into the analysis object and provider results.

**Step 4: Run test to verify it passes**

Run: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_google_dorks_provider_integration -v`

Expected: PASS

### Task 5: Verify full stack compatibility

**Files:**
- Modify if needed: `shared/osint-providers.ts`
- Modify if needed: `osint_engine.py`
- Modify if needed: `google_dork_provider.py`
- Test: `server/provider-catalog.test.ts`
- Test: `server/recon-runner.test.ts`
- Test: `osint_engine_test.py`

**Step 1: Run targeted verification**

Run: `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts`

Expected: PASS

**Step 2: Run Python verification**

Run: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests osint_engine_test.OsintEngineTests -v`

Expected: PASS

**Step 3: Run build verification**

Run: `npm run build`

Expected: PASS
