# Google Provider Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Google as a selectable search provider for website discovery, mentions, email dorks, and social fallback evidence.

**Architecture:** Reuse the existing search-provider patterns in the Python engine, add a new `google` provider to the shared catalog, and thread Google through the same provider-results evidence model already used for Brave, DuckDuckGo, and Baidu. Keep the implementation lightweight and diagnostic-first because Google HTML scraping is fragile.

**Tech Stack:** Python, TypeScript, React provider catalog, existing OSINT provider-results model

---

### Task 1: Add failing tests for the Google provider

**Files:**
- Modify: `osint_engine_test.py`
- Modify: `server/provider-catalog.test.ts`

**Step 1: Write the failing tests**

Add tests that expect:
- `google` to be selectable in the provider catalog
- Google website discovery to work when selected
- Google passive search evidence to record emails and mentions

**Step 2: Run tests to verify they fail**

Run:
- `node --test --import tsx server/provider-catalog.test.ts`
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

Expected: FAIL because Google does not exist yet

### Task 2: Add Google to the provider catalog

**Files:**
- Modify: `shared/osint-providers.ts`

**Step 1: Add the provider entry**

Create a new `Discovery` provider with no API key requirement and selectable `true`.

**Step 2: Run the catalog test**

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: provider catalog test moves toward green

### Task 3: Implement Google discovery and evidence capture

**Files:**
- Modify: `osint_engine.py`

**Step 1: Make website discovery pass**

Add a Google HTML-search branch to `find_website()`.

**Step 2: Make passive evidence pass**

Add Google search evidence collection for:
- mentions
- email dorks

**Step 3: Add social fallback**

Use Google for search-based social-profile discovery in the existing social flow.

**Step 4: Run targeted Python tests**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

### Task 4: Verify the full app

**Files:**
- No additional source files required

**Step 1: Run verification**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
- `npm run check`
- `npm run build`

Expected: all passing
