# Provider Evidence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a provider-by-provider evidence view that shows the exact findings each selected provider gathered after a recon scan.

**Architecture:** Extend the Python engine to collect provider-scoped results in parallel with the existing merged report, return that new map in the JSON response, and render it in a dedicated `Providers` tab on the dashboard. The merged tabs remain unchanged, while the new tab exposes exact per-provider artifacts with duplicates allowed.

**Tech Stack:** Python, Node/TypeScript, React, existing OSINT provider catalog

---

### Task 1: Add failing tests for provider evidence output

**Files:**
- Modify: `osint_engine_test.py`
- Possibly create: `server/provider-results.test.ts`

**Step 1: Write the failing test**

Add tests that expect:
- provider-specific email lists to be returned separately
- skipped providers to report a status and note
- duplicates to remain provider-scoped instead of being deduplicated away

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because provider result tracking does not exist yet

**Step 3: Write minimal implementation**

Introduce a provider result helper structure and thread it through representative providers.

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 2: Return provider evidence from the Python report

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the failing contract assertion**

Add a test that `run_recon()` returns `provider_results`.

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because the report has no provider result map

**Step 3: Write minimal implementation**

Populate provider status, notes, and exact gathered detail arrays per provider while preserving the merged output.

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 3: Render the Providers tab in the dashboard

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`

**Step 1: Write the failing UI contract**

Use the TypeScript build as the contract by adding the new result types and tab references.

**Step 2: Run typecheck to verify it fails**

Run: `npm run check`
Expected: FAIL until the new provider-result types and rendering are implemented

**Step 3: Write minimal implementation**

Add a `Providers` tab and provider result cards that show exact findings by evidence type.

**Step 4: Run typecheck to verify it passes**

Run: `npm run check`
Expected: PASS

### Task 4: Verify end to end

**Files:**
- No new source files required

**Step 1: Run automated verification**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
- `npm run check`
- `npm run build`

Expected: all passing

**Step 2: Run live smoke verification**

Run a real scan with multiple providers selected and verify:
- the `Providers` tab is present
- each selected provider shows its own exact findings
- duplicates remain visible under each provider card
