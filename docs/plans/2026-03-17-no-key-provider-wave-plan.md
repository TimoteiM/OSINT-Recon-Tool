# No-Key Provider Wave Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the remaining no-key providers selectable and operational so they can be compared in the application and benchmark workflow.

**Architecture:** Extend the Python engine with lightweight passive integrations for the remaining public providers, update the shared provider catalog to mark them selectable, and surface exact provider evidence through the existing provider-results view. Keep integrations diagnostic-first so blocked or stale endpoints still report useful notes.

**Tech Stack:** Python, TypeScript, React, existing OSINT provider catalog and provider-results UI

---

### Task 1: Add failing tests for the new provider integrations

**Files:**
- Modify: `osint_engine_test.py`
- Modify: `server/provider-catalog.test.ts`

**Step 1: Write the failing tests**

Add tests that expect:
- `subdomaincenter`, `subdomainfinderc99`, and `thc` to record subdomains
- `baidu` and `yahoo` to record mention or email evidence
- catalog entries for all six providers to become selectable

**Step 2: Run tests to verify they fail**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `node --test --import tsx server/provider-catalog.test.ts`

Expected: FAIL because the integrations and catalog changes do not exist yet

**Step 3: Write minimal implementation**

Add only the smallest code needed to satisfy each test.

**Step 4: Run tests to verify they pass**

Run the same commands again.

### Task 2: Implement passive subdomain providers

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the failing test**

Add a test for each passive source:
- `subdomaincenter`
- `subdomainfinderc99`
- `thc`

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

**Step 3: Write minimal implementation**

Add provider-gated public fetches, parse subdomains, record exact findings, and record failure notes when the endpoint is blocked or empty.

**Step 4: Run test to verify it passes**

Run the same Python test command.

### Task 3: Implement search-engine providers

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the failing test**

Add tests that expect `baidu` and `yahoo` to contribute search evidence through mentions and search-based email extraction.

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

**Step 3: Write minimal implementation**

Add lightweight search fetch/parsing logic for:
- website discovery support
- mention capture
- passive email/social extraction

**Step 4: Run test to verify it passes**

Run the same Python test command.

### Task 4: Implement Windvane carefully

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the failing test**

Add a test that documents the expected behavior for `windvane`, either:
- records parsed findings, or
- records a clear diagnostic note if the public response is not usable

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

**Step 3: Write minimal implementation**

Implement the stable path only. If the source is too brittle, keep it diagnostic-first rather than forcing a noisy integration.

**Step 4: Run test to verify it passes**

Run the same Python test command.

### Task 5: Update the catalog and verify end to end

**Files:**
- Modify: `shared/osint-providers.ts`
- Modify: `server/provider-catalog.test.ts`

**Step 1: Make the six providers selectable**

Update catalog metadata and status text as needed.

**Step 2: Run verification**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
- `npm run check`
- `npm run build`

Expected: all passing

### Task 6: Re-benchmark the new providers

**Files:**
- No source edits required

**Step 1: Run a focused benchmark**

Benchmark the newly implemented providers across the representative domain sample.

**Step 2: Update conclusions**

Summarize whether any of the six should move into `Keep`, `Conditional`, or `Drop`.
