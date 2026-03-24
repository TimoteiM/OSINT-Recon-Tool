# Provider Diagnostics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make provider cards explain why a source produced no findings and credit providers that already contribute but are currently invisible in the results view.

**Architecture:** Extend the existing Python `provider_results` flow with lightweight attribution and diagnostic notes. Record website-discovery attribution for search providers, record Wikidata social evidence, and add explicit notes for auth failures, parse mismatches, and empty but successful provider runs.

**Tech Stack:** Python, requests, unittest, shared provider results model

---

### Task 1: Add failing tests for attribution and provider diagnostics

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Write the failing tests**

Add tests for:
- website discovery attribution to `bing` and `duckduckgo`
- social attribution to `wikidata`
- provider notes for `hibp` 401, `github_code` 401, `phonebook_cz` HTML payload, `bufferoverun` 403, and `threatminer` 500

**Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL on missing attribution/notes

**Step 3: Write minimal implementation**

Patch only the provider-result attribution and note paths needed for those tests.

**Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 2: Implement provider diagnostics in the engine

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`

**Step 1: Write the failing test**

Add at least one test that verifies a selected provider remains visible with a note like `401 unauthorized` or `Unexpected HTML response`.

**Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Implement:
- helper functions for provider notes on auth/parse/empty responses
- search-provider attribution when website discovery succeeds
- Wikidata social attribution
- explicit notes for empty provider runs where helpful

**Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 3: Run project verification and live smoke

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`

**Step 1: Run the test suites**

Run: `node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
Expected: PASS

Run: `npm run check`
Expected: PASS

Run: `npm run build`
Expected: PASS

**Step 2: Restart the live server and verify diagnostics**

Run a live `POST` to `http://localhost:5000/api/recon` with selected providers from the problematic list.
Expected:
- `provider_results` still includes the selected providers
- cards now contain exact notes like auth failures, blocked endpoints, or unsupported payloads
