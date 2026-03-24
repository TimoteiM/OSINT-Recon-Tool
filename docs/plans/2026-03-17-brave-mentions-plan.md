# Brave Mentions Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Brave Search return exact domain mentions in the provider evidence view, including forums, news, documents, jobs, and generic web hits.

**Architecture:** Extend the shared provider-result schema with a `mentions` field, capture Brave search hits from explicit domain-mention queries in the Python engine, classify those hits lightly, and render them in the existing `Providers` tab. Keep existing merged report behavior and Brave email extraction intact.

**Tech Stack:** Python, React, TypeScript, existing provider evidence UI

---

### Task 1: Add failing tests for Brave mention evidence

**Files:**
- Modify: `osint_engine_test.py`

**Step 1: Write the failing test**

Add tests that expect:
- Brave mention queries to record exact mention objects under `provider_results["brave"]["mentions"]`
- Brave forum hits to be categorized as `forum`

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because Brave mention evidence is not yet persisted

**Step 3: Write minimal implementation**

Add the `mentions` field and a Brave mention capture path that records exact hits.

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 2: Capture and classify Brave mention hits

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the failing test**

Add a test that validates a Brave Reddit result becomes a `forum` mention and retains title, URL, snippet, and query.

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because the helper does not exist yet

**Step 3: Write minimal implementation**

Introduce:
- provider result support for `mentions`
- Brave mention query execution
- mention classification helper
- Brave mention recording into `provider_results`

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 3: Render Brave mentions in the Providers tab

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`

**Step 1: Write the failing UI contract**

Use the TypeScript build as the contract by adding `mentions` to the provider result type assumptions.

**Step 2: Run typecheck to verify it fails**

Run: `npm run check`
Expected: FAIL until `mentions` is handled in the UI

**Step 3: Write minimal implementation**

Render Brave `mentions` grouped by category while leaving other provider cards unchanged.

**Step 4: Run typecheck to verify it passes**

Run: `npm run check`
Expected: PASS

### Task 4: Verify end to end

**Files:**
- No new source files required

**Step 1: Run automated verification**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `npm run check`
- `npm run build`

Expected: all passing

**Step 2: Run live smoke verification**

Run a real scan with Brave selected and verify the `Providers` tab shows exact mention hits, including forum results when available.
