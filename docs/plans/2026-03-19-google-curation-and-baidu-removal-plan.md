# Google Curation And Baidu Removal Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove Baidu from the app, make Google return compact and relevant email/mention evidence, and align Censys provider messaging with the current org-enabled account requirement.

**Architecture:** The change is contained to the shared provider catalog, the Python OSINT engine, and the existing provider-results UI contract. Google keeps the same outward provider shape but shifts from raw HTML evidence to curated structured evidence, while Baidu is removed end to end.

**Tech Stack:** TypeScript, React, Python, unittest, Node test runner

---

### Task 1: Lock the expected behavior with tests

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing tests**

- Remove the Baidu-specific assertions and add:
  - a provider catalog assertion that `baidu` is no longer selectable
  - a Google evidence test that expects only curated domain emails and cleaned mention entries

**Step 2: Run the targeted tests to verify they fail**

Run:
```bash
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_run_emailharvest_passive_collects_google_evidence -v
node --test --import tsx server/provider-catalog.test.ts
```

**Step 3: Confirm the failures are for the expected reasons**

- Google still emits noisy/raw results or wrong structure
- Baidu is still present in the catalog

### Task 2: Remove Baidu from the catalog and runtime

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Remove the provider catalog entry**

- Delete the `baidu` provider object from `osint-providers.ts`

**Step 2: Remove Baidu runtime logic**

- Delete `baidu` website discovery handling
- Delete `baidu` passive email/mention collection
- Remove `baidu` from discovery attribution loops/maps

**Step 3: Update tests to match removal**

- Delete the Baidu engine test
- Keep the catalog/engine expectations aligned

### Task 3: Curate Google search evidence

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Add a structured Google extraction helper**

- Extract candidate hits from Google search HTML
- Ignore internal/support/result-shell Google URLs
- Normalize title/url/snippet into structured mention objects

**Step 2: Reuse that helper for discovery and passive evidence**

- Website discovery should use curated Google result URLs
- Passive Google evidence should record:
  - matching emails
  - compact mentions only

**Step 3: Cap noisy Google output**

- Limit the number of stored mention hits per category/provider
- Trim snippets before storing them

**Step 4: Run the targeted Google test to verify it passes**

Run:
```bash
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_run_emailharvest_passive_collects_google_evidence osint_engine_test.OsintEngineTests.test_find_website_uses_google_search_when_selected -v
```

### Task 4: Clarify Censys provider messaging

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Test: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Update provider details/limits**

- Explain that the current Censys search integration needs an org-enabled account/context

**Step 2: Keep selectable behavior unchanged**

- Do not hide the provider; keep it visible for evaluation

### Task 5: Full verification

**Files:**
- Verify only

**Step 1: Run Python tests**

```bash
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
```

**Step 2: Run Node tests**

```bash
node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts
```

**Step 3: Run typecheck and build**

```bash
npm run check
npm run build
```

**Step 4: Restart the live server and smoke test**

- Confirm `GET http://localhost:5000/api/health`
- Run one `google`-only recon request and summarize the provider evidence
