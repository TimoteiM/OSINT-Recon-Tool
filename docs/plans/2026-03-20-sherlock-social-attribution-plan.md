# Sherlock Social Attribution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Attribute social-profile findings clearly in the UI and add Sherlock-based brand-handle plus impersonation discovery to the recon workflow.

**Architecture:** The change extends the existing social discovery pipeline in Python, adds two social-oriented provider entries to the shared catalog, and expands the `Identities`/`Providers` UI to show both legitimate social sources and impersonation candidates. Sherlock is integrated as a local CLI dependency invoked from the Python engine.

**Tech Stack:** Python, React, TypeScript, unittest, Node test runner, local Sherlock CLI

---

### Task 1: Lock the new social data model with tests

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing tests**

- Add a test that social profiles found by slug probing are recorded under `social_probe`
- Add a test that Sherlock parsed results produce separate legitimate and impersonation findings
- Add a provider-catalog test that `social_probe` and `sherlock` are selectable/visible

**Step 2: Run the targeted tests to verify they fail**

Run:
```bash
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_social_probe_profiles_are_attributed osint_engine_test.OsintEngineTests.test_sherlock_results_are_split_between_legitimate_and_impersonation -v
node --test --import tsx server/provider-catalog.test.ts
```

**Step 3: Confirm the failures are for the expected reasons**

- `social_probe` does not exist yet
- `sherlock` does not exist yet
- impersonation results are not represented yet

### Task 2: Add provider catalog entries

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Test: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Add `social_probe`**

- Category: `Social Presence`
- Status: `active`
- Selectable: `true`

**Step 2: Add `sherlock`**

- Category: `Social Presence`
- Status: `active` or `limited` depending on install/runtime constraints
- Selectable: `true`

### Task 3: Add social attribution and impersonation structures in Python

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Extend the identity result shape**

- Add an `impersonation_candidates` list to the identities result
- Preserve the existing `source` field on social profiles

**Step 2: Record `social_probe` results**

- When slug/probe logic finds legitimate profiles, write them to `provider_results.social_probe.social_profiles`

**Step 3: Add Sherlock helpers**

- Build handle candidates from domain/company name
- Build suspicious variations conservatively
- Parse Sherlock CLI output into:
  - legitimate profile hits
  - possible impersonation hits

### Task 4: Install and wire Sherlock

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Test: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Install Sherlock in the local environment**

- Use the project virtualenv or a CLI wrapper path consistent with the existing tool integration style

**Step 2: Add tool lookup and execution**

- Reuse `_which()`-style discovery patterns used for other local tools
- Make missing Sherlock a clean provider note, not a crash

**Step 3: Run targeted tests**

Run:
```bash
.\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_sherlock_results_are_split_between_legitimate_and_impersonation -v
```

### Task 5: Render attribution and impersonation in the frontend

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\pages\Dashboard.tsx`

**Step 1: Show source labels on social profiles**

- Add a compact source tag per profile in `Social Media Presence`

**Step 2: Add `Possible Impersonation` section**

- Render impersonation candidates separately from legitimate profiles

**Step 3: Extend the `Providers` tab rendering**

- Show `social_probe` legitimate profiles
- Show Sherlock legitimate hits and suspicious hits

### Task 6: Full verification

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

**Step 4: Restart and smoke test**

- Confirm `GET http://localhost:5000/api/health`
- Run one recon request for a brand-style domain and inspect:
  - attributed social profiles
  - `social_probe` provider card
  - `sherlock` provider card
  - `Possible Impersonation` section
