# Sherlock Bounded Scan and SpiderFoot Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Sherlock fast and useful enough for live recon runs, then add SpiderFoot as a selectable CLI provider that returns exact provider evidence.

**Architecture:** Tighten the existing Sherlock helper in `osint_engine.py` so it uses fewer candidates, a curated site list, and partial-result-aware timeout handling. Then add a SpiderFoot runner/parser that normalizes CLI findings into the same provider-results schema used by the rest of the app.

**Tech Stack:** Python, TypeScript, Node test runner, unittest, existing provider catalog and recon engine.

---

### Task 1: Document the approved design

**Files:**
- Create: `docs/plans/2026-03-20-sherlock-bounded-and-spiderfoot-design.md`
- Create: `docs/plans/2026-03-20-sherlock-bounded-and-spiderfoot-plan.md`

**Step 1: Write the design document**

Capture the bounded Sherlock approach, partial timeout behavior, and SpiderFoot CLI integration scope.

**Step 2: Save the implementation plan**

Write this plan with exact files, tests, and commands.

### Task 2: Add Sherlock regression tests first

**Files:**
- Modify: `osint_engine_test.py`

**Step 1: Write the failing tests**

Add tests for:
- reduced Sherlock candidate generation
- timeout after partial findings preserving captured data
- partial timeout note replacing the current hard error behavior

**Step 2: Run targeted tests to verify they fail**

Run:

```powershell
c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_sherlock_handle_candidates_are_bounded osint_engine_test.OsintEngineTests.test_run_sherlock_keeps_partial_results_on_timeout -v
```

Expected: failing assertions until the implementation is added.

### Task 3: Implement bounded Sherlock behavior

**Files:**
- Modify: `osint_engine.py`

**Step 1: Write the minimal implementation**

Update:
- `sherlock_handle_candidates()`
- `sherlock_impersonation_candidates()`
- `run_sherlock()`

Behavior:
- smaller candidate list
- curated site set passed to the CLI
- partial results retained across timeout paths
- timeout note reflects partial success when applicable

**Step 2: Run targeted tests to verify they pass**

Run the same targeted Python tests and confirm green.

### Task 4: Add SpiderFoot tests first

**Files:**
- Modify: `osint_engine_test.py`
- Modify: `server/provider-catalog.test.ts`

**Step 1: Write the failing tests**

Add tests for:
- `spiderfoot` being selectable in the provider catalog
- CLI not found path for SpiderFoot
- SpiderFoot parser mapping findings into provider results

**Step 2: Run the targeted tests to verify they fail**

Run:

```powershell
node --test --import tsx server/provider-catalog.test.ts
c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.OsintEngineTests.test_run_spiderfoot_skips_when_not_installed osint_engine_test.OsintEngineTests.test_run_spiderfoot_parses_relevant_findings -v
```

Expected: failures until the provider and parser are implemented.

### Task 5: Implement SpiderFoot provider catalog and parser

**Files:**
- Modify: `shared/osint-providers.ts`
- Modify: `osint_engine.py`

**Step 1: Add the provider catalog entry**

Add `spiderfoot` as a selectable provider in a relevant category with accurate status/details.

**Step 2: Add minimal SpiderFoot runtime support**

Implement:
- CLI discovery
- constrained command invocation
- parser that extracts emails, subdomains, social profiles, mentions, and simple hosting clues
- provider-result recording

**Step 3: Merge normalized findings**

Ensure SpiderFoot findings contribute to the same aggregate identity/subdomain/social structures the UI already uses.

**Step 4: Run targeted tests to verify they pass**

Re-run the targeted Node and Python tests.

### Task 6: Verify the complete change set

**Files:**
- Modify: `osint_engine_test.py`
- Modify: `shared/osint-providers.ts`
- Modify: `osint_engine.py`
- Modify: any frontend files only if required by data shape changes

**Step 1: Run the full verification suite**

Run:

```powershell
c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts
npm run check
npm run build
```

Expected: all commands succeed.

**Step 2: Run a live smoke test**

Run a local recon request with:
- `social_probe`
- `sherlock`
- `spiderfoot`

Verify:
- the app accepts all provider IDs
- Sherlock returns either bounded findings or a partial-scan note
- SpiderFoot provider card appears and records exact findings or a clear install note
