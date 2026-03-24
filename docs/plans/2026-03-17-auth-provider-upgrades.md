# Auth Provider Upgrades Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve the usefulness of GitHub, HIBP, RocketReach, and DeHashed by adding authenticated flows where possible, stronger matching for RocketReach, and clearer wording for hint-only breach results.

**Architecture:** Extend the existing env-driven provider model with `GITHUB_TOKEN` and `HIBP_API_KEY`, pass them through the existing runner, and keep all new behavior inside the Python engine. GitHub and HIBP should use auth when configured but still degrade cleanly with explanatory provider notes when not configured.

**Tech Stack:** Python, requests, Node/TypeScript env loading, unittest, Node test runner

---

### Task 1: Add failing tests for auth-backed provider behavior

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\recon-runner.test.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\env.test.ts`

**Step 1: Write the failing tests**

Add tests for:
- GitHub code search using `GITHUB_TOKEN`
- HIBP requests using `HIBP_API_KEY`
- RocketReach domain-aware/company-variant matching
- DeHashed note text saying hint-only, not full results
- env propagation for the new keys

**Step 2: Run tests to verify they fail**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL on missing auth/domain-aware behavior

Run: `node --test --import tsx server/env.test.ts server/recon-runner.test.ts`
Expected: FAIL on missing env propagation expectations

**Step 3: Write minimal implementation**

Implement only the auth propagation and provider code needed to satisfy those tests.

**Step 4: Run tests to verify they pass**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

Run: `node --test --import tsx server/env.test.ts server/recon-runner.test.ts`
Expected: PASS

### Task 2: Upgrade GitHub and HIBP provider requests

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env.example`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env`

**Step 1: Write the failing test**

Add tests expecting:
- auth headers when `GITHUB_TOKEN` is set
- auth headers when `HIBP_API_KEY` is set
- authenticated paths to avoid the existing `401` results

**Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Implement:
- helper(s) for GitHub auth headers
- helper(s) for HIBP auth headers
- better GitHub repo query variants

**Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 3: Improve RocketReach matching and DeHashed wording

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`

**Step 1: Write the failing test**

Add tests for:
- RocketReach matching on domain-linked emails even when employer naming differs
- DeHashed note text mentioning public hint / auth required rather than implying records are available

**Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Implement:
- domain-aware RocketReach normalization and broader company variants
- clearer DeHashed wording in result notes

**Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 4: Verify the whole app and live provider diagnostics

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`

**Step 1: Run project verification**

Run: `node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
Expected: PASS

Run: `npm run check`
Expected: PASS

Run: `npm run build`
Expected: PASS

**Step 2: Restart the live server and verify**

Run a live `POST` to `http://localhost:5000/api/recon` with:
- `github_code`
- `github_repos`
- `hibp`
- `dehashed`
- `rocketreach`

Expected:
- selected providers appear in `provider_results`
- notes are more useful than before
- authenticated providers stop reporting unauthenticated `401`s when keys are configured
