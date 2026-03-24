# RocketReach Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add local `.env`-based API key loading and integrate RocketReach as a selectable identity/email provider in the application.

**Architecture:** Load secrets from a root `.env` file into the Node process at startup, propagate `ROCKETREACH_API_KEY` through the existing recon runner environment, and add a Python RocketReach helper that is gated by both source selection and key presence. Update the shared provider catalog so RocketReach appears as a real frontend provider with key-backed details.

**Tech Stack:** Node/TypeScript, Express, Python, requests, RocketReach Python SDK, shared provider catalog

---

### Task 1: Add environment file support

**Files:**
- Create: `server/env.ts`
- Create: `server/env.test.ts`
- Modify: `server/index.ts`
- Modify: `.gitignore`
- Create: `.env.example`
- Create: `.env`

**Step 1: Write the failing test**

Add a test proving a `.env` file is parsed into process env variables.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/env.test.ts`
Expected: FAIL because the loader does not exist yet.

**Step 3: Write minimal implementation**

Implement a small env-file loader, call it from server startup, ignore `.env`, commit `.env.example`, and create the local `.env` with `ROCKETREACH_API_KEY`.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/env.test.ts`
Expected: PASS

### Task 2: Propagate RocketReach key to Python

**Files:**
- Modify: `server/recon-runner.test.ts`
- Modify: `server/recon-runner.ts`

**Step 1: Write the failing test**

Add a test expecting `ROCKETREACH_API_KEY` in runner env when present.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/recon-runner.test.ts`
Expected: FAIL until env propagation is explicit and covered.

**Step 3: Write minimal implementation**

Pass the key through the runner env alongside the selected sources payload.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/recon-runner.test.ts`
Expected: PASS

### Task 3: Add RocketReach provider behavior in Python

**Files:**
- Modify: `osint_engine_test.py`
- Modify: `osint_engine.py`

**Step 1: Write the failing test**

Add tests proving RocketReach:
- is skipped without a key
- is skipped when not selected
- extracts matching emails when selected and configured

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because RocketReach helper does not exist.

**Step 3: Write minimal implementation**

Add a RocketReach helper using the official Python SDK if installed, falling back cleanly when unavailable. Merge its emails into identity harvesting.

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 4: Update provider catalog and frontend

**Files:**
- Modify: `shared/osint-providers.ts`
- Modify: `client/src/pages/Dashboard.tsx`
- Modify: `server/provider-catalog.test.ts`

**Step 1: Write the failing test**

Update catalog expectations so RocketReach is selectable by default only when it is a configured key-backed source in the catalog.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: FAIL until the provider metadata is updated.

**Step 3: Write minimal implementation**

Make RocketReach visible as a selectable provider with a `Needs API key` status and accurate details in the dashboard.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: PASS

### Task 5: Verify end to end

**Files:**
- No new files required

**Step 1: Run automated verification**

Run:
- `node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `npm run check`
- `npm run build`

Expected: all passing

**Step 2: Run live verification**

Run a real `POST /api/recon` with `sources` including `rocketreach` and verify the request returns `200` and the logs show RocketReach participation or graceful no-result behavior.
