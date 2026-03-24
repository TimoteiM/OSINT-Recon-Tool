# Provider Checklist Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a detailed provider checklist to the dashboard and wire selected providers through the backend into the Python recon engine.

**Architecture:** A shared TypeScript provider catalog will drive both UI rendering and backend request validation. The frontend will submit a selected provider ID list with each recon request, the Node runner will pass that selection into the Python process via environment variables, and the Python engine will use lightweight source guards to enable or skip supported integrations.

**Tech Stack:** React, TypeScript, Express, Node test runner, Python, existing OSINT engine

---

### Task 1: Save provider catalog contract

**Files:**
- Create: `shared/osint-providers.ts`
- Test: `server/provider-catalog.test.ts`

**Step 1: Write the failing test**

Create a test that expects:
- known provider IDs to exist
- default selections to include active implemented sources
- disabled providers to stay out of defaults

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: FAIL because the catalog file does not exist yet

**Step 3: Write minimal implementation**

Add the shared provider metadata, helper functions, and exported IDs needed by both frontend and backend.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/provider-catalog.test.ts`
Expected: PASS

### Task 2: Add selected-source request plumbing

**Files:**
- Modify: `server/routes.ts`
- Modify: `server/recon-runner.ts`
- Modify: `server/recon-runner.test.ts`
- Create: `server/recon-routes.test.ts`

**Step 1: Write the failing tests**

Add tests that expect:
- valid `sources` are accepted
- invalid source IDs are rejected with `400`
- selected source IDs are passed to the Python child process environment

**Step 2: Run tests to verify they fail**

Run: `node --test --import tsx server/recon-runner.test.ts server/recon-routes.test.ts`
Expected: FAIL because `sources` are not validated or passed through yet

**Step 3: Write minimal implementation**

Update route parsing and runner options so selected sources are validated and propagated.

**Step 4: Run tests to verify they pass**

Run: `node --test --import tsx server/recon-runner.test.ts server/recon-routes.test.ts`
Expected: PASS

### Task 3: Gate Python integrations by selected providers

**Files:**
- Modify: `osint_engine.py`
- Modify: `osint_engine_test.py`

**Step 1: Write the failing test**

Add focused tests around source selection helpers and one or two representative guarded integrations.

**Step 2: Run test to verify it fails**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: FAIL because the engine does not yet read selected providers

**Step 3: Write minimal implementation**

Read `OSINT_SELECTED_SOURCES`, add helper predicates, and gate supported providers without changing the default all-enabled behavior.

**Step 4: Run test to verify it passes**

Run: `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
Expected: PASS

### Task 4: Build the provider selection UI

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`
- Possibly modify: `client/src/lib/queryClient.ts`
- Reuse: `client/src/components/ui/checkbox.tsx`

**Step 1: Write the failing contract test**

Use the existing TypeScript build as the contract by importing the shared catalog into the dashboard and shaping the request payload in typed code.

**Step 2: Run typecheck to verify breakage**

Run: `npm run check`
Expected: FAIL until the new types and usage line up

**Step 3: Write minimal implementation**

Render the checklist, connect it to local state, show provider details, and include selected sources in the mutation payload.

**Step 4: Run typecheck to verify it passes**

Run: `npm run check`
Expected: PASS

### Task 5: Verify end to end

**Files:**
- No additional source changes required

**Step 1: Run targeted automated verification**

Run:
- `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts server/recon-routes.test.ts server/typecheck.test.ts`
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `npm run check`
- `npm run build`

Expected: all passing

**Step 2: Run live smoke verification**

Run a real `POST /api/recon` with a reduced source list and verify the server returns `200` and includes the selected provider IDs in metadata.

**Step 3: Review UX**

Open the dashboard and confirm:
- every provider is visible
- supported providers can be toggled
- unsupported providers are clearly labeled
- each provider shows evidence/details and limitations
