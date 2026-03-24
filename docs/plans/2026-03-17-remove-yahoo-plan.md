# Remove Yahoo Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove Yahoo completely from the app so it is no longer selectable, rendered, or executed.

**Architecture:** Delete the Yahoo provider from the catalog, remove its search and evidence hooks from the Python engine, and update the tests to assert the reduced provider surface. This is a removal-only change with no new behavior added elsewhere.

**Tech Stack:** TypeScript, Python, React provider catalog, existing OSINT engine tests

---

### Task 1: Add failing removal tests

**Files:**
- Modify: `server/provider-catalog.test.ts`
- Modify: `osint_engine_test.py`

**Step 1: Write the failing test**

Adjust tests so they no longer expect Yahoo to be selectable or active.

**Step 2: Run tests to verify they fail**

Run:
- `node --test --import tsx server/provider-catalog.test.ts`
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`

Expected: FAIL while Yahoo still exists

### Task 2: Remove Yahoo from the catalog and engine

**Files:**
- Modify: `shared/osint-providers.ts`
- Modify: `osint_engine.py`

**Step 1: Remove the catalog entry**

Delete the Yahoo provider object entirely.

**Step 2: Remove engine references**

Delete Yahoo-specific logic from website discovery, passive evidence collection, attribution maps, and any remaining source lists.

**Step 3: Run targeted tests**

Run the same targeted commands until they pass.

### Task 3: Full verification

**Files:**
- No additional source files required

**Step 1: Run verification**

Run:
- `.venv\\Scripts\\python.exe -m unittest osint_engine_test.py -v`
- `node --test --import tsx server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts`
- `npm run check`
- `npm run build`

Expected: all passing
