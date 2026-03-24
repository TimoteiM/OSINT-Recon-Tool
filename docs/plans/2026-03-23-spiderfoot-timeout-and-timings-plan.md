# SpiderFoot Timeout and Timings Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Raise SpiderFoot's default timeout to 90 seconds and show real investigation timings in the UI.

**Architecture:** The Python engine records timings as part of the recon report so the Node layer can pass them through unchanged. The React dashboard reads that timing object and renders total duration plus per-stage durations.

**Tech Stack:** Python, Node/Express, React, TypeScript

---

### Task 1: Add failing timing and timeout tests

**Files:**
- Modify: `osint_engine_test.py`

Add regression tests for:
- SpiderFoot default timeout using 90 seconds when no env override is present
- `run_recon()` returning a `timings` object

### Task 2: Implement backend timing capture

**Files:**
- Modify: `osint_engine.py`

Add timing helpers, capture stage timings in `run_recon()`, capture provider timings in SpiderFoot and Sherlock, and raise SpiderFoot default timeout to 90 seconds.

### Task 3: Render timings in the dashboard

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`

Add TypeScript types for the timing payload, show total duration in the overview, and add a compact per-investigation timing panel.

### Task 4: Verify and refresh the live app

**Files:**
- Modify: `dist/*` via build output

Run focused Python tests, build the app, restart the local server, and verify the live endpoint responds.
