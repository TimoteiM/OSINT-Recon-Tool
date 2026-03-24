# SpiderFoot Background Job Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Run SpiderFoot asynchronously in the background and stream progress plus partial findings into the current UI through polling.

**Architecture:** The synchronous recon request returns the standard report immediately while a Node-managed SpiderFoot background job continues separately. The frontend polls a job endpoint and merges SpiderFoot progress and provider results into the active report in place.

**Tech Stack:** Python, Node/Express, React, TypeScript

---

### Task 1: Add backend tests for async SpiderFoot job behavior

**Files:**
- Modify: `server/routes.test.ts`
- Modify: `server/recon-runner.test.ts`

Cover:
- synchronous recon strips SpiderFoot from the inline Python selection
- a SpiderFoot job is created when selected
- job status endpoint returns progress and result snapshots

### Task 2: Add Node-side SpiderFoot job manager

**Files:**
- Create: `server/spiderfoot-jobs.ts`
- Modify: `server/recon-runner.ts`
- Modify: `server/routes.ts`

Implement:
- job store
- background spawn path
- status fetching route
- initial `running` provider state in the main response

### Task 3: Add Python SpiderFoot-only execution helper if needed

**Files:**
- Modify: `osint_engine.py`
- Modify: `osint_engine_test.py`

Keep Python reusable for SpiderFoot-only runs so Node can request only SpiderFoot results cleanly.

### Task 4: Add frontend polling and live SpiderFoot UI

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`

Implement:
- polling when `spiderfoot_job` exists
- in-place merge of SpiderFoot partial data
- live progress section in the Providers tab

### Task 5: Verify and refresh the live app

**Files:**
- Modify: `dist/*` via build output

Run tests, build, restart the local server, and verify the live API responds.
