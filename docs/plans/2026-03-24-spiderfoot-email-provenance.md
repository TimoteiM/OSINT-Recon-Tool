# SpiderFoot Email Provenance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Preserve SpiderFoot email provenance in reports without changing the existing email discovery functionality.

**Architecture:** Keep `emails` as the stable compatibility layer and add a parallel `email_sources` metadata array in SpiderFoot provider results and top-level identities data. Populate provenance during event-row ingestion and let the dashboard render it as optional secondary detail.

**Tech Stack:** TypeScript, Node.js, React, existing SpiderFoot polling/report merge pipeline

---

### Task 1: Add failing backend tests for email provenance

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`

**Step 1: Write the failing test**

Add tests proving:
- `EMAILADDR` still lands in `provider_result.emails`
- `EMAILADDR_GENERIC` still lands in `provider_result.emails`
- both events create provenance entries with module and API/public classification
- `job.report.identities.email_sources` is populated

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`

Expected: FAIL because `email_sources` does not exist yet.

**Step 3: Write minimal implementation**

Add the smallest backend changes needed to collect and expose provenance.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`

Expected: PASS

### Task 2: Implement backend provenance storage

**Files:**
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Add a typed provenance shape**

Create an internal `SpiderfootEmailSource` type and add `email_sources` to `SpiderfootProviderResult`.

**Step 2: Capture provenance during event ingestion**

When processing `EMAILADDR` and `EMAILADDR_GENERIC`, capture:
- normalized email
- SpiderFoot module name from the event row
- source value from the event row
- event type
- derived `module_type`
- derived `api_backed`

**Step 3: Expose provenance in partial reports**

Include `email_sources` in `identities` and the provider result payload.

**Step 4: Keep compatibility**

Do not remove or change `emails`.

### Task 3: Wire optional provenance into the dashboard

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`

**Step 1: Extend frontend types**

Add optional `email_sources` to `IdentityData` and `ProviderResult`.

**Step 2: Merge SpiderFoot provenance**

Extend the existing SpiderFoot report merge so `identities.email_sources` is merged by a stable key.

**Step 3: Render optional provenance**

Show a small secondary source line beneath each email when provenance exists, but keep the email list working if it does not.

### Task 4: Verify

**Files:**
- Modify if needed: `server/spiderfoot-jobs.test.ts`
- Modify if needed: `client/src/pages/Dashboard.tsx`

**Step 1: Run targeted tests**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/typecheck.test.ts`

Expected: PASS

**Step 2: Run build**

Run: `npm run build`

Expected: PASS
