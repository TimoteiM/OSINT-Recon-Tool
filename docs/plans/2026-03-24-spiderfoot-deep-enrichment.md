# SpiderFoot Deep Enrichment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn `SpiderFoot Deep` into an email/leak/social enrichment mode and ensure the Identities tab only renders clean, clickable profile-style SpiderFoot findings.

**Architecture:** Keep lightweight `spiderfoot` behavior intact while giving `spiderfoot_deep` a dedicated scan configuration and a stricter backend normalization layer. Normalize raw SpiderFoot events into clean identity records on the server, then rely on the existing dashboard merge/render flow to display only trusted social and impersonation findings.

**Tech Stack:** TypeScript, Express, React, existing Node test runner with `tsx`

---

### Task 1: Lock the new SpiderFoot Deep scan configuration with tests

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

Add a test that starts a `spiderfoot_deep` job with a mocked transport and asserts:
- `usecase` is no longer the plain passive mode used by `spiderfoot`
- `typelist` still includes leak/email event types
- deep mode can provide a curated `modulelist`

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because `spiderfoot_deep` still uses the passive configuration.

**Step 3: Write minimal implementation**

Add a helper in `server/spiderfoot-jobs.ts` that returns scan config by provider ID and use it when posting `/startscan`.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 2: Lock backend normalization for clean social profiles and impersonation candidates

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing tests**

Add tests that verify:
- a recognized social URL is stored in `social_profiles`
- a clean clickable account/profile URL is stored in `impersonation_candidates`
- a bare username with no URL is ignored
- an affiliate-domain hint with no profile URL is ignored
- an encoded `SFURL` payload is normalized into a real URL when possible

**Step 2: Run tests to verify they fail**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because current normalization accepts noisy candidates and does not parse encoded profile links.

**Step 3: Write minimal implementation**

Add normalization helpers in `server/spiderfoot-jobs.ts` to:
- extract/clean URLs from SpiderFoot values
- classify supported profile hosts
- generate clean app-level candidate objects
- drop non-clickable or malformed findings

**Step 4: Run tests to verify they pass**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 3: Lock backend breach-hint handling for deep enrichment

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

Add a test that verifies `LEAKSITE_URL`, `LEAKSITE_CONTENT`, and compromised-email style events are preserved as `breach_hints` for deep scans when they carry target-relevant evidence.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL if the current filter drops useful leak evidence.

**Step 3: Write minimal implementation**

Adjust deep breach filtering so meaningful leak evidence survives normalization without flooding the UI with unrelated noise.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 4: Lock dashboard rendering against noisy SpiderFoot identity entries

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`
- Modify: `server/typecheck.test.ts`

**Step 1: Write the failing test**

Add or extend a type-level or rendering-adjacent test that reflects the stricter identity contract, then update `Dashboard.tsx` logic so the impersonation section assumes clickable candidates only.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/typecheck.test.ts`
Expected: FAIL if the new candidate normalization contract is not reflected cleanly in the dashboard flow.

**Step 3: Write minimal implementation**

Update `Dashboard.tsx` merge/render helpers to:
- preserve normalized social profile links
- render impersonation entries with clean labels and clickable URLs
- avoid displaying placeholder `unknown` values when the backend omitted weak candidates

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/typecheck.test.ts`
Expected: PASS

### Task 5: Run focused verification and production build

**Files:**
- No new files

**Step 1: Run focused tests**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/typecheck.test.ts`
Expected: PASS

**Step 2: Run production build**

Run: `npm run build`
Expected: PASS

**Step 3: Commit**

```bash
git add docs/plans/2026-03-24-spiderfoot-deep-enrichment-design.md docs/plans/2026-03-24-spiderfoot-deep-enrichment.md server/spiderfoot-jobs.ts server/spiderfoot-jobs.test.ts client/src/pages/Dashboard.tsx server/typecheck.test.ts
git commit -m "feat: improve spiderfoot deep identity enrichment"
```
