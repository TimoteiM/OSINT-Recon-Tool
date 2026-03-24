# SpiderFoot Auth Email Enrichment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `spiderfoot_deep` use authenticated SpiderFoot email/breach modules from existing `.env` keys while keeping public fallback email modules enabled.

**Architecture:** Extend the deep SpiderFoot scan configuration with a module-option builder that derives SpiderFoot-compatible settings from `.env`. Apply those options only to deep scans, keep lightweight `spiderfoot` unchanged, and let missing keys degrade gracefully without blocking the scan.

**Tech Stack:** TypeScript, Express, SpiderFoot local web API, Node test runner with `tsx`

---

### Task 1: Lock env-to-SpiderFoot option mapping with tests

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

Add a test that verifies `spiderfoot_deep` derives module options from env:
- `Hunter_API_KEY` or `HunterIO_API_KEY` maps to `sfp_hunter.api_key`
- `HaveIBeenPwned_API_KEY` maps to `sfp_haveibeenpwned.api_key`
- missing values are omitted

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because deep scans do not currently build or apply module options from env.

**Step 3: Write minimal implementation**

Add a helper in `server/spiderfoot-jobs.ts` that builds deep SpiderFoot module options from env.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 2: Lock scan startup behavior for deep-only auth config

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

Add a test that verifies:
- `spiderfoot_deep` applies the module options during scan startup
- plain `spiderfoot` does not try to apply deep auth options
- fallback modules remain in the deep module list regardless of env

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because startup currently only posts `/startscan`.

**Step 3: Write minimal implementation**

Update the SpiderFoot startup path to apply the derived options before launching the deep scan.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 3: Run focused verification and build

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
git add docs/plans/2026-03-24-spiderfoot-auth-email-design.md docs/plans/2026-03-24-spiderfoot-auth-email.md server/spiderfoot-jobs.ts server/spiderfoot-jobs.test.ts
git commit -m "feat: wire spiderfoot deep auth email modules"
```
