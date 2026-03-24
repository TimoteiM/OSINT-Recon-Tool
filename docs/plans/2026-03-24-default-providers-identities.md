# Default Providers And Identities Enrichment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make every selectable provider enabled by default and turn the Identities tab into a deduplicated canonical view that stays clean during live SpiderFoot enrichment.

**Architecture:** Update provider-default selection at the shared catalog layer, then add a shared client-side identity normalization layer for emails, social profiles, and impersonation candidates. Reuse the existing SpiderFoot live-merge path so long-running providers keep progressive updates without changing their backend orchestration.

**Tech Stack:** TypeScript, React, shared provider catalog helpers, Node test runner, Vite build

---

### Task 1: Make all selectable providers default-selected

**Files:**
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing test**

Add a test asserting `getDefaultSelectedProviderIds()` equals `getSelectableProviderIds()`.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/provider-catalog.test.ts`

Expected: FAIL because not all selectable providers are default-selected yet.

**Step 3: Write minimal implementation**

Change `getDefaultSelectedProviderIds()` to return every selectable provider ID.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/provider-catalog.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add shared/osint-providers.ts server/provider-catalog.test.ts
git commit -m "feat: default to all selectable providers"
```

### Task 2: Add a shared identities normalization helper

**Files:**
- Create: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-normalization.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-normalization.test.ts`

**Step 1: Write the failing test**

Add tests covering:

- duplicate emails collapse case-insensitively
- richer email provenance wins when duplicates exist
- social profiles dedupe by normalized platform and URL
- impersonation candidates remain deduped using the existing cleanup helper

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx client/src/lib/identity-normalization.test.ts`

Expected: FAIL because the helper does not exist yet.

**Step 3: Write minimal implementation**

Create a shared normalization module that returns canonical:

- `emails`
- `emailSourceMap`
- `socialProfiles`
- `impersonationCandidates`

Use lowercasing and URL normalization to collapse duplicates safely.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx client/src/lib/identity-normalization.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add client/src/lib/identity-normalization.ts client/src/lib/identity-normalization.test.ts
git commit -m "feat: add identity normalization helpers"
```

### Task 3: Use canonical identities in the dashboard and live SpiderFoot merge

**Files:**
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\pages\Dashboard.tsx`
- Reuse: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\impersonation-candidates.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-normalization.test.ts`

**Step 1: Write the failing test**

Extend the normalization tests or add a UI-adjacent unit test proving a live merge with repeated SpiderFoot email/social/candidate data still renders one canonical entry per identity.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx client/src/lib/identity-normalization.test.ts`

Expected: FAIL because the live merge path still performs ad hoc merging.

**Step 3: Write minimal implementation**

Update `Dashboard.tsx` so:

- initial Identities rendering uses the shared normalization helper
- `mergeSpiderfootJobIntoResult()` normalizes merged identities after combining new live data
- the Identities panel uses canonical social profiles and canonical email provenance

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx client/src/lib/identity-normalization.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add client/src/pages/Dashboard.tsx client/src/lib/identity-normalization.test.ts
git commit -m "feat: dedupe identities in dashboard"
```

### Task 4: Verify provider defaults and app build

**Files:**
- Verify only

**Step 1: Run focused tests**

Run:

```bash
node --test --import tsx server/provider-catalog.test.ts client/src/lib/identity-normalization.test.ts server/routes.test.ts
```

Expected: PASS.

**Step 2: Run production build**

Run:

```bash
npm run build
```

Expected: PASS.

**Step 3: Manual sanity check**

Start the dev server and confirm:

- all selectable providers are preselected on first load
- `spiderfoot`/`spiderfoot_deep` still appear as running/live providers when selected
- Identities shows deduplicated emails, social profiles, and impersonation candidates

**Step 4: Commit**

```bash
git add .
git commit -m "feat: enrich default providers and identities"
```
