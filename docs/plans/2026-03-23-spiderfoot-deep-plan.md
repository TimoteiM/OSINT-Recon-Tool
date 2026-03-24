# SpiderFoot Deep Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new `SpiderFoot Deep` provider that runs through the existing background SpiderFoot API flow but expands email, breach, credential, and impersonation-candidate coverage.

**Architecture:** Reuse the current SpiderFoot job manager and polling endpoints, but make them mode-aware with a provider id and a deeper event profile. Keep the UI contract stable by continuing to return one `spiderfoot_job` object, now annotated with `provider_id`, and merge job payloads into the matching provider card.

**Tech Stack:** TypeScript, Express, shared provider catalog, React dashboard polling UI, Node test runner

---

### Task 1: Add failing tests for the new selectable provider and route selection

**Files:**
- Modify: `server/provider-catalog.test.ts`
- Modify: `server/routes.test.ts`
- Modify: `shared/osint-providers.ts`
- Modify: `server/routes.ts`

**Step 1: Write the failing test**

```ts
test("provider catalog exposes SpiderFoot Deep as a selectable provider", () => {
  const selectable = new Set(getSelectableProviderIds());
  assert.ok(selectable.has("spiderfoot_deep"));
});

test("splitSpiderfootSelection prefers spiderfoot_deep when both SpiderFoot modes are selected", () => {
  const result = splitSpiderfootSelection(["spiderfoot", "spiderfoot_deep", "whois"]);
  assert.deepEqual(result.inlineSources, ["whois"]);
  assert.equal(result.backgroundProviderId, "spiderfoot_deep");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/provider-catalog.test.ts server/routes.test.ts`
Expected: FAIL because `spiderfoot_deep` does not exist and route selection only knows about `spiderfoot`

**Step 3: Write minimal implementation**

Add `spiderfoot_deep` to the shared provider catalog and make route splitting mode-aware.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/provider-catalog.test.ts server/routes.test.ts`
Expected: PASS

### Task 2: Add failing tests for deep-mode breach and impersonation parsing

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

```ts
test("SpiderFoot Deep maps breach and impersonation event types into provider findings", async () => {
  const job = await startSpiderfootJob({ companyName: "metrorex.ro", providerId: "spiderfoot_deep", ... });
  await pollSpiderfootJob(job.job_id, { transport: fakeTransportWithDeepEvents });
  const snapshot = getSpiderfootJob(job.job_id);
  assert.ok(snapshot?.provider_result.breach_hints?.length);
  assert.ok(snapshot?.provider_result.impersonation_candidates?.length);
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because current parser ignores those event types

**Step 3: Write minimal implementation**

Add provider-aware event parsing and map deep breach/credential/impersonation event types into existing fields.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

### Task 3: Make SpiderFoot jobs provider-aware

**Files:**
- Modify: `server/spiderfoot-jobs.ts`
- Modify: `server/routes.ts`
- Modify: `client/src/pages/Dashboard.tsx`

**Step 1: Write the failing test**

```ts
test("SpiderFoot jobs expose the selected provider id in their snapshot", async () => {
  const job = await startSpiderfootJob({ companyName: "metrorex.ro", providerId: "spiderfoot_deep", ... });
  assert.equal(job.provider_id, "spiderfoot_deep");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because jobs are hard-coded to `spiderfoot`

**Step 3: Write minimal implementation**

Add `provider_id` to the job shape, create the right running provider result in `/api/recon`, and make the dashboard merge job updates into the matching provider card.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/routes.test.ts`
Expected: PASS

### Task 4: Verify full stack behavior

**Files:**
- Modify: `shared/osint-providers.ts`
- Modify: `server/routes.ts`
- Modify: `server/spiderfoot-jobs.ts`
- Modify: `client/src/pages/Dashboard.tsx`
- Modify: `server/provider-catalog.test.ts`
- Modify: `server/routes.test.ts`
- Modify: `server/spiderfoot-jobs.test.ts`

**Step 1: Run focused tests**

Run: `node --test --import tsx server/provider-catalog.test.ts server/routes.test.ts server/spiderfoot-jobs.test.ts server/recon-runner.test.ts`
Expected: PASS

**Step 2: Build app**

Run: `npm run build`
Expected: PASS

**Step 3: Restart local app and verify live mode selection**

Run: `POST /api/recon` with `["spiderfoot_deep"]`
Expected: quick response with `spiderfoot_job.provider_id === "spiderfoot_deep"`

Run: poll `/api/recon/jobs/:jobId`
Expected: `SpiderFoot Deep` provider receives live findings including breach hints and possible impersonation candidates when SpiderFoot emits them
