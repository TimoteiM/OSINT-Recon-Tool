# SpiderFoot Live API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current log-only SpiderFoot background runner with a real SpiderFoot web/API scan flow that streams live findings into the existing report while the scan is running.

**Architecture:** Keep the main `/api/recon` request fast by continuing to split SpiderFoot into a background job, but change the job runner to manage a long-lived embedded SpiderFoot web server and poll SpiderFoot's own `/startscan`, `/scanstatus`, `/scanlog`, and `/scaneventresults` endpoints. Translate SpiderFoot event rows into the existing provider/report shape incrementally so the dashboard can update the provider card and aggregate sections without waiting for scan completion.

**Tech Stack:** Node.js, TypeScript, Express, native `fetch`, `child_process.spawn`, SpiderFoot `sf.py` web server, Node test runner, React dashboard polling UI

---

### Task 1: Write the failing SpiderFoot API client tests

**Files:**
- Create: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

```ts
test("startSpiderfootJob starts a SpiderFoot API scan and stores the returned scan id", async () => {
  const transport = createFakeSpiderFootTransport({
    startscan: ["SUCCESS", "scan-123"],
  });

  const job = await startSpiderfootJob({
    companyName: "metrorex.ro",
    transport,
    ensureService: async () => {},
  });

  assert.equal(job.scan_id, "scan-123");
  assert.equal(job.status, "running");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because `startSpiderfootJob()` is synchronous today and does not call SpiderFoot API endpoints or expose `scan_id`

**Step 3: Write minimal implementation**

```ts
export async function startSpiderfootJob(...) {
  await ensureService();
  const response = await transport.post("/startscan", payload);
  const [, scanId] = response;
  return createJob({ scanId, status: "running" });
}
```

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts server/spiderfoot-jobs.test.ts
git commit -m "test: cover SpiderFoot API job startup"
```

### Task 2: Write the failing partial-results polling tests

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

```ts
test("pollSpiderfootJob merges live event rows into provider findings before completion", async () => {
  const job = createJobForTest("scan-123");
  const transport = createFakeSpiderFootTransport({
    scanstatus: ["scan", "metrorex.ro", "", "", "", "RUNNING", {}],
    scanlog: [["2026-03-23 10:00:00", "INFO", "STATUS", "Email harvesting", 5]],
    scaneventresults: [
      ["2026-03-23 10:00:01", "EMAILADDR", "contact@metrorex.ro", "module", "src", "", "", "", "", "", "id-1"],
      ["2026-03-23 10:00:02", "INTERNET_NAME", "mail.metrorex.ro", "module", "src", "", "", "", "", "", "id-2"],
    ],
  });

  await pollSpiderfootJob(job.job_id, { transport });

  assert.deepEqual(job.provider_result.emails, ["contact@metrorex.ro"]);
  assert.deepEqual(job.provider_result.subdomains, ["mail.metrorex.ro"]);
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because current background job only appends stderr logs and waits for final JSON

**Step 3: Write minimal implementation**

```ts
const events = await transport.get("/scaneventresults", { id: job.scan_id });
mergeSpiderFootEventsIntoProvider(job.provider_result, events, job.domain);
job.progress_logs = mergeLogs(job.progress_logs, await transport.get("/scanlog", { id: job.scan_id }));
```

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts server/spiderfoot-jobs.test.ts
git commit -m "feat: merge live SpiderFoot API findings into jobs"
```

### Task 3: Write the failing completion and error-state tests

**Files:**
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/spiderfoot-jobs.ts`

**Step 1: Write the failing test**

```ts
test("pollSpiderfootJob marks the job completed when SpiderFoot reports FINISHED", async () => {
  const job = createJobForTest("scan-123");
  const transport = createFakeSpiderFootTransport({
    scanstatus: ["scan", "metrorex.ro", "", "", "", "FINISHED", {}],
    scanlog: [],
    scaneventresults: [],
  });

  await pollSpiderfootJob(job.job_id, { transport });

  assert.equal(job.status, "completed");
  assert.equal(job.provider_result.status, "ok");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because current code only transitions on child-process exit

**Step 3: Write minimal implementation**

```ts
if (scanState === "FINISHED") {
  job.status = "completed";
  job.provider_result.status = hasFindings(job.provider_result) ? "ok" : "partial";
}
if (scanState === "ABORTED" || scanState === "ERROR-FAILED") {
  job.status = "error";
  job.provider_result.status = "error";
}
```

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts server/spiderfoot-jobs.test.ts
git commit -m "feat: finalize SpiderFoot API job states"
```

### Task 4: Replace the background CLI runner with the API-backed service manager

**Files:**
- Modify: `server/spiderfoot-jobs.ts`
- Modify: `server/routes.ts`
- Test: `server/spiderfoot-jobs.test.ts`

**Step 1: Write the failing test**

```ts
test("getSpiderfootJob returns incrementally updated report data while the scan is running", async () => {
  const job = await startSpiderfootJob(...);
  await pollSpiderfootJob(job.job_id, ...);

  const snapshot = getSpiderfootJob(job.job_id);

  assert.equal(snapshot?.provider_result.status, "running");
  assert.match(snapshot?.progress_logs[0] ?? "", /Email harvesting/);
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/routes.test.ts`
Expected: FAIL because route snapshots are still tied to the old spawned CLI job lifecycle

**Step 3: Write minimal implementation**

```ts
ensureSpiderfootService();
scheduleJobPolling(job.job_id);
return job;
```

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/routes.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts server/routes.ts server/spiderfoot-jobs.test.ts server/routes.test.ts
git commit -m "feat: back SpiderFoot jobs with the live API service"
```

### Task 5: Update the dashboard merge path for richer live SpiderFoot payloads

**Files:**
- Modify: `client/src/pages/Dashboard.tsx`
- Test: `server/spiderfoot-jobs.test.ts`

**Step 1: Write the failing test**

```ts
test("SpiderFoot job snapshots include partial report sections for the dashboard merge path", async () => {
  const snapshot = buildSpiderfootJobSnapshot({
    provider_result: {
      emails: ["contact@metrorex.ro"],
      subdomains: ["mail.metrorex.ro"],
    },
  });

  assert.deepEqual(snapshot.report.identities.emails, ["contact@metrorex.ro"]);
  assert.equal(snapshot.report.dns.subdomains[0].subdomain, "mail.metrorex.ro");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: FAIL because the current job payload does not build a partial merged report from live API findings

**Step 3: Write minimal implementation**

```ts
job.report = buildSpiderfootPartialReport(job.provider_result);
```

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts client/src/pages/Dashboard.tsx server/spiderfoot-jobs.test.ts
git commit -m "feat: surface live SpiderFoot report snapshots to the dashboard"
```

### Task 6: Verify the full stack and rebuild the local app

**Files:**
- Modify: `server/spiderfoot-jobs.ts`
- Modify: `server/routes.ts`
- Modify: `client/src/pages/Dashboard.tsx`
- Modify: `server/spiderfoot-jobs.test.ts`
- Modify: `server/routes.test.ts`

**Step 1: Run focused server tests**

Run: `node --test --import tsx server/spiderfoot-jobs.test.ts server/routes.test.ts server/recon-runner.test.ts`
Expected: PASS

**Step 2: Run the frontend build**

Run: `npm run build`
Expected: PASS

**Step 3: Restart the local app**

Run: `node codex-launch-local.cjs`
Expected: local server starts on `http://127.0.0.1:5000`

**Step 4: Verify the live SpiderFoot flow**

Run: `Invoke-RestMethod -Method Post -Uri http://localhost:5000/api/recon -ContentType 'application/json' -Body '{"company":"metrorex.ro","sources":["spiderfoot"]}'`
Expected: response returns quickly with `spiderfoot_job.job_id`

Run: `Invoke-RestMethod http://localhost:5000/api/recon/jobs/<job_id>`
Expected: response shows changing `progress_logs`, `elapsed_ms`, and non-empty partial findings before completion

**Step 5: Commit**

```bash
git add server/spiderfoot-jobs.ts server/routes.ts client/src/pages/Dashboard.tsx server/spiderfoot-jobs.test.ts server/routes.test.ts docs/plans/2026-03-23-spiderfoot-live-api-plan.md
git commit -m "feat: stream SpiderFoot live API findings"
```
