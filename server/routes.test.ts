import assert from "node:assert/strict";
import test from "node:test";

import {
  attachSherlockBackgroundScan,
  attachSpiderfootBackgroundScan,
  hasInvalidRequestedProviderIds,
  splitBackgroundSelection,
} from "./routes";

test("route validation accepts google_dorks by itself", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google_dorks"]), false);
});

test("route validation accepts legacy google alias alongside google_dorks", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google", "google_dorks"]), false);
});

test("route validation rejects unknown provider IDs", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google_dorks", "not_real"]), true);
});

test("splitBackgroundSelection keeps non-background providers inline", () => {
  assert.deepEqual(splitBackgroundSelection(["google_dorks"]), {
    inlineSources: ["google_dorks"],
    backgroundProviderIds: [],
  });
});

test("splitBackgroundSelection moves Sherlock and SpiderFoot providers to the background list", () => {
  assert.deepEqual(splitBackgroundSelection(["google_dorks", "sherlock", "spiderfoot", "spiderfoot_deep"]), {
    inlineSources: ["google_dorks"],
    backgroundProviderIds: ["spiderfoot_deep", "sherlock"],
  });
});

test("attachSpiderfootBackgroundScan preserves the report when SpiderFoot startup fails", async () => {
  const report: Record<string, any> = { provider_results: {} };

  await attachSpiderfootBackgroundScan(
    report,
    "expertware.net",
    "spiderfoot_deep",
    async () => {
      throw new Error("SpiderFoot optsraw did not return a token");
    },
  );

  assert.equal(report.spiderfoot_job, undefined);
  assert.equal(report.provider_results.spiderfoot_deep.status, "error");
  assert.deepEqual(report.provider_results.spiderfoot_deep.notes, [
    "SpiderFoot startup failed: SpiderFoot optsraw did not return a token",
  ]);
});

test("attachSherlockBackgroundScan preserves the report when Sherlock startup fails", async () => {
  const report: Record<string, any> = { provider_results: {} };

  await attachSherlockBackgroundScan(
    report,
    "expertware.net",
    async () => {
      throw new Error("Sherlock runner failed to start");
    },
  );

  assert.equal(report.background_jobs, undefined);
  assert.equal(report.provider_results.sherlock.status, "error");
  assert.deepEqual(report.provider_results.sherlock.notes, [
    "Sherlock startup failed: Sherlock runner failed to start",
  ]);
});

test("attachSherlockBackgroundScan attaches a retrievable Sherlock job summary", async () => {
  const report: Record<string, any> = { provider_results: {} };

  await attachSherlockBackgroundScan(
    report,
    "expertware.net",
    async () => ({
      job_id: "job-123",
      provider_id: "sherlock",
      scan_id: "scan-123",
      company_name: "expertware.net",
      target_domain: "expertware.net",
      status: "running",
      started_at: "2026-03-24T12:00:00.000Z",
      updated_at: "2026-03-24T12:00:00.000Z",
      elapsed_ms: 0,
      progress_logs: [],
      provider_result: {
        status: "running",
        notes: [],
        progress_logs: [],
        duration_ms: null,
        emails: [],
        email_sources: [],
        social_profiles: {},
        impersonation_candidates: [],
        subdomains: [],
        repos: [],
        breach_hints: [],
        dns_records: [],
        whois: [],
        ssl: [],
        tech: [],
        ports: [],
        hosting: [],
        mentions: [],
      },
      report: null,
    } as any),
  );

  assert.equal(report.provider_results.sherlock.status, "running");
  assert.equal(report.sherlock_job.job_id, "job-123");
  assert.equal(report.sherlock_job.provider_id, "sherlock");
  assert.equal(report.sherlock_job.scan_id, "scan-123");
  assert.equal(report.background_jobs[0].scan_id, "scan-123");
});
