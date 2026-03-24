import assert from "node:assert/strict";
import test from "node:test";

import { attachSpiderfootBackgroundScan, hasInvalidRequestedProviderIds, splitSpiderfootSelection } from "./routes";

test("route validation accepts google_dorks by itself", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google_dorks"]), false);
});

test("route validation accepts legacy google alias alongside google_dorks", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google", "google_dorks"]), false);
});

test("route validation rejects unknown provider IDs", () => {
  assert.equal(hasInvalidRequestedProviderIds(["google_dorks", "not_real"]), true);
});

test("splitSpiderfootSelection keeps non-spiderfoot providers inline", () => {
  assert.deepEqual(splitSpiderfootSelection(["google_dorks"]), {
    inlineSources: ["google_dorks"],
    backgroundProviderId: null,
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
