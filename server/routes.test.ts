import assert from "node:assert/strict";
import test from "node:test";

import { normalizeReconError, splitSpiderfootSelection } from "./routes";

test("normalizeReconError maps timeout-style recon failures to a non-500 scan response", () => {
  const result = normalizeReconError(
    new Error(
      JSON.stringify({
        error: "OSINT scan exceeded the configured timeout before producing JSON output",
        logs: "[*] SSL inspection: example.com",
      }),
    ),
  );

  assert.equal(result.status, 200);
  assert.equal(result.body.success, false);
  assert.equal(result.body.error, "OSINT scan exceeded the configured timeout before producing JSON output");
  assert.equal(result.body.logs, "[*] SSL inspection: example.com");
});

test("normalizeReconError keeps unexpected recon failures as server errors", () => {
  const result = normalizeReconError(new Error("boom"));

  assert.equal(result.status, 500);
  assert.deepEqual(result.body, { error: "boom" });
});

test("splitSpiderfootSelection removes spiderfoot from inline sources and keeps the background flag", () => {
  const result = splitSpiderfootSelection(["whois", "spiderfoot", "ssl_inspection"]);

  assert.deepEqual(result.inlineSources, ["whois", "ssl_inspection"]);
  assert.equal(result.backgroundProviderId, "spiderfoot");
});

test("splitSpiderfootSelection leaves non-spiderfoot selections unchanged", () => {
  const result = splitSpiderfootSelection(["whois", "ssl_inspection"]);

  assert.deepEqual(result.inlineSources, ["whois", "ssl_inspection"]);
  assert.equal(result.backgroundProviderId, null);
});

test("splitSpiderfootSelection prefers spiderfoot_deep when both SpiderFoot modes are selected", () => {
  const result = splitSpiderfootSelection(["whois", "spiderfoot", "spiderfoot_deep", "ssl_inspection"]);

  assert.deepEqual(result.inlineSources, ["whois", "ssl_inspection"]);
  assert.equal(result.backgroundProviderId, "spiderfoot_deep");
});
