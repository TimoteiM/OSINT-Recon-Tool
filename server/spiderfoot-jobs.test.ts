import assert from "node:assert/strict";
import test from "node:test";

import { getSpiderfootJob, pollSpiderfootJob, startSpiderfootJob } from "./spiderfoot-jobs";

type FakeTransport = {
  postJson: (path: string, params?: Record<string, unknown>) => Promise<unknown>;
  getJson: (path: string, params?: Record<string, unknown>) => Promise<unknown>;
};

function createFakeSpiderfootTransport(responses: {
  startscan?: unknown[];
  scanstatus?: unknown[];
  scanlog?: unknown[][];
  scaneventresults?: unknown[][];
}): FakeTransport {
  const scanstatusQueue = [...(responses.scanstatus || [])];
  const scanlogQueue = [...(responses.scanlog || [])];
  const scaneventresultsQueue = [...(responses.scaneventresults || [])];

  return {
    async postJson(path) {
      if (path === "/startscan") {
        return responses.startscan || ["SUCCESS", "scan-123"];
      }
      throw new Error(`Unhandled POST ${path}`);
    },
    async getJson(path) {
      if (path === "/scanlist") {
        return [];
      }
      if (path === "/scanstatus") {
        return scanstatusQueue.shift() || ["scan-123", "metrorex.ro", "", "", "", "RUNNING", {}];
      }
      if (path === "/scanlog") {
        return scanlogQueue.shift() || [];
      }
      if (path === "/scaneventresults") {
        return scaneventresultsQueue.shift() || [];
      }
      throw new Error(`Unhandled GET ${path}`);
    },
  };
}

test("startSpiderfootJob starts a SpiderFoot API scan and stores the returned scan id", async () => {
  const job = await startSpiderfootJob({
    companyName: "startup.metrorex.ro",
    providerId: "spiderfoot",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-123"],
    }),
    schedulePolling: false,
  });

  assert.equal(job.scan_id, "scan-123");
  assert.equal(job.status, "running");
  assert.equal(job.provider_id, "spiderfoot");
});

test("startSpiderfootJob reuses an existing running SpiderFoot scan for the same target", async () => {
  let startscanCalled = false;
  const job = await startSpiderfootJob({
    companyName: "reuse-scan.metrorex.ro",
    providerId: "spiderfoot",
    ensureService: async () => {},
    transport: {
      async postJson(path) {
        if (path === "/startscan") {
          startscanCalled = true;
        }
        throw new Error("startscan should not be called when a running scan already exists");
      },
      async getJson(path) {
        if (path === "/scanlist") {
          return [
            ["ABC12345", "reuse-scan.metrorex.ro", "reuse-scan.metrorex.ro", "", "", "Not yet", "RUNNING", 10, {}],
          ];
        }
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.equal(startscanCalled, false);
  assert.equal(job.scan_id, "ABC12345");
  assert.equal(job.status, "running");
});

test("SpiderFoot Deep does not reuse a passive SpiderFoot scan for the same target", async () => {
  let startscanCalls = 0;
  const job = await startSpiderfootJob({
    companyName: "deep-isolated.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: {
      async postJson(path) {
        if (path === "/startscan") {
          startscanCalls += 1;
          return ["SUCCESS", "DEEP9999"];
        }
        throw new Error(`Unhandled POST ${path}`);
      },
      async getJson(path) {
        if (path === "/scanlist") {
          return [
            ["ABC12345", "metrorex.ro", "metrorex.ro", "", "", "Not yet", "RUNNING", 10, {}],
          ];
        }
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.equal(startscanCalls, 1);
  assert.equal(job.scan_id, "DEEP9999");
});

test("startSpiderfootJob reuses an existing in-memory running job before calling SpiderFoot again", async () => {
  const firstJob = await startSpiderfootJob({
    companyName: "reuse-job.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "MEM12345"],
    }),
    schedulePolling: false,
  });

  let touchedSpiderFoot = false;
  const secondJob = await startSpiderfootJob({
    companyName: "reuse-job.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: {
      async postJson() {
        touchedSpiderFoot = true;
        throw new Error("should not call SpiderFoot");
      },
      async getJson() {
        touchedSpiderFoot = true;
        throw new Error("should not call SpiderFoot");
      },
    },
    schedulePolling: false,
  });

  assert.equal(touchedSpiderFoot, false);
  assert.equal(secondJob.job_id, firstJob.job_id);
});

test("pollSpiderfootJob merges live event rows into provider findings before completion", async () => {
  const job = await startSpiderfootJob({
    companyName: "poll.metrorex.ro",
    providerId: "spiderfoot",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-123"],
      scanstatus: [["scan-123", "metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-23 10:00:00", "INFO", "STATUS", "Email harvesting", 5]]],
      scaneventresults: [[
        ["2026-03-23 10:00:01", "contact@poll.metrorex.ro", "poll.metrorex.ro", "module", 100, 100, 0, "id-1", 0, 0, "EMAILADDR"],
        ["2026-03-23 10:00:02", "mail.poll.metrorex.ro", "poll.metrorex.ro", "module", 100, 100, 0, "id-2", 0, 0, "INTERNET_NAME"],
      ]],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-123", "metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-23 10:00:00", "INFO", "STATUS", "Email harvesting", 5]]],
      scaneventresults: [[
        ["2026-03-23 10:00:01", "contact@poll.metrorex.ro", "poll.metrorex.ro", "module", 100, 100, 0, "id-1", 0, 0, "EMAILADDR"],
        ["2026-03-23 10:00:02", "mail.poll.metrorex.ro", "poll.metrorex.ro", "module", 100, 100, 0, "id-2", 0, 0, "INTERNET_NAME"],
        ["2026-03-23 10:00:03", "95.76.156.205", "poll.metrorex.ro", "module", 100, 100, 0, "id-3", 0, 0, "IP_ADDRESS"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.emails, ["contact@poll.metrorex.ro"]);
  assert.deepEqual(snapshot?.provider_result.subdomains, ["mail.poll.metrorex.ro"]);
  assert.deepEqual(snapshot?.provider_result.hosting, [{ value: "95.76.156.205", type: "IP_ADDRESS" }]);
  assert.match(snapshot?.progress_logs[0] ?? "", /Email harvesting/);
});

test("pollSpiderfootJob marks the job completed when SpiderFoot reports FINISHED", async () => {
  const job = await startSpiderfootJob({
    companyName: "finished.metrorex.ro",
    providerId: "spiderfoot",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-123"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-123", "metrorex.ro", "", "", "", "FINISHED", {}]],
      scanlog: [[]],
      scaneventresults: [[]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.status, "completed");
  assert.equal(snapshot?.provider_result.status, "partial");
});

test("SpiderFoot Deep maps breach and impersonation event types into provider findings", async () => {
  const job = await startSpiderfootJob({
    companyName: "metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-deep"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-deep", "metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-23 10:00:00", "INFO", "STATUS", "Deep enrichment", 9]]],
      scaneventresults: [[
        ["2026-03-23 10:00:01", "alice@metrorex.ro", "metrorex.ro", "module", 100, 100, 0, "deep-1", 0, 0, "EMAILADDR"],
        ["2026-03-23 10:00:02", "alice@metrorex.ro [paste-1]", "metrorex.ro", "module", 100, 100, 0, "deep-2", 0, 0, "EMAILADDR_COMPROMISED"],
        ["2026-03-23 10:00:03", "alice:Password123 [paste-1]", "metrorex.ro", "module", 100, 100, 0, "deep-3", 0, 0, "PASSWORD_COMPROMISED"],
        ["2026-03-23 10:00:04", "https://facebook.com/metrorex.support", "metrorex.ro", "module", 100, 100, 0, "deep-4", 0, 0, "SOCIAL_MEDIA"],
        ["2026-03-23 10:00:05", "metrorex-support.ro", "metrorex.ro", "module", 100, 100, 0, "deep-5", 0, 0, "AFFILIATE_DOMAIN_NAME"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.provider_id, "spiderfoot_deep");
  assert.ok((snapshot?.provider_result.breach_hints || []).length > 0);
  assert.ok((snapshot?.provider_result.impersonation_candidates || []).length > 0);
});

test("SpiderFoot Deep does not promote weak affiliate domains to impersonation candidates", async () => {
  const job = await startSpiderfootJob({
    companyName: "noise.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-noise"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-noise", "noise.metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-23 10:00:00", "INFO", "STATUS", "Noise filtering", 12]]],
      scaneventresults: [[
        ["2026-03-23 10:00:01", "random-domain/noise.metrorex.ro", "noise.metrorex.ro", "module", 100, 100, 0, "noise-1", 0, 0, "AFFILIATE_DOMAIN_NAME"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.impersonation_candidates, []);
  assert.equal(snapshot?.provider_result.mentions?.length ?? 0, 0);
});

test("SpiderFoot Deep keeps breach hints only when they include target-domain email evidence", async () => {
  const job = await startSpiderfootJob({
    companyName: "evidence.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-evidence"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-evidence", "evidence.metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-23 10:00:00", "INFO", "STATUS", "Evidence filtering", 15]]],
      scaneventresults: [[
        ["2026-03-23 10:00:01", "alice@evidence.metrorex.ro [paste-1]", "evidence.metrorex.ro", "module", 100, 100, 0, "ev-1", 0, 0, "EMAILADDR_COMPROMISED"],
        ["2026-03-23 10:00:02", "bob@gmail.com [paste-2]", "evidence.metrorex.ro", "module", 100, 100, 0, "ev-2", 0, 0, "EMAILADDR_COMPROMISED"],
        ["2026-03-23 10:00:03", "Password123 leaked", "evidence.metrorex.ro", "module", 100, 100, 0, "ev-3", 0, 0, "PASSWORD_COMPROMISED"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.provider_result.breach_hints?.length, 1);
  assert.match(JSON.stringify(snapshot?.provider_result.breach_hints?.[0]), /alice@evidence\.metrorex\.ro/);
});
