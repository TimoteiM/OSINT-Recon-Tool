import assert from "node:assert/strict";
import http from "node:http";
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
  onStartscan?: (params?: Record<string, unknown>) => void;
}): FakeTransport {
  const scanstatusQueue = [...(responses.scanstatus || [])];
  const scanlogQueue = [...(responses.scanlog || [])];
  const scaneventresultsQueue = [...(responses.scaneventresults || [])];

  return {
    async postJson(path, params) {
      if (path === "/startscan") {
        responses.onStartscan?.(params);
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

test("SpiderFoot Deep starts with a dedicated enrichment configuration", async () => {
  let capturedParams: Record<string, unknown> | undefined;

  await startSpiderfootJob({
    companyName: "enrich.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-enrich"],
      onStartscan: (params) => {
        capturedParams = params;
      },
    }),
    schedulePolling: false,
  });

  assert.equal(capturedParams?.usecase, "all");
  assert.equal(typeof capturedParams?.modulelist, "string");
  assert.notEqual(capturedParams?.modulelist, "");
  assert.match(String(capturedParams?.typelist), /EMAILADDR_COMPROMISED/);
  assert.match(String(capturedParams?.typelist), /EMAILADDR_GENERIC/);
  assert.match(String(capturedParams?.typelist), /LEAKSITE_URL/);
  assert.equal(capturedParams?.scantarget, "enrich.metrorex.ro");
});

test("SpiderFoot Deep seeds domain-driven scans with the normalized target domain when available", async () => {
  let capturedParams: Record<string, unknown> | undefined;

  await startSpiderfootJob({
    companyName: "https://www.metrorex.ro/company/about",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-domain-target"],
      onStartscan: (params) => {
        capturedParams = params;
      },
    }),
    schedulePolling: false,
  });

  assert.equal(capturedParams?.scantarget, "www.metrorex.ro");
});

test("SpiderFoot Deep derives authenticated module options from env", async () => {
  let optionCalls: Array<Record<string, unknown>> = [];

  await startSpiderfootJob({
    companyName: "auth.metrorex.ro",
    providerId: "spiderfoot_deep",
    env: {
      ...process.env,
      Hunter_API_KEY: "hunter-key",
      HaveIBeenPwned_API_KEY: "hibp-key",
    },
    ensureService: async () => {},
    transport: {
      async postJson(path, params) {
        if (path === "/savesettingsraw") {
          const parsed = JSON.parse(String(params?.allopts || "{}")) as Record<string, string>;
          const [key, val] = Object.entries(parsed)[0] || [];
          const [, mod, opt] = (key || "").split(".");
          optionCalls.push({ mod, opt, val });
          return ["SUCCESS", "OK"];
        }
        if (path === "/startscan") {
          return ["SUCCESS", "scan-auth"];
        }
        throw new Error(`Unhandled POST ${path}`);
      },
      async getJson(path) {
        if (path === "/scanlist") return [];
        if (path === "/optsraw") return ["SUCCESS", { token: "test-token", data: {} }];
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.deepEqual(optionCalls, [
    { opt: "api_key", val: "hunter-key", mod: "sfp_hunter" },
    { opt: "api_key", val: "hibp-key", mod: "sfp_haveibeenpwned" },
  ]);
});

test("SpiderFoot Deep falls back to HunterIO env key when Hunter_API_KEY is missing", async () => {
  let optionCalls: Array<Record<string, unknown>> = [];

  await startSpiderfootJob({
    companyName: "hunterio.metrorex.ro",
    providerId: "spiderfoot_deep",
    env: {
      ...process.env,
      HunterIO_API_KEY: "hunterio-key",
    },
    ensureService: async () => {},
    transport: {
      async postJson(path, params) {
        if (path === "/savesettingsraw") {
          const parsed = JSON.parse(String(params?.allopts || "{}")) as Record<string, string>;
          const [key, val] = Object.entries(parsed)[0] || [];
          const [, mod, opt] = (key || "").split(".");
          optionCalls.push({ mod, opt, val });
          return ["SUCCESS", "OK"];
        }
        if (path === "/startscan") {
          return ["SUCCESS", "scan-hunterio"];
        }
        throw new Error(`Unhandled POST ${path}`);
      },
      async getJson(path) {
        if (path === "/scanlist") return [];
        if (path === "/optsraw") return ["SUCCESS", { token: "test-token", data: {} }];
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.deepEqual(optionCalls, [
    { opt: "api_key", val: "hunterio-key", mod: "sfp_hunter" },
  ]);
});

test("SpiderFoot Deep accepts numeric optsraw tokens from the live SpiderFoot API", async () => {
  let savedToken = "";

  await startSpiderfootJob({
    companyName: "numeric-token.metrorex.ro",
    providerId: "spiderfoot_deep",
    env: {
      ...process.env,
      Hunter_API_KEY: "hunter-key",
    },
    ensureService: async () => {},
    transport: {
      async postJson(path, params) {
        if (path === "/savesettingsraw") {
          savedToken = String(params?.token || "");
          return ["SUCCESS", "OK"];
        }
        if (path === "/startscan") {
          return ["SUCCESS", "scan-numeric-token"];
        }
        throw new Error(`Unhandled POST ${path}`);
      },
      async getJson(path) {
        if (path === "/scanlist") return [];
        if (path === "/optsraw") return ["SUCCESS", { token: 45768763, data: {} }];
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.equal(savedToken, "45768763");
});

test("SpiderFoot Deep preserves the SpiderFoot session cookie across optsraw and savesettingsraw", async () => {
  let sawCookieOnSave = false;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/scanlist") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([]));
      return;
    }

    if (req.method === "GET" && url.pathname === "/optsraw") {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "spiderfoot=test-session; Path=/",
      });
      res.end(JSON.stringify(["SUCCESS", { token: 49866519, data: {} }]));
      return;
    }

    if (req.method === "POST" && url.pathname === "/savesettingsraw") {
      sawCookieOnSave = String(req.headers.cookie || "").includes("spiderfoot=test-session");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(sawCookieOnSave
        ? ["SUCCESS", "OK"]
        : ["ERROR", "Invalid token (49866519)."]));
      return;
    }

    if (req.method === "POST" && url.pathname === "/startscan") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(["SUCCESS", "scan-cookie-aware"]));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify(["ERROR", "Not found"]));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");

  try {
    const job = await startSpiderfootJob({
      companyName: "cookie.metrorex.ro",
      providerId: "spiderfoot_deep",
      env: {
        ...process.env,
        SPIDERFOOT_API_BASE_URL: `http://127.0.0.1:${address.port}`,
        Hunter_API_KEY: "hunter-key",
      },
      ensureService: async () => {},
      schedulePolling: false,
    });

    assert.equal(job.scan_id, "scan-cookie-aware");
    assert.equal(sawCookieOnSave, true);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("lightweight SpiderFoot does not apply deep authenticated module options", async () => {
  let optionCalls = 0;

  await startSpiderfootJob({
    companyName: "plain.metrorex.ro",
    providerId: "spiderfoot",
    env: {
      ...process.env,
      Hunter_API_KEY: "hunter-key",
      HaveIBeenPwned_API_KEY: "hibp-key",
    },
    ensureService: async () => {},
    transport: {
      async postJson(path) {
        if (path === "/savesettingsraw") {
          optionCalls += 1;
          return ["SUCCESS", "OK"];
        }
        if (path === "/startscan") {
          return ["SUCCESS", "scan-plain"];
        }
        throw new Error(`Unhandled POST ${path}`);
      },
      async getJson(path) {
        if (path === "/scanlist") return [];
        if (path === "/optsraw") return ["SUCCESS", { token: "test-token", data: {} }];
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.equal(optionCalls, 0);
});

test("lightweight SpiderFoot reuses an existing in-memory running job before calling SpiderFoot again", async () => {
  const firstJob = await startSpiderfootJob({
    companyName: "reuse-job.metrorex.ro",
    providerId: "spiderfoot",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "MEM12345"],
    }),
    schedulePolling: false,
  });

  let touchedSpiderFoot = false;
  const secondJob = await startSpiderfootJob({
    companyName: "reuse-job.metrorex.ro",
    providerId: "spiderfoot",
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

test("SpiderFoot Deep starts a fresh in-memory job instead of reusing a running one for the same target", async () => {
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
        return ["SUCCESS", "MEM67890"];
      },
      async getJson(path) {
        touchedSpiderFoot = true;
        if (path === "/scanlist") {
          return [];
        }
        if (path === "/optsraw") {
          return ["SUCCESS", { token: "test-token", data: {} }];
        }
        throw new Error(`Unhandled GET ${path}`);
      },
    },
    schedulePolling: false,
  });

  assert.equal(touchedSpiderFoot, true);
  assert.notEqual(secondJob.job_id, firstJob.job_id);
  assert.notEqual(secondJob.scan_id, firstJob.scan_id);
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
        ["2026-03-23 10:00:01", "contact@poll.metrorex.ro", "poll.metrorex.ro", "sfp_emailformat", 100, 100, 0, "id-1", 0, 0, "EMAILADDR"],
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
        ["2026-03-23 10:00:01", "contact@poll.metrorex.ro", "poll.metrorex.ro", "sfp_emailformat", 100, 100, 0, "id-1", 0, 0, "EMAILADDR"],
        ["2026-03-23 10:00:02", "mail.poll.metrorex.ro", "poll.metrorex.ro", "module", 100, 100, 0, "id-2", 0, 0, "INTERNET_NAME"],
        ["2026-03-23 10:00:03", "95.76.156.205", "poll.metrorex.ro", "module", 100, 100, 0, "id-3", 0, 0, "IP_ADDRESS"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.emails, ["contact@poll.metrorex.ro"]);
  assert.deepEqual(snapshot?.provider_result.email_sources, [
    {
      api_backed: false,
      email: "contact@poll.metrorex.ro",
      event_type: "EMAILADDR",
      module: "sfp_emailformat",
      module_type: "public",
      source: "poll.metrorex.ro",
    },
  ]);
  assert.deepEqual(snapshot?.provider_result.subdomains, ["mail.poll.metrorex.ro"]);
  assert.deepEqual(snapshot?.provider_result.hosting, [{ value: "95.76.156.205", type: "IP_ADDRESS" }]);
  assert.match(snapshot?.progress_logs[0] ?? "", /Email harvesting/);
  assert.deepEqual((snapshot?.report?.identities as Record<string, unknown> | undefined)?.email_sources, [
    {
      api_backed: false,
      email: "contact@poll.metrorex.ro",
      event_type: "EMAILADDR",
      module: "sfp_emailformat",
      module_type: "public",
      source: "poll.metrorex.ro",
    },
  ]);
});

test("pollSpiderfootJob treats generic SpiderFoot mailbox events as discovered emails", async () => {
  const job = await startSpiderfootJob({
    companyName: "generic.metrorex.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-generic"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-generic", "generic.metrorex.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-24 10:00:00", "INFO", "STATUS", "Generic email harvesting", 5]]],
      scaneventresults: [[
        ["2026-03-24 10:00:01", "info@generic.metrorex.ro", "generic.metrorex.ro", "sfp_hunter", 100, 100, 0, "generic-1", 0, 0, "EMAILADDR_GENERIC"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.emails, ["info@generic.metrorex.ro"]);
  assert.deepEqual(snapshot?.provider_result.email_sources, [
    {
      api_backed: true,
      email: "info@generic.metrorex.ro",
      event_type: "EMAILADDR_GENERIC",
      module: "sfp_hunter",
      module_type: "api",
      source: "generic.metrorex.ro",
    },
  ]);
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

test("SpiderFoot Deep maps breach, social, and clickable account events into provider findings", async () => {
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
        ["2026-03-23 10:00:05", "GitHub <SFURL>https://github.com/metrorex-support</SFURL>", "metrorex.ro", "module", 100, 100, 0, "deep-5", 0, 0, "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.provider_id, "spiderfoot_deep");
  assert.ok((snapshot?.provider_result.breach_hints || []).length > 0);
  assert.equal(snapshot?.provider_result.social_profiles.Facebook?.url, "https://facebook.com/metrorex.support");
  assert.ok((snapshot?.provider_result.impersonation_candidates || []).length > 0);
});

test("SpiderFoot Deep promotes clean profile URLs into social presence and clickable impersonation candidates", async () => {
  const job = await startSpiderfootJob({
    companyName: "profiles.revantage.com",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-profiles"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-profiles", "revantage.com", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-24 10:00:00", "INFO", "STATUS", "Profile enrichment", 20]]],
      scaneventresults: [[
        ["2026-03-24 10:00:01", "https://www.linkedin.com/company/revantage/", "revantage.com", "module", 100, 100, 0, "profile-1", 0, 0, "SOCIAL_MEDIA"],
        ["2026-03-24 10:00:02", "Docker Hub (Organization) <SFURL>https://hub.docker.com/u/revantage</SFURL>", "revantage.com", "module", 100, 100, 0, "profile-2", 0, 0, "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.provider_result.social_profiles.LinkedIn?.url, "https://www.linkedin.com/company/revantage");
  assert.deepEqual(snapshot?.provider_result.impersonation_candidates, [
    {
      platform: "Docker Hub",
      username: "revantage",
      url: "https://hub.docker.com/u/revantage",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ]);
});

test("SpiderFoot Deep normalizes HTML-escaped SFURL account candidates into clickable impersonation links", async () => {
  const job = await startSpiderfootJob({
    companyName: "tarom.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-escaped"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-escaped", "tarom.ro", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-24 10:00:00", "INFO", "STATUS", "Escaped profile parsing", 23]]],
      scaneventresults: [[
        ["2026-03-24 10:00:01", "Bandcamp (Category: music)\\n&lt;SFURL&gt;https://bandcamp.com/tarom&lt;/SFURL&gt;", "tarom.ro", "module", 100, 100, 0, "escaped-1", 0, 0, "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.impersonation_candidates, [
    {
      platform: "Bandcamp",
      username: "tarom",
      url: "https://bandcamp.com/tarom",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ]);
});

test("getSpiderfootJob upgrades legacy stored SpiderFoot impersonation candidates into clickable links", async () => {
  const job = await startSpiderfootJob({
    companyName: "legacy.tarom.ro",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-legacy"],
    }),
    schedulePolling: false,
  });

  const stored = getSpiderfootJob(job.job_id);
  if (!stored) throw new Error("expected stored job");
  stored.provider_result.impersonation_candidates = [
    {
      username: "Discogs (Category: music)\\n&lt;SFURL&gt;https://www.discogs.com/user/tarom&lt;/SFURL&gt;",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ];

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.impersonation_candidates, [
    {
      platform: "Discogs",
      username: "tarom",
      url: "https://www.discogs.com/user/tarom",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ]);
});

test("SpiderFoot Deep ignores bare usernames and malformed account strings without clickable URLs", async () => {
  const job = await startSpiderfootJob({
    companyName: "noise.revantage.com",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-no-click"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-no-click", "revantage.com", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-24 10:00:00", "INFO", "STATUS", "Noise filtering", 21]]],
      scaneventresults: [[
        ["2026-03-24 10:00:01", "revantage", "revantage.com", "module", 100, 100, 0, "noise-username", 0, 0, "USERNAME"],
        ["2026-03-24 10:00:02", "Blogspot (Category: blog) <SFURL>not-a-url</SFURL>", "revantage.com", "module", 100, 100, 0, "noise-blogspot", 0, 0, "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.deepEqual(snapshot?.provider_result.impersonation_candidates, []);
  assert.deepEqual(snapshot?.provider_result.social_profiles, {});
});

test("SpiderFoot Deep keeps leak hints when a leak event references a target-domain email", async () => {
  const job = await startSpiderfootJob({
    companyName: "leaks.revantage.com",
    providerId: "spiderfoot_deep",
    ensureService: async () => {},
    transport: createFakeSpiderfootTransport({
      startscan: ["SUCCESS", "scan-leaks"],
    }),
    schedulePolling: false,
  });

  await pollSpiderfootJob(job.job_id, {
    transport: createFakeSpiderfootTransport({
      scanstatus: [["scan-leaks", "leaks.revantage.com", "", "", "", "RUNNING", {}]],
      scanlog: [[["2026-03-24 10:00:00", "INFO", "STATUS", "Leak enrichment", 22]]],
      scaneventresults: [[
        ["2026-03-24 10:00:01", "https://paste.example/leak analyst@leaks.revantage.com", "leaks.revantage.com", "module", 100, 100, 0, "leak-1", 0, 0, "LEAKSITE_URL"],
        ["2026-03-24 10:00:02", "generic unrelated leak", "leaks.revantage.com", "module", 100, 100, 0, "leak-2", 0, 0, "LEAKSITE_CONTENT"],
      ]],
    }),
  });

  const snapshot = getSpiderfootJob(job.job_id);
  assert.equal(snapshot?.provider_result.breach_hints?.length, 1);
  assert.match(JSON.stringify(snapshot?.provider_result.breach_hints?.[0]), /analyst@leaks\.revantage\.com/);
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
