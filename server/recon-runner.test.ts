import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { resolvePythonCommand, runRecon } from "./recon-runner";

test("resolvePythonCommand prefers an explicit environment override", () => {
  const command = resolvePythonCommand({
    cwd: "C:\\repo",
    env: { OSINT_PYTHON_PATH: "C:\\Python312\\python.exe" },
    platform: "win32",
    fileExists: () => false,
  });

  assert.equal(command, "C:\\Python312\\python.exe");
});

test("resolvePythonCommand falls back to a local Windows virtualenv before PATH", () => {
  const expected = "C:\\repo\\.venv\\Scripts\\python.exe";
  const command = resolvePythonCommand({
    cwd: "C:\\repo",
    env: {},
    platform: "win32",
    fileExists: (candidate) => candidate === expected,
  });

  assert.equal(command, expected);
});

test("runRecon rejects when the Python process cannot be spawned", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  const runPromise = runRecon({
    companyName: "OpenAI",
    cwd: "C:\\repo",
    env: {},
    platform: "win32",
    fileExists: () => false,
    spawnProcess: () => {
      queueMicrotask(() => child.emit("error", new Error("spawn python ENOENT")));
      return child as never;
    },
  });

  await assert.rejects(runPromise, /spawn python ENOENT/);
});

test("runRecon uses the configured timeout from the environment", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  let observedTimeout: number | undefined;

  const runPromise = runRecon({
    companyName: "OpenAI",
    cwd: "C:\\repo",
    env: { RECON_TIMEOUT_MS: "180000" },
    platform: "win32",
    fileExists: () => false,
    spawnProcess: (_command, _args, options) => {
      observedTimeout = options.timeout;
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"ok":true}'));
        child.emit("close");
      });
      return child as never;
    },
  });

  const result = await runPromise;

  assert.equal(observedTimeout, 180000);
  assert.deepEqual(result.data, { ok: true });
});

test("runRecon uses a default timeout long enough for slower recon scans", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  let observedTimeout: number | undefined;

  const runPromise = runRecon({
    companyName: "metrorex",
    cwd: "C:\\repo",
    env: {},
    platform: "win32",
    fileExists: () => false,
    spawnProcess: (_command, _args, options) => {
      observedTimeout = options.timeout;
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"ok":true}'));
        child.emit("close");
      });
      return child as never;
    },
  });

  const result = await runPromise;

  assert.equal(observedTimeout, 600000);
  assert.deepEqual(result.data, { ok: true });
});

test("runRecon reports a timeout-specific error when the child is terminated before producing JSON", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();

  const runPromise = runRecon({
    companyName: "tarom.ro",
    cwd: "C:\\repo",
    env: {},
    platform: "win32",
    fileExists: () => false,
    spawnProcess: () => {
      queueMicrotask(() => {
        child.stderr.emit("data", Buffer.from("[*] Email harvesting: tarom.ro"));
        child.emit("close", null, "SIGTERM");
      });
      return child as never;
    },
  });

  await assert.rejects(
    runPromise,
    /OSINT scan exceeded the configured timeout before producing JSON output/,
  );
});

test("runRecon passes selected provider IDs to the Python process environment", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  let observedSelectedSources: string | undefined;

  const runPromise = runRecon({
    companyName: "metrorex.ro",
    selectedSources: ["theharvester", "duckduckgo", "crtsh"],
    cwd: "C:\\repo",
    env: {},
    platform: "win32",
    fileExists: () => false,
    spawnProcess: (_command, _args, options) => {
      observedSelectedSources = options.env.OSINT_SELECTED_SOURCES;
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"ok":true}'));
        child.emit("close");
      });
      return child as never;
    },
  });

  const result = await runPromise;

  assert.equal(observedSelectedSources, JSON.stringify(["theharvester", "duckduckgo", "crtsh"]));
  assert.deepEqual(result.data, { ok: true });
});

test("runRecon forwards configured RocketReach credentials to the Python process", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  let observedKey: string | undefined;

  const runPromise = runRecon({
    companyName: "OpenAI",
    selectedSources: ["rocketreach"],
    cwd: "C:\\repo",
    env: { ROCKETREACH_API_KEY: "rr-test-key" },
    platform: "win32",
    fileExists: () => false,
    spawnProcess: (_command, _args, options) => {
      observedKey = options.env.ROCKETREACH_API_KEY;
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"ok":true}'));
        child.emit("close");
      });
      return child as never;
    },
  });

  await runPromise;

  assert.equal(observedKey, "rr-test-key");
});

test("runRecon forwards configured GitHub and HIBP credentials to the Python process", async () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    stderr = new EventEmitter();
  }

  const child = new FakeChild();
  let observedGithubToken: string | undefined;
  let observedHibpKey: string | undefined;

  const runPromise = runRecon({
    companyName: "OpenAI",
    selectedSources: ["github_code", "hibp"],
    cwd: "C:\\repo",
    env: { GITHUB_TOKEN: "gh-test-token", HIBP_API_KEY: "hibp-test-key" },
    platform: "win32",
    fileExists: () => false,
    spawnProcess: (_command, _args, options) => {
      observedGithubToken = options.env.GITHUB_TOKEN;
      observedHibpKey = options.env.HIBP_API_KEY;
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"ok":true}'));
        child.emit("close");
      });
      return child as never;
    },
  });

  await runPromise;

  assert.equal(observedGithubToken, "gh-test-token");
  assert.equal(observedHibpKey, "hibp-test-key");
});
