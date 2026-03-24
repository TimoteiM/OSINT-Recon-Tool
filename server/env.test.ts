import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadEnvFile } from "./env";

test("loadEnvFile reads key/value pairs into the provided environment", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "osint-env-"));
  const envPath = path.join(tempDir, ".env");
  fs.writeFileSync(
    envPath,
    "ROCKETREACH_API_KEY=test-key\nBRAVE_SEARCH_API_KEY=brave-test-key\nHaveIBeenPwned_API_KEY=hibp-test-key\nHunter_API_KEY=hunter-test-key\nHunterIO_API_KEY=hunterio-test-key\nProject_Discovery_API_KEY=pd-test-key\nCensys_Token=censys-pat-test-token\nCensys_Organization_ID=org-123\nRECON_TIMEOUT_MS=420000\n",
    "utf8",
  );

  const env: NodeJS.ProcessEnv = {};
  loadEnvFile({ envPath, env });

  assert.equal(env.ROCKETREACH_API_KEY, "test-key");
  assert.equal(env.BRAVE_SEARCH_API_KEY, "brave-test-key");
  assert.equal(env.HaveIBeenPwned_API_KEY, "hibp-test-key");
  assert.equal(env.Hunter_API_KEY, "hunter-test-key");
  assert.equal(env.HunterIO_API_KEY, "hunterio-test-key");
  assert.equal(env.Project_Discovery_API_KEY, "pd-test-key");
  assert.equal(env.Censys_Token, "censys-pat-test-token");
  assert.equal(env.Censys_Organization_ID, "org-123");
  assert.equal(env.RECON_TIMEOUT_MS, "420000");
});
