import assert from "node:assert/strict";
import test from "node:test";

import { getSherlockJob, startSherlockJob } from "./sherlock-jobs";

test("startSherlockJob starts a background Sherlock scan and stores the returned report", async () => {
  const job = await startSherlockJob({
    companyName: "expertware.net",
    runReconImpl: async () => ({
      data: {
        provider_results: {
          sherlock: {
            status: "ok",
            notes: [],
            duration_ms: 1234,
            progress_logs: [],
            social_profiles: [
              { GitHub: { url: "https://github.com/expertware", status: "found", source: "sherlock" } },
            ],
            impersonation_candidates: [],
            emails: [],
            email_sources: [],
            mentions: [],
            subdomains: [],
            repos: [],
            breach_hints: [],
            dns_records: [],
            whois: [],
            ssl: [],
            tech: [],
            ports: [],
            hosting: [],
          },
        },
        identities: {
          domain: "expertware.net",
          emails: [],
          email_sources: [],
          email_format: null,
          github_repos: [],
          social_profiles: {},
          impersonation_candidates: [],
          breaches: [],
          provider_results: {},
          threat_intelligence: { findings: [] },
        },
      },
      logs: "[*] Sherlock completed",
    }),
  });

  await new Promise((resolve) => setTimeout(resolve, 0));

  const snapshot = getSherlockJob(job.job_id);
  assert.equal(snapshot?.status, "completed");
  assert.equal(snapshot?.provider_id, "sherlock");
  assert.equal(snapshot?.target_domain, "expertware.net");
  assert.equal(snapshot?.provider_result.status, "ok");
  assert.equal((snapshot?.report?.provider_results as Record<string, any>)?.sherlock?.status, "ok");
  assert.deepEqual(snapshot?.progress_logs, ["[*] Sherlock completed"]);
});

test("startSherlockJob records startup failures as error jobs", async () => {
  const job = await startSherlockJob({
    companyName: "expertware.net",
    runReconImpl: async () => {
      throw new Error("Sherlock runner failed to start");
    },
  });

  await new Promise((resolve) => setTimeout(resolve, 0));

  const snapshot = getSherlockJob(job.job_id);
  assert.equal(snapshot?.status, "error");
  assert.equal(snapshot?.provider_result.status, "error");
  assert.match(snapshot?.error || "", /Sherlock runner failed to start/);
});
