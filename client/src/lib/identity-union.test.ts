import assert from "node:assert/strict";
import test from "node:test";

import { buildCanonicalIdentitiesFromProviders } from "./identity-union";

test("buildCanonicalIdentitiesFromProviders merges identity evidence from all providers into one union", () => {
  const result = buildCanonicalIdentitiesFromProviders(
    {
      domain: "example.com",
      emails: ["contact@example.com"],
      email_format: "firstname@domain",
      github_repos: [],
      social_profiles: {
        LinkedIn: { url: "https://linkedin.com/company/example", status: "found", source: "wikidata" },
      },
      impersonation_candidates: [],
      breaches: [],
    },
    {
      hunter: {
        status: "ok",
        notes: [],
        emails: ["press@example.com"],
        email_sources: [
          {
            email: "press@example.com",
            module: "hunter",
            module_type: "api",
            event_type: "EMAILADDR",
            source: "hunter",
            api_backed: true,
          },
        ],
      },
      sherlock: {
        status: "ok",
        notes: [],
        social_profiles: [
          {
            GitHub: { url: "https://github.com/example", status: "found", source: "sherlock" },
          },
        ],
        impersonation_candidates: [
          {
            platform: "GitHub",
            username: "example_support",
            url: "https://github.com/example_support",
            reason: "support suffix variation",
            source: "sherlock",
          },
        ],
      },
      google_dorks: {
        status: "ok",
        notes: [],
        emails: ["security@example.com"],
        mentions: [
          {
            category: "social",
            title: "Example on Facebook",
            url: "https://facebook.com/example",
            snippet: "Official profile",
            source_domain: "facebook.com",
            matched_domain: "example.com",
            query: 'site:facebook.com "example"',
          },
        ],
        repos: [
          {
            name: "example/tools",
            url: "https://github.com/example/tools",
            stars: 20,
            description: "Example tools",
          },
        ],
      },
      spiderfoot_deep: {
        status: "ok",
        notes: [],
        social_profiles: {
          Instagram: { url: "https://instagram.com/example", status: "found", source: "spiderfoot_deep" },
        },
      },
    } as Record<string, any>,
  );

  assert.deepEqual(result.emails, [
    "contact@example.com",
    "press@example.com",
    "security@example.com",
  ]);
  assert.equal(result.email_sources?.length, 1);
  assert.deepEqual(Object.keys(result.social_profiles), ["LinkedIn", "GitHub", "Facebook", "Instagram"]);
  assert.equal(result.github_repos.length, 1);
  assert.equal(result.impersonation_candidates?.length, 1);
});

test("buildCanonicalIdentitiesFromProviders deduplicates overlapping provider evidence", () => {
  const result = buildCanonicalIdentitiesFromProviders(
    {
      domain: "example.com",
      emails: ["Press@Example.com"],
      email_format: null,
      github_repos: [],
      social_profiles: {},
      impersonation_candidates: [],
      breaches: [],
    },
    {
      hunter: {
        status: "ok",
        notes: [],
        emails: ["press@example.com"],
        email_sources: [
          {
            email: "press@example.com",
            module: "hunter",
            module_type: "api",
            event_type: "EMAILADDR",
            source: "hunter",
            api_backed: true,
          },
        ],
      },
      google_dorks: {
        status: "ok",
        notes: [],
        mentions: [
          {
            category: "social",
            title: "Example on Facebook",
            url: "https://www.facebook.com/example/",
            snippet: "Official profile",
            source_domain: "facebook.com",
            matched_domain: "example.com",
            query: 'site:facebook.com "example"',
          },
        ],
      },
      social_probe: {
        status: "ok",
        notes: [],
        social_profiles: [
          {
            Facebook: { url: "https://facebook.com/example", status: "found", source: "social_probe" },
          },
        ],
      },
    } as Record<string, any>,
  );

  assert.deepEqual(result.emails, ["press@example.com"]);
  assert.equal(result.email_sources?.[0].module, "hunter");
  assert.deepEqual(result.social_profiles, {
    Facebook: { url: "https://facebook.com/example", status: "found", source: "social_probe" },
  });
});
