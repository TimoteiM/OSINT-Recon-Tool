import assert from "node:assert/strict";
import test from "node:test";

import { normalizeIdentityData } from "./identity-normalization";

test("normalizeIdentityData deduplicates emails case-insensitively and keeps richer provenance", () => {
  const result = normalizeIdentityData({
    emails: ["Press@Example.com", "press@example.com", "info@example.com"],
    email_sources: [
      {
        email: "Press@Example.com",
        module: "sfp_emailformat",
        module_type: "public",
        event_type: "EMAILADDR_GENERIC",
        source: "spiderfoot_deep",
        api_backed: false,
      },
      {
        email: "press@example.com",
        module: "sfp_hunter",
        module_type: "api",
        event_type: "EMAILADDR",
        source: "spiderfoot_deep",
        api_backed: true,
      },
      {
        email: "info@example.com",
        module: "website_crawl",
        module_type: "unknown",
        event_type: "EMAILADDR",
        source: "website_crawl",
        api_backed: false,
      },
    ],
  });

  assert.deepEqual(result.emails, ["press@example.com", "info@example.com"]);
  assert.equal(result.email_sources?.length, 2);
  assert.deepEqual(result.email_sources?.[0], {
    email: "press@example.com",
    module: "sfp_hunter",
    module_type: "api",
    event_type: "EMAILADDR",
    source: "spiderfoot_deep",
    api_backed: true,
  });
});

test("normalizeIdentityData deduplicates social profiles by normalized platform and url", () => {
  const result = normalizeIdentityData({
    social_profiles: {
      LinkedIn: { url: "https://www.linkedin.com/company/example/", status: "found", source: "wikidata" },
      linkedin: { url: "https://linkedin.com/company/example", status: "found", source: "social_probe" },
      Instagram: { url: "https://instagram.com/example/", status: "found", source: "spiderfoot" },
    },
  });

  assert.deepEqual(result.social_profiles, {
    LinkedIn: { url: "https://linkedin.com/company/example", status: "found", source: "wikidata" },
    Instagram: { url: "https://instagram.com/example", status: "found", source: "spiderfoot" },
  });
});

test("normalizeIdentityData prefers stronger found social profiles when duplicates normalize together", () => {
  const result = normalizeIdentityData({
    social_profiles: [
      {
        LinkedIn: { url: "https://www.linkedin.com/company/example/", status: "possible" },
      },
      {
        linkedin: { url: "https://linkedin.com/company/example", status: "found", source: "social_probe" },
      },
    ],
  });

  assert.deepEqual(result.social_profiles, {
    LinkedIn: { url: "https://linkedin.com/company/example", status: "found", source: "social_probe" },
  });
});

test("normalizeIdentityData deduplicates impersonation candidates through the shared cleaner", () => {
  const result = normalizeIdentityData({
    impersonation_candidates: [
      {
        username: "Ameblo (Category: blog) <SFURL>https://ameblo.jp/tarom</SFURL>",
        reason: "SpiderFoot deep account candidate",
        source: "spiderfoot_deep",
      },
      {
        platform: "Ameblo",
        username: "tarom",
        url: "https://ameblo.jp/tarom/",
        reason: "SpiderFoot deep account candidate",
        source: "spiderfoot_deep",
      },
    ],
  });

  assert.equal(result.impersonation_candidates.length, 1);
  assert.deepEqual(result.impersonation_candidates[0], {
    platform: "Ameblo",
    username: "tarom",
    url: "https://ameblo.jp/tarom",
    reason: "SpiderFoot deep account candidate",
    source: "spiderfoot_deep",
  });
});
