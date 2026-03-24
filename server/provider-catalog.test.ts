import assert from "node:assert/strict";
import test from "node:test";

import {
  getDefaultSelectedProviderIds,
  getSelectableProviderIds,
  osintProviders,
  serializeSelectedProviderIdsForRequest,
  stripSpiderfootProviderIds,
  sanitizeSelectedProviderIds,
} from "../shared/osint-providers";

test("provider catalog exposes implemented providers as default selections", () => {
  const ids = new Set(osintProviders.map((provider) => provider.id));
  const defaults = getDefaultSelectedProviderIds();
  const selectable = new Set(getSelectableProviderIds());

  assert.ok(ids.has("theharvester"));
  assert.ok(ids.has("recon_ng"));
  assert.ok(ids.has("direct_dns"));
  assert.ok(ids.has("ssl_inspection"));

  assert.ok(defaults.includes("whois"));
  assert.ok(defaults.includes("google_dorks"));
  assert.ok(defaults.includes("spiderfoot"));
  assert.ok(defaults.includes("spiderfoot_deep"));
  assert.ok(defaults.every((providerId) => selectable.has(providerId)));
  assert.ok(!defaults.includes("google"));
});

test("default-selected providers include every selectable provider", () => {
  assert.deepEqual(
    getDefaultSelectedProviderIds().slice().sort(),
    getSelectableProviderIds().slice().sort(),
  );
});

test("provider catalog separates selectable providers from visible-but-disabled ones", () => {
  const selectable = new Set(getSelectableProviderIds());

  assert.ok(selectable.has("theharvester"));
  assert.ok(selectable.has("dehashed"));
  assert.ok(selectable.has("rocketreach"));
  assert.ok(selectable.has("brave"));
  assert.ok(selectable.has("bufferoverun"));
  assert.ok(selectable.has("rapiddns"));
  assert.ok(selectable.has("threatminer"));
  assert.ok(selectable.has("urlscan"));
  assert.ok(selectable.has("hackertarget"));
  assert.ok(selectable.has("subdomaincenter"));
  assert.ok(selectable.has("subdomainfinderc99"));
  assert.ok(selectable.has("thc"));
  assert.ok(selectable.has("windvane"));
  assert.ok(selectable.has("google_dorks"));
  assert.ok(!selectable.has("google"));
  assert.ok(selectable.has("social_probe"));
  assert.ok(selectable.has("sherlock"));
  assert.ok(selectable.has("spiderfoot"));
  assert.ok(selectable.has("spiderfoot_deep"));
  assert.ok(selectable.has("projectdiscovery"));
  assert.ok(selectable.has("censys"));
  assert.ok(!selectable.has("baidu"));
  assert.ok(!selectable.has("yahoo"));
  assert.ok(!selectable.has("shodan"));
});

test("provider sanitization aliases legacy google selections to google_dorks", () => {
  assert.deepEqual(
    sanitizeSelectedProviderIds(["google", "google_dorks", "whois", "unknown"]),
    ["google_dorks", "whois"],
  );
});

test("request serialization aliases google_dorks back to google for older servers", () => {
  assert.deepEqual(
    serializeSelectedProviderIdsForRequest(["google_dorks", "whois"]),
    ["google", "whois"],
  );
});

test("stripSpiderfootProviderIds removes both SpiderFoot modes for fallback retries", () => {
  assert.deepEqual(
    stripSpiderfootProviderIds(["whois", "spiderfoot", "spiderfoot_deep", "google_dorks"]),
    ["whois", "google_dorks"],
  );
});
