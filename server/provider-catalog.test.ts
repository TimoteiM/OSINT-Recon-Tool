import assert from "node:assert/strict";
import test from "node:test";

import {
  getDefaultSelectedProviderIds,
  getSelectableProviderIds,
  osintProviders,
} from "../shared/osint-providers";

test("provider catalog exposes implemented providers as default selections", () => {
  const ids = new Set(osintProviders.map((provider) => provider.id));
  const defaults = getDefaultSelectedProviderIds();

  assert.ok(ids.has("theharvester"));
  assert.ok(ids.has("recon_ng"));
  assert.ok(ids.has("direct_dns"));
  assert.ok(ids.has("ssl_inspection"));

  assert.ok(defaults.includes("whois"));
  assert.ok(defaults.includes("port_scan"));
  assert.ok(defaults.includes("tech_fingerprint"));
  assert.ok(!defaults.includes("direct_dns"));
  assert.ok(!defaults.includes("ssl_inspection"));
  assert.ok(!defaults.includes("ipwhois"));
  assert.ok(!defaults.includes("crtsh"));
  assert.ok(!defaults.includes("duckduckgo"));
  assert.ok(!defaults.includes("bing"));
  assert.ok(!defaults.includes("social_probe"));
  assert.ok(!defaults.includes("theharvester"));
  assert.ok(!defaults.includes("recon_ng"));
  assert.ok(!defaults.includes("hunter"));
  assert.ok(!defaults.includes("phonebook_cz"));
  assert.ok(!defaults.includes("github_code"));
  assert.ok(!defaults.includes("github_repos"));
  assert.ok(!defaults.includes("hibp"));
  assert.ok(!defaults.includes("dehashed"));
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
  assert.ok(selectable.has("google"));
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
