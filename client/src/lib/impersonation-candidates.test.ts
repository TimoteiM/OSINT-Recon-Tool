import assert from "node:assert/strict";
import test from "node:test";

import { cleanImpersonationCandidates, type IdentityCandidate } from "./impersonation-candidates";

test("cleanImpersonationCandidates deduplicates candidates that normalize to the same clickable URL", () => {
  const candidates: IdentityCandidate[] = [
    {
      username: "Freelancer (Category: work)\n&lt;SFURL&gt;https://www.freelancer.com/u/expertware&lt;/SFURL&gt;",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
    {
      platform: "Freelancer",
      username: "expertware",
      url: "https://www.freelancer.com/u/expertware",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ];

  assert.deepEqual(cleanImpersonationCandidates(candidates), [
    {
      platform: "Freelancer",
      username: "expertware",
      url: "https://www.freelancer.com/u/expertware",
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    },
  ]);
});
