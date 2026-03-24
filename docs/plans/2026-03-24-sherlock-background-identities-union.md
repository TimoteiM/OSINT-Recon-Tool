# Sherlock Background And Identities Union Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move Sherlock to a progressive background provider and make the Identities tab a canonical union of identity evidence from all providers.

**Architecture:** Keep the existing fast inline scan for website, DNS, tech, and fast identity providers, but treat Sherlock like SpiderFoot so it enriches in the background. Replace the current hand-curated identities assembly with a canonical union builder that derives top-level `identities` from `provider_results` and preserves provenance while deduplicating.

**Tech Stack:** TypeScript, React, Node test runner, existing Express routes, background job patterns, Python provider output

---

### Task 1: Add a canonical identity union helper

**Files:**
- Create: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-union.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-union.test.ts`
- Reuse: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-normalization.ts`

**Step 1: Write the failing test**

Add tests proving a mixed `provider_results` object contributes a union of:

- emails from multiple providers
- social profiles from multiple providers
- impersonation candidates from multiple providers
- provider-level email provenance where available

The test should also prove duplicate identities collapse into one canonical item.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: FAIL because the helper does not exist yet.

**Step 3: Write minimal implementation**

Create a helper that:

- reads provider-level identity evidence from all providers
- merges emails, `email_sources`, social profiles, impersonation candidates, GitHub repos, and breach-like identity hints where appropriate
- passes the combined result through the existing identity normalizer

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add client/src/lib/identity-union.ts client/src/lib/identity-union.test.ts
git commit -m "feat: add canonical identity union builder"
```

### Task 2: Rebuild Identities from provider results in the dashboard

**Files:**
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\pages\Dashboard.tsx`
- Reuse: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-union.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-union.test.ts`

**Step 1: Write the failing test**

Extend the union test so a report containing provider-level emails/social/impersonation but sparse top-level `identities` still produces the full merged identity view.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: FAIL because the dashboard still trusts top-level `identities` too directly.

**Step 3: Write minimal implementation**

Update `Dashboard.tsx` so:

- the Identities tab renders from the canonical union helper
- live provider merges rebuild the union after each provider update
- provider-specific cards remain unchanged, but top-level identities no longer miss provider evidence

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add client/src/pages/Dashboard.tsx client/src/lib/identity-union.test.ts
git commit -m "feat: rebuild identities from provider union"
```

### Task 3: Add Sherlock background job orchestration on the server

**Files:**
- Create or modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\sherlock-jobs.ts`
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\routes.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\routes.test.ts`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\sherlock-jobs.test.ts`

**Step 1: Write the failing test**

Add tests proving:

- selecting `sherlock` returns a successful initial scan without waiting for Sherlock completion
- a background Sherlock job record is attached
- startup failures degrade to provider error details rather than 500ing the request

**Step 2: Run test to verify it fails**

Run:

```bash
node --test --import tsx server/routes.test.ts server/sherlock-jobs.test.ts
```

Expected: FAIL because Sherlock has no background job orchestration yet.

**Step 3: Write minimal implementation**

Implement a Sherlock background job module modeled after the SpiderFoot route shape, but only for the app’s needs:

- start a job
- track status and elapsed time
- store provider results for `social_profiles` and `impersonation_candidates`
- expose a polling endpoint or reuse a generic jobs route if appropriate

Keep the implementation intentionally narrower than SpiderFoot.

**Step 4: Run test to verify it passes**

Run:

```bash
node --test --import tsx server/routes.test.ts server/sherlock-jobs.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add server/routes.ts server/routes.test.ts server/sherlock-jobs.ts server/sherlock-jobs.test.ts
git commit -m "feat: run sherlock as background provider"
```

### Task 4: Remove Sherlock from the blocking identities path

**Files:**
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`

**Step 1: Write the failing test**

Add tests proving:

- `harvest_emails()` no longer blocks on Sherlock when running through the fast inline pass
- provider results still keep enough information for later Sherlock union merging

**Step 2: Run test to verify it fails**

Run:

```bash
C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests -v
```

Expected: FAIL because Sherlock still runs inline.

**Step 3: Write minimal implementation**

Refactor the identities stage so:

- inline Python scan excludes blocking Sherlock execution
- Sherlock-specific provider handling moves to the background route path
- fast identities still return emails/social data from non-Sherlock providers

**Step 4: Run test to verify it passes**

Run:

```bash
C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add osint_engine.py osint_engine_test.py
git commit -m "refactor: remove sherlock from blocking identities stage"
```

### Task 5: Wire live Sherlock updates into canonical Identities

**Files:**
- Modify: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\pages\Dashboard.tsx`
- Test: `C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\client\src\lib\identity-union.test.ts`

**Step 1: Write the failing test**

Add a test proving a live Sherlock job update enriches the canonical identities union with:

- new social profiles
- new impersonation candidates

without duplicating preexisting identity entries.

**Step 2: Run test to verify it fails**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: FAIL because live Sherlock updates are not merged yet.

**Step 3: Write minimal implementation**

Extend the dashboard job polling/merge path to support Sherlock background results and rebuild canonical identities after every update.

**Step 4: Run test to verify it passes**

Run: `node --test --import tsx client/src/lib/identity-union.test.ts`

Expected: PASS.

**Step 5: Commit**

```bash
git add client/src/pages/Dashboard.tsx client/src/lib/identity-union.test.ts
git commit -m "feat: merge live sherlock into canonical identities"
```

### Task 6: Full verification

**Files:**
- Verify only

**Step 1: Run focused TypeScript tests**

Run:

```bash
node --test --import tsx server/provider-catalog.test.ts server/routes.test.ts server/sherlock-jobs.test.ts client/src/lib/identity-normalization.test.ts client/src/lib/identity-union.test.ts client/src/lib/impersonation-candidates.test.ts
```

Expected: PASS.

**Step 2: Run Python tests**

Run:

```bash
C:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.venv\Scripts\python.exe -m unittest osint_engine_test.GoogleDorkProviderTests -v
```

Expected: PASS.

**Step 3: Run production build**

Run:

```bash
npm run build
```

Expected: PASS.

**Step 4: Manual sanity check**

Confirm that:

- all selectable providers are still preselected
- initial scan returns quickly even when Sherlock is selected
- Sherlock enriches later through live progress
- Identities displays a union of provider evidence rather than only a hardcoded subset

**Step 5: Commit**

```bash
git add .
git commit -m "feat: background sherlock and identities union"
```
