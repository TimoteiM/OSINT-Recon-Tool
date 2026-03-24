# Keyed Provider Alignment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Align the app with the user’s existing keyed-provider `.env` names and make Brave, RocketReach, HIBP, Hunter, ProjectDiscovery, and Censys truthfully implemented in the runtime and provider catalog.

**Architecture:** Add centralized auth helpers in `osint_engine.py`, upgrade the keyed provider request paths to use the exact local env names, implement `projectdiscovery` and `censys` as real provider-result producers, and update the shared provider catalog to match runtime truth. Drive the work test-first and keep the server env contract stable.

**Tech Stack:** Python, Node.js, TypeScript, unittest, node:test, Vite/React shared catalog

---

### Task 1: Lock env-name handling with tests

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\env.test.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env.example`

**Step 1: Write the failing tests**

- Add Python tests that prove the engine reads the existing local env names for:
  - Brave
  - HIBP
  - Hunter
  - ProjectDiscovery
  - Censys
- Add/update Node env-file tests so `.env.example` documents the new names.

**Step 2: Run tests to verify they fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/env.test.ts
```

Expected: failures showing missing helper behavior or missing env docs.

**Step 3: Write minimal implementation**

- Add/update env helper functions in `osint_engine.py`.
- Extend `.env.example` with the exact provider key names the runtime will now use.

**Step 4: Run tests to verify they pass**

Run the same commands and confirm the new tests pass.

### Task 2: Upgrade authenticated HIBP and Hunter flows

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`

**Step 1: Write the failing tests**

- Add tests for:
  - HIBP requests using the existing env name, `hibp-api-key`, and `user-agent`
  - Hunter API calls using the existing env names and authenticated domain-search parameters
  - provider-result notes for empty success cases

**Step 2: Run tests to verify they fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
```

Expected: failing assertions on headers, query parameters, or provider notes.

**Step 3: Write minimal implementation**

- Replace limited HIBP auth handling with the documented authenticated headers.
- Normalize Hunter key selection and use the authenticated API path.
- Update provider catalog text/status to reflect the authenticated implementation.

**Step 4: Run tests to verify they pass**

Run the same Python test command and confirm green.

### Task 3: Implement ProjectDiscovery Chaos as a real provider

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing tests**

- Add tests proving `projectdiscovery`:
  - becomes selectable
  - reads `Project_Discovery_API_KEY`
  - records subdomains into `provider_results`

**Step 2: Run tests to verify they fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/provider-catalog.test.ts
```

Expected: failures for missing runtime support and catalog mismatch.

**Step 3: Write minimal implementation**

- Add Chaos API request logic to the passive subdomain collection path.
- Record exact provider-owned subdomain evidence and notes.
- Mark the provider as selectable in the shared catalog.

**Step 4: Run tests to verify they pass**

Run the same commands and confirm green.

### Task 4: Implement Censys as a real provider

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\provider-catalog.test.ts`

**Step 1: Write the failing tests**

- Add tests proving `censys`:
  - becomes selectable
  - parses the existing `Censys_Token` format correctly
  - records subdomains / cert or host evidence into `provider_results`

**Step 2: Run tests to verify they fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/provider-catalog.test.ts
```

Expected: failures for missing helper behavior and provider catalog mismatch.

**Step 3: Write minimal implementation**

- Add credential parsing and a minimal Censys host/cert lookup.
- Record exact evidence and provider notes.
- Mark `censys` as selectable with truthful details.

**Step 4: Run tests to verify they pass**

Run the same commands and confirm green.

### Task 5: Full verification and live smoke test

**Files:**
- Verify only

**Step 1: Run the full automated verification**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts
npm run check
npm run build
```

**Step 2: Run a live smoke test**

Run one or two direct recon requests using keyed providers and confirm:

- API returns `200`
- provider cards receive evidence or explicit auth/empty-result notes
- new catalog entries are visible/selectable

**Step 3: Summarize actual outcomes**

- Report which providers are now truly active
- Report any residual limitations honestly
