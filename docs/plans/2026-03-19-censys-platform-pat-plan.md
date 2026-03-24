# Censys Platform PAT Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the app's Legacy Search Censys auth flow with a Platform API PAT flow using `Censys_Token`.

**Architecture:** Update env handling, switch the Censys runtime helper to read the PAT, keep the same provider-results shape, and rewrite the tests around bearer-auth behavior.

**Tech Stack:** Python, unittest, Node.js, TypeScript

---

### Task 1: Write failing Censys PAT tests

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine_test.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\server\env.test.ts`

**Step 1: Write the failing tests**

- verify `Censys_Token` is documented
- verify bearer auth is used for Censys requests
- verify invalid PAT notes

**Step 2: Run tests to verify they fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test -v
node --test --import tsx server/env.test.ts
```

**Step 3: Write minimal implementation**

- switch the helper to `Censys_Token`
- remove legacy credential-shape logic

**Step 4: Run tests to verify they pass**

Run the same commands and confirm green.

### Task 2: Update runtime and catalog

**Files:**
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\osint_engine.py`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\shared\osint-providers.ts`
- Modify: `c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon\.env.example`

**Step 1: Implement PAT-based runtime**

- read `Censys_Token`
- use bearer auth
- improve status notes

**Step 2: Update provider docs text**

- make the provider text match PAT-based behavior

**Step 3: Run targeted verification**

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test -v
```

### Task 3: Full verification and live test

**Files:**
- Verify only

**Step 1: Run automated checks**

```powershell
.\.venv\Scripts\python.exe -m unittest osint_engine_test.py -v
node --test --import tsx server/env.test.ts server/provider-catalog.test.ts server/recon-runner.test.ts server/typecheck.test.ts
npm run check
npm run build
```

**Step 2: Restart the live app and test `censys`**

- confirm `/api/health`
- call `/api/recon` with `sources: ["censys"]`
- inspect provider notes/results
