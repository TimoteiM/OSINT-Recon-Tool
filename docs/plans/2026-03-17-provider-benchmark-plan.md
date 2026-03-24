# Provider Benchmark Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Benchmark all selectable providers across 50 representative domains and produce an explicit keep/conditional/drop recommendation for each provider.

**Architecture:** Run the benchmark directly through `osint_engine.py` with the current selectable provider set, capture `provider_results` for each domain, and aggregate counts, evidence types, and failure notes into a final summary. Use the benchmark as an evaluation artifact rather than modifying application behavior.

**Tech Stack:** Python, existing OSINT engine, PowerShell command execution

---

### Task 1: Define benchmark inputs

**Files:**
- Create: `docs/plans/2026-03-17-provider-benchmark-design.md`
- Create: `docs/plans/2026-03-17-provider-benchmark-plan.md`

**Step 1: Choose a representative 50-domain sample**

Use a balanced public sample across multiple industries and organization types.

**Step 2: Confirm provider scope**

Include all currently selectable providers, even weak or failing ones.

### Task 2: Run the batch benchmark

**Files:**
- No source edits required

**Step 1: Execute a direct-engine batch run**

Run `osint_engine.run_recon()` against all 50 domains with the selectable provider set.

**Step 2: Capture per-provider evidence**

Persist domain-level provider status, notes, and evidence counts for aggregation.

### Task 3: Aggregate results

**Files:**
- No source edits required

**Step 1: Summarize provider performance**

Compute:
- domains with findings
- total findings by provider and evidence type
- frequent failure modes

**Step 2: Classify providers**

Assign `Keep`, `Conditional`, or `Drop` based on consistency, signal, and operational cost.

### Task 4: Report conclusions

**Files:**
- No source edits required

**Step 1: Present the tested domain list**

Include the exact 50 domains used.

**Step 2: Present provider recommendations**

List each provider with results, failure notes, and recommendation.

**Step 3: Call out residual risk**

Document that live API/UI benchmarking remains more fragile than direct-engine benchmarking because the Node server has shown instability on long scans.
